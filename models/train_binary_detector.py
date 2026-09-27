from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler


BENIGN_ID = 0


def load_current(path: Path, split: str) -> tuple[np.ndarray, np.ndarray]:
    with np.load(path / f"{split}.npz", allow_pickle=False) as data:
        x = np.asarray(data["x"][:, -1, :], dtype=np.float64)
        current = np.asarray(data["current_label"], dtype=np.int64)
    y = np.where(current == BENIGN_ID, "BENIGN", "ATTACK")
    return x, y


def combine(public: tuple[np.ndarray, np.ndarray], local: tuple[np.ndarray, np.ndarray], repeat: int) -> tuple[np.ndarray, np.ndarray]:
    px, py = public
    lx, ly = local
    return np.concatenate([px, *([lx] * repeat)]), np.concatenate([py, *([ly] * repeat)])


def attack_probability(model: Any, x: np.ndarray) -> np.ndarray:
    raw = model.predict_proba(x)
    labels = [str(value) for value in model.classes_]
    return raw[:, labels.index("ATTACK")]


def ensemble_probability(logistic: Any, forest: Any, x: np.ndarray) -> np.ndarray:
    return (attack_probability(logistic, x) + attack_probability(forest, x)) / 2.0


def metrics(y: np.ndarray, probability: np.ndarray, threshold: float) -> dict[str, Any]:
    truth = y == "ATTACK"
    pred = probability >= threshold
    negative = ~truth
    return {
        "threshold": float(threshold),
        "recall": float(np.mean(pred[truth])) if truth.any() else 0.0,
        "fpr": float(np.mean(pred[negative])) if negative.any() else 0.0,
        "precision": float(np.mean(truth[pred])) if pred.any() else 1.0,
        "accuracy": float(np.mean(pred == truth)),
        "attack_samples": int(truth.sum()),
        "benign_samples": int(negative.sum()),
    }


def choose_threshold(y: np.ndarray, probability: np.ndarray, max_fpr: float = 0.01) -> dict[str, Any]:
    candidates = sorted(set(float(x) for x in np.concatenate([np.linspace(0.01, 0.99, 99), probability])))
    rows = [metrics(y, probability, threshold) for threshold in candidates]
    feasible = [row for row in rows if row["fpr"] <= max_fpr]
    if feasible:
        return max(feasible, key=lambda row: (row["recall"], row["precision"], -row["threshold"]))
    return min(rows, key=lambda row: (row["fpr"], -row["recall"]))


def main() -> int:
    parser = argparse.ArgumentParser(description="Train the production binary current-state attack detector challenger.")
    parser.add_argument("--public-dir", type=Path, required=True)
    parser.add_argument("--local-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--local-repeat", type=int, default=25)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    public_manifest = json.loads((args.public_dir / "manifest.json").read_text(encoding="utf-8"))
    local_manifest = json.loads((args.local_dir / "manifest.json").read_text(encoding="utf-8"))
    if list(public_manifest["features"]) != list(local_manifest["features"]):
        raise RuntimeError("feature schema mismatch")
    train_x, train_y = combine(load_current(args.public_dir, "train"), load_current(args.local_dir, "train"), args.local_repeat)
    public_val_x, public_val_y = load_current(args.public_dir, "val")
    local_val_x, local_val_y = load_current(args.local_dir, "val")
    local_test_x, local_test_y = load_current(args.local_dir, "test")
    public_test_x, public_test_y = load_current(args.public_dir, "test")

    logistic = Pipeline(
        [
            ("log1p", FunctionTransformer(np.log1p, validate=False)),
            ("scale", StandardScaler()),
            ("classifier", LogisticRegression(max_iter=2500, class_weight="balanced", C=0.5, random_state=args.seed)),
        ]
    )
    forest = Pipeline(
        [
            ("log1p", FunctionTransformer(np.log1p, validate=False)),
            ("classifier", RandomForestClassifier(
                n_estimators=500,
                min_samples_leaf=2,
                class_weight="balanced_subsample",
                n_jobs=-1,
                random_state=args.seed,
            )),
        ]
    )
    logistic.fit(train_x, train_y)
    forest.fit(train_x, train_y)
    local_val_prob = ensemble_probability(logistic, forest, local_val_x)
    operating = choose_threshold(local_val_y, local_val_prob, max_fpr=0.01)
    threshold = float(operating["threshold"])
    local = metrics(local_test_y, ensemble_probability(logistic, forest, local_test_x), threshold)
    public = metrics(public_test_y, ensemble_probability(logistic, forest, public_test_x), threshold)
    public_validation = metrics(
        public_val_y,
        ensemble_probability(logistic, forest, public_val_x),
        threshold,
    )
    promotion = (
        local["benign_samples"] >= 100
        and local["attack_samples"] >= 30
        and local["fpr"] <= 0.01
        and local["recall"] >= 0.90
        and public["fpr"] <= 0.01
        and public["recall"] >= 0.90
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(logistic, args.output_dir / "logistic_pipeline.joblib")
    joblib.dump(forest, args.output_dir / "random_forest_pipeline.joblib")
    metadata = {
        "model_release": args.output_dir.name,
        "model_type": "binary_present_attack_detector",
        "evidence_status": "real_hybrid_current_state",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "features": list(public_manifest["features"]),
        "classes": ["BENIGN", "ATTACK"],
        "attack_probability_threshold": threshold,
        "data_sources": [public_manifest.get("release"), local_manifest.get("release")],
        "threshold_calibration": "local EVE validation split only",
        "promotion_eligible": bool(promotion),
        "alert_authority": False,
        "promotion_policy": {
            "min_local_benign_samples": 100,
            "min_local_attack_samples": 30,
            "max_local_fpr": 0.01,
            "min_local_recall": 0.90,
            "max_public_fpr": 0.01,
            "min_public_recall": 0.90,
        },
    }
    result = {
        "local_validation_operating_point": operating,
        "public_validation_at_local_threshold": public_validation,
        "local_eve_test": local,
        "public_genis_test": public,
        "promotion_eligible": bool(promotion),
    }
    (args.output_dir / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    (args.output_dir / "metrics.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output_dir), **result}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
