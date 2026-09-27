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
from sklearn.metrics import accuracy_score, f1_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler


ROOT = Path(__file__).resolve().parents[1]
CLASSES = (
    "BENIGN",
    "RECONNAISSANCE",
    "INITIAL_ACCESS_PATTERN",
    "LATERAL_MOVEMENT",
    "C2_BEACON_PATTERN",
    "EXFILTRATION_LIKE",
    "DDOS_LOW",
    "DDOS_MEDIUM",
    "DDOS_HIGH",
)


def load_current(data_dir: Path, split: str) -> tuple[np.ndarray, np.ndarray]:
    with np.load(data_dir / f"{split}.npz", allow_pickle=False) as data:
        x = np.asarray(data["x"][:, -1, :], dtype=np.float64)
        y_ids = np.asarray(data["current_label"], dtype=np.int64)
    y = np.asarray([CLASSES[int(value)] for value in y_ids], dtype="U64")
    return x, y


def combine(public: tuple[np.ndarray, np.ndarray], local: tuple[np.ndarray, np.ndarray], local_repeat: int) -> tuple[np.ndarray, np.ndarray]:
    public_x, public_y = public
    local_x, local_y = local
    return (
        np.concatenate([public_x, *([local_x] * local_repeat)], axis=0),
        np.concatenate([public_y, *([local_y] * local_repeat)], axis=0),
    )


def ensemble(logistic: Any, forest: Any, x: np.ndarray) -> tuple[np.ndarray, list[str]]:
    labels = sorted(set(str(v) for v in logistic.classes_) | set(str(v) for v in forest.classes_))
    probs = np.zeros((len(x), len(labels)), dtype=np.float64)
    for model in (logistic, forest):
        raw = model.predict_proba(x)
        for source_index, label in enumerate(model.classes_):
            probs[:, labels.index(str(label))] += raw[:, source_index] / 2.0
    return probs, labels


def operating_metrics(y: np.ndarray, probs: np.ndarray, labels: list[str], threshold: float) -> dict[str, Any]:
    pred_index = probs.argmax(axis=1)
    confidence = probs.max(axis=1)
    pred = np.asarray([labels[int(index)] for index in pred_index], dtype="U64")
    accepted = confidence >= threshold
    benign_truth = y == "BENIGN"
    attack_truth = ~benign_truth
    attack_pred = accepted & (pred != "BENIGN")
    fpr = float(np.mean(attack_pred[benign_truth])) if benign_truth.any() else 0.0
    recall = float(np.mean(attack_pred[attack_truth])) if attack_truth.any() else 0.0
    retained_accuracy = float(np.mean(pred[accepted] == y[accepted])) if accepted.any() else 0.0
    return {
        "threshold": float(threshold),
        "coverage": float(np.mean(accepted)),
        "retained_accuracy": retained_accuracy,
        "attack_recall": recall,
        "benign_fpr": fpr,
        "benign_samples": int(benign_truth.sum()),
        "attack_samples": int(attack_truth.sum()),
        "abstained": int((~accepted).sum()),
        "exact_accuracy_without_abstention": float(accuracy_score(y, pred)),
        "macro_f1_without_abstention": float(f1_score(y, pred, average="macro", zero_division=0)),
    }


def choose_threshold(y: np.ndarray, probs: np.ndarray, labels: list[str]) -> dict[str, Any]:
    rows = [operating_metrics(y, probs, labels, float(value)) for value in np.arange(0.40, 0.91, 0.01)]
    feasible = [row for row in rows if row["benign_fpr"] <= 0.01 and row["attack_recall"] >= 0.80]
    if feasible:
        return max(feasible, key=lambda row: (row["retained_accuracy"], row["coverage"]))
    return min(
        rows,
        key=lambda row: (
            max(0.0, row["benign_fpr"] - 0.01) * 20.0
            + max(0.0, 0.80 - row["attack_recall"]) * 5.0
            - row["retained_accuracy"]
        ),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Train a real-data current-state detector challenger.")
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
    features = list(public_manifest["features"])

    train_x, train_y = combine(load_current(args.public_dir, "train"), load_current(args.local_dir, "train"), args.local_repeat)
    val_x, val_y = combine(load_current(args.public_dir, "val"), load_current(args.local_dir, "val"), max(1, args.local_repeat // 2))
    local_test_x, local_test_y = load_current(args.local_dir, "test")
    public_test_x, public_test_y = load_current(args.public_dir, "test")

    logistic = Pipeline(
        [
            ("log1p", FunctionTransformer(np.log1p, validate=False)),
            ("scale", StandardScaler()),
            (
                "classifier",
                LogisticRegression(
                    max_iter=2500,
                    class_weight="balanced",
                    C=0.5,
                    random_state=args.seed,
                ),
            ),
        ]
    )
    forest = Pipeline(
        [
            ("log1p", FunctionTransformer(np.log1p, validate=False)),
            (
                "classifier",
                RandomForestClassifier(
                    n_estimators=500,
                    min_samples_leaf=2,
                    class_weight="balanced_subsample",
                    n_jobs=-1,
                    random_state=args.seed,
                ),
            ),
        ]
    )
    logistic.fit(train_x, train_y)
    forest.fit(train_x, train_y)
    val_probs, labels = ensemble(logistic, forest, val_x)
    operating = choose_threshold(val_y, val_probs, labels)
    threshold = float(operating["threshold"])
    local_probs, local_labels = ensemble(logistic, forest, local_test_x)
    public_probs, public_labels = ensemble(logistic, forest, public_test_x)
    local_metrics = operating_metrics(local_test_y, local_probs, local_labels, threshold)
    public_metrics = operating_metrics(public_test_y, public_probs, public_labels, threshold)
    supported = sorted(set(str(value) for value in train_y))
    promotion = (
        local_metrics["benign_samples"] >= 100
        and local_metrics["attack_samples"] >= 30
        and local_metrics["benign_fpr"] <= 0.01
        and local_metrics["attack_recall"] >= 0.80
        and local_metrics["retained_accuracy"] >= 0.90
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(logistic, args.output_dir / "logistic_pipeline.joblib")
    joblib.dump(forest, args.output_dir / "random_forest_pipeline.joblib")
    metadata = {
        "model_release": args.output_dir.name,
        "evidence_status": "real_hybrid_current_state",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "features": features,
        "feature_count": len(features),
        "supported_classes": supported,
        "unsupported_classes": [name for name in CLASSES if name not in supported],
        "confidence_threshold": threshold,
        "data_sources": [public_manifest.get("release"), local_manifest.get("release")],
        "local_repeat": args.local_repeat,
        "promotion_eligible": bool(promotion),
        "alert_authority": False,
        "promotion_policy": {
            "min_local_benign_samples": 100,
            "min_local_attack_samples": 30,
            "max_local_benign_fpr": 0.01,
            "min_local_attack_recall": 0.80,
            "min_local_retained_accuracy": 0.90,
        },
    }
    metrics = {
        "validation_operating_point": operating,
        "local_eve_test": local_metrics,
        "public_genis_test": public_metrics,
        "promotion_eligible": bool(promotion),
    }
    (args.output_dir / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    (args.output_dir / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output_dir), **metrics}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
