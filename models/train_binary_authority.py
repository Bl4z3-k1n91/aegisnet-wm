#!/usr/bin/env python3
"""Train an authority challenger with explicit hard-negative validation."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler


def local(path: Path, split: str) -> tuple[np.ndarray, np.ndarray]:
    with np.load(path / f"{split}.npz", allow_pickle=False) as data:
        return np.asarray(data["x"], dtype=np.float64), np.asarray(data["y"], dtype="U16")


def public(path: Path, split: str) -> tuple[np.ndarray, np.ndarray]:
    with np.load(path / f"{split}.npz", allow_pickle=False) as data:
        x = np.asarray(data["x"][:, -1, :], dtype=np.float64)
        y = np.where(np.asarray(data["current_label"], dtype=np.int64) == 0, "BENIGN", "ATTACK")
        return x, y


def p(model: Any, x: np.ndarray) -> np.ndarray:
    raw = model.predict_proba(x)
    labels = [str(v) for v in model.classes_]
    return raw[:, labels.index("ATTACK")]


def metric(y: np.ndarray, prob: np.ndarray, threshold: float) -> dict[str, Any]:
    truth = y == "ATTACK"; neg = ~truth; pred = prob >= threshold
    return {
        "threshold": float(threshold),
        "recall": float(pred[truth].mean()) if truth.any() else 0.0,
        "fpr": float(pred[neg].mean()) if neg.any() else 0.0,
        "precision": float(truth[pred].mean()) if pred.any() else 1.0,
        "attack_samples": int(truth.sum()), "benign_samples": int(neg.sum()),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public-dir", type=Path, required=True)
    parser.add_argument("--local-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--local-repeat", type=int, default=30)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--max-validation-fpr", type=float, default=0.03)
    args = parser.parse_args()
    pub_manifest = json.loads((args.public_dir / "manifest.json").read_text(encoding="utf-8"))
    loc_manifest = json.loads((args.local_dir / "manifest.json").read_text(encoding="utf-8"))
    if list(pub_manifest["features"]) != list(loc_manifest["features"]):
        raise RuntimeError("feature schema mismatch")
    px, py = public(args.public_dir, "train"); lx, ly = local(args.local_dir, "train")
    train_x = np.concatenate([px, *([lx] * args.local_repeat)])
    train_y = np.concatenate([py, *([ly] * args.local_repeat)])
    val_x, val_y = local(args.local_dir, "val")

    models: dict[str, Any] = {
        "logistic": Pipeline([
            ("log1p", FunctionTransformer(np.log1p, validate=False)),
            ("scale", StandardScaler()),
            ("classifier", LogisticRegression(max_iter=3000, class_weight="balanced", C=0.35, random_state=args.seed)),
        ]),
        "forest": Pipeline([
            ("log1p", FunctionTransformer(np.log1p, validate=False)),
            ("classifier", RandomForestClassifier(n_estimators=700, min_samples_leaf=2, max_features="sqrt", class_weight="balanced_subsample", n_jobs=-1, random_state=args.seed)),
        ]),
        "extra": Pipeline([
            ("log1p", FunctionTransformer(np.log1p, validate=False)),
            ("classifier", ExtraTreesClassifier(n_estimators=700, min_samples_leaf=2, max_features="sqrt", class_weight="balanced", n_jobs=-1, random_state=args.seed)),
        ]),
    }
    for model in models.values(): model.fit(train_x, train_y)
    probs = {name: p(model, val_x) for name, model in models.items()}

    candidates: list[dict[str, Any]] = []
    weights = [(0.0,0.5,0.5),(0.2,0.4,0.4),(0.4,0.3,0.3),(0.0,0.7,0.3),(0.0,0.3,0.7)]
    for wl,wf,we in weights:
        probability = wl*probs["logistic"] + wf*probs["forest"] + we*probs["extra"]
        for threshold in np.arange(0.20, 0.951, 0.005):
            row = metric(val_y, probability, float(threshold))
            if row["fpr"] <= args.max_validation_fpr:
                candidates.append({**row, "weights": {"logistic":wl,"forest":wf,"extra":we}})
    if not candidates:
        raise RuntimeError("no validation operating point satisfies max FPR")
    operating = max(candidates, key=lambda row: (row["recall"], row["precision"], -row["fpr"], -row["threshold"]))

    args.output_dir.mkdir(parents=True, exist_ok=True)
    for name, model in models.items(): joblib.dump(model, args.output_dir / f"{name}_pipeline.joblib")
    # compatibility names consumed by the current live service/evaluator
    joblib.dump(models["logistic"], args.output_dir / "logistic_pipeline.joblib")
    joblib.dump(models["forest"], args.output_dir / "random_forest_pipeline.joblib")
    metadata = {
        "model_release": args.output_dir.name,
        "model_type": "binary_present_attack_detector_authority_challenger",
        "evidence_status": "real_hybrid_current_state_hard_negative",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "features": list(pub_manifest["features"]),
        "classes": ["BENIGN","ATTACK"],
        "attack_probability_threshold": operating["threshold"],
        "ensemble_weights": operating["weights"],
        "threshold_calibration": "run-disjoint EVE development validation; final acceptance campaign excluded",
        "data_sources": [pub_manifest.get("release"), loc_manifest.get("release")],
        "alert_authority": False,
        "promotion_eligible": False,
    }
    (args.output_dir / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    result = {"validation_operating_point": operating, "candidate_count": len(candidates)}
    (args.output_dir / "metrics.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output_dir), **result}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
