#!/usr/bin/env python3
"""Train the 30-second temporal EVE-local authority challenger."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier


def load_sequences(path: Path, split: str, history_steps: int) -> tuple[np.ndarray, np.ndarray]:
    with np.load(path / f"{split}.npz", allow_pickle=False) as data:
        x = np.asarray(data["x"], dtype=np.float64)
        y = np.asarray(data["y"], dtype="U16")
        run_id = np.asarray(data["run_id"], dtype=np.int64)
        phase_id = np.asarray(data["phase_id"], dtype=np.int64)
    sequences: list[np.ndarray] = []
    labels: list[str] = []
    start = 0
    for i in range(len(x) + 1):
        if i == len(x) or run_id[i] != run_id[start] or phase_id[i] != phase_id[start]:
            for end in range(start + history_steps - 1, i):
                sequences.append(x[end - history_steps + 1:end + 1].reshape(-1))
                labels.append(str(y[end]))
            start = i
    if not sequences:
        raise RuntimeError(f"no {history_steps}-step sequences in {split}")
    return np.asarray(sequences, dtype=np.float64), np.asarray(labels, dtype="U16")


def metrics(y: np.ndarray, p: np.ndarray, threshold: float) -> dict[str, Any]:
    truth = y == "ATTACK"; negative = ~truth; pred = p >= threshold
    return {
        "threshold": float(threshold),
        "recall": float(pred[truth].mean()) if truth.any() else 0.0,
        "fpr": float(pred[negative].mean()) if negative.any() else 0.0,
        "precision": float(truth[pred].mean()) if pred.any() else 1.0,
        "attack_sequences": int(truth.sum()),
        "benign_sequences": int(negative.sum()),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--history-steps", type=int, default=3)
    parser.add_argument("--max-validation-fpr", type=float, default=0.03)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    manifest = json.loads((args.local_dir / "manifest.json").read_text(encoding="utf-8"))
    train_x, train_y = load_sequences(args.local_dir, "train", args.history_steps)
    val_x, val_y = load_sequences(args.local_dir, "val", args.history_steps)
    model = RandomForestClassifier(
        n_estimators=1200,
        min_samples_leaf=1,
        max_features="sqrt",
        class_weight={"BENIGN": 1.0, "ATTACK": 5.0},
        n_jobs=-1,
        random_state=args.seed,
    )
    model.fit(np.log1p(np.clip(train_x, 0.0, None)), train_y)
    classes = [str(value) for value in model.classes_]
    probability = model.predict_proba(np.log1p(np.clip(val_x, 0.0, None)))[:, classes.index("ATTACK")]
    candidates = []
    for threshold in np.arange(0.01, 0.991, 0.005):
        row = metrics(val_y, probability, float(threshold))
        if row["fpr"] <= args.max_validation_fpr:
            candidates.append(row)
    if not candidates:
        raise RuntimeError("no operating point meets validation FPR budget")
    operating = max(candidates, key=lambda row: (row["recall"], row["precision"], -row["fpr"], -row["threshold"]))
    args.output_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, args.output_dir / "authority_model.joblib")
    metadata = {
        "model_release": args.output_dir.name,
        "model_type": "temporal_binary_present_attack_detector",
        "evidence_status": "real_local_eve_temporal_hard_negative",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "features": list(manifest["features"]),
        "history_steps": args.history_steps,
        "window_seconds": int(manifest.get("window_seconds", 10)),
        "feature_transform": "log1p",
        "attack_probability_threshold": operating["threshold"],
        "threshold_calibration": "run-disjoint attack-stratified EVE development validation; locked authority campaign excluded",
        "development_release": manifest.get("release"),
        "excluded_acceptance_campaigns": manifest.get("excluded_campaigns", []),
        "alert_authority": False,
        "promotion_eligible": False,
    }
    (args.output_dir / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    result = {"validation_operating_point": operating, "train_sequences": len(train_y), "validation_sequences": len(val_y)}
    (args.output_dir / "metrics.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output_dir), **result}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
