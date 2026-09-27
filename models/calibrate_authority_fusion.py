#!/usr/bin/env python3
"""Calibrate a conservative binary+stage authority fusion on validation data only."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np


ROOT = Path(__file__).resolve().parents[1]


def load_xy(path: Path, split: str) -> tuple[np.ndarray, np.ndarray]:
    with np.load(path / f"{split}.npz", allow_pickle=False) as data:
        x = np.asarray(data["x"][:, -1, :], dtype=np.float64)
        y = np.asarray(data["current_label"], dtype=np.int64) != 0
    return x, y


def class_probability(model: Any, x: np.ndarray, label: str) -> np.ndarray:
    raw = model.predict_proba(x)
    labels = [str(value) for value in model.classes_]
    return raw[:, labels.index(label)]


def binary_probability(logistic: Any, forest: Any, x: np.ndarray) -> np.ndarray:
    return (class_probability(logistic, x, "ATTACK") + class_probability(forest, x, "ATTACK")) / 2.0


def stage_attack_probability(logistic: Any, forest: Any, x: np.ndarray) -> np.ndarray:
    benign = (class_probability(logistic, x, "BENIGN") + class_probability(forest, x, "BENIGN")) / 2.0
    return 1.0 - benign


def metrics(y: np.ndarray, pred: np.ndarray) -> dict[str, float | int]:
    attack = y.astype(bool)
    benign = ~attack
    return {
        "recall": float(np.mean(pred[attack])) if attack.any() else 0.0,
        "fpr": float(np.mean(pred[benign])) if benign.any() else 0.0,
        "attack_samples": int(attack.sum()),
        "benign_samples": int(benign.sum()),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary-artifact", type=Path, required=True)
    parser.add_argument("--stage-artifact", type=Path, required=True)
    parser.add_argument("--public-dir", type=Path, required=True)
    parser.add_argument("--local-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--max-validation-fpr", type=float, default=0.01)
    args = parser.parse_args()

    binary_meta = json.loads((args.binary_artifact / "metadata.json").read_text(encoding="utf-8"))
    binary_threshold = float(binary_meta["attack_probability_threshold"])
    binary_log = joblib.load(args.binary_artifact / "logistic_pipeline.joblib")
    binary_rf = joblib.load(args.binary_artifact / "random_forest_pipeline.joblib")
    stage_log = joblib.load(args.stage_artifact / "logistic_pipeline.joblib")
    stage_rf = joblib.load(args.stage_artifact / "random_forest_pipeline.joblib")

    public_x, public_y = load_xy(args.public_dir, "val")
    local_x, local_y = load_xy(args.local_dir, "val")
    x = np.concatenate([public_x, local_x])
    y = np.concatenate([public_y, local_y])
    bin_prob = binary_probability(binary_log, binary_rf, x)
    stage_prob = stage_attack_probability(stage_log, stage_rf, x)
    binary_pred = bin_prob >= binary_threshold

    candidates = np.arange(0.40, 0.991, 0.005)
    rows = []
    for stage_threshold in candidates:
        pred = binary_pred | (stage_prob >= float(stage_threshold))
        row = metrics(y, pred)
        row["stage_threshold"] = float(stage_threshold)
        rows.append(row)
    feasible = [row for row in rows if float(row["fpr"]) <= args.max_validation_fpr]
    if not feasible:
        chosen = min(rows, key=lambda row: (float(row["fpr"]), -float(row["recall"]), -float(row["stage_threshold"])))
    else:
        chosen = max(feasible, key=lambda row: (float(row["recall"]), -float(row["fpr"]), float(row["stage_threshold"])))

    args.output_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 1,
        "model_release": args.output_dir.name,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "method": "binary_or_stage_attack_mass",
        "binary_artifact": str(args.binary_artifact.resolve()),
        "stage_artifact": str(args.stage_artifact.resolve()),
        "binary_threshold": binary_threshold,
        "stage_threshold": float(chosen["stage_threshold"]),
        "calibration_data": [args.public_dir.name + ":val", args.local_dir.name + ":val"],
        "calibration_metrics": chosen,
        "max_validation_fpr": args.max_validation_fpr,
        "alert_authority": False,
    }
    (args.output_dir / "fusion.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
