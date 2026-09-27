#!/usr/bin/env python3
"""Train prototype multiclass cyber classifiers on ntro-clean-traffic-v1.

The dataset is intentionally small. We therefore train production artifacts on
all accepted rows and report 2-fold stratified CV only as a provisional signal.
Those CV numbers are *not* treated as final generalisation metrics because some
classes currently come from a single experimental run and adjacent windows
overlap.
"""

from __future__ import annotations

import csv
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "dataset" / "releases" / "ntro-clean-traffic-v1"
DATASET = DATA_DIR / "training_states.csv"
MANIFEST = DATA_DIR / "manifest.json"
OUTPUT_DIR = ROOT / "models" / "artifacts" / "ntro-clean-traffic-v1"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def evaluate_cv(name: str, estimator: Pipeline, x: pd.DataFrame, y: pd.Series) -> dict[str, object]:
    splitter = StratifiedKFold(n_splits=2, shuffle=True, random_state=42)
    prediction = cross_val_predict(estimator, x, y, cv=splitter, method="predict")
    labels = sorted(y.unique().tolist())
    report = classification_report(
        y,
        prediction,
        labels=labels,
        output_dict=True,
        zero_division=0,
    )
    return {
        "name": name,
        "accuracy": float(accuracy_score(y, prediction)),
        "macro_f1": float(f1_score(y, prediction, average="macro", zero_division=0)),
        "weighted_f1": float(f1_score(y, prediction, average="weighted", zero_division=0)),
        "labels": labels,
        "confusion_matrix": confusion_matrix(y, prediction, labels=labels).tolist(),
        "classification_report": report,
        "prediction": prediction.tolist(),
    }


def main() -> int:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    features = list(manifest["features"])
    frame = pd.read_csv(DATASET)
    x = frame[features].astype(float).fillna(0.0)
    y = frame["label"].astype(str)

    logistic = Pipeline(
        [
            ("scale", StandardScaler()),
            (
                "model",
                LogisticRegression(
                    max_iter=5000,
                    class_weight="balanced",
                    C=0.7,
                    solver="lbfgs",
                ),
            ),
        ]
    )
    forest = Pipeline(
        [
            (
                "model",
                RandomForestClassifier(
                    n_estimators=500,
                    max_depth=6,
                    min_samples_leaf=1,
                    class_weight="balanced_subsample",
                    random_state=42,
                    n_jobs=-1,
                ),
            )
        ]
    )

    logistic_cv = evaluate_cv("logistic_regression", logistic, x, y)
    forest_cv = evaluate_cv("random_forest", forest, x, y)

    logistic.fit(x, y)
    forest.fit(x, y)
    logistic_train = logistic.predict(x)
    forest_train = forest.predict(x)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(logistic, OUTPUT_DIR / "logistic_pipeline.joblib")
    joblib.dump(forest, OUTPUT_DIR / "random_forest_pipeline.joblib")

    classes = logistic.named_steps["model"].classes_.tolist()
    coefficients = logistic.named_steps["model"].coef_
    coefficient_map = {
        label: {
            feature: float(value)
            for feature, value in zip(features, coefficients[index])
        }
        for index, label in enumerate(classes)
    }

    metrics = {
        "dataset": str(DATASET),
        "dataset_sha256": sha256(DATASET),
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "rows": int(len(frame)),
        "features": features,
        "feature_count": len(features),
        "classes": classes,
        "class_counts": frame["label"].value_counts().sort_index().to_dict(),
        "validation_status": "prototype_only",
        "validation_warning": (
            "2-fold stratified CV is provisional because adjacent windows overlap and "
            "several classes currently originate from a single run. Do not treat these "
            "scores as final run-level generalisation metrics."
        ),
        "logistic_regression": {
            "cv": {key: value for key, value in logistic_cv.items() if key != "prediction"},
            "training_accuracy": float(accuracy_score(y, logistic_train)),
            "training_macro_f1": float(f1_score(y, logistic_train, average="macro", zero_division=0)),
        },
        "random_forest": {
            "cv": {key: value for key, value in forest_cv.items() if key != "prediction"},
            "training_accuracy": float(accuracy_score(y, forest_train)),
            "training_macro_f1": float(f1_score(y, forest_train, average="macro", zero_division=0)),
        },
        "logistic_coefficients": coefficient_map,
    }
    (OUTPUT_DIR / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")

    predictions_path = OUTPUT_DIR / "cv_predictions.csv"
    with predictions_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["row", "run_id", "phase_id", "actual", "logistic_cv", "forest_cv"])
        for index, row in frame.iterrows():
            writer.writerow(
                [
                    index,
                    int(row["run_id"]),
                    int(row["phase_id"]),
                    row["label"],
                    logistic_cv["prediction"][index],
                    forest_cv["prediction"][index],
                ]
            )

    print(json.dumps({
        "rows": len(frame),
        "classes": len(classes),
        "logistic_cv_macro_f1": logistic_cv["macro_f1"],
        "forest_cv_macro_f1": forest_cv["macro_f1"],
        "logistic_training_accuracy": accuracy_score(y, logistic_train),
        "forest_training_accuracy": accuracy_score(y, forest_train),
        "output_dir": str(OUTPUT_DIR),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
