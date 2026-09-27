from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

import joblib
import numpy as np

from config import CLASSES
from train_open_world import history_summary


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ARTIFACT = ROOT / 'models' / 'artifacts' / 'genis-next-stage-v1'


class NextStageForecaster:
    """Transition-focused predictor kept separate from alert authority."""

    def __init__(self, artifact_dir: Path = DEFAULT_ARTIFACT) -> None:
        self.artifact_dir = Path(artifact_dir)
        self.metadata = json.loads((self.artifact_dir / 'metadata.json').read_text(encoding='utf-8'))
        self.features = list(self.metadata['features'])
        self.history_steps = int(self.metadata['history_steps'])
        self.model = joblib.load(self.artifact_dir / 'next_stage.joblib')

    def _matrix(self, states: Iterable[dict[str, Any]], current_label: str) -> tuple[np.ndarray, int]:
        rows = list(states)
        if not rows:
            rows = [{feature: 0.0 for feature in self.features}]
        observed = len(rows)
        if len(rows) < self.history_steps:
            rows = [rows[0]] * (self.history_steps - len(rows)) + rows
        rows = rows[-self.history_steps:]
        raw = np.asarray(
            [[float(row.get(feature) or 0.0) for feature in self.features] for row in rows],
            dtype=np.float32,
        )[None, :, :]
        summary = history_summary(raw)
        current = np.zeros((1, len(CLASSES)), dtype=np.float32)
        if current_label in CLASSES:
            current[0, CLASSES.index(current_label)] = 1.0
        return np.concatenate([summary, current], axis=1), min(observed, self.history_steps)

    def forecast(self, states: Iterable[dict[str, Any]], current_label: str) -> dict[str, Any]:
        matrix, observed = self._matrix(states, current_label)
        probabilities = self.model.predict_proba(matrix)[0]
        classes = [int(value) for value in self.model.classes_]
        pairs = sorted(
            ((CLASSES[class_id], float(probability)) for class_id, probability in zip(classes, probabilities)),
            key=lambda item: item[1],
            reverse=True,
        )
        label, confidence = pairs[0]
        return {
            'model_release': self.metadata['model_release'],
            'evidence_status': self.metadata['evidence_status'],
            'alert_authority': False,
            'history_steps_observed': observed,
            'history_steps_required': self.history_steps,
            'current_stage': current_label,
            'predicted_next_stage': label,
            'confidence': confidence,
            'stage_change_predicted': label != current_label,
            'probabilities': dict(pairs),
        }
