from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

import joblib
import numpy as np

from train_open_world import history_summary


class OpenWorldAttackForecaster:
    def __init__(self, artifact_dir: Path) -> None:
        self.artifact_dir = Path(artifact_dir)
        self.metadata = json.loads((self.artifact_dir / 'metadata.json').read_text(encoding='utf-8'))
        self.calibration = json.loads((self.artifact_dir / 'calibration.json').read_text(encoding='utf-8'))
        self.features = list(self.metadata['features'])
        self.history_steps = int(self.metadata['history_steps'])
        self.horizons = [int(value) for value in self.metadata['horizons_steps']]
        self.window_seconds = int(self.metadata['window_seconds'])
        self.models = {
            horizon: joblib.load(self.artifact_dir / f'attack_h{horizon}.joblib')
            for horizon in self.horizons
        }

    def _matrix(self, states: Iterable[dict[str, Any]]) -> tuple[np.ndarray, int]:
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
        return history_summary(raw), min(observed, self.history_steps)

    def forecast(self, states: Iterable[dict[str, Any]]) -> dict[str, Any]:
        matrix, observed = self._matrix(states)
        horizons: dict[str, Any] = {}
        for horizon in self.horizons:
            probability = float(self.models[horizon].predict_proba(matrix)[0, 1])
            threshold = float(self.calibration[str(horizon)]['threshold'])
            horizons[str(horizon)] = {
                'seconds': horizon * self.window_seconds,
                'future_attack_probability': probability,
                'threshold': threshold,
                'alert': bool(probability >= threshold and observed >= 3),
            }
        return {
            'model_release': self.metadata['model_release'],
            'evidence_status': self.metadata['evidence_status'],
            'history_steps_observed': observed,
            'history_steps_required': self.history_steps,
            'horizons': horizons,
        }
