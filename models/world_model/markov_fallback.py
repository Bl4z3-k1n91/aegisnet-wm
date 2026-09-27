from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np

from config import CLASSES, INFILTRATION_CLASSES, VICTIM_BY_CLASS

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ARTIFACT = ROOT / 'models' / 'artifacts' / 'ntro-world-bootstrap-v1'


class MarkovFallback:
    """Zero-neural-dependency forecast using empirical P(S[t+h] | S[t])."""

    def __init__(self, artifact_dir: Path = DEFAULT_ARTIFACT) -> None:
        self.artifact_dir = Path(artifact_dir)
        metrics = json.loads((self.artifact_dir / 'metrics.json').read_text(encoding='utf-8'))
        metadata = json.loads((self.artifact_dir / 'metadata.json').read_text(encoding='utf-8'))
        self.matrices = {
            int(horizon): np.asarray(payload['transition_matrix'], dtype=np.float64)
            for horizon, payload in metrics['classical_baselines']['markov'].items()
        }
        self.window_seconds = int(metadata['window_seconds'])
        self.evidence_status = str(metadata['evidence_status'])

    def forecast(self, current_label: str) -> dict[str, Any]:
        if current_label not in CLASSES:
            current_label = 'BENIGN'
        source_index = CLASSES.index(current_label)
        horizons: dict[str, Any] = {}
        for horizon, matrix in sorted(self.matrices.items()):
            probabilities = matrix[source_index]
            target_index = int(probabilities.argmax())
            target = CLASSES[target_index]
            attack_probability = float(1.0 - probabilities[CLASSES.index('BENIGN')])
            infiltration_probability = float(
                sum(probabilities[CLASSES.index(label)] for label in INFILTRATION_CLASSES)
            )
            horizons[str(horizon)] = {
                'seconds': horizon * self.window_seconds,
                'predicted_class': target,
                'confidence': float(probabilities[target_index]),
                'abstain': False,
                'threshold': 0.0,
                'attack_onset_probability': attack_probability if current_label == 'BENIGN' else 0.0,
                'infiltration_probability': infiltration_probability,
                'predicted_victim': VICTIM_BY_CLASS[target],
                'victim_confidence': float(probabilities[target_index]),
                'class_probabilities': {
                    label: float(probabilities[index]) for index, label in enumerate(CLASSES)
                },
                'top_features': [],
            }
        return {
            'model_release': 'empirical-markov-fallback-v1',
            'evidence_status': self.evidence_status,
            'history_steps_observed': 0,
            'history_steps_required': 0,
            'history_fill_ratio': 1.0,
            'fallback': True,
            'horizons': horizons,
        }
