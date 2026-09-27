from __future__ import annotations

import json
import sys
from collections import deque
from pathlib import Path
from typing import Any, Iterable

import numpy as np
import torch

from config import CLASSES, HORIZONS, VICTIMS, WorldModelConfig
from model import LatentWorldModel

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ARTIFACT = ROOT / 'models' / 'artifacts' / 'ntro-world-bootstrap-v1'


class WorldForecaster:
    def __init__(self, artifact_dir: Path = DEFAULT_ARTIFACT) -> None:
        self.artifact_dir = Path(artifact_dir)
        self.metadata = json.loads((self.artifact_dir / 'metadata.json').read_text(encoding='utf-8'))
        self.calibration = json.loads((self.artifact_dir / 'calibration.json').read_text(encoding='utf-8'))
        scaler = np.load(self.artifact_dir / 'scaler.npz')
        self.mean = scaler['mean'].astype(np.float32)
        self.std = scaler['std'].astype(np.float32)
        self.features = list(self.metadata['features'])
        self.feature_transform = str(self.metadata.get('feature_transform', 'identity'))
        self.config = WorldModelConfig(
            history_steps=int(self.metadata.get('history_steps', 6)),
            horizons=tuple(int(value) for value in self.metadata.get('horizons_steps', (1, 3, 6))),
            window_seconds=int(self.metadata.get('window_seconds', 10)),
            latent_dim=int(self.metadata.get('latent_dim', 64)),
        )
        payload = torch.load(self.artifact_dir / 'world_model.pt', map_location='cpu', weights_only=True)
        self.model = LatentWorldModel(int(payload['feature_count']), self.config)
        self.model.load_state_dict(payload['state_dict'])
        self.model.eval()

    def _matrix(self, states: Iterable[dict[str, Any]]) -> tuple[np.ndarray, int]:
        rows = list(states)
        if not rows:
            rows = [{feature: 0.0 for feature in self.features}]
        observed = len(rows)
        if len(rows) < self.config.history_steps:
            rows = [rows[0]] * (self.config.history_steps - len(rows)) + rows
        rows = rows[-self.config.history_steps:]
        matrix = np.asarray(
            [[float(row.get(feature) or 0.0) for feature in self.features] for row in rows],
            dtype=np.float32,
        )
        if self.feature_transform == 'log1p':
            matrix = np.log1p(np.clip(matrix, 0.0, None)).astype(np.float32)
        elif self.feature_transform != 'identity':
            raise ValueError(f'unsupported feature transform: {self.feature_transform}')
        matrix = (matrix - self.mean) / self.std
        return matrix, min(observed, self.config.history_steps)

    @staticmethod
    def _softmax(tensor: torch.Tensor) -> np.ndarray:
        return torch.softmax(tensor, dim=-1).detach().cpu().numpy()[0]

    def forecast(self, states: Iterable[dict[str, Any]], top_features: int = 8) -> dict[str, Any]:
        matrix, observed = self._matrix(states)
        x = torch.tensor(matrix[None, :, :], dtype=torch.float32, requires_grad=True)
        output = self.model(x)
        result: dict[str, Any] = {
            'model_release': self.metadata['model_release'],
            'evidence_status': self.metadata['evidence_status'],
            'history_steps_observed': observed,
            'history_steps_required': self.config.history_steps,
            'history_fill_ratio': observed / self.config.history_steps,
            'horizons': {},
        }
        for horizon in self.config.horizons:
            class_prob = self._softmax(output.class_logits[horizon])
            victim_prob = self._softmax(output.victim_logits[horizon])
            attack = float(torch.sigmoid(output.attack_logits[horizon]).detach().cpu()[0])
            change = float(torch.sigmoid(output.change_logits[horizon]).detach().cpu()[0])
            onset = float(torch.sigmoid(output.onset_logits[horizon]).detach().cpu()[0])
            infiltration = float(torch.sigmoid(output.infiltration_logits[horizon]).detach().cpu()[0])
            class_index = int(class_prob.argmax())
            victim_index = int(victim_prob.argmax())
            confidence = float(class_prob[class_index])
            threshold = float(self.calibration[str(horizon)]['threshold'])
            abstain = confidence < threshold or observed < 3
            selected_logit = output.class_logits[horizon][0, class_index]
            gradient = torch.autograd.grad(selected_logit, x, retain_graph=True)[0][0]
            attribution = (gradient * x[0]).abs().detach().cpu().numpy().mean(axis=0)
            ranked = np.argsort(attribution)[::-1][:top_features]
            result['horizons'][str(horizon)] = {
                'seconds': horizon * self.config.window_seconds,
                'predicted_class': CLASSES[class_index],
                'confidence': confidence,
                'abstain': bool(abstain),
                'threshold': threshold,
                'future_attack_probability': attack,
                'state_change_probability': change,
                'attack_onset_probability': onset,
                'infiltration_probability': infiltration,
                'predicted_victim': VICTIMS[victim_index],
                'victim_confidence': float(victim_prob[victim_index]),
                'class_probabilities': {name: float(class_prob[index]) for index, name in enumerate(CLASSES)},
                'top_features': [
                    {'feature': self.features[int(index)], 'attribution': float(attribution[int(index)])}
                    for index in ranked
                ],
            }
        return result


class StateHistory:
    def __init__(self, maxlen: int = 12) -> None:
        self._states: deque[dict[str, Any]] = deque(maxlen=maxlen)

    def append(self, state: dict[str, Any]) -> None:
        self._states.append(dict(state))

    def clear(self) -> None:
        self._states.clear()

    def values(self) -> list[dict[str, Any]]:
        return list(self._states)
