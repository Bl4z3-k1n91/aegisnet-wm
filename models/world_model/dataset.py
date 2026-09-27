from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from config import (
    ATTACK_CHAINS,
    CLASSES,
    CLASS_TO_ID,
    HORIZONS,
    HISTORY_STEPS,
    INFILTRATION_CLASSES,
    VICTIM_BY_CLASS,
    VICTIM_TO_ID,
    WorldModelConfig,
)

ROOT = Path(__file__).resolve().parents[2]
CLEAN_RELEASE = ROOT / 'dataset' / 'releases' / 'ntro-clean-traffic-v1'
DEFAULT_OUTPUT = ROOT / 'dataset' / 'releases' / 'ntro-world-bootstrap-v1'


def _load_prototypes() -> tuple[pd.DataFrame, list[str]]:
    manifest = json.loads((CLEAN_RELEASE / 'manifest.json').read_text(encoding='utf-8'))
    features = list(manifest['features'])
    frame = pd.read_csv(CLEAN_RELEASE / 'training_states.csv')
    missing = [name for name in features if name not in frame.columns]
    if missing:
        raise ValueError(f'missing clean prototype features: {missing}')
    return frame, features


def _timeline(rng: np.random.Generator, total_steps: int) -> list[str]:
    mode = float(rng.random())
    if mode < 0.25:
        return ['BENIGN'] * total_steps
    if mode < 0.40:
        stable = CLASSES[int(rng.integers(1, len(CLASSES)))]
        return [stable] * total_steps
    if mode < 0.70:
        chain = ATTACK_CHAINS[int(rng.integers(0, len(ATTACK_CHAINS)))]
        future: list[str] = []
        for stage in chain[1:]:
            future.extend([stage] * int(rng.integers(1, 4)))
        while len(future) < total_steps - HISTORY_STEPS:
            future.append(chain[-1])
        return (['BENIGN'] * HISTORY_STEPS + future)[:total_steps]
    chain = ATTACK_CHAINS[int(rng.integers(0, len(ATTACK_CHAINS)))]
    labels: list[str] = []
    for stage in chain:
        duration = int(rng.integers(1, 4))
        labels.extend([stage] * duration)
    while len(labels) < total_steps:
        labels.extend([chain[-1]] * int(rng.integers(1, 4)))
    if len(labels) > total_steps:
        max_offset = len(labels) - total_steps
        offset = int(rng.integers(0, max_offset + 1)) if max_offset else 0
        labels = labels[offset:offset + total_steps]
    return labels[:total_steps]


def _sample_state(
    rng: np.random.Generator,
    label: str,
    prototypes: dict[str, np.ndarray],
    spread: dict[str, np.ndarray],
) -> np.ndarray:
    values = prototypes[label]
    base = values[int(rng.integers(0, len(values)))].astype(np.float64, copy=True)
    sigma = spread[label]
    jitter = rng.normal(0.0, 0.08, size=base.shape)
    additive = rng.normal(0.0, 0.05, size=base.shape) * (sigma + np.abs(base) * 0.05 + 1e-6)
    result = base * (1.0 + jitter) + additive
    return np.clip(result, 0.0, None).astype(np.float32)


def generate_split(
    *,
    split: str,
    count: int,
    seed: int,
    frame: pd.DataFrame,
    features: list[str],
    config: WorldModelConfig,
) -> dict[str, np.ndarray]:
    rng = np.random.default_rng(seed)
    prototypes: dict[str, np.ndarray] = {}
    spread: dict[str, np.ndarray] = {}
    for label, group in frame.groupby('label'):
        values = group[features].astype(float).fillna(0.0).to_numpy(dtype=np.float64)
        prototypes[str(label)] = values
        spread[str(label)] = np.std(values, axis=0) if len(values) > 1 else np.abs(values[0]) * 0.05

    required = set(CLASS_TO_ID)
    if required - set(prototypes):
        raise ValueError(f'missing class prototypes: {sorted(required - set(prototypes))}')

    max_horizon = max(config.horizons)
    total_steps = config.history_steps + max_horizon
    feature_count = len(features)
    x = np.zeros((count, config.history_steps, feature_count), dtype=np.float32)
    future_state = np.zeros((count, len(config.horizons), feature_count), dtype=np.float32)
    future_label = np.zeros((count, len(config.horizons)), dtype=np.int64)
    attack = np.zeros((count, len(config.horizons)), dtype=np.float32)
    change = np.zeros((count, len(config.horizons)), dtype=np.float32)
    infiltration = np.zeros((count, len(config.horizons)), dtype=np.float32)
    onset = np.zeros((count, len(config.horizons)), dtype=np.float32)
    victim = np.zeros((count, len(config.horizons)), dtype=np.int64)
    current_label = np.zeros(count, dtype=np.int64)
    campaign_id = np.empty(count, dtype='U32')

    for index in range(count):
        labels = _timeline(rng, total_steps)
        states = np.stack([
            _sample_state(rng, label, prototypes, spread)
            for label in labels
        ])
        current_label_name = labels[config.history_steps - 1]
        immediate_future = labels[config.history_steps]
        if current_label_name == 'BENIGN' and immediate_future != 'BENIGN':
            precursor_weights = (0.08, 0.16, 0.28)
            precursor_positions = range(config.history_steps - len(precursor_weights), config.history_steps)
            for position, weight in zip(precursor_positions, precursor_weights):
                attack_state = _sample_state(rng, immediate_future, prototypes, spread)
                states[position] = (
                    (1.0 - weight) * states[position] + weight * attack_state
                ).astype(np.float32)
        x[index] = states[:config.history_steps]
        current = current_label_name
        current_label[index] = CLASS_TO_ID[current]
        campaign_id[index] = f'{split}-{seed}-{index:06d}'
        for horizon_index, horizon in enumerate(config.horizons):
            target_position = config.history_steps - 1 + horizon
            target_label = labels[target_position]
            future_state[index, horizon_index] = states[target_position]
            future_label[index, horizon_index] = CLASS_TO_ID[target_label]
            attack[index, horizon_index] = float(target_label != 'BENIGN')
            change[index, horizon_index] = float(target_label != current)
            onset[index, horizon_index] = float(current == 'BENIGN' and target_label != 'BENIGN')
            infiltration[index, horizon_index] = float(target_label in INFILTRATION_CLASSES)
            victim[index, horizon_index] = VICTIM_TO_ID[VICTIM_BY_CLASS[target_label]]

    return {
        'x': x,
        'future_state': future_state,
        'future_label': future_label,
        'attack': attack,
        'change': change,
        'onset': onset,
        'infiltration': infiltration,
        'victim': victim,
        'current_label': current_label,
        'campaign_id': campaign_id,
    }


def write_release(output: Path, train_count: int, val_count: int, test_count: int) -> dict[str, Any]:
    frame, features = _load_prototypes()
    config = WorldModelConfig()
    output.mkdir(parents=True, exist_ok=True)
    specs = (
        ('train', train_count, 1103),
        ('val', val_count, 2207),
        ('test', test_count, 3301),
    )
    summary: dict[str, Any] = {}
    for split, count, seed in specs:
        arrays = generate_split(
            split=split,
            count=count,
            seed=seed,
            frame=frame,
            features=features,
            config=config,
        )
        np.savez_compressed(output / f'{split}.npz', **arrays)
        summary[split] = {
            'rows': count,
            'seed': seed,
            'campaigns': int(len(set(arrays['campaign_id'].tolist()))),
        }

    manifest = {
        'release': 'ntro-world-bootstrap-v1',
        'purpose': 'temporal world-model bootstrap and integration testing',
        'evidence_status': 'synthetic_transition_bootstrap',
        'warning': (
            'This release bootstraps temporal progressions from clean lab class prototypes. '
            'It is suitable for implementation/demo validation, not final generalisation claims. '
            'Final metrics must be produced on independent real temporal datasets/campaigns.'
        ),
        'source_release': 'ntro-clean-traffic-v1',
        'features': features,
        'feature_count': len(features),
        'history_steps': config.history_steps,
        'window_seconds': config.window_seconds,
        'history_seconds': config.history_steps * config.window_seconds,
        'horizons_steps': list(config.horizons),
        'horizons_seconds': [item * config.window_seconds for item in config.horizons],
        'classes': list(CLASS_TO_ID),
        'victims': list(VICTIM_TO_ID),
        'split_strategy': 'independent campaign generation with disjoint split seeds',
        'splits': summary,
    }
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument('--train', type=int, default=1800)
    parser.add_argument('--val', type=int, default=360)
    parser.add_argument('--test', type=int, default=360)
    args = parser.parse_args()
    manifest = write_release(args.output, args.train, args.val, args.test)
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
