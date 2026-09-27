from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import accuracy_score, f1_score

from config import CLASSES
from train_open_world import history_summary


ROOT = Path(__file__).resolve().parents[2]


def load_split(data_dir: Path, split: str) -> dict[str, np.ndarray]:
    with np.load(data_dir / f'{split}.npz', allow_pickle=False) as data:
        return {name: data[name] for name in data.files}


def derive_next_stage(arrays: dict[str, np.ndarray]) -> np.ndarray:
    if 'next_stage' in arrays:
        return arrays['next_stage'].astype(np.int64)
    current = arrays['current_label'].astype(np.int64)
    future = arrays['future_label'].astype(np.int64)
    target = current.copy()
    for index in range(len(target)):
        for label in future[index]:
            if int(label) != int(current[index]):
                target[index] = int(label)
                break
    return target


def matrix(arrays: dict[str, np.ndarray]) -> np.ndarray:
    summary = history_summary(arrays['x'])
    current = arrays['current_label'].astype(np.int64)
    onehot = np.eye(len(CLASSES), dtype=np.float32)[current]
    return np.concatenate([summary, onehot], axis=1).astype(np.float32)


def evaluate(current: np.ndarray, truth: np.ndarray, pred: np.ndarray) -> dict[str, Any]:
    transition = truth != current
    result: dict[str, Any] = {
        'samples': int(len(truth)),
        'transition_samples': int(transition.sum()),
        'accuracy': float(accuracy_score(truth, pred)),
        'macro_f1': float(f1_score(truth, pred, average='macro', zero_division=0)),
    }
    if transition.any():
        result['transition_accuracy'] = float(accuracy_score(truth[transition], pred[transition]))
        result['transition_macro_f1'] = float(
            f1_score(truth[transition], pred[transition], average='macro', zero_division=0)
        )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data-dir', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--seed', type=int, default=42)
    args = parser.parse_args()

    manifest = json.loads((args.data_dir / 'manifest.json').read_text(encoding='utf-8'))
    train = load_split(args.data_dir, 'train')
    val = load_split(args.data_dir, 'val')
    test = load_split(args.data_dir, 'test')
    y_train = derive_next_stage(train)
    y_val = derive_next_stage(val)
    y_test = derive_next_stage(test)
    x_train = matrix(train)
    x_val = matrix(val)
    x_test = matrix(test)

    counts = np.bincount(y_train, minlength=len(CLASSES)).astype(np.float64)
    weights = np.ones(len(y_train), dtype=np.float64)
    nonzero = counts > 0
    class_weights = np.zeros(len(CLASSES), dtype=np.float64)
    if nonzero.any():
        class_weights[nonzero] = counts[nonzero].sum() / (nonzero.sum() * counts[nonzero])
        weights = class_weights[y_train]
    transition = y_train != train['current_label'].astype(np.int64)
    weights = weights * np.where(transition, 3.0, 1.0)

    model = HistGradientBoostingClassifier(
        max_iter=240,
        learning_rate=0.05,
        max_leaf_nodes=31,
        l2_regularization=1.5,
        random_state=args.seed,
    )
    model.fit(x_train, y_train, sample_weight=weights)
    val_pred = model.predict(x_val)
    test_pred = model.predict(x_test)
    metrics = {
        'validation': evaluate(val['current_label'].astype(np.int64), y_val, val_pred),
        'test': evaluate(test['current_label'].astype(np.int64), y_test, test_pred),
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, args.output_dir / 'next_stage.joblib')
    metadata = {
        'model_release': args.output_dir.name,
        'model_type': 'transition_focused_hist_gradient_boosting',
        'evidence_status': manifest.get('evidence_status', 'unknown'),
        'data_release': manifest.get('release', args.data_dir.name),
        'features': list(manifest['features']),
        'history_steps': int(manifest['history_steps']),
        'window_seconds': int(manifest['window_seconds']),
        'target_definition': 'earliest observed future stage different from current stage; otherwise current stage',
        'transition_sample_weight': 3.0,
        'alert_authority': False,
        'seed': args.seed,
    }
    (args.output_dir / 'metadata.json').write_text(json.dumps(metadata, indent=2) + '\n', encoding='utf-8')
    (args.output_dir / 'metrics.json').write_text(json.dumps(metrics, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'output': str(args.output_dir), 'metrics': metrics}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
