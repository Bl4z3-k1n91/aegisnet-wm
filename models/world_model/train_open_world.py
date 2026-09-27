from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import (
    average_precision_score,
    balanced_accuracy_score,
    precision_recall_fscore_support,
    roc_auc_score,
)

ROOT = Path(__file__).resolve().parents[2]


def history_summary(x: np.ndarray) -> np.ndarray:
    x = np.log1p(np.clip(np.asarray(x, dtype=np.float32), 0.0, None))
    last = x[:, -1, :]
    mean = x.mean(axis=1)
    std = x.std(axis=1)
    delta = x[:, -1, :] - x[:, -2, :]
    slope = (x[:, -1, :] - x[:, 0, :]) / max(x.shape[1] - 1, 1)
    return np.concatenate([last, mean, std, delta, slope], axis=1).astype(np.float32)


def load_split(data_dir: Path, split: str) -> dict[str, np.ndarray]:
    with np.load(data_dir / f'{split}.npz', allow_pickle=False) as data:
        return {name: data[name] for name in data.files}


def safe_auc(y: np.ndarray, p: np.ndarray) -> dict[str, float | None]:
    if len(np.unique(y)) < 2:
        return {'auroc': None, 'auprc': None}
    return {
        'auroc': float(roc_auc_score(y, p)),
        'auprc': float(average_precision_score(y, p)),
    }


def choose_threshold(y: np.ndarray, p: np.ndarray) -> dict[str, float]:
    best = {'threshold': 0.5, 'balanced_accuracy': -1.0, 'f1': -1.0}
    for threshold in np.linspace(0.02, 0.98, 97):
        pred = (p >= threshold).astype(np.int64)
        if len(np.unique(y)) < 2:
            balanced = float(np.mean(pred == y))
        else:
            balanced = float(balanced_accuracy_score(y, pred))
        _, _, f1, _ = precision_recall_fscore_support(y, pred, average='binary', zero_division=0)
        candidate = (balanced, float(f1), -abs(float(threshold) - 0.5))
        incumbent = (best['balanced_accuracy'], best['f1'], -abs(best['threshold'] - 0.5))
        if candidate > incumbent:
            best = {'threshold': float(threshold), 'balanced_accuracy': balanced, 'f1': float(f1)}
    return best


def evaluate(y: np.ndarray, p: np.ndarray, threshold: float) -> dict[str, Any]:
    pred = (p >= threshold).astype(np.int64)
    precision, recall, f1, _ = precision_recall_fscore_support(y, pred, average='binary', zero_division=0)
    negative = y == 0
    fpr = float(np.mean(pred[negative] == 1)) if negative.any() else 0.0
    result: dict[str, Any] = {
        **safe_auc(y, p),
        'threshold': float(threshold),
        'balanced_accuracy': float(balanced_accuracy_score(y, pred)) if len(np.unique(y)) > 1 else float(np.mean(pred == y)),
        'precision': float(precision),
        'recall': float(recall),
        'f1': float(f1),
        'false_positive_rate': fpr,
        'positive_rate': float(np.mean(y)),
        'predicted_positive_rate': float(np.mean(pred)),
    }
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
    x_train = history_summary(train['x'])
    x_val = history_summary(val['x'])
    x_test = history_summary(test['x'])
    horizons = [int(value) for value in manifest['horizons_steps']]
    args.output_dir.mkdir(parents=True, exist_ok=True)

    metrics: dict[str, Any] = {}
    calibration: dict[str, Any] = {}
    for hi, horizon in enumerate(horizons):
        y_train = train['attack'][:, hi].astype(np.int64)
        y_val = val['attack'][:, hi].astype(np.int64)
        y_test = test['attack'][:, hi].astype(np.int64)
        positives = max(int(y_train.sum()), 1)
        negatives = max(int(len(y_train) - y_train.sum()), 1)
        weights = np.where(y_train == 1, negatives / positives, 1.0).astype(np.float64)
        model = HistGradientBoostingClassifier(
            max_iter=220,
            learning_rate=0.05,
            max_leaf_nodes=31,
            l2_regularization=1.5,
            random_state=args.seed + horizon,
        )
        model.fit(x_train, y_train, sample_weight=weights)
        val_prob = model.predict_proba(x_val)[:, 1]
        threshold_info = choose_threshold(y_val, val_prob)
        threshold = threshold_info['threshold']
        test_prob = model.predict_proba(x_test)[:, 1]
        result = evaluate(y_test, test_prob, threshold)

        # True onset evaluation: only histories that are benign at t=0.
        onset_mask = test['current_label'] == 0
        onset_truth = test['onset'][onset_mask, hi].astype(np.int64)
        onset_prob = test_prob[onset_mask]
        result['onset_benign_histories'] = int(onset_mask.sum())
        result['onset_positive_samples'] = int(onset_truth.sum())
        result['onset'] = safe_auc(onset_truth, onset_prob)
        if len(onset_truth):
            onset_pred = (onset_prob >= threshold).astype(np.int64)
            _, onset_recall, onset_f1, _ = precision_recall_fscore_support(
                onset_truth, onset_pred, average='binary', zero_division=0
            )
            onset_negative = onset_truth == 0
            result['onset']['recall_at_threshold'] = float(onset_recall)
            result['onset']['f1_at_threshold'] = float(onset_f1)
            result['onset']['false_positive_rate_at_threshold'] = (
                float(np.mean(onset_pred[onset_negative] == 1)) if onset_negative.any() else 0.0
            )

        metrics[str(horizon)] = result
        calibration[str(horizon)] = threshold_info
        joblib.dump(model, args.output_dir / f'attack_h{horizon}.joblib')
        print(
            f'h={horizon} AUROC={result.get("auroc")} AUPRC={result.get("auprc")} '
            f'balacc={result["balanced_accuracy"]:.4f} threshold={threshold:.2f}',
            flush=True,
        )

    metadata = {
        'model_release': args.output_dir.name,
        'model_type': 'hist_gradient_boosted_open_world_attack_forecaster',
        'evidence_status': manifest.get('evidence_status', 'unknown'),
        'data_release': manifest.get('release', args.data_dir.name),
        'features': list(manifest['features']),
        'history_steps': int(manifest['history_steps']),
        'window_seconds': int(manifest['window_seconds']),
        'horizons_steps': horizons,
        'horizons_seconds': [int(h) * int(manifest['window_seconds']) for h in horizons],
        'input_transform': 'log1p_nonnegative + [last,mean,std,last_delta,history_slope]',
        'split_strategy': manifest.get('split_strategy'),
        'seed': args.seed,
    }
    (args.output_dir / 'metadata.json').write_text(json.dumps(metadata, indent=2) + '\n', encoding='utf-8')
    (args.output_dir / 'calibration.json').write_text(json.dumps(calibration, indent=2) + '\n', encoding='utf-8')
    (args.output_dir / 'metrics.json').write_text(json.dumps(metrics, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'output': str(args.output_dir), 'metrics': metrics}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
