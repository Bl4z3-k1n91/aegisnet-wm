from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Iterable

import joblib
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, precision_recall_fscore_support, roc_auc_score

from open_world import OpenWorldAttackForecaster


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ARTIFACT = ROOT / 'models' / 'artifacts' / 'eve-shadow-calibration-v1'
DEFAULT_SHADOW_ARTIFACTS = {
    'GENIS': ROOT / 'models' / 'artifacts' / 'genis-open-world-v1',
    'CTU13': ROOT / 'models' / 'artifacts' / 'ctu13-open-world-v1',
    'CICIDS2017': ROOT / 'models' / 'artifacts' / 'cicids2017-open-world-v1',
}
MODEL_NAMES = tuple(DEFAULT_SHADOW_ARTIFACTS)


def _safe_auc(y: np.ndarray, p: np.ndarray) -> dict[str, float | None]:
    if len(np.unique(y)) < 2:
        return {'auroc': None, 'auprc': None}
    return {
        'auroc': float(roc_auc_score(y, p)),
        'auprc': float(average_precision_score(y, p)),
    }


def _evaluate_binary(y: np.ndarray, p: np.ndarray, threshold: float, window_seconds: int) -> dict[str, Any]:
    pred = (p >= threshold).astype(np.int64)
    precision, recall, f1, _ = precision_recall_fscore_support(
        y, pred, average='binary', zero_division=0
    )
    negative = y == 0
    false_positive_count = int(np.sum(pred[negative] == 1)) if negative.any() else 0
    negative_hours = float(negative.sum() * window_seconds) / 3600.0
    false_alerts_per_hour = (
        false_positive_count / negative_hours if negative_hours > 0 else 0.0
    )
    return {
        **_safe_auc(y, p),
        'threshold': float(threshold),
        'precision': float(precision),
        'recall': float(recall),
        'f1': float(f1),
        'false_positive_rate': (
            float(np.mean(pred[negative] == 1)) if negative.any() else 0.0
        ),
        'false_positive_count': false_positive_count,
        'raw_false_alerts_per_hour': float(false_alerts_per_hour),
        'positive_samples': int(np.sum(y == 1)),
        'negative_samples': int(np.sum(y == 0)),
        'positive_rate': float(np.mean(y)) if len(y) else 0.0,
    }


def choose_guarded_threshold(
    y: np.ndarray,
    p: np.ndarray,
    *,
    max_fpr: float,
) -> dict[str, float]:
    candidates = sorted(
        set(float(value) for value in np.concatenate([np.linspace(0.01, 0.99, 99), p]))
    )
    best: tuple[float, float, float, float] | None = None
    best_payload: dict[str, float] | None = None
    for threshold in candidates:
        pred = p >= threshold
        positive = y == 1
        negative = y == 0
        recall = float(np.mean(pred[positive])) if positive.any() else 0.0
        fpr = float(np.mean(pred[negative])) if negative.any() else 0.0
        precision = (
            float(np.mean(y[pred] == 1)) if pred.any() else 1.0
        )
        feasible = 1.0 if fpr <= max_fpr else 0.0
        score = (feasible, recall if feasible else -fpr, precision, threshold)
        if best is None or score > best:
            best = score
            best_payload = {
                'threshold': float(threshold),
                'validation_recall': recall,
                'validation_fpr': fpr,
                'validation_precision': precision,
                'met_fpr_target': bool(feasible),
            }
    return best_payload or {
        'threshold': 0.5,
        'validation_recall': 0.0,
        'validation_fpr': 1.0,
        'validation_precision': 0.0,
        'met_fpr_target': False,
    }


def raw_shadow_forecast(
    forecasters: dict[str, OpenWorldAttackForecaster],
    history: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    models: dict[str, Any] = {}
    by_seconds: dict[int, list[dict[str, Any]]] = {}
    states = list(history)
    for name, forecaster in forecasters.items():
        result = forecaster.forecast(states)
        horizons: dict[str, Any] = {}
        for item in result.get('horizons', {}).values():
            seconds = int(item.get('seconds') or 0)
            record = {
                'seconds': seconds,
                'future_attack_probability': float(item.get('future_attack_probability') or 0.0),
                'native_threshold': float(item.get('threshold') or 0.0),
                'native_alert': bool(item.get('alert')),
            }
            horizons[str(seconds)] = record
            by_seconds.setdefault(seconds, []).append({'model': name, **record})
        models[name] = {'horizons': horizons}
    consensus: dict[str, Any] = {}
    for seconds, items in by_seconds.items():
        probabilities = [float(item['future_attack_probability']) for item in items]
        votes = sum(bool(item['native_alert']) for item in items)
        consensus[str(seconds)] = {
            'seconds': seconds,
            'model_count': len(items),
            'mean_probability': float(np.mean(probabilities)),
            'max_probability': float(np.max(probabilities)),
            'min_probability': float(np.min(probabilities)),
            'native_alert_fraction': float(votes / len(items)),
        }
    return {'models': models, 'consensus': consensus}


def stacking_feature_names(model_names: Iterable[str] = MODEL_NAMES) -> list[str]:
    names: list[str] = []
    for name in model_names:
        names.extend([f'{name}_probability', f'{name}_present'])
    names.extend(
        ['mean_probability', 'max_probability', 'min_probability', 'spread',
         'native_alert_fraction', 'model_fraction']
    )
    return names


def stacking_vector(
    shadow: dict[str, Any],
    seconds: int,
    model_names: Iterable[str] = MODEL_NAMES,
) -> np.ndarray:
    values: list[float] = []
    present_probs: list[float] = []
    native_votes: list[float] = []
    names = tuple(model_names)
    models = shadow.get('models') or {}
    for name in names:
        item = ((models.get(name) or {}).get('horizons') or {}).get(str(seconds))
        if item:
            probability = float(item.get('future_attack_probability') or 0.0)
            values.extend([probability, 1.0])
            present_probs.append(probability)
            native_votes.append(1.0 if item.get('native_alert') else 0.0)
        else:
            values.extend([0.0, 0.0])
    if present_probs:
        mean_probability = float(np.mean(present_probs))
        max_probability = float(np.max(present_probs))
        min_probability = float(np.min(present_probs))
        spread = max_probability - min_probability
        vote_fraction = float(np.mean(native_votes))
    else:
        mean_probability = max_probability = min_probability = spread = vote_fraction = 0.0
    values.extend(
        [
            mean_probability,
            max_probability,
            min_probability,
            spread,
            vote_fraction,
            len(present_probs) / max(len(names), 1),
        ]
    )
    return np.asarray(values, dtype=np.float64)


class EveShadowCalibrator:
    """Local-domain probability stacker.

    Loading this artifact never grants alert authority.  Promotion eligibility is
    surfaced as evidence only and must be acted on explicitly outside this class.
    """

    def __init__(self, artifact_dir: Path = DEFAULT_ARTIFACT) -> None:
        self.artifact_dir = Path(artifact_dir)
        self.metadata = json.loads((self.artifact_dir / 'metadata.json').read_text(encoding='utf-8'))
        self.thresholds = json.loads((self.artifact_dir / 'thresholds.json').read_text(encoding='utf-8'))
        self.promotion = json.loads((self.artifact_dir / 'promotion.json').read_text(encoding='utf-8'))
        self.model_names = tuple(self.metadata['shadow_models'])
        self.models = {
            int(seconds): joblib.load(self.artifact_dir / f'meta_h{seconds}.joblib')
            for seconds in self.metadata['horizons_seconds']
            if (self.artifact_dir / f'meta_h{seconds}.joblib').exists()
        }

    def enrich(self, shadow: dict[str, Any]) -> dict[str, Any]:
        horizons: dict[str, Any] = {}
        for seconds, model in self.models.items():
            vector = stacking_vector(shadow, seconds, self.model_names)[None, :]
            probability = float(model.predict_proba(vector)[0, 1])
            threshold_info = self.thresholds[str(seconds)]
            threshold = float(threshold_info['threshold'])
            watch_threshold = float(threshold_info.get('watch_threshold', threshold))
            horizons[str(seconds)] = {
                'seconds': seconds,
                'calibrated_attack_probability': probability,
                'threshold': threshold,
                'shadow_alert': bool(probability >= threshold),
                'watch_threshold': watch_threshold,
                'shadow_watch': bool(probability >= watch_threshold),
            }
        return {
            'mode': 'EVE_CALIBRATED_SHADOW',
            'alert_authority': False,
            'promotion_eligible': bool(self.promotion.get('eligible', False)),
            'promotion_reason': self.promotion.get('reason'),
            'artifact': self.metadata.get('model_release', self.artifact_dir.name),
            'horizons': horizons,
        }


def _load_npz(path: Path) -> dict[str, np.ndarray]:
    with np.load(path, allow_pickle=False) as data:
        return {name: data[name] for name in data.files}


def _states_from_row(row: np.ndarray, features: list[str]) -> list[dict[str, float]]:
    return [
        {feature: float(value) for feature, value in zip(features, state)}
        for state in row
    ]


def _shadow_matrices(
    arrays: dict[str, np.ndarray],
    features: list[str],
    forecasters: dict[str, OpenWorldAttackForecaster],
    horizons_seconds: list[int],
) -> dict[int, np.ndarray]:
    rows: dict[int, list[np.ndarray]] = {seconds: [] for seconds in horizons_seconds}
    for sequence in arrays['x']:
        shadow = raw_shadow_forecast(forecasters, _states_from_row(sequence, features))
        for seconds in horizons_seconds:
            rows[seconds].append(stacking_vector(shadow, seconds, forecasters.keys()))
    return {seconds: np.asarray(values, dtype=np.float64) for seconds, values in rows.items()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data-dir', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, default=DEFAULT_ARTIFACT)
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--max-fpr', type=float, default=0.01)
    parser.add_argument('--watch-max-fpr', type=float, default=0.15)
    parser.add_argument('--min-recall', type=float, default=0.80)
    parser.add_argument('--max-false-alerts-per-hour', type=float, default=1.0)
    args = parser.parse_args()

    manifest = json.loads((args.data_dir / 'manifest.json').read_text(encoding='utf-8'))
    features = list(manifest['features'])
    window_seconds = int(manifest['window_seconds'])
    horizon_steps = [int(value) for value in manifest.get('horizons_steps', (1, 3, 6))]
    horizons_seconds = [step * window_seconds for step in horizon_steps]
    train = _load_npz(args.data_dir / 'train.npz')
    val = _load_npz(args.data_dir / 'val.npz')
    test = _load_npz(args.data_dir / 'test.npz')

    forecasters = {
        name: OpenWorldAttackForecaster(path)
        for name, path in DEFAULT_SHADOW_ARTIFACTS.items()
        if (path / 'metadata.json').exists()
    }
    if not forecasters:
        raise RuntimeError('no public shadow forecasters are available')

    matrices = {
        split: _shadow_matrices(arrays, features, forecasters, horizons_seconds)
        for split, arrays in [('train', train), ('val', val), ('test', test)]
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    metrics: dict[str, Any] = {}
    thresholds: dict[str, Any] = {}
    gates: dict[str, Any] = {}

    for hi, (step, seconds) in enumerate(zip(horizon_steps, horizons_seconds)):
        y_train = train['attack'][:, hi].astype(np.int64)
        y_val = val['attack'][:, hi].astype(np.int64)
        y_test = test['attack'][:, hi].astype(np.int64)
        if len(np.unique(y_train)) < 2:
            metrics[str(seconds)] = {'status': 'skipped_single_class_train'}
            gates[str(seconds)] = {'eligible': False, 'reason': 'single-class training split'}
            continue
        model = LogisticRegression(
            max_iter=2000,
            class_weight='balanced',
            random_state=args.seed + step,
        )
        model.fit(matrices['train'][seconds], y_train)
        val_prob = model.predict_proba(matrices['val'][seconds])[:, 1]
        threshold_info = choose_guarded_threshold(y_val, val_prob, max_fpr=args.max_fpr)
        watch_info = choose_guarded_threshold(
            y_val,
            val_prob,
            max_fpr=args.watch_max_fpr,
        )
        threshold = float(threshold_info['threshold'])
        watch_threshold = float(watch_info['threshold'])
        test_prob = model.predict_proba(matrices['test'][seconds])[:, 1]
        result = _evaluate_binary(y_test, test_prob, threshold, window_seconds)
        result['validation'] = threshold_info
        result['watch'] = _evaluate_binary(y_test, test_prob, watch_threshold, window_seconds)
        result['watch']['validation'] = watch_info
        metrics[str(seconds)] = result
        thresholds[str(seconds)] = {
            **threshold_info,
            'watch_threshold': watch_threshold,
            'watch_validation_recall': float(watch_info['validation_recall']),
            'watch_validation_fpr': float(watch_info['validation_fpr']),
            'watch_validation_precision': float(watch_info['validation_precision']),
            'watch_met_fpr_target': bool(watch_info['met_fpr_target']),
            'watch_max_fpr': float(args.watch_max_fpr),
        }
        eligible = (
            bool(threshold_info['met_fpr_target'])
            and result['positive_samples'] >= 10
            and result['negative_samples'] >= 100
            and result['false_positive_rate'] <= args.max_fpr
            and result['recall'] >= args.min_recall
            and result['raw_false_alerts_per_hour'] <= args.max_false_alerts_per_hour
        )
        gates[str(seconds)] = {
            'eligible': bool(eligible),
            'requirements': {
                'min_test_positive_samples': 10,
                'min_test_negative_samples': 100,
                'max_test_fpr': args.max_fpr,
                'min_test_recall': args.min_recall,
                'max_raw_false_alerts_per_hour': args.max_false_alerts_per_hour,
            },
        }
        joblib.dump(model, args.output_dir / f'meta_h{seconds}.joblib')

    all_required = all(str(seconds) in gates for seconds in horizons_seconds)
    eligible = all_required and all(bool(gates[str(seconds)].get('eligible')) for seconds in horizons_seconds)
    promotion = {
        'eligible': bool(eligible),
        'alert_authority': False,
        'reason': (
            'all local-domain validation gates passed; manual promotion review still required'
            if eligible
            else 'one or more local-domain validation gates failed; remain shadow-only'
        ),
        'gates': gates,
    }
    metadata = {
        'model_release': args.output_dir.name,
        'model_type': 'eve_domain_shadow_stacker',
        'evidence_status': 'real_local_eve_calibration',
        'data_release': manifest.get('release', args.data_dir.name),
        'shadow_models': list(forecasters),
        'features': stacking_feature_names(forecasters.keys()),
        'horizons_seconds': horizons_seconds,
        'window_seconds': window_seconds,
        'split_strategy': manifest.get('split_strategy'),
        'seed': args.seed,
        'authority_policy': 'never auto-promote; runtime remains shadow-only',
        'watch_policy': 'advisory early-warning tier only; never changes operator health state',
    }
    (args.output_dir / 'metadata.json').write_text(json.dumps(metadata, indent=2) + '\n', encoding='utf-8')
    (args.output_dir / 'thresholds.json').write_text(json.dumps(thresholds, indent=2) + '\n', encoding='utf-8')
    (args.output_dir / 'metrics.json').write_text(json.dumps(metrics, indent=2) + '\n', encoding='utf-8')
    (args.output_dir / 'promotion.json').write_text(json.dumps(promotion, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'output': str(args.output_dir), 'promotion': promotion, 'metrics': metrics}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
