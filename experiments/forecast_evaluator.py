#!/usr/bin/env python3
"""Evaluate live AegisNet forecasts against exact EVE scenario phase ground truth."""

from __future__ import annotations

import argparse
import csv
import json
import sqlite3
import sys
from functools import lru_cache
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.metrics import average_precision_score, f1_score, precision_recall_fscore_support, roc_auc_score


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'models' / 'world_model'))

from config import CLASSES  # noqa: E402
from lab_temporal_dataset import canonical  # noqa: E402

CALIBRATION_THRESHOLDS = ROOT / 'models' / 'artifacts' / 'eve-shadow-calibration-v1' / 'thresholds.json'


@lru_cache(maxsize=1)
def current_calibration_thresholds() -> dict[str, Any]:
    try:
        value = json.loads(CALIBRATION_THRESHOLDS.read_text(encoding='utf-8'))
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


def parse_time(value: Any) -> datetime:
    result = datetime.fromisoformat(str(value))
    return result if result.tzinfo else result.replace(tzinfo=timezone.utc)


def label_at(phases: list[sqlite3.Row], moment: datetime) -> str | None:
    for phase in phases:
        start = parse_time(phase['started_at'])
        end = parse_time(phase['ended_at'])
        if start <= moment < end:
            return canonical(phase['label'])
    return None


def safe_auc(y: np.ndarray, p: np.ndarray) -> dict[str, float | None]:
    if len(np.unique(y)) < 2:
        return {'auroc': None, 'auprc': None}
    return {
        'auroc': float(roc_auc_score(y, p)),
        'auprc': float(average_precision_score(y, p)),
    }


def world_item(forecast: dict[str, Any], seconds: int) -> dict[str, Any] | None:
    for item in (forecast.get('horizons') or {}).values():
        if int(item.get('seconds') or 0) == seconds:
            return item
    return None


def signal_item(
    forecast: dict[str, Any],
    seconds: int,
    source: str,
    world_threshold: float,
) -> tuple[float, float, bool, str | None] | None:
    world = world_item(forecast, seconds)
    if source == 'world':
        if not world:
            return None
        probability = float(world.get('future_attack_probability') or 0.0)
        return probability, world_threshold, probability >= world_threshold, str(world.get('predicted_class') or '')

    shadow = forecast.get('shadow_real_models') or {}
    if source == 'eve-calibrated':
        calibration = shadow.get('eve_calibration') or {}
        item = (calibration.get('horizons') or {}).get(str(seconds))
        if not item:
            return None
        probability = float(item.get('calibrated_attack_probability') or 0.0)
        threshold = float(item.get('threshold') or 0.5)
        predicted_class = str(world.get('predicted_class') or '') if world else None
        return probability, threshold, probability >= threshold, predicted_class

    if source == 'eve-watch':
        calibration = shadow.get('eve_calibration') or {}
        item = (calibration.get('horizons') or {}).get(str(seconds))
        if not item:
            return None
        probability = float(item.get('calibrated_attack_probability') or 0.0)
        threshold = item.get('watch_threshold')
        if threshold is None:
            threshold = (current_calibration_thresholds().get(str(seconds)) or {}).get(
                'watch_threshold'
            )
        if threshold is None:
            return None
        threshold = float(threshold)
        predicted_class = str(world.get('predicted_class') or '') if world else None
        return probability, threshold, probability >= threshold, predicted_class

    if source == 'shadow-mean':
        item = (shadow.get('consensus') or {}).get(str(seconds))
        if not item:
            return None
        probability = float(item.get('mean_probability') or 0.0)
        threshold = world_threshold
        predicted_class = str(world.get('predicted_class') or '') if world else None
        return probability, threshold, probability >= threshold, predicted_class

    raise ValueError(source)


def first_attack_onset(phases: list[sqlite3.Row]) -> datetime | None:
    ordered = sorted(phases, key=lambda row: parse_time(row['started_at']))
    for phase in ordered:
        label = canonical(phase['label'])
        if label and label != 'BENIGN':
            return parse_time(phase['started_at'])
    return None


def evaluate_records(records: list[dict[str, Any]], window_seconds: int) -> dict[str, Any]:
    y = np.asarray([int(row['attack_truth']) for row in records], dtype=np.int64)
    p = np.asarray([float(row['probability']) for row in records], dtype=np.float64)
    pred = np.asarray([bool(row['alert']) for row in records], dtype=bool)
    positive = y == 1
    negative = ~positive
    precision, recall, f1, _ = precision_recall_fscore_support(
        y, pred.astype(np.int64), average='binary', zero_division=0
    )
    fp_windows = int(np.sum(pred[negative])) if negative.any() else 0
    negative_hours = float(negative.sum() * window_seconds) / 3600.0

    # Count alert episode starts, not every repeated alert window.
    episodes = 0
    by_run: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for row in records:
        by_run[int(row['run_id'])].append(row)
    for rows in by_run.values():
        previous = False
        for row in sorted(rows, key=lambda item: item['event_time']):
            active_false_alert = bool(row['alert']) and not bool(row['attack_truth'])
            if active_false_alert and not previous:
                episodes += 1
            previous = active_false_alert

    result: dict[str, Any] = {
        **safe_auc(y, p),
        'samples': len(records),
        'positive_samples': int(positive.sum()),
        'negative_samples': int(negative.sum()),
        'precision': float(precision),
        'recall': float(recall),
        'f1': float(f1),
        'false_positive_rate': float(np.mean(pred[negative])) if negative.any() else 0.0,
        'false_alert_windows': fp_windows,
        'raw_false_alert_windows_per_hour': (
            fp_windows / negative_hours if negative_hours > 0 else 0.0
        ),
        'false_alert_episodes': episodes,
        'false_alert_episodes_per_hour': (
            episodes / negative_hours if negative_hours > 0 else 0.0
        ),
    }

    stage_rows = [row for row in records if row.get('predicted_class') in CLASSES]
    if stage_rows:
        truth_ids = np.asarray([CLASSES.index(row['future_label']) for row in stage_rows], dtype=np.int64)
        pred_ids = np.asarray([CLASSES.index(row['predicted_class']) for row in stage_rows], dtype=np.int64)
        result['exact_stage_accuracy'] = float(np.mean(truth_ids == pred_ids))
        result['exact_stage_macro_f1'] = float(
            f1_score(truth_ids, pred_ids, average='macro', zero_division=0)
        )
        transition = np.asarray(
            [row['future_label'] != row['current_label'] for row in stage_rows], dtype=bool
        )
        result['transition_samples'] = int(transition.sum())
        if transition.any():
            result['transition_exact_stage_accuracy'] = float(
                np.mean(truth_ids[transition] == pred_ids[transition])
            )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', type=Path, default=ROOT / 'outputs' / 'telemetry.db')
    parser.add_argument('--campaign-id')
    parser.add_argument('--run-id', type=int, action='append')
    parser.add_argument('--signal', choices=('world', 'eve-calibrated', 'eve-watch', 'shadow-mean'), default='eve-calibrated')
    parser.add_argument('--world-threshold', type=float, default=0.5)
    parser.add_argument('--window-seconds', type=int, default=10)
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'outputs' / 'evaluations')
    args = parser.parse_args()

    connection = sqlite3.connect(f'file:{args.database.as_posix()}?mode=ro', uri=True)
    connection.row_factory = sqlite3.Row
    try:
        query = "SELECT * FROM scenario_runs WHERE status='COMPLETED' AND scenario LIKE 'cyber-%'"
        params: list[Any] = []
        if args.campaign_id:
            query += ' AND campaign_id=?'
            params.append(args.campaign_id)
        if args.run_id:
            query += ' AND id IN (' + ','.join('?' for _ in args.run_id) + ')'
            params.extend(args.run_id)
        query += ' ORDER BY id'
        runs = connection.execute(query, params).fetchall()
        if not runs:
            raise RuntimeError('no completed cyber scenario runs match the selection')

        all_records: dict[int, list[dict[str, Any]]] = defaultdict(list)
        run_summary: list[dict[str, Any]] = []
        lead_candidates: dict[int, list[float]] = defaultdict(list)

        for run in runs:
            phases = connection.execute(
                'SELECT * FROM scenario_phases WHERE run_id=? AND ended_at IS NOT NULL ORDER BY started_at',
                (run['id'],),
            ).fetchall()
            if not phases:
                continue
            start = min(parse_time(row['started_at']) for row in phases)
            end = max(parse_time(row['ended_at']) for row in phases)
            onset = first_attack_onset(phases)
            forecasts = connection.execute(
                """
                SELECT id,event_time,forecast_json FROM forecast_predictions
                WHERE julianday(event_time)>=julianday(?) AND julianday(event_time)<julianday(?)
                ORDER BY julianday(event_time),id
                """,
                (start.isoformat(), end.isoformat()),
            ).fetchall()
            used = 0
            for forecast_row in forecasts:
                event_time = parse_time(forecast_row['event_time'])
                current_label = label_at(phases, event_time)
                if current_label is None:
                    continue
                forecast = json.loads(str(forecast_row['forecast_json']))
                for seconds in (10, 30, 60):
                    future_label = label_at(phases, event_time + timedelta(seconds=seconds))
                    if future_label is None:
                        continue
                    signal = signal_item(forecast, seconds, args.signal, args.world_threshold)
                    if signal is None:
                        continue
                    probability, threshold, alert, predicted_class = signal
                    record = {
                        'run_id': int(run['id']),
                        'scenario': str(run['scenario']),
                        'event_time': event_time.isoformat(),
                        'seconds': seconds,
                        'current_label': current_label,
                        'future_label': future_label,
                        'attack_truth': int(future_label != 'BENIGN'),
                        'probability': probability,
                        'threshold': threshold,
                        'alert': int(alert),
                        'predicted_class': predicted_class,
                        'pre_onset': bool(onset is not None and event_time < onset),
                    }
                    all_records[seconds].append(record)
                    used += 1
                    if (
                        onset is not None
                        and event_time < onset
                        and future_label != 'BENIGN'
                        and alert
                    ):
                        lead = (onset - event_time).total_seconds()
                        if 0 < lead <= seconds + args.window_seconds:
                            lead_candidates[int(run['id'])].append(float(lead))
            run_summary.append(
                {
                    'run_id': int(run['id']),
                    'scenario': str(run['scenario']),
                    'split': str(run['split']),
                    'onset': onset.isoformat() if onset else None,
                    'forecast_rows': len(forecasts),
                    'evaluated_horizon_rows': used,
                }
            )
    finally:
        connection.close()

    metrics = {
        str(seconds): evaluate_records(records, args.window_seconds)
        for seconds, records in sorted(all_records.items())
        if records
    }
    per_run_lead = {
        str(run_id): max(values)
        for run_id, values in lead_candidates.items()
        if values
    }
    lead_values = np.asarray(list(per_run_lead.values()), dtype=np.float64)
    lead_time = {
        'runs_with_true_pre_onset_warning': len(per_run_lead),
        'median_warning_seconds': float(np.median(lead_values)) if len(lead_values) else 0.0,
        'p95_warning_seconds': float(np.percentile(lead_values, 95)) if len(lead_values) else 0.0,
        'per_run_seconds': per_run_lead,
        'definition': 'earliest true-positive alert emitted before exact attack phase start; post-onset alerts excluded',
    }
    report = {
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'signal': args.signal,
        'database': str(args.database),
        'runs': run_summary,
        'metrics_by_horizon_seconds': metrics,
        'lead_time': lead_time,
        'claim_guard': 'lead time excludes post-onset rows; only exact scenario phase boundaries define ground truth',
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    json_path = args.output_dir / f'eve-forecast-eval-{args.signal}-{stamp}.json'
    csv_path = args.output_dir / f'eve-forecast-eval-{args.signal}-{stamp}.csv'
    json_path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    flat = [row for rows in all_records.values() for row in rows]
    if flat:
        with csv_path.open('w', newline='', encoding='utf-8') as handle:
            writer = csv.DictWriter(handle, fieldnames=list(flat[0]))
            writer.writeheader()
            writer.writerows(flat)
    print(json.dumps({'report': str(json_path), 'rows': len(flat), 'metrics': metrics, 'lead_time': lead_time}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
