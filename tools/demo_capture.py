#!/usr/bin/env python3
"""Capture a judge-facing AegisNet live demo timeline without feeding labels to inference."""

from __future__ import annotations

import argparse
import json
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
STATUS = ROOT / 'outputs' / 'analysis-status.json'
DB = ROOT / 'outputs' / 'telemetry.db'


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def jload(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding='utf-8'))
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


def current_truth(connection: sqlite3.Connection, campaign_id: str, moment: datetime) -> dict[str, Any]:
    connection.row_factory = sqlite3.Row
    run = connection.execute(
        """
        SELECT * FROM scenario_runs
        WHERE campaign_id=?
        ORDER BY id DESC LIMIT 1
        """,
        (campaign_id,),
    ).fetchone()
    if not run:
        return {'run_id': None, 'phase': None, 'label': None}
    phase = connection.execute(
        """
        SELECT * FROM scenario_phases
        WHERE run_id=?
          AND julianday(started_at) <= julianday(?)
          AND (ended_at IS NULL OR julianday(ended_at) >= julianday(?))
        ORDER BY id DESC LIMIT 1
        """,
        (run['id'], moment.isoformat(), moment.isoformat()),
    ).fetchone()
    return {
        'run_id': int(run['id']),
        'scenario': str(run['scenario']),
        'run_status': str(run['status']),
        'phase': str(phase['phase']) if phase else None,
        'label': str(phase['label']) if phase else None,
        'phase_started_at': str(phase['started_at']) if phase else None,
    }


def compact_status(status: dict[str, Any]) -> dict[str, Any]:
    forecast = status.get('forecast') or {}
    shadow = forecast.get('shadow_real_models') or {}
    calibration = shadow.get('eve_calibration') or {}
    result: dict[str, Any] = {
        'present_label': status.get('predicted_label'),
        'raw_present_label': status.get('raw_predicted_label'),
        'present_confidence': status.get('confidence'),
        'cyber_risk': status.get('cyber_risk'),
        'decision_source': status.get('decision_source'),
        'history_fill_ratio': forecast.get('history_fill_ratio'),
        'event_time': status.get('last_event_time'),
        'calibration_alert_authority': calibration.get('alert_authority'),
        'calibration_promotion_eligible': calibration.get('promotion_eligible'),
        'horizons': {},
    }
    world = forecast.get('horizons') or {}
    consensus = shadow.get('consensus') or {}
    calibrated = calibration.get('horizons') or {}
    for seconds in (10, 30, 60):
        world_item = next(
            (item for item in world.values() if int(item.get('seconds') or 0) == seconds),
            {},
        )
        cal_item = calibrated.get(str(seconds)) or {}
        raw_item = consensus.get(str(seconds)) or {}
        result['horizons'][str(seconds)] = {
            'world_attack_probability': world_item.get('future_attack_probability'),
            'world_predicted_class': world_item.get('predicted_class'),
            'calibrated_attack_probability': cal_item.get('calibrated_attack_probability'),
            'calibrated_threshold': cal_item.get('threshold'),
            'calibrated_shadow_alert': cal_item.get('shadow_alert'),
            'watch_threshold': cal_item.get('watch_threshold'),
            'calibrated_shadow_watch': cal_item.get('shadow_watch'),
            'raw_shadow_mean_probability': raw_item.get('mean_probability'),
        }
    next_stage = forecast.get('next_stage_forecast') or {}
    result['next_stage'] = {
        'label': next_stage.get('predicted_next_stage'),
        'confidence': next_stage.get('confidence'),
        'alert_authority': next_stage.get('alert_authority'),
    }
    return result


def summarize(rows: list[dict[str, Any]], campaign_id: str) -> dict[str, Any]:
    attack_labels = {'INITIAL_ACCESS_PATTERN', 'DDOS_LOW', 'DDOS_MEDIUM', 'DDOS_HIGH'}
    onset = None
    for row in rows:
        if row.get('ground_truth_label') in attack_labels:
            onset = datetime.fromisoformat(row['captured_at'])
            break
    first_pre_onset_alert: dict[str, Any] = {}
    peak_pre_onset: dict[str, float] = {}
    for seconds in (10, 30, 60):
        key = str(seconds)
        candidates = []
        alert_rows = []
        for row in rows:
            captured = datetime.fromisoformat(row['captured_at'])
            if onset is not None and captured >= onset:
                continue
            item = (row.get('model') or {}).get('horizons', {}).get(key, {})
            probability = item.get('calibrated_attack_probability')
            if probability is not None:
                candidates.append(float(probability))
            if item.get('calibrated_shadow_alert'):
                alert_rows.append(row)
        peak_pre_onset[key] = max(candidates) if candidates else 0.0
        if alert_rows and onset is not None:
            first = alert_rows[0]
            when = datetime.fromisoformat(first['captured_at'])
            first_pre_onset_alert[key] = {
                'captured_at': first['captured_at'],
                'lead_seconds': max(0.0, (onset - when).total_seconds()),
            }
        else:
            first_pre_onset_alert[key] = None
    return {
        'campaign_id': campaign_id,
        'samples': len(rows),
        'observed_attack_onset': onset.isoformat() if onset else None,
        'peak_pre_onset_calibrated_probability': peak_pre_onset,
        'first_pre_onset_calibrated_alert': first_pre_onset_alert,
        'claim_guard': 'ground-truth phase data is captured only for evaluation/display and is not passed into the inference service',
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--campaign-id', default='eve-demo-v1')
    parser.add_argument('--duration', type=float, default=300)
    parser.add_argument('--interval', type=float, default=2)
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'outputs' / 'demo')
    args = parser.parse_args()
    if args.duration <= 0 or args.interval <= 0:
        parser.error('duration and interval must be positive')

    args.output_dir.mkdir(parents=True, exist_ok=True)
    stamp = now_utc().strftime('%Y%m%dT%H%M%SZ')
    jsonl_path = args.output_dir / f'{args.campaign_id}-{stamp}.jsonl'
    summary_path = args.output_dir / f'{args.campaign_id}-{stamp}-summary.json'
    rows: list[dict[str, Any]] = []
    deadline = time.monotonic() + args.duration
    connection = sqlite3.connect(f'file:{DB.as_posix()}?mode=ro', uri=True)
    try:
        while time.monotonic() < deadline:
            captured = now_utc()
            truth = current_truth(connection, args.campaign_id, captured)
            status = jload(STATUS)
            row = {
                'captured_at': captured.isoformat(),
                'run_id': truth.get('run_id'),
                'scenario': truth.get('scenario'),
                'run_status': truth.get('run_status'),
                'ground_truth_phase': truth.get('phase'),
                'ground_truth_label': truth.get('label'),
                'ground_truth_phase_started_at': truth.get('phase_started_at'),
                'model': compact_status(status),
            }
            rows.append(row)
            with jsonl_path.open('a', encoding='utf-8') as handle:
                handle.write(json.dumps(row, sort_keys=True) + '\n')
            time.sleep(args.interval)
    finally:
        connection.close()

    summary = summarize(rows, args.campaign_id)
    summary['timeline'] = str(jsonl_path)
    summary_path.write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
    (args.output_dir / 'latest-summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'timeline': str(jsonl_path), 'summary': str(summary_path), **summary}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
