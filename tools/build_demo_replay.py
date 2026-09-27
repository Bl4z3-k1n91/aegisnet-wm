#!/usr/bin/env python3
"""Build a judge-facing replay package from one held-out EVE cyber scenario."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'models' / 'world_model'))
sys.path.insert(0, str(ROOT / 'experiments'))

from eve_shadow_calibration import EveShadowCalibrator, raw_shadow_forecast  # noqa: E402
from inference import WorldForecaster  # noqa: E402
from lab_temporal_dataset import run_states  # noqa: E402
from next_stage import NextStageForecaster  # noqa: E402
from open_world import OpenWorldAttackForecaster  # noqa: E402
from config import WorldModelConfig  # noqa: E402


WORLD_ARTIFACT = ROOT / 'models' / 'artifacts' / 'ntro-world-bootstrap-v1'
CALIBRATION_ARTIFACT = ROOT / 'models' / 'artifacts' / 'eve-shadow-calibration-v1'
NEXT_STAGE_ARTIFACT = ROOT / 'models' / 'artifacts' / 'genis-next-stage-v1'
SHADOW_ARTIFACTS = {
    'GENIS': ROOT / 'models' / 'artifacts' / 'genis-open-world-v1',
    'CTU13': ROOT / 'models' / 'artifacts' / 'ctu13-open-world-v1',
    'CICIDS2017': ROOT / 'models' / 'artifacts' / 'cicids2017-open-world-v1',
}


def states_as_dicts(rows: list[np.ndarray], features: list[str]) -> list[dict[str, float]]:
    return [
        {feature: float(value) for feature, value in zip(features, row)}
        for row in rows
    ]


def horizon_item(forecast: dict[str, Any], seconds: int) -> dict[str, Any] | None:
    for item in (forecast.get('horizons') or {}).values():
        if int(item.get('seconds') or 0) == seconds:
            return item
    return None


def phase_transitions(labels: list[str], sample_times: list[str]) -> list[dict[str, Any]]:
    transitions: list[dict[str, Any]] = []
    previous = None
    for label, timestamp in zip(labels, sample_times):
        if label != previous:
            transitions.append({'timestamp': timestamp, 'label': label})
            previous = label
    return transitions


def build_replay(database: Path, run_id: int) -> dict[str, Any]:
    connection = sqlite3.connect(f'file:{database.as_posix()}?mode=ro', uri=True)
    connection.row_factory = sqlite3.Row
    try:
        run = connection.execute('SELECT * FROM scenario_runs WHERE id=?', (run_id,)).fetchone()
        if run is None:
            raise RuntimeError(f'run {run_id} not found')
        if str(run['status']) != 'COMPLETED':
            raise RuntimeError(f'run {run_id} status is {run["status"]}, not COMPLETED')

        world = WorldForecaster(WORLD_ARTIFACT)
        features = list(world.features)
        config = WorldModelConfig(
            history_steps=world.config.history_steps,
            horizons=world.config.horizons,
            window_seconds=world.config.window_seconds,
            latent_dim=world.config.latent_dim,
        )
        rows, labels, sample_times = run_states(connection, run, features, config)
    finally:
        connection.close()

    shadow_models = {
        name: OpenWorldAttackForecaster(path)
        for name, path in SHADOW_ARTIFACTS.items()
        if (path / 'metadata.json').exists()
    }
    calibrator = EveShadowCalibrator(CALIBRATION_ARTIFACT)
    next_stage = NextStageForecaster(NEXT_STAGE_ARTIFACT)

    history_steps = config.history_steps
    max_horizon = max(config.horizons)
    timeline: list[dict[str, Any]] = []
    for index in range(history_steps - 1, len(rows) - max_horizon):
        history_rows = rows[index - history_steps + 1:index + 1]
        history = states_as_dicts(history_rows, features)
        world_result = world.forecast(history)
        shadow = raw_shadow_forecast(shadow_models, history)
        eve = calibrator.enrich(shadow)
        next_result = next_stage.forecast(history, labels[index])
        item: dict[str, Any] = {
            'index': index,
            'timestamp': sample_times[index],
            'truth_now': labels[index],
            'next_stage': next_result,
            'horizons': {},
        }
        for step in config.horizons:
            seconds = step * config.window_seconds
            truth_index = index + step
            truth_future = labels[truth_index]
            world_h = horizon_item(world_result, seconds) or {}
            shadow_h = (shadow.get('consensus') or {}).get(str(seconds), {})
            cal_h = (eve.get('horizons') or {}).get(str(seconds), {})
            item['horizons'][str(seconds)] = {
                'truth_future': truth_future,
                'world_predicted_class': world_h.get('predicted_class'),
                'world_attack_probability': float(world_h.get('future_attack_probability') or 0.0),
                'world_abstain': bool(world_h.get('abstain')),
                'shadow_mean_probability': float(shadow_h.get('mean_probability') or 0.0),
                'calibrated_attack_probability': float(cal_h.get('calibrated_attack_probability') or 0.0),
                'calibrated_threshold': float(cal_h.get('threshold') or 0.0),
                'calibrated_shadow_alert': bool(cal_h.get('shadow_alert')),
            }
        timeline.append(item)

    transitions = phase_transitions(labels, sample_times)
    attack_transitions = [x for x in transitions if x['label'] != 'BENIGN']
    first_attack = datetime.fromisoformat(attack_transitions[0]['timestamp']) if attack_transitions else None
    escalation_transition = next(
        (
            x for x in attack_transitions
            if x['label'] not in {'RECONNAISSANCE'}
        ),
        None,
    )
    escalation_time = (
        datetime.fromisoformat(escalation_transition['timestamp'])
        if escalation_transition else None
    )
    warnings: list[dict[str, Any]] = []
    escalation_warnings: list[dict[str, Any]] = []
    if first_attack is not None:
        for row in timeline:
            now = datetime.fromisoformat(row['timestamp'])
            if now >= first_attack:
                continue
            for seconds, h in row['horizons'].items():
                if h['calibrated_shadow_alert'] and h['truth_future'] != 'BENIGN':
                    warnings.append({
                        'timestamp': row['timestamp'],
                        'horizon_seconds': int(seconds),
                        'probability': h['calibrated_attack_probability'],
                        'threshold': h['calibrated_threshold'],
                        'lead_seconds': (first_attack - now).total_seconds(),
                    })
    if escalation_time is not None:
        for row in timeline:
            now = datetime.fromisoformat(row['timestamp'])
            if now >= escalation_time:
                continue
            for seconds, h in row['horizons'].items():
                if (
                    h['calibrated_shadow_alert']
                    and h['truth_future'] == escalation_transition['label']
                ):
                    lead = (escalation_time - now).total_seconds()
                    if 0 < lead <= int(seconds) + config.window_seconds:
                        escalation_warnings.append({
                            'timestamp': row['timestamp'],
                            'target_stage': escalation_transition['label'],
                            'target_timestamp': escalation_transition['timestamp'],
                            'horizon_seconds': int(seconds),
                            'probability': h['calibrated_attack_probability'],
                            'threshold': h['calibrated_threshold'],
                            'lead_seconds': lead,
                        })
    best_warning = max(warnings, key=lambda x: x['lead_seconds']) if warnings else None
    best_escalation_warning = (
        max(escalation_warnings, key=lambda x: x['lead_seconds'])
        if escalation_warnings else None
    )
    return {
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'run': {
            'id': int(run['id']),
            'scenario': str(run['scenario']),
            'campaign_id': str(run['campaign_id']),
            'split': str(run['split']),
            'status': str(run['status']),
        },
        'held_out_demo': str(run['campaign_id']) != 'eve-cyber-v1',
        'calibration_campaign': 'eve-cyber-v1',
        'authority_policy': 'all replay forecasts are evidence-only; local present-state detector retains alert authority',
        'phase_transitions': transitions,
        'best_pre_onset_warning': best_warning,
        'best_pre_escalation_warning': best_escalation_warning,
        'timeline': timeline,
    }


def markdown(replay: dict[str, Any]) -> str:
    run = replay['run']
    lines = [
        '# AegisNet-WM Held-Out Demo Replay',
        '',
        f"Run **{run['id']}** · `{run['scenario']}` · campaign `{run['campaign_id']}`",
        '',
        f"Held out from calibration campaign: **{replay['held_out_demo']}**",
        '',
        '## Ground-truth progression',
        '',
    ]
    for transition in replay['phase_transitions']:
        lines.append(f"- `{transition['timestamp']}` → **{transition['label']}**")
    lines += ['', '## Pre-onset warning', '']
    warning = replay.get('best_pre_onset_warning')
    if warning:
        lines.append(
            f"Conservative EVE-calibrated shadow warning appeared **{warning['lead_seconds']:.0f}s before** "
            f"the first attack phase at the +{warning['horizon_seconds']}s horizon "
            f"(p={warning['probability']:.1%}, threshold={warning['threshold']:.1%})."
        )
    else:
        lines.append(
            'No conservative EVE-calibrated pre-onset alert occurred on this held-out run. '
            'The replay still shows probability evolution and abstention honestly.'
        )
    lines += ['', '## Pre-escalation warning', '']
    escalation = replay.get('best_pre_escalation_warning')
    if escalation:
        lines.append(
            f"While the network was already in reconnaissance, the calibrated shadow forecaster crossed "
            f"threshold **{escalation['lead_seconds']:.0f}s before** the next stage "
            f"**{escalation['target_stage']}** at the +{escalation['horizon_seconds']}s horizon "
            f"(p={escalation['probability']:.1%}, threshold={escalation['threshold']:.1%})."
        )
    else:
        lines.append('No conservative pre-escalation warning occurred on this held-out run.')
    lines += [
        '',
        '## Replay timeline',
        '',
        '| Time | Truth now | +10s calibrated | +30s calibrated | +60s calibrated | Next-stage shadow |',
        '|---|---|---:|---:|---:|---|',
    ]
    for row in replay['timeline']:
        values = []
        for seconds in ('10', '30', '60'):
            h = row['horizons'].get(seconds, {})
            marker = ' ⚠' if h.get('calibrated_shadow_alert') else ''
            values.append(f"{float(h.get('calibrated_attack_probability') or 0):.1%}{marker}")
        next_stage = row.get('next_stage') or {}
        lines.append(
            f"| {row['timestamp'][11:19]} | {row['truth_now']} | {values[0]} | {values[1]} | {values[2]} | "
            f"{next_stage.get('predicted_next_stage','UNKNOWN')} ({float(next_stage.get('confidence') or 0):.1%}) |"
        )
    lines += [
        '',
        '> Demo rule: calibrated/public/next-stage outputs are shadow evidence only and cannot change the operator alert state.',
        '',
    ]
    return '\n'.join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-id', type=int, default=90)
    parser.add_argument('--database', type=Path, default=ROOT / 'outputs' / 'telemetry.db')
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'outputs' / 'demo')
    args = parser.parse_args()
    replay = build_replay(args.database, args.run_id)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    json_path = args.output_dir / f'demo-run-{args.run_id}.json'
    md_path = args.output_dir / f'demo-run-{args.run_id}.md'
    json_path.write_text(json.dumps(replay, indent=2) + '\n', encoding='utf-8')
    md_path.write_text(markdown(replay), encoding='utf-8')
    (args.output_dir / 'latest.json').write_text(json.dumps(replay, indent=2) + '\n', encoding='utf-8')
    (args.output_dir / 'latest.md').write_text(markdown(replay), encoding='utf-8')
    print(json.dumps({
        'json': str(json_path),
        'markdown': str(md_path),
        'held_out_demo': replay['held_out_demo'],
        'best_pre_onset_warning': replay['best_pre_onset_warning'],
        'best_pre_escalation_warning': replay['best_pre_escalation_warning'],
        'timeline_rows': len(replay['timeline']),
    }, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
