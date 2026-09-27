#!/usr/bin/env python3
"""Build one reproducible AegisNet evidence bundle from current artifacts/runtime."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'intelligence'))
from audit_chain import verify as verify_audit  # noqa: E402


def jload(path: Path) -> Any:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except Exception as exc:
        return {'error': f'{type(exc).__name__}: {exc}', 'path': str(path)}


def sha256(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def latest_eval() -> dict[str, Any] | None:
    folder = ROOT / 'outputs' / 'evaluations'
    files = sorted(folder.glob('eve-forecast-eval-*.json'), key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        return None
    data = jload(files[0])
    return {'path': str(files[0]), 'data': data}


def latest_demo() -> dict[str, Any] | None:
    path = ROOT / 'outputs' / 'demo' / 'latest.json'
    if not path.exists():
        return None
    return {'path': str(path), 'data': jload(path)}


def ablation_table(metrics: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(metrics, dict):
        return {}
    world = metrics.get('world_model') or {}
    direct = metrics.get('direct_gru_baseline') or {}
    classical = metrics.get('classical_baselines') or {}
    result: dict[str, Any] = {}
    for horizon in ('1', '3', '6'):
        result[horizon] = {
            'persistence': (classical.get('persistence') or {}).get(horizon),
            'markov': (classical.get('markov') or {}).get(horizon),
            'logistic_forecast': (classical.get('logistic_forecast') or {}).get(horizon),
            'direct_gru_no_rollout': direct.get(horizon),
            'latent_world_model': world.get(horizon),
        }
    return result


def render_markdown(bundle: dict[str, Any]) -> str:
    lines = [
        '# AegisNet-WM Evidence Bundle',
        '',
        f"Generated: {bundle['generated_at']}",
        '',
        '## Runtime',
        '',
        f"- Analysis: `{(bundle.get('runtime', {}).get('analysis') or {}).get('state', 'unknown')}`",
        f"- Telemetry: `{(bundle.get('runtime', {}).get('telemetry') or {}).get('state', 'unknown')}`",
        f"- Forecast audit valid: `{(bundle.get('audit') or {}).get('valid', False)}`",
        '',
        '## GeNIS 3-seed future-attack evidence',
        '',
        '| Horizon | AUROC | AUPRC | Exact macro-F1 | Benign FPR |',
        '|---:|---:|---:|---:|---:|',
    ]
    aggregate = bundle.get('genis_multiseed') or {}
    for step, seconds in [('1', 10), ('3', 30), ('6', 60)]:
        item = (aggregate.get('horizons') or {}).get(step, {})
        def mean(name: str) -> float:
            return float((item.get(name) or {}).get('mean') or 0.0)
        lines.append(
            f"| +{seconds}s | {mean('attack_auroc'):.3f} | {mean('attack_auprc'):.3f} | "
            f"{mean('macro_f1'):.3f} | {mean('benign_false_positive_rate'):.3f} |"
        )
    lines += [
        '',
        '## Transition-specific model',
        '',
    ]
    next_stage = ((bundle.get('next_stage') or {}).get('test') or {})
    if next_stage:
        lines.append(
            f"Held-out transition accuracy: **{float(next_stage.get('transition_accuracy') or 0):.1%}** "
            f"over **{int(next_stage.get('transition_samples') or 0)}** transition samples."
        )
    else:
        lines.append('No next-stage artifact found.')
    lines += [
        '',
        '## Local EVE calibration',
        '',
    ]
    promotion = bundle.get('eve_calibration_promotion')
    if promotion:
        lines.append(f"- Promotion eligible: `{bool(promotion.get('eligible'))}`")
        lines.append(f"- Alert authority: `{bool(promotion.get('alert_authority'))}`")
        lines.append(f"- Reason: {promotion.get('reason')}")
    else:
        lines.append('- Not trained yet. Collect run-level EVE cyber scenarios first.')
    lines += [
        '',
        '## Claim guard',
        '',
        '> Public-dataset models and the transition-specific model remain evidence-only. '
        'The local present-state detector retains operator-facing alert authority until '
        'EVE-domain calibration and false-alert gates pass and are manually reviewed.',
        '',
        '## Ablation',
        '',
        'The JSON bundle contains the full persistence / Markov / logistic / direct-GRU / latent-world-model comparison. '
        'Overall persistence metrics are intentionally retained because they expose how easy long steady-state windows are; '
        'transition-only metrics must be used when making forecasting claims.',
        '',
    ]
    return '\n'.join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-tests', action='store_true')
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'outputs' / 'evidence')
    args = parser.parse_args()

    genis_metrics_path = ROOT / 'models' / 'artifacts' / 'genis-world-v1' / 'metrics.json'
    aggregate_path = ROOT / 'models' / 'artifacts' / 'genis-world-multiseed-v1' / 'aggregate.json'
    next_stage_path = ROOT / 'models' / 'artifacts' / 'genis-next-stage-v1' / 'metrics.json'
    open_world_path = ROOT / 'models' / 'artifacts' / 'genis-open-world-v1' / 'metrics.json'
    eve_metrics_path = ROOT / 'models' / 'artifacts' / 'eve-shadow-calibration-v1' / 'metrics.json'
    eve_promotion_path = ROOT / 'models' / 'artifacts' / 'eve-shadow-calibration-v1' / 'promotion.json'

    test_result: dict[str, Any] | None = None
    if args.run_tests:
        completed = subprocess.run(
            [sys.executable, '-m', 'unittest', 'discover', '-s', str(ROOT / 'tests'), '-v'],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        test_result = {
            'returncode': completed.returncode,
            'passed': completed.returncode == 0,
            'output_tail': '\n'.join((completed.stdout + completed.stderr).splitlines()[-20:]),
        }

    genis_metrics = jload(genis_metrics_path)
    bundle: dict[str, Any] = {
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'runtime': {
            'analysis': jload(ROOT / 'outputs' / 'analysis-status.json'),
            'telemetry': jload(ROOT / 'outputs' / 'telemetry-status.json'),
        },
        'audit': verify_audit(ROOT / 'outputs' / 'forecast-audit.jsonl'),
        'tests': test_result,
        'genis_world': genis_metrics,
        'genis_multiseed': jload(aggregate_path),
        'genis_open_world': jload(open_world_path),
        'next_stage': jload(next_stage_path),
        'eve_calibration_metrics': jload(eve_metrics_path),
        'eve_calibration_promotion': jload(eve_promotion_path),
        'latest_eve_evaluation': latest_eval(),
        'held_out_demo': latest_demo(),
        'ablation': ablation_table(genis_metrics if isinstance(genis_metrics, dict) else None),
        'artifact_hashes': {
            str(path.relative_to(ROOT)): sha256(path)
            for path in (
                genis_metrics_path,
                aggregate_path,
                next_stage_path,
                open_world_path,
                eve_metrics_path,
                eve_promotion_path,
            )
            if path.exists()
        },
        'authority_policy': {
            'present_detector': 'operator alert authority',
            'public_models': 'shadow only',
            'eve_calibrated_shadow': 'shadow only even if promotion gates pass; manual review required',
            'next_stage': 'shadow evidence only',
        },
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    json_path = args.output_dir / f'evidence-{stamp}.json'
    md_path = args.output_dir / f'evidence-{stamp}.md'
    json_path.write_text(json.dumps(bundle, indent=2) + '\n', encoding='utf-8')
    md_path.write_text(render_markdown(bundle), encoding='utf-8')
    (args.output_dir / 'latest.json').write_text(json.dumps(bundle, indent=2) + '\n', encoding='utf-8')
    (args.output_dir / 'latest.md').write_text(render_markdown(bundle), encoding='utf-8')
    print(json.dumps({'json': str(json_path), 'markdown': str(md_path)}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
