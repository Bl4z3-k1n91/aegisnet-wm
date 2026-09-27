from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
REPORT_DIR = ROOT / 'outputs' / 'reports'


def render_markdown(current: dict[str, Any], forecast: dict[str, Any]) -> str:
    lines = [
        '# AegisNet-WM Forecast Incident Brief',
        '',
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        f"Current state: {current.get('label', 'UNKNOWN')}",
        f"Current confidence: {float(current.get('confidence') or 0):.1%}",
        f"Cyber risk: {float(current.get('risk') or 0):.1%}",
        '',
        '## Forecast trajectory',
        '',
        '| Horizon | Predicted state | Confidence | Infiltration | Next victim | Path | MITRE |',
        '|---:|---|---:|---:|---|---|---|',
    ]
    for _, item in sorted(forecast.get('horizons', {}).items(), key=lambda kv: int(kv[0])):
        mitre = item.get('mitre') or {}
        path = ' -> '.join(item.get('topology_path') or []) or 'n/a'
        mitre_text = ' / '.join(part for part in [mitre.get('tactic_id'), mitre.get('technique_id')] if part) or 'n/a'
        predicted = 'ABSTAIN' if item.get('abstain') else item.get('predicted_class', 'UNKNOWN')
        lines.append(
            f"| +{item.get('seconds')}s | {predicted} | {float(item.get('confidence') or 0):.1%} | "
            f"{float(item.get('infiltration_probability') or 0):.1%} | {item.get('predicted_victim', 'NONE')} | {path} | {mitre_text} |"
        )
    lines += ['', '## Evidence', '']
    first = next(iter(forecast.get('horizons', {}).values()), {})
    for feature in first.get('top_features', []):
        lines.append(f"- {feature.get('feature')}: attribution {float(feature.get('attribution') or 0):.5f}")
    lines += [
        '',
        '## Evidence status',
        '',
        str(forecast.get('evidence_status', 'unknown')),
        '',
        '> Bootstrap forecasts are implementation/demo evidence only until validated on independent real temporal campaigns or public datasets.',
    ]
    return '\n'.join(lines) + '\n'


def write_report(current: dict[str, Any], forecast: dict[str, Any], prefix: str = 'forecast') -> Path:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    path = REPORT_DIR / f'{prefix}-{stamp}.md'
    path.write_text(render_markdown(current, forecast), encoding='utf-8')
    return path
