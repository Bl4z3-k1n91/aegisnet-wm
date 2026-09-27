from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / 'data' / 'knowledge_cache'


def _load(name: str) -> dict[str, Any] | None:
    path = CACHE / name
    if not path.exists():
        return None
    try:
        value = json.loads(path.read_text(encoding='utf-8'))
        return value if isinstance(value, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def enrich_forecast(forecast: dict[str, Any]) -> dict[str, Any]:
    capec = _load('capec_by_attack.json')
    cves = _load('cve_by_asset.json')
    enriched = dict(forecast)
    horizons = {}
    for key, original in forecast.get('horizons', {}).items():
        item = dict(original)
        mitre = item.get('mitre') or {}
        technique_id = mitre.get('technique_id')
        victim = str(item.get('predicted_victim') or 'NONE')
        item['knowledge'] = {
            'capec_status': 'available' if capec is not None else 'cache_missing',
            'capec': list((capec or {}).get(str(technique_id), [])),
            'cve_status': 'available' if cves is not None else 'cache_missing',
            'cves': list((cves or {}).get(victim, [])),
        }
        horizons[key] = item
    enriched['horizons'] = horizons
    return enriched
