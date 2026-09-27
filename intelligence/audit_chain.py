from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
AUDIT_PATH = ROOT / 'outputs' / 'forecast-audit.jsonl'


def canonical(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(',', ':'), default=str)


def last_hash(path: Path = AUDIT_PATH) -> str:
    if not path.exists():
        return '0' * 64
    last = ''
    with path.open('r', encoding='utf-8') as handle:
        for line in handle:
            if line.strip():
                last = line
    if not last:
        return '0' * 64
    try:
        return str(json.loads(last)['hash'])
    except Exception:
        return '0' * 64


def append_event(event_type: str, payload: dict[str, Any], path: Path = AUDIT_PATH) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    previous = last_hash(path)
    body = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'event_type': event_type,
        'payload': payload,
        'previous_hash': previous,
    }
    digest = hashlib.sha256((previous + canonical(body)).encode('utf-8')).hexdigest()
    record = {**body, 'hash': digest}
    with path.open('a', encoding='utf-8') as handle:
        handle.write(canonical(record) + '\n')
    return record


def verify(path: Path = AUDIT_PATH) -> dict[str, Any]:
    previous = '0' * 64
    count = 0
    if not path.exists():
        return {'valid': True, 'records': 0, 'last_hash': previous}
    with path.open('r', encoding='utf-8') as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            record = json.loads(line)
            supplied = str(record.get('hash'))
            body = {key: value for key, value in record.items() if key != 'hash'}
            expected = hashlib.sha256((previous + canonical(body)).encode('utf-8')).hexdigest()
            if body.get('previous_hash') != previous or supplied != expected:
                return {'valid': False, 'records': count, 'failed_line': line_number, 'last_hash': previous}
            previous = supplied
            count += 1
    return {'valid': True, 'records': count, 'last_hash': previous}
