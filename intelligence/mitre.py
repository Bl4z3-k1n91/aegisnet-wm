from __future__ import annotations

from typing import Any

ATTACK_MAP = {
    'BENIGN': {'tactic': 'None', 'tactic_id': None, 'technique': None, 'technique_id': None},
    'RECONNAISSANCE': {'tactic': 'Reconnaissance', 'tactic_id': 'TA0043', 'technique': 'Network Service Scanning', 'technique_id': 'T1046'},
    'INITIAL_ACCESS_PATTERN': {'tactic': 'Initial Access', 'tactic_id': 'TA0001', 'technique': 'External Remote Services', 'technique_id': 'T1133'},
    'LATERAL_MOVEMENT': {'tactic': 'Lateral Movement', 'tactic_id': 'TA0008', 'technique': 'Remote Services', 'technique_id': 'T1021'},
    'C2_BEACON_PATTERN': {'tactic': 'Command and Control', 'tactic_id': 'TA0011', 'technique': 'Application Layer Protocol', 'technique_id': 'T1071'},
    'EXFILTRATION_LIKE': {'tactic': 'Exfiltration', 'tactic_id': 'TA0010', 'technique': 'Exfiltration Over C2 Channel', 'technique_id': 'T1041'},
    'DDOS_LOW': {'tactic': 'Impact', 'tactic_id': 'TA0040', 'technique': 'Network Denial of Service', 'technique_id': 'T1498'},
    'DDOS_MEDIUM': {'tactic': 'Impact', 'tactic_id': 'TA0040', 'technique': 'Network Denial of Service', 'technique_id': 'T1498'},
    'DDOS_HIGH': {'tactic': 'Impact', 'tactic_id': 'TA0040', 'technique': 'Network Denial of Service', 'technique_id': 'T1498'},
}


def mitre_for_class(label: str) -> dict[str, Any]:
    return dict(ATTACK_MAP.get(label, {'tactic': 'Unknown', 'tactic_id': None, 'technique': None, 'technique_id': None}))


def enrich_forecast(forecast: dict[str, Any]) -> dict[str, Any]:
    enriched = dict(forecast)
    horizons = {}
    for key, original in forecast.get('horizons', {}).items():
        item = dict(original)
        item['mitre'] = mitre_for_class(str(item.get('predicted_class')))
        horizons[key] = item
    enriched['horizons'] = horizons
    return enriched
