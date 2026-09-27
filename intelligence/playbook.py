from __future__ import annotations

PLAYBOOKS = {
    'BENIGN': ['Continue monitoring; no containment action recommended.'],
    'RECONNAISSANCE': [
        'Validate whether the scanning source is authorized.',
        'Review destination-port fan-out and repeated SYN behavior.',
        'Rate-limit or isolate the source only after operator verification.',
    ],
    'INITIAL_ACCESS_PATTERN': [
        'Review authentication/service logs on the predicted target.',
        'Confirm exposed service inventory and recent configuration changes.',
        'Prepare host isolation if compromise evidence appears.',
    ],
    'LATERAL_MOVEMENT': [
        'Inspect east-west sessions and identity context for the source host.',
        'Check remote-service use on predicted next targets.',
        'Segment or quarantine only after operator validation.',
    ],
    'C2_BEACON_PATTERN': [
        'Validate periodic destination and process ownership.',
        'Inspect DNS/proxy/session logs for repeated callbacks.',
        'Prepare egress containment if C2 is confirmed.',
    ],
    'EXFILTRATION_LIKE': [
        'Inspect unusual outbound volume and destination ownership.',
        'Correlate transfer timing with host/process activity.',
        'Preserve evidence before containment where policy permits.',
    ],
    'DDOS_LOW': ['Confirm victim/service saturation indicators.', 'Apply bounded rate controls if operator-approved.'],
    'DDOS_MEDIUM': ['Confirm multi-source convergence on the victim.', 'Prepare upstream filtering/rate controls and service protection.'],
    'DDOS_HIGH': ['Escalate as potential impact event.', 'Validate upstream filtering, rate controls, and service failover options.'],
}


def recommendations(label: str) -> list[str]:
    return list(PLAYBOOKS.get(label, ['Investigate telemetry and validate the forecast before action.']))


def enrich_forecast(forecast: dict) -> dict:
    enriched = dict(forecast)
    horizons = {}
    for key, original in forecast.get('horizons', {}).items():
        item = dict(original)
        item['operator_recommendations'] = recommendations(str(item.get('predicted_class')))
        horizons[key] = item
    enriched['horizons'] = horizons
    return enriched
