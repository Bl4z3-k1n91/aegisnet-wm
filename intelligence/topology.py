from __future__ import annotations

from collections import Counter, deque
from typing import Any, Iterable

IP_TO_SITE = {
    '10.1.10.10': 'BR1',
    '10.2.10.10': 'BR2',
    '10.10.10.10': 'HUB',
    '10.20.10.10': 'DC',
}
GRAPH = {
    'BR1': ('CORE',),
    'BR2': ('CORE',),
    'HUB': ('CORE',),
    'DC': ('CORE',),
    'CORE': ('BR1', 'BR2', 'HUB', 'DC'),
}


def dominant_source_site(rows: Iterable[dict[str, Any]]) -> str | None:
    counts = Counter(IP_TO_SITE.get(str(row.get('src_ip'))) for row in rows)
    counts.pop(None, None)
    return counts.most_common(1)[0][0] if counts else None


def shortest_path(source: str | None, target: str | None) -> list[str]:
    if not source or not target or target in {'NONE', 'MULTI'}:
        return []
    if source == target:
        return [source]
    queue: deque[tuple[str, list[str]]] = deque([(source, [source])])
    seen = {source}
    while queue:
        node, path = queue.popleft()
        for neighbor in GRAPH.get(node, ()):
            if neighbor in seen:
                continue
            candidate = path + [neighbor]
            if neighbor == target:
                return candidate
            seen.add(neighbor)
            queue.append((neighbor, candidate))
    return []


def enrich_forecast(forecast: dict[str, Any], source_site: str | None) -> dict[str, Any]:
    enriched = dict(forecast)
    horizons = {}
    for key, original in forecast.get('horizons', {}).items():
        item = dict(original)
        victim = str(item.get('predicted_victim') or 'NONE')
        item['source_site'] = source_site
        item['topology_path'] = shortest_path(source_site, victim)
        horizons[key] = item
    enriched['horizons'] = horizons
    return enriched
