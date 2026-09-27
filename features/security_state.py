"""Build continuous security-oriented network state vectors from flow records.

The world model should consume a sequence of network states rather than isolated
flow labels.  This module intentionally uses only standard-library dependencies
so state construction remains reproducible and usable in the offline lab.
"""

from __future__ import annotations

import ipaddress
import json
import math
import statistics
from bisect import bisect_left
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Any, Iterable, Mapping, Sequence


TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20

DEFAULT_INTERNAL_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


def _as_dict(record: Mapping[str, Any] | Any) -> dict[str, Any]:
    if isinstance(record, dict):
        row = dict(record)
    elif hasattr(record, "keys"):
        row = {key: record[key] for key in record.keys()}
    else:
        row = dict(record)
    raw = row.get("raw_json")
    if raw:
        try:
            decoded = json.loads(raw)
        except (TypeError, json.JSONDecodeError):
            decoded = {}
        if isinstance(decoded, dict):
            for key, value in decoded.items():
                if key not in row or row[key] is None:
                    row[key] = value
    return row


def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None


def _event_time(record: Mapping[str, Any]) -> datetime | None:
    """Prefer reconstructed flow end time over collector receipt time."""

    return _parse_time(record.get("flow_end")) or _parse_time(record.get("timestamp"))


def _percentile(values: Sequence[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    position = (len(ordered) - 1) * fraction
    low = math.floor(position)
    high = math.ceil(position)
    if low == high:
        return float(ordered[low])
    weight = position - low
    return float(ordered[low] * (1 - weight) + ordered[high] * weight)


def _is_internal(address: Any, networks: Sequence[ipaddress._BaseNetwork]) -> bool:
    if not address:
        return False
    try:
        ip = ipaddress.ip_address(str(address))
    except ValueError:
        return False
    return any(ip in network for network in networks if ip.version == network.version)


def _flow_duration_ms(record: Mapping[str, Any]) -> float | None:
    start = _parse_time(record.get("flow_start"))
    end = _parse_time(record.get("flow_end"))
    if start is not None and end is not None and end >= start:
        return (end - start).total_seconds() * 1000.0
    start_ms = record.get("flow_start_uptime_ms")
    end_ms = record.get("flow_end_uptime_ms")
    if isinstance(start_ms, (int, float)) and isinstance(end_ms, (int, float)):
        if end_ms >= start_ms:
            return float(end_ms - start_ms)
    return None


def _normalized_entropy(values: Iterable[int]) -> float:
    counts = Counter(values)
    total = sum(counts.values())
    if total <= 1 or len(counts) <= 1:
        return 0.0
    entropy = -sum(
        (count / total) * math.log2(count / total) for count in counts.values()
    )
    return entropy / math.log2(len(counts))


def _sequential_port_score(records: Sequence[Mapping[str, Any]]) -> float:
    """Fraction of per-source/destination port transitions that are sequential."""

    groups: dict[tuple[str, str], list[tuple[datetime, int]]] = defaultdict(list)
    for record in records:
        port = record.get("dst_port")
        timestamp = _event_time(record)
        src, dst = record.get("src_ip"), record.get("dst_ip")
        if not src or not dst or not timestamp or not isinstance(port, int) or port <= 0:
            continue
        groups[(str(src), str(dst))].append((timestamp, port))

    transitions = 0
    sequential = 0
    for events in groups.values():
        events.sort(key=lambda item: item[0])
        ports = [port for _, port in events]
        for previous, current in zip(ports, ports[1:]):
            transitions += 1
            if abs(current - previous) == 1:
                sequential += 1
    return sequential / transitions if transitions else 0.0


def build_state(
    records: Iterable[Mapping[str, Any] | Any],
    *,
    previous_records: Iterable[Mapping[str, Any] | Any] = (),
    internal_networks: Sequence[ipaddress._BaseNetwork] = DEFAULT_INTERNAL_NETWORKS,
) -> dict[str, Any]:
    """Aggregate flow records into one security-oriented world-model state."""

    rows = [_as_dict(record) for record in records]
    previous = [_as_dict(record) for record in previous_records]

    src_ips = {str(row["src_ip"]) for row in rows if row.get("src_ip")}
    dst_ips = {str(row["dst_ip"]) for row in rows if row.get("dst_ip")}
    dst_ports = {
        int(row["dst_port"])
        for row in rows
        if isinstance(row.get("dst_port"), int) and int(row["dst_port"]) > 0
    }
    previous_dst_ips = {
        str(row["dst_ip"]) for row in previous if row.get("dst_ip")
    }
    previous_dst_ports = {
        int(row["dst_port"])
        for row in previous
        if isinstance(row.get("dst_port"), int) and int(row["dst_port"]) > 0
    }

    flags = [int(row.get("tcp_flags") or 0) for row in rows if row.get("protocol") == 6]
    tcp_flows = len(flags)
    syn_count = sum(bool(flag & TCP_SYN) for flag in flags)
    ack_count = sum(bool(flag & TCP_ACK) for flag in flags)
    rst_count = sum(bool(flag & TCP_RST) for flag in flags)
    fin_count = sum(bool(flag & TCP_FIN) for flag in flags)
    psh_count = sum(bool(flag & TCP_PSH) for flag in flags)
    urg_count = sum(bool(flag & TCP_URG) for flag in flags)
    syn_only_count = sum(bool(flag & TCP_SYN) and not bool(flag & TCP_ACK) for flag in flags)

    fanout: dict[str, set[str]] = defaultdict(set)
    port_fanout: dict[str, set[int]] = defaultdict(set)
    for row in rows:
        src, dst = row.get("src_ip"), row.get("dst_ip")
        if src and dst:
            fanout[str(src)].add(str(dst))
        port = row.get("dst_port")
        if src and isinstance(port, int) and port > 0:
            port_fanout[str(src)].add(port)

    timestamps = sorted(
        timestamp
        for timestamp in (_event_time(row) for row in rows)
        if timestamp is not None
    )
    iats_ms = [
        (current - previous_time).total_seconds() * 1000.0
        for previous_time, current in zip(timestamps, timestamps[1:])
        if current >= previous_time
    ]
    durations = [
        duration for duration in (_flow_duration_ms(row) for row in rows) if duration is not None
    ]

    east_west = 0
    north_south = 0
    for row in rows:
        src_internal = _is_internal(row.get("src_ip"), internal_networks)
        dst_internal = _is_internal(row.get("dst_ip"), internal_networks)
        if src_internal and dst_internal:
            east_west += 1
        elif src_internal != dst_internal:
            north_south += 1

    packet_count = sum(int(row.get("packets") or 0) for row in rows)
    byte_count = sum(int(row.get("bytes") or 0) for row in rows)
    iat_mean = statistics.fmean(iats_ms) if iats_ms else None
    iat_std = statistics.stdev(iats_ms) if len(iats_ms) > 1 else (0.0 if iats_ms else None)

    port_events = [
        int(row["dst_port"])
        for row in rows
        if isinstance(row.get("dst_port"), int) and int(row["dst_port"]) > 0
    ]

    return {
        "flow_count": len(rows),
        "packet_count": packet_count,
        "byte_count": byte_count,
        "unique_src_ips": len(src_ips),
        "unique_dst_ips": len(dst_ips),
        "unique_dst_ports": len(dst_ports),
        "new_dst_hosts": len(dst_ips - previous_dst_ips),
        "new_dst_ports": len(dst_ports - previous_dst_ports),
        "tcp_flow_count": tcp_flows,
        "syn_count": syn_count,
        "ack_count": ack_count,
        "rst_count": rst_count,
        "fin_count": fin_count,
        "psh_count": psh_count,
        "urg_count": urg_count,
        "syn_only_count": syn_only_count,
        "syn_ack_ratio": syn_count / max(ack_count, 1),
        "rst_ratio": rst_count / max(tcp_flows, 1),
        "max_host_fanout": max((len(values) for values in fanout.values()), default=0),
        "max_port_fanout": max((len(values) for values in port_fanout.values()), default=0),
        "port_entropy": _normalized_entropy(port_events),
        "sequential_port_score": _sequential_port_score(rows),
        "east_west_flows": east_west,
        "north_south_flows": north_south,
        "iat_mean_ms": iat_mean,
        "iat_std_ms": iat_std,
        "iat_cv": None if not iat_mean else (iat_std or 0.0) / iat_mean,
        "flow_duration_mean_ms": statistics.fmean(durations) if durations else None,
        "flow_duration_p95_ms": _percentile(durations, 0.95),
    }


def build_state_windows(
    connection: Any,
    start: str | datetime,
    end: str | datetime,
    *,
    window_seconds: float = 10.0,
    stride_seconds: float = 10.0,
    lookback_seconds: float = 60.0,
) -> list[dict[str, Any]]:
    """Build a continuous timeline of flow states from the telemetry database."""

    start_dt = _parse_time(start) if not isinstance(start, datetime) else start
    end_dt = _parse_time(end) if not isinstance(end, datetime) else end
    if start_dt is None or end_dt is None or end_dt <= start_dt:
        raise ValueError("start and end must be valid increasing timestamps")
    if window_seconds <= 0 or stride_seconds <= 0 or lookback_seconds < 0:
        raise ValueError("window/stride must be positive and lookback non-negative")

    width = timedelta(seconds=window_seconds)
    stride = timedelta(seconds=stride_seconds)
    lookback = timedelta(seconds=lookback_seconds)
    query_start = start_dt - lookback
    all_rows = connection.execute(
        """
        SELECT * FROM flows
        WHERE julianday(COALESCE(flow_end,timestamp)) >= julianday(?)
          AND julianday(COALESCE(flow_end,timestamp)) < julianday(?)
        ORDER BY julianday(COALESCE(flow_end,timestamp)), id
        """,
        (query_start.isoformat(), end_dt.isoformat()),
    ).fetchall()
    all_rows = [_as_dict(row) for row in all_rows]
    row_times = [_event_time(row) for row in all_rows]
    valid = [
        (timestamp, row)
        for timestamp, row in zip(row_times, all_rows)
        if timestamp is not None
    ]
    row_times = [item[0] for item in valid]
    all_rows = [item[1] for item in valid]

    cursor = start_dt
    states: list[dict[str, Any]] = []
    while cursor < end_dt:
        window_end = min(cursor + width, end_dt)
        current_start = bisect_left(row_times, cursor)
        current_end = bisect_left(row_times, window_end)
        previous_start = bisect_left(row_times, cursor - lookback)
        previous_end = current_start
        rows = all_rows[current_start:current_end]
        previous_rows = all_rows[previous_start:previous_end]
        state = build_state(rows, previous_records=previous_rows)
        state.update(
            {
                "window_start": cursor.isoformat(),
                "window_end": window_end.isoformat(),
                "window_seconds": (window_end - cursor).total_seconds(),
            }
        )
        states.append(state)
        cursor += stride
    return states
