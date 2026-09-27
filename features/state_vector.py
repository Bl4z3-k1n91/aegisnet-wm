"""Versioned fused network-state schema for the NTRO world model.

`ntro-state-v1` combines behavioral NetFlow features, optional packet/PCAP
features and selected network-health telemetry into one flat numeric state.  The
fixed feature order is intentionally explicit so classical baselines and neural
models consume exactly the same state representation.
"""

from __future__ import annotations

import statistics
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping, Sequence

from packet_state import aggregate_packet_state
from security_state import build_state


STATE_SCHEMA_VERSION = "ntro-state-v1"

FLOW_FEATURES = (
    "flow_count",
    "packet_count",
    "byte_count",
    "unique_src_ips",
    "unique_dst_ips",
    "unique_dst_ports",
    "new_dst_hosts",
    "new_dst_ports",
    "tcp_flow_count",
    "syn_count",
    "ack_count",
    "rst_count",
    "fin_count",
    "psh_count",
    "urg_count",
    "syn_only_count",
    "syn_ack_ratio",
    "rst_ratio",
    "max_host_fanout",
    "max_port_fanout",
    "port_entropy",
    "sequential_port_score",
    "east_west_flows",
    "north_south_flows",
    "iat_mean_ms",
    "iat_std_ms",
    "iat_cv",
    "flow_duration_mean_ms",
    "flow_duration_p95_ms",
)

PACKET_FEATURE_MAP = {
    "packet_event_count": "packet_event_count",
    "ttl_mean": "packet_ttl_mean",
    "ttl_std": "packet_ttl_std",
    "ttl_min": "packet_ttl_min",
    "ttl_max": "packet_ttl_max",
    "tcp_window_mean": "packet_tcp_window_mean",
    "tcp_window_std": "packet_tcp_window_std",
    "payload_mean": "packet_payload_mean",
    "payload_std": "packet_payload_std",
    "payload_p95": "packet_payload_p95",
    "payload_max": "packet_payload_max",
    "packet_iat_mean_ms": "packet_iat_mean_ms",
    "packet_iat_std_ms": "packet_iat_std_ms",
    "fragmented_packet_count": "packet_fragmented_count",
    "dont_fragment_count": "packet_df_count",
    "retransmission_count": "packet_retransmission_count",
    "retransmission_ratio": "packet_retransmission_ratio",
    "packet_unique_dst_ports": "packet_unique_dst_ports",
    "packet_dst_port_frequency_max": "packet_dst_port_frequency_max",
}

PACKET_FEATURES = ("packet_capture_present",) + tuple(PACKET_FEATURE_MAP.values())

HEALTH_FEATURES = (
    "health_device_samples",
    "health_reachable_ratio",
    "health_cpu_mean",
    "health_cpu_max",
    "health_memory_util_mean",
    "health_bgp_total",
    "health_ospf_total",
    "health_eigrp_total",
    "health_dmvpn_total",
    "health_crypto_total",
    "sla_sample_count",
    "sla_rtt_mean",
    "sla_rtt_p95",
    "sla_failure_delta",
    "sla_success_ratio",
    "sla_mpls_rtt_mean",
    "sla_internet_rtt_mean",
    "sla_mpls_failure_delta",
    "sla_internet_failure_delta",
    "interface_sample_count",
    "interface_input_bps_mean",
    "interface_output_bps_mean",
    "interface_input_drop_delta",
    "interface_output_drop_delta",
    "interface_input_error_delta",
    "interface_output_error_delta",
    "qos_sample_count",
    "qos_offered_bps_mean",
    "qos_drop_bps_mean",
    "qos_drop_delta",
    "syslog_count",
    "syslog_warning_or_higher",
)

MODEL_FEATURES = FLOW_FEATURES + PACKET_FEATURES + HEALTH_FEATURES


def _parse_time(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        result = value
    else:
        result = datetime.fromisoformat(value)
    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)
    return result


def _rows(connection: Any, query: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
    cursor = connection.execute(query, params)
    columns = [item[0] for item in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


def _mean(values: Sequence[float]) -> float | None:
    return statistics.fmean(values) if values else None


def _percentile(values: Sequence[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    position = (len(ordered) - 1) * fraction
    low = int(position)
    high = min(low + 1, len(ordered) - 1)
    weight = position - low
    return float(ordered[low] * (1.0 - weight) + ordered[high] * weight)


def _health_state(connection: Any, start: datetime, end: datetime) -> dict[str, Any]:
    params = (start.isoformat(), end.isoformat())
    devices = _rows(
        connection,
        """
        SELECT timestamp,device,reachable,cpu_5s,memory_total,memory_used,bgp_established,
               ospf_full,eigrp_neighbors,dmvpn_up,ikev2_ready
        FROM device_samples
        WHERE julianday(timestamp) >= julianday(?)
          AND julianday(timestamp) < julianday(?)
        """,
        params,
    )
    sla = _rows(
        connection,
        """
        SELECT transport,rtt_ms,success_delta,failure_delta
        FROM sla_samples
        WHERE julianday(timestamp) >= julianday(?)
          AND julianday(timestamp) < julianday(?)
        """,
        params,
    )
    interfaces = _rows(
        connection,
        """
        SELECT input_bps,output_bps,input_drop_delta,output_drop_delta,
               input_error_delta,output_error_delta
        FROM interface_samples
        WHERE julianday(timestamp) >= julianday(?)
          AND julianday(timestamp) < julianday(?)
        """,
        params,
    )
    qos = _rows(
        connection,
        """
        SELECT offered_bps,drop_bps,drop_delta
        FROM qos_samples
        WHERE julianday(timestamp) >= julianday(?)
          AND julianday(timestamp) < julianday(?)
        """,
        params,
    )
    syslog = _rows(
        connection,
        """
        SELECT severity FROM syslog_events
        WHERE julianday(timestamp) >= julianday(?)
          AND julianday(timestamp) < julianday(?)
        """,
        params,
    )

    cpus = [float(row["cpu_5s"]) for row in devices if row["cpu_5s"] is not None]
    memory_util = [
        float(row["memory_used"]) / float(row["memory_total"])
        for row in devices
        if row["memory_used"] is not None and row["memory_total"]
    ]
    latest_devices: dict[str, dict[str, Any]] = {}
    for row in devices:
        device = str(row["device"])
        previous = latest_devices.get(device)
        if previous is None or str(row["timestamp"]) > str(previous["timestamp"]):
            latest_devices[device] = row
    latest = list(latest_devices.values())
    rtts = [float(row["rtt_ms"]) for row in sla if row["rtt_ms"] is not None]

    def sla_transport(name: str, field: str) -> list[float]:
        return [
            float(row[field])
            for row in sla
            if str(row.get("transport") or "").upper() == name
            and row.get(field) is not None
        ]

    success_delta = sum(int(row.get("success_delta") or 0) for row in sla)
    failure_delta = sum(int(row.get("failure_delta") or 0) for row in sla)
    attempts = success_delta + failure_delta

    return {
        "health_device_samples": len(devices),
        "health_reachable_ratio": (
            sum(int(row.get("reachable") or 0) for row in devices) / len(devices)
            if devices
            else None
        ),
        "health_cpu_mean": _mean(cpus),
        "health_cpu_max": max(cpus) if cpus else None,
        "health_memory_util_mean": _mean(memory_util),
        "health_bgp_total": sum(int(row.get("bgp_established") or 0) for row in latest),
        "health_ospf_total": sum(int(row.get("ospf_full") or 0) for row in latest),
        "health_eigrp_total": sum(int(row.get("eigrp_neighbors") or 0) for row in latest),
        "health_dmvpn_total": sum(int(row.get("dmvpn_up") or 0) for row in latest),
        "health_crypto_total": sum(int(row.get("ikev2_ready") or 0) for row in latest),
        "sla_sample_count": len(sla),
        "sla_rtt_mean": _mean(rtts),
        "sla_rtt_p95": _percentile(rtts, 0.95),
        "sla_failure_delta": failure_delta,
        "sla_success_ratio": success_delta / attempts if attempts else None,
        "sla_mpls_rtt_mean": _mean(sla_transport("MPLS", "rtt_ms")),
        "sla_internet_rtt_mean": _mean(sla_transport("INTERNET", "rtt_ms")),
        "sla_mpls_failure_delta": sum(sla_transport("MPLS", "failure_delta")),
        "sla_internet_failure_delta": sum(sla_transport("INTERNET", "failure_delta")),
        "interface_sample_count": len(interfaces),
        "interface_input_bps_mean": _mean(
            [float(row["input_bps"]) for row in interfaces if row["input_bps"] is not None]
        ),
        "interface_output_bps_mean": _mean(
            [float(row["output_bps"]) for row in interfaces if row["output_bps"] is not None]
        ),
        "interface_input_drop_delta": sum(int(row.get("input_drop_delta") or 0) for row in interfaces),
        "interface_output_drop_delta": sum(int(row.get("output_drop_delta") or 0) for row in interfaces),
        "interface_input_error_delta": sum(int(row.get("input_error_delta") or 0) for row in interfaces),
        "interface_output_error_delta": sum(int(row.get("output_error_delta") or 0) for row in interfaces),
        "qos_sample_count": len(qos),
        "qos_offered_bps_mean": _mean(
            [float(row["offered_bps"]) for row in qos if row["offered_bps"] is not None]
        ),
        "qos_drop_bps_mean": _mean(
            [float(row["drop_bps"]) for row in qos if row["drop_bps"] is not None]
        ),
        "qos_drop_delta": sum(int(row.get("drop_delta") or 0) for row in qos),
        "syslog_count": len(syslog),
        "syslog_warning_or_higher": sum(
            row.get("severity") is not None and int(row["severity"]) <= 4 for row in syslog
        ),
    }


def build_state_vector(
    connection: Any,
    start: str | datetime,
    end: str | datetime,
    *,
    lookback_seconds: float = 60.0,
    packet_events: Iterable[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build one fused state vector for `[start, end)`."""

    start_dt = _parse_time(start)
    end_dt = _parse_time(end)
    if end_dt <= start_dt:
        raise ValueError("end must be after start")
    if lookback_seconds < 0:
        raise ValueError("lookback_seconds must be non-negative")

    flows = _rows(
        connection,
        """
        SELECT * FROM flows
        WHERE julianday(COALESCE(flow_end,timestamp)) >= julianday(?)
          AND julianday(COALESCE(flow_end,timestamp)) < julianday(?)
        ORDER BY julianday(COALESCE(flow_end,timestamp)),id
        """,
        (start_dt.isoformat(), end_dt.isoformat()),
    )
    previous = _rows(
        connection,
        """
        SELECT * FROM flows
        WHERE julianday(COALESCE(flow_end,timestamp)) >= julianday(?)
          AND julianday(COALESCE(flow_end,timestamp)) < julianday(?)
        ORDER BY julianday(COALESCE(flow_end,timestamp)),id
        """,
        ((start_dt - timedelta(seconds=lookback_seconds)).isoformat(), start_dt.isoformat()),
    )
    flow_state = build_state(flows, previous_records=previous)

    start_ts = start_dt.timestamp()
    end_ts = end_dt.timestamp()
    packet_capture_present = packet_events is not None
    packets = (
        [
            dict(event)
            for event in packet_events
            if start_ts <= float(event["timestamp"]) < end_ts
        ]
        if packet_events is not None
        else []
    )
    packet_state = aggregate_packet_state(packets)
    packet_state = {
        output_name: packet_state[input_name]
        for input_name, output_name in PACKET_FEATURE_MAP.items()
    }
    packet_state["packet_capture_present"] = int(packet_capture_present)

    state = {
        "schema_version": STATE_SCHEMA_VERSION,
        "window_start": start_dt.isoformat(),
        "window_end": end_dt.isoformat(),
        "window_seconds": (end_dt - start_dt).total_seconds(),
        **flow_state,
        **packet_state,
        **_health_state(connection, start_dt, end_dt),
    }
    missing = [name for name in MODEL_FEATURES if name not in state]
    if missing:
        raise RuntimeError(f"state schema is incomplete: {', '.join(missing)}")
    return state


def model_row(state: Mapping[str, Any], *, fill_missing: float = 0.0) -> list[float]:
    """Convert a state to the stable numeric model feature order."""

    if state.get("schema_version") != STATE_SCHEMA_VERSION:
        raise ValueError(
            f"expected schema {STATE_SCHEMA_VERSION!r}, got {state.get('schema_version')!r}"
        )
    return [
        fill_missing if state.get(name) is None else float(state[name])
        for name in MODEL_FEATURES
    ]
