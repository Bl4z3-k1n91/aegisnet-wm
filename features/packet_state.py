"""Packet-level feature extraction for offline PCAP analysis.

This module turns packets into timestamped events and aggregates them into
world-model state features.  Payload contents are never retained; only sizes
and protocol metadata required by the NTRO challenge are extracted.
"""

from __future__ import annotations

import math
import statistics
from collections import Counter
from bisect import bisect_left
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Sequence

from scapy.all import IP, IPv6, TCP, UDP, PcapReader  # type: ignore[import-untyped]


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


def packet_to_event(packet: Any) -> dict[str, Any] | None:
    """Convert one Scapy packet to a compact metadata-only event."""

    if IP in packet:
        network = packet[IP]
        src_ip = str(network.src)
        dst_ip = str(network.dst)
        ttl = int(network.ttl)
        ip_flags = int(network.flags)
        fragment_offset = int(network.frag)
        protocol = int(network.proto)
    elif IPv6 in packet:
        network = packet[IPv6]
        src_ip = str(network.src)
        dst_ip = str(network.dst)
        ttl = int(network.hlim)
        ip_flags = 0
        fragment_offset = 0
        protocol = int(network.nh)
    else:
        return None

    event: dict[str, Any] = {
        "timestamp": float(packet.time),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "ttl": ttl,
        "ip_flags": ip_flags,
        "dont_fragment": int(bool(ip_flags & 0x2)),
        "more_fragments": int(bool(ip_flags & 0x1)),
        "fragment_offset": fragment_offset,
        "src_port": None,
        "dst_port": None,
        "tcp_flags": None,
        "tcp_window": None,
        "tcp_seq": None,
        "tcp_ack": None,
        "payload_bytes": 0,
    }
    if TCP in packet:
        transport = packet[TCP]
        event.update(
            {
                "protocol": 6,
                "src_port": int(transport.sport),
                "dst_port": int(transport.dport),
                "tcp_flags": int(transport.flags),
                "tcp_window": int(transport.window),
                "tcp_seq": int(transport.seq),
                "tcp_ack": int(transport.ack),
                "payload_bytes": len(bytes(transport.payload)),
            }
        )
    elif UDP in packet:
        transport = packet[UDP]
        event.update(
            {
                "protocol": 17,
                "src_port": int(transport.sport),
                "dst_port": int(transport.dport),
                "payload_bytes": len(bytes(transport.payload)),
            }
        )
    return event


def read_pcap_events(path: Path) -> list[dict[str, Any]]:
    """Read a PCAP/PCAPNG file without loading packet payloads into the dataset."""

    events: list[dict[str, Any]] = []
    with PcapReader(str(path)) as reader:
        for packet in reader:
            event = packet_to_event(packet)
            if event is not None:
                events.append(event)
    events.sort(key=lambda event: event["timestamp"])
    return events


def mark_tcp_retransmissions(events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Mark repeated TCP sequence/payload tuples within each directional flow.

    This intentionally uses a conservative payload-bearing heuristic. Duplicate
    pure ACKs are not counted as retransmissions because they are ambiguous.
    """

    seen: set[tuple[str, str, int, int, int, int]] = set()
    output: list[dict[str, Any]] = []
    for original in events:
        event = dict(original)
        event["retransmission"] = 0
        if event.get("protocol") == 6 and int(event.get("payload_bytes") or 0) > 0:
            key = (
                str(event.get("src_ip")),
                str(event.get("dst_ip")),
                int(event.get("src_port") or 0),
                int(event.get("dst_port") or 0),
                int(event.get("tcp_seq") or 0),
                int(event.get("payload_bytes") or 0),
            )
            if key in seen:
                event["retransmission"] = 1
            else:
                seen.add(key)
        output.append(event)
    return output


def aggregate_packet_state(events: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate packet events into one packet-level network state."""

    rows = mark_tcp_retransmissions(sorted(events, key=lambda event: event["timestamp"]))
    ttls = [float(event["ttl"]) for event in rows if event.get("ttl") is not None]
    windows = [
        float(event["tcp_window"])
        for event in rows
        if event.get("tcp_window") is not None
    ]
    payloads = [float(event.get("payload_bytes") or 0) for event in rows]
    timestamps = [float(event["timestamp"]) for event in rows]
    iats_ms = [
        (current - previous) * 1000.0
        for previous, current in zip(timestamps, timestamps[1:])
        if current >= previous
    ]
    dst_ports = [
        int(event["dst_port"])
        for event in rows
        if isinstance(event.get("dst_port"), int) and int(event["dst_port"]) > 0
    ]

    def mean(values: Sequence[float]) -> float | None:
        return statistics.fmean(values) if values else None

    def std(values: Sequence[float]) -> float | None:
        if not values:
            return None
        return statistics.stdev(values) if len(values) > 1 else 0.0

    return {
        "packet_event_count": len(rows),
        "ttl_mean": mean(ttls),
        "ttl_std": std(ttls),
        "ttl_min": min(ttls) if ttls else None,
        "ttl_max": max(ttls) if ttls else None,
        "tcp_window_mean": mean(windows),
        "tcp_window_std": std(windows),
        "payload_mean": mean(payloads),
        "payload_std": std(payloads),
        "payload_p95": _percentile(payloads, 0.95),
        "payload_max": max(payloads) if payloads else None,
        "packet_iat_mean_ms": mean(iats_ms),
        "packet_iat_std_ms": std(iats_ms),
        "fragmented_packet_count": sum(
            bool(event.get("more_fragments")) or int(event.get("fragment_offset") or 0) > 0
            for event in rows
        ),
        "dont_fragment_count": sum(bool(event.get("dont_fragment")) for event in rows),
        "retransmission_count": sum(int(event.get("retransmission") or 0) for event in rows),
        "retransmission_ratio": (
            sum(int(event.get("retransmission") or 0) for event in rows) / len(rows)
            if rows
            else 0.0
        ),
        "packet_unique_dst_ports": len(set(dst_ports)),
        "packet_dst_port_frequency_max": max(Counter(dst_ports).values(), default=0),
    }


def build_packet_state_windows(
    events: Iterable[dict[str, Any]],
    start: float | datetime,
    end: float | datetime,
    *,
    window_seconds: float = 10.0,
    stride_seconds: float = 10.0,
) -> list[dict[str, Any]]:
    """Aggregate packet events into a continuous sequence of fixed-time states."""

    start_ts = start.timestamp() if isinstance(start, datetime) else float(start)
    end_ts = end.timestamp() if isinstance(end, datetime) else float(end)
    if end_ts <= start_ts:
        raise ValueError("start and end must be increasing")
    if window_seconds <= 0 or stride_seconds <= 0:
        raise ValueError("window and stride must be positive")

    rows = sorted((dict(event) for event in events), key=lambda event: event["timestamp"])
    timestamps_ns = [round(float(event["timestamp"]) * 1_000_000_000) for event in rows]
    states: list[dict[str, Any]] = []
    start_ns = round(start_ts * 1_000_000_000)
    end_ns = round(end_ts * 1_000_000_000)
    width_ns = round(window_seconds * 1_000_000_000)
    stride_ns = round(stride_seconds * 1_000_000_000)
    cursor_ns = start_ns
    while cursor_ns < end_ns:
        window_end_ns = min(cursor_ns + width_ns, end_ns)
        left = bisect_left(timestamps_ns, cursor_ns)
        right = bisect_left(timestamps_ns, window_end_ns)
        state = aggregate_packet_state(rows[left:right])
        state.update(
            {
                "packet_window_start": cursor_ns / 1_000_000_000,
                "packet_window_end": window_end_ns / 1_000_000_000,
                "packet_window_seconds": (window_end_ns - cursor_ns) / 1_000_000_000,
            }
        )
        states.append(state)
        cursor_ns += stride_ns
    return states
