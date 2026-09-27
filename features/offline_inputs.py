"""Offline PCAP/CSV ingestion for the competition-facing file analysis path.

Judges may hand the system either packet captures or flow CSVs. This module
normalises both into the same 10-second security-state representation consumed
by the temporal world model. PCAP inputs additionally retain the packet-level
evidence required by the NTRO brief: TTL, TCP window, fragmentation, payload
distribution, scan pattern, inter-arrival timing and retransmissions.
"""

from __future__ import annotations

import math
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

import pandas as pd

from packet_state import aggregate_packet_state, read_pcap_events
from security_state import build_state
from state_vector import HEALTH_FEATURES, PACKET_FEATURE_MAP, STATE_SCHEMA_VERSION


PCAP_SUFFIXES = {".pcap", ".pcapng", ".cap"}
CSV_SUFFIXES = {".csv"}


def _canon(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


ALIASES: dict[str, tuple[str, ...]] = {
    "timestamp": ("timestamp", "time", "starttime", "datetime", "datefirstseen"),
    "src_ip": ("srcip", "sourceip", "srcaddr", "sourceaddress", "idorigh"),
    "dst_ip": ("dstip", "destinationip", "dstaddr", "destinationaddress", "idresph"),
    "src_port": ("srcport", "sourceport", "sport", "idorigp"),
    "dst_port": ("dstport", "destinationport", "dport", "idrespp"),
    "protocol": ("protocol", "proto", "protocolname"),
    "packets": ("packets", "totpkts", "totalpackets", "flowpackets"),
    "fwd_packets": ("totfwdpkts", "totalfwdpackets", "fwdpackets"),
    "bwd_packets": ("totbwdpkts", "totalbackwardpackets", "bwdpackets"),
    "bytes": ("bytes", "totbytes", "totalbytes", "flowbytes"),
    "fwd_bytes": ("totlenfwdpkts", "totallengthoffwdpackets", "srcbytes", "fwdbytes"),
    "bwd_bytes": ("totlenbwdpkts", "totallengthofbwdpackets", "dstbytes", "bwdbytes"),
    "duration": ("flowduration", "duration", "dur"),
    "tcp_flags": ("tcpflags", "flags", "state"),
    "syn_count": ("synflagcnt", "synflagcount"),
    "ack_count": ("ackflagcnt", "ackflagcount"),
    "rst_count": ("rstflagcnt", "rstflagcount"),
    "fin_count": ("finflagcnt", "finflagcount"),
    "psh_count": ("pshflagcnt", "pshflagcount"),
    "urg_count": ("urgflagcnt", "urgflagcount"),
    "label": ("label", "class", "attackcat", "category"),
}


def _columns(frame: pd.DataFrame) -> dict[str, str]:
    by_canon = {_canon(column): str(column) for column in frame.columns}
    result: dict[str, str] = {}
    for field, aliases in ALIASES.items():
        for alias in aliases:
            if alias in by_canon:
                result[field] = by_canon[alias]
                break
    return result


def _number(value: Any, default: float = 0.0) -> float:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _integer(value: Any, default: int = 0) -> int:
    return int(round(_number(value, float(default))))


def _protocol(value: Any) -> int:
    text = str(value or "").strip().lower()
    if text in {"tcp", "6"}:
        return 6
    if text in {"udp", "17"}:
        return 17
    if text in {"icmp", "1"}:
        return 1
    try:
        return int(float(text))
    except ValueError:
        return 0


def _flags(row: Mapping[str, Any], columns: dict[str, str]) -> int:
    raw_column = columns.get("tcp_flags")
    if raw_column:
        raw = row.get(raw_column)
        if isinstance(raw, (int, float)) and not pd.isna(raw):
            return int(raw)
        text = str(raw or "").strip().upper()
        try:
            return int(text, 0)
        except ValueError:
            value = 0
            for token, bit in (("F", 1), ("S", 2), ("R", 4), ("P", 8), ("A", 16), ("U", 32)):
                if token in text:
                    value |= bit
            if value:
                return value
    value = 0
    for key, bit in (("fin_count", 1), ("syn_count", 2), ("rst_count", 4), ("psh_count", 8), ("ack_count", 16), ("urg_count", 32)):
        column = columns.get(key)
        if column and _number(row.get(column)) > 0:
            value |= bit
    return value


def _timestamps(series: pd.Series) -> pd.Series:
    parsed = pd.to_datetime(series, errors="coerce", utc=True)
    if parsed.notna().sum() < max(1, len(series) // 2):
        parsed = pd.to_datetime(series, errors="coerce", utc=True, dayfirst=True)
    return parsed


def read_flow_csv(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    frame = pd.read_csv(path, low_memory=False)
    if frame.empty:
        raise ValueError("CSV contains no rows")
    columns = _columns(frame)
    missing = sorted({"timestamp", "src_ip", "dst_ip"} - set(columns))
    if missing:
        raise ValueError("CSV missing required columns: " + ", ".join(missing))
    time_values = _timestamps(frame[columns["timestamp"]])
    records: list[dict[str, Any]] = []
    labels: dict[str, int] = defaultdict(int)
    for position, (_, raw) in enumerate(frame.iterrows()):
        timestamp = time_values.iloc[position]
        if pd.isna(timestamp):
            continue
        packets = _integer(raw.get(columns.get("packets", "")))
        if columns.get("fwd_packets") or columns.get("bwd_packets"):
            packets = _integer(raw.get(columns.get("fwd_packets", ""))) + _integer(raw.get(columns.get("bwd_packets", "")))
        byte_count = _integer(raw.get(columns.get("bytes", "")))
        if columns.get("fwd_bytes") or columns.get("bwd_bytes"):
            byte_count = _integer(raw.get(columns.get("fwd_bytes", ""))) + _integer(raw.get(columns.get("bwd_bytes", "")))
        duration_raw = _number(raw.get(columns.get("duration", "")))
        duration_seconds = duration_raw / 1_000_000.0 if duration_raw > 100_000 else duration_raw
        end = timestamp.to_pydatetime()
        start = end - timedelta(seconds=max(0.0, duration_seconds))
        records.append(
            {
                "timestamp": end.isoformat(),
                "flow_start": start.isoformat(),
                "flow_end": end.isoformat(),
                "src_ip": str(raw[columns["src_ip"]]),
                "dst_ip": str(raw[columns["dst_ip"]]),
                "src_port": _integer(raw.get(columns.get("src_port", ""))),
                "dst_port": _integer(raw.get(columns.get("dst_port", ""))),
                "protocol": _protocol(raw.get(columns.get("protocol", ""))),
                "packets": packets,
                "bytes": byte_count,
                "tcp_flags": _flags(raw, columns),
            }
        )
        label_column = columns.get("label")
        if label_column:
            labels[str(raw.get(label_column, "UNKNOWN"))] += 1
    if not records:
        raise ValueError("CSV contains no rows with parseable timestamps")
    records.sort(key=lambda row: str(row["flow_end"]))
    return records, {
        "input_type": "csv",
        "rows": len(records),
        "column_mapping": columns,
        "labels_present": bool(columns.get("label")),
        "label_counts": dict(labels),
        "packet_capture_present": False,
    }


def pcap_events_to_flows(events: Iterable[Mapping[str, Any]], *, bucket_seconds: float = 10.0) -> list[dict[str, Any]]:
    groups: dict[tuple[int, str, str, int, int, int], list[Mapping[str, Any]]] = defaultdict(list)
    for event in events:
        timestamp = float(event["timestamp"])
        key = (
            int(timestamp // bucket_seconds),
            str(event.get("src_ip") or ""),
            str(event.get("dst_ip") or ""),
            int(event.get("src_port") or 0),
            int(event.get("dst_port") or 0),
            int(event.get("protocol") or 0),
        )
        groups[key].append(event)
    flows: list[dict[str, Any]] = []
    for (_, src, dst, sport, dport, protocol), rows in groups.items():
        ordered = sorted(rows, key=lambda row: float(row["timestamp"]))
        flags = 0
        for row in ordered:
            flags |= int(row.get("tcp_flags") or 0)
        start = datetime.fromtimestamp(float(ordered[0]["timestamp"]), tz=timezone.utc)
        end = datetime.fromtimestamp(float(ordered[-1]["timestamp"]), tz=timezone.utc)
        flows.append(
            {
                "timestamp": end.isoformat(),
                "flow_start": start.isoformat(),
                "flow_end": end.isoformat(),
                "src_ip": src,
                "dst_ip": dst,
                "src_port": sport,
                "dst_port": dport,
                "protocol": protocol,
                "packets": len(ordered),
                "bytes": sum(
                    int(row.get("payload_bytes") or 0) + (40 if protocol == 6 else 28 if protocol == 17 else 20)
                    for row in ordered
                ),
                "tcp_flags": flags,
            }
        )
    return sorted(flows, key=lambda row: str(row["flow_end"]))


def _event_time(record: Mapping[str, Any]) -> datetime:
    return datetime.fromisoformat(str(record.get("flow_end") or record.get("timestamp")))


def build_offline_states(
    path: Path,
    *,
    window_seconds: float = 10.0,
    stride_seconds: float = 10.0,
    lookback_seconds: float = 60.0,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    suffix = path.suffix.lower()
    packet_events: list[dict[str, Any]] | None = None
    if suffix in PCAP_SUFFIXES:
        packet_events = read_pcap_events(path)
        if not packet_events:
            raise ValueError("PCAP contains no IPv4/IPv6 packets")
        records = pcap_events_to_flows(packet_events, bucket_seconds=window_seconds)
        metadata: dict[str, Any] = {
            "input_type": "pcap",
            "packet_events": len(packet_events),
            "flow_records": len(records),
            "packet_capture_present": True,
        }
        start = datetime.fromtimestamp(float(packet_events[0]["timestamp"]), tz=timezone.utc)
        end = datetime.fromtimestamp(float(packet_events[-1]["timestamp"]), tz=timezone.utc) + timedelta(microseconds=1)
    elif suffix in CSV_SUFFIXES:
        records, metadata = read_flow_csv(path)
        start = _event_time(records[0])
        end = _event_time(records[-1]) + timedelta(microseconds=1)
    else:
        raise ValueError(f"unsupported input type {suffix}; expected PCAP/PCAPNG/CSV")

    states: list[dict[str, Any]] = []
    cursor = start
    width = timedelta(seconds=window_seconds)
    stride = timedelta(seconds=stride_seconds)
    lookback = timedelta(seconds=lookback_seconds)
    while cursor < end:
        window_end = min(cursor + width, end)
        current = [row for row in records if cursor <= _event_time(row) < window_end]
        previous = [row for row in records if cursor - lookback <= _event_time(row) < cursor]
        flow_state = build_state(current, previous_records=previous)
        window_packets = [
            event
            for event in (packet_events or [])
            if cursor.timestamp() <= float(event["timestamp"]) < window_end.timestamp()
        ]
        packet_raw = aggregate_packet_state(window_packets)
        packet_state = {
            output_name: packet_raw[input_name]
            for input_name, output_name in PACKET_FEATURE_MAP.items()
        }
        packet_state["packet_capture_present"] = int(packet_events is not None)
        state = {
            "schema_version": STATE_SCHEMA_VERSION,
            "window_start": cursor.isoformat(),
            "window_end": window_end.isoformat(),
            "window_seconds": (window_end - cursor).total_seconds(),
            **flow_state,
            **packet_state,
        }
        state.update({name: 0.0 for name in HEALTH_FEATURES})
        states.append(state)
        cursor += stride
    metadata.update(
        {
            "source_name": path.name,
            "window_seconds": window_seconds,
            "stride_seconds": stride_seconds,
            "state_count": len(states),
            "start": start.isoformat(),
            "end": end.isoformat(),
        }
    )
    return states, metadata
