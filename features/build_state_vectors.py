#!/usr/bin/env python3
"""Export continuous `ntro-state-v1` vectors from the telemetry database."""

from __future__ import annotations

import argparse
import csv
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from packet_state import read_pcap_events
from state_vector import MODEL_FEATURES, build_state_vector


ROOT = Path(__file__).resolve().parents[1]


def parse_time(value: str) -> datetime:
    result = datetime.fromisoformat(value)
    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)
    return result


def latest_timestamp(connection: sqlite3.Connection) -> datetime:
    values = []
    for table in ("flows", "device_samples"):
        row = connection.execute(f"SELECT MAX(timestamp) FROM {table}").fetchone()
        if row and row[0]:
            values.append(parse_time(str(row[0])))
    if not values:
        raise RuntimeError("telemetry database has no timestamped flow/device data")
    return max(values)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, default=ROOT / "outputs" / "telemetry.db")
    parser.add_argument("--output", type=Path, default=ROOT / "outputs" / "ntro-state-v1.csv")
    parser.add_argument("--start", help="ISO-8601 start time; defaults to --last-seconds before latest sample")
    parser.add_argument("--end", help="ISO-8601 end time; defaults to latest sample")
    parser.add_argument("--last-seconds", type=float, default=300.0)
    parser.add_argument("--window-seconds", type=float, default=10.0)
    parser.add_argument("--stride-seconds", type=float, default=10.0)
    parser.add_argument("--lookback-seconds", type=float, default=60.0)
    parser.add_argument("--pcap", type=Path, help="Optional PCAP/PCAPNG aligned by packet timestamps")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    connection = sqlite3.connect(f"file:{args.database.as_posix()}?mode=ro", uri=True)
    try:
        end = parse_time(args.end) if args.end else latest_timestamp(connection)
        start = parse_time(args.start) if args.start else end - timedelta(seconds=args.last_seconds)
        if end <= start:
            raise ValueError("end must be after start")
        if args.window_seconds <= 0 or args.stride_seconds <= 0:
            raise ValueError("window and stride must be positive")
        packet_events = read_pcap_events(args.pcap) if args.pcap else None
        rows = []
        cursor = start
        while cursor < end:
            window_end = min(cursor + timedelta(seconds=args.window_seconds), end)
            state = build_state_vector(
                connection,
                cursor,
                window_end,
                lookback_seconds=args.lookback_seconds,
                packet_events=packet_events,
            )
            rows.append(state)
            cursor += timedelta(seconds=args.stride_seconds)
    finally:
        connection.close()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    metadata = ["schema_version", "window_start", "window_end", "window_seconds"]
    with args.output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=metadata + list(MODEL_FEATURES))
        writer.writeheader()
        writer.writerows(rows)
    print(f"Exported {len(rows)} {rows[0]['schema_version'] if rows else 'state'} vectors to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
