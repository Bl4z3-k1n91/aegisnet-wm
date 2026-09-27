#!/usr/bin/env python3
"""Export traffic-isolated cyber training windows from accepted lab phases."""

from __future__ import annotations

import csv
import json
import sqlite3
import sys
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "features"))

from security_state import build_state  # noqa: E402
from state_vector import FLOW_FEATURES  # noqa: E402


SCHEMA_VERSION = "ntro-cyber-flow-v1"
CONTROLLED_IPS = ("10.1.10.10", "10.2.10.10", "10.10.10.10", "10.20.10.10")

PHASE_LABELS = {
    242: ("BENIGN", "benign", 0),
    243: ("RECONNAISSANCE", "reconnaissance", 1),
    244: ("INITIAL_ACCESS_PATTERN", "initial_access_pattern", 2),
    249: ("LATERAL_MOVEMENT", "lateral_movement", 3),
    250: ("C2_BEACON_PATTERN", "command_and_control_pattern", 4),
    255: ("EXFILTRATION_LIKE", "exfiltration_like", 5),
    252: ("DDOS_LOW", "ddos", 6),
    253: ("DDOS_MEDIUM", "ddos", 7),
    254: ("DDOS_HIGH", "ddos", 8),
}


def _rows(
    connection: sqlite3.Connection,
    start: datetime,
    end: datetime,
) -> list[dict[str, object]]:
    placeholders = ",".join("?" for _ in CONTROLLED_IPS)
    query = f"""
        SELECT * FROM flows
        WHERE src_ip IN ({placeholders})
          AND dst_ip IN ({placeholders})
          AND julianday(COALESCE(flow_end,timestamp)) >= julianday(?)
          AND julianday(COALESCE(flow_end,timestamp)) < julianday(?)
        ORDER BY julianday(COALESCE(flow_end,timestamp)),id
    """
    params = (*CONTROLLED_IPS, *CONTROLLED_IPS, start.isoformat(), end.isoformat())
    cursor = connection.execute(query, params)
    columns = [item[0] for item in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


def main() -> int:
    database = ROOT / "outputs" / "telemetry.db"
    output_dir = ROOT / "dataset" / "releases" / "ntro-clean-traffic-v1"
    output_dir.mkdir(parents=True, exist_ok=True)
    output = output_dir / "training_states.csv"

    connection = sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        placeholders = ",".join("?" for _ in PHASE_LABELS)
        phases = connection.execute(
            f"""
            SELECT p.id phase_id,p.run_id,p.label source_label,p.started_at,p.ended_at,
                   r.status run_status,r.scenario
            FROM scenario_phases p
            JOIN scenario_runs r ON r.id=p.run_id
            WHERE p.id IN ({placeholders}) AND p.ended_at IS NOT NULL
            ORDER BY p.id
            """,
            tuple(PHASE_LABELS),
        ).fetchall()

        rows: list[dict[str, object]] = []
        summaries: list[dict[str, object]] = []
        for phase in phases:
            phase_id = int(phase["phase_id"])
            label, stage, stage_id = PHASE_LABELS[phase_id]
            phase_start = datetime.fromisoformat(str(phase["started_at"]))
            phase_end = datetime.fromisoformat(str(phase["ended_at"]))
            start = phase_start + timedelta(seconds=2)
            end = phase_end - timedelta(seconds=2)
            cursor = start
            index = 0
            phase_rows = 0
            while cursor + timedelta(seconds=10) <= end:
                current = _rows(connection, cursor, cursor + timedelta(seconds=10))
                previous = _rows(connection, cursor - timedelta(seconds=60), cursor)
                state = build_state(current, previous_records=previous)
                rows.append(
                    {
                        "schema_version": SCHEMA_VERSION,
                        "run_id": int(phase["run_id"]),
                        "phase_id": phase_id,
                        "source_label": phase["source_label"],
                        "label": label,
                        "attack_stage": stage,
                        "stage_id": stage_id,
                        "attack_active": int(stage_id > 0),
                        "window_index": index,
                        "window_start": cursor.isoformat(),
                        "window_end": (cursor + timedelta(seconds=10)).isoformat(),
                        **state,
                    }
                )
                phase_rows += 1
                index += 1
                cursor += timedelta(seconds=5)

            all_phase = _rows(connection, phase_start, phase_end)
            aggregate = build_state(all_phase)
            summaries.append(
                {
                    "phase_id": phase_id,
                    "run_id": int(phase["run_id"]),
                    "label": label,
                    "run_status": phase["run_status"],
                    "training_windows": phase_rows,
                    "flow_count": aggregate["flow_count"],
                    "byte_count": aggregate["byte_count"],
                    "unique_src_ips": aggregate["unique_src_ips"],
                    "unique_dst_ips": aggregate["unique_dst_ips"],
                    "unique_dst_ports": aggregate["unique_dst_ports"],
                    "syn_count": aggregate["syn_count"],
                    "max_host_fanout": aggregate["max_host_fanout"],
                    "max_port_fanout": aggregate["max_port_fanout"],
                    "port_entropy": aggregate["port_entropy"],
                    "east_west_flows": aggregate["east_west_flows"],
                }
            )
    finally:
        connection.close()

    metadata = [
        "schema_version",
        "run_id",
        "phase_id",
        "source_label",
        "label",
        "attack_stage",
        "stage_id",
        "attack_active",
        "window_index",
        "window_start",
        "window_end",
    ]
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=metadata + list(FLOW_FEATURES))
        writer.writeheader()
        writer.writerows(rows)

    summary_path = output_dir / "phase_summary.csv"
    with summary_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(summaries[0]))
        writer.writeheader()
        writer.writerows(summaries)

    manifest = {
        "release": "ntro-clean-traffic-v1",
        "schema_version": SCHEMA_VERSION,
        "feature_count": len(FLOW_FEATURES),
        "features": list(FLOW_FEATURES),
        "controlled_endpoint_ips": list(CONTROLLED_IPS),
        "accepted_phase_ids": sorted(PHASE_LABELS),
        "rows": len(rows),
        "label_counts": dict(sorted(Counter(str(row["label"]) for row in rows).items())),
        "window_seconds": 10,
        "stride_seconds": 5,
        "phase_guard_seconds": 2,
        "event_time": "COALESCE(flow_end,collector_timestamp)",
        "cleanliness": [
            "Only flows whose source and destination are controlled service endpoints are included.",
            "DMVPN/EIGRP/NHRP/crypto/device-health features are excluded from this release.",
            "Attack labels come from bounded, fixed lab behaviors with explicit phase timestamps.",
            "Runs/phases with failed traffic-evidence checks are not included.",
        ],
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(manifest, indent=2))
    print(summary_path)
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
