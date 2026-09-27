#!/usr/bin/env python3
"""Print a concise current-state summary from the telemetry database."""

from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def rows(connection: sqlite3.Connection, query: str) -> list[dict[str, object]]:
    return [dict(row) for row in connection.execute(query)]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--database", type=Path, default=ROOT / "outputs" / "telemetry.db"
    )
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if not args.database.is_file():
        parser.error(f"database not found: {args.database}")

    connection = sqlite3.connect(args.database)
    connection.row_factory = sqlite3.Row
    report = {
        "devices": rows(
            connection,
            """
            SELECT d.device, d.management_ip, d.reachable, d.cpu_5s, d.cpu_1m,
                   d.memory_free, d.bgp_established, d.ospf_full,
                   d.eigrp_neighbors, d.dmvpn_up, d.ikev2_ready, d.poll_ms,
                   d.timestamp
            FROM device_samples d
            JOIN (
                SELECT device, MAX(id) AS id
                FROM device_samples GROUP BY device
            ) latest ON latest.id = d.id
            ORDER BY d.device
            """,
        ),
        "sla": rows(
            connection,
            """
            SELECT s.device, s.operation_id, s.transport, s.target_role,
                   s.rtt_ms, s.return_code,
                   s.success_delta, s.failure_delta, s.track_state, s.timestamp
            FROM sla_samples s
            JOIN (
                SELECT device, operation_id, MAX(id) AS id
                FROM sla_samples GROUP BY device, operation_id
            ) latest ON latest.id = s.id
            ORDER BY s.device, s.operation_id
            """,
        ),
        "recent_syslog": rows(
            connection,
            """
            SELECT timestamp, device, severity, message
            FROM syslog_events ORDER BY id DESC LIMIT 5
            """,
        ),
        "flow_totals": rows(
            connection,
            """
            SELECT device, COUNT(*) AS records,
                   COALESCE(SUM(bytes), 0) AS bytes,
                   COALESCE(SUM(packets), 0) AS packets
            FROM flows
            WHERE timestamp >= datetime('now', '-5 minutes')
            GROUP BY device ORDER BY device
            """,
        ),
    }
    connection.close()
    if args.json:
        print(json.dumps(report, indent=2))
        return 0

    print("DEVICE HEALTH")
    for item in report["devices"]:
        print(
            f"{item['device']:<5} reachable={item['reachable']} "
            f"cpu={item['cpu_5s']}% bgp={item['bgp_established']} "
            f"ospf={item['ospf_full']} eigrp={item['eigrp_neighbors']} "
            f"dmvpn={item['dmvpn_up']} ike={item['ikev2_ready']} "
            f"poll={item['poll_ms']}ms"
        )
    print("\nIP SLA")
    for item in report["sla"]:
        print(
            f"{item['device']:<5} op={item['operation_id']} "
            f"{item['transport']}->{item['target_role']} "
            f"rtt={item['rtt_ms']}ms code={item['return_code']} "
            f"track={item['track_state']} failures+={item['failure_delta']}"
        )
    print("\nFLOW TOTALS (5 MIN)")
    for item in report["flow_totals"]:
        print(
            f"{str(item['device']):<5} records={item['records']} "
            f"packets={item['packets']} bytes={item['bytes']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
