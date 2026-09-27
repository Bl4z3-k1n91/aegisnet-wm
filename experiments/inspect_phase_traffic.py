#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize flow volume by labelled EVE phase.")
    parser.add_argument("run_id", type=int)
    parser.add_argument("--database", type=Path, default=ROOT / "outputs" / "telemetry.db")
    args = parser.parse_args()
    connection = sqlite3.connect(f"file:{args.database.as_posix()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        phases = connection.execute(
            "SELECT id,label,started_at,ended_at FROM scenario_phases WHERE run_id=? ORDER BY id",
            (args.run_id,),
        ).fetchall()
        output = []
        for phase in phases:
            stats = connection.execute(
                """
                SELECT COUNT(*) flows,
                       COALESCE(SUM(packets),0) packets,
                       COALESCE(SUM(bytes),0) bytes,
                       COALESCE(SUM(CASE WHEN protocol=17 THEN 1 ELSE 0 END),0) udp_flows,
                       COALESCE(SUM(CASE WHEN protocol=17 THEN packets ELSE 0 END),0) udp_packets,
                       COALESCE(SUM(CASE WHEN protocol=17 THEN bytes ELSE 0 END),0) udp_bytes,
                       COUNT(DISTINCT CASE WHEN protocol=17 THEN dst_port END) udp_ports
                FROM flows
                WHERE julianday(COALESCE(flow_end,timestamp))>=julianday(?)
                  AND julianday(COALESCE(flow_end,timestamp))<julianday(?)
                """,
                (phase["started_at"], phase["ended_at"]),
            ).fetchone()
            row = dict(phase)
            row.update(dict(stats))
            top_udp = connection.execute(
                """
                SELECT dst_ip,dst_port,COUNT(*) flows,
                       COALESCE(SUM(packets),0) packets,COALESCE(SUM(bytes),0) bytes
                FROM flows
                WHERE protocol=17
                  AND julianday(COALESCE(flow_end,timestamp))>=julianday(?)
                  AND julianday(COALESCE(flow_end,timestamp))<julianday(?)
                GROUP BY dst_ip,dst_port
                ORDER BY bytes DESC
                LIMIT 5
                """,
                (phase["started_at"], phase["ended_at"]),
            ).fetchall()
            row["top_udp_services"] = [dict(item) for item in top_udp]
            output.append(row)
    finally:
        connection.close()
    print(json.dumps(output, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
