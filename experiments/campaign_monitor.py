#!/usr/bin/env python3
"""Report campaign progress and optionally export/audit when collection ends."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


def parse_time(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def snapshot(
    connection: sqlite3.Connection, campaign_id: str
) -> dict[str, Any]:
    connection.row_factory = sqlite3.Row
    campaign = connection.execute(
        "SELECT * FROM dataset_campaigns WHERE campaign_id=?", (campaign_id,)
    ).fetchone()
    if campaign is None:
        raise RuntimeError(f"campaign {campaign_id!r} does not exist")
    rows = connection.execute(
        """
        SELECT * FROM dataset_campaign_plan
        WHERE campaign_id=? ORDER BY sequence_index
        """,
        (campaign_id,),
    ).fetchall()
    durations = []
    for row in rows:
        started, ended = parse_time(row["started_at"]), parse_time(row["ended_at"])
        if started and ended and row["status"] == "COMPLETED":
            durations.append((ended - started).total_seconds())
    pending = sum(row["status"] == "PENDING" for row in rows)
    running = [dict(row) for row in rows if row["status"] == "RUNNING"]
    mean_seconds = sum(durations) / len(durations) if durations else None
    eta_seconds = (
        mean_seconds * (pending + len(running)) if mean_seconds is not None else None
    )
    return {
        "campaign_id": campaign_id,
        "status": campaign["status"],
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "total": len(rows),
        "completed": sum(row["status"] == "COMPLETED" for row in rows),
        "failed": sum(row["status"] == "FAILED" for row in rows),
        "pending": pending,
        "running": running,
        "mean_run_seconds": mean_seconds,
        "eta_seconds": eta_seconds,
    }


def finalize(args: argparse.Namespace) -> None:
    release = ROOT / "dataset" / "releases" / args.campaign_id
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "experiments" / "dataset_quality.py"),
            "--campaign-id", args.campaign_id,
            "--export",
            "--output", str(release),
        ],
        cwd=ROOT,
        check=False,
    )
    if os.environ.get("EVE_PASSWORD"):
        subprocess.run(
            [
                sys.executable,
                str(ROOT / "tools" / "audit_lab.py"),
                "--eve-url", args.eve_url,
                "--eve-path", args.eve_path,
                "--subnet", args.subnet,
                "--output", str(
                    ROOT / "outputs" / f"{args.campaign_id}-post-audit.json"
                ),
            ],
            cwd=ROOT,
            check=False,
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign_id")
    parser.add_argument("--watch", action="store_true")
    parser.add_argument("--interval", type=float, default=30)
    parser.add_argument("--finalize", action="store_true")
    parser.add_argument(
        "--database", type=Path, default=ROOT / "outputs" / "telemetry.db"
    )
    parser.add_argument("--eve-url", default="http://192.168.58.128")
    parser.add_argument("--eve-path", default="/RS")
    parser.add_argument("--subnet", default="10.117.155.0/24")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    connection = sqlite3.connect(args.database)
    try:
        while True:
            state = snapshot(connection, args.campaign_id)
            print(json.dumps(state, indent=2), flush=True)
            status_path = ROOT / "outputs" / f"{args.campaign_id}-status.json"
            temporary = status_path.with_suffix(".tmp")
            temporary.write_text(
                json.dumps(state, indent=2) + "\n", encoding="utf-8"
            )
            temporary.replace(status_path)
            terminal = (
                state["pending"] == 0
                and not state["running"]
                and state["status"] != "RUNNING"
            )
            if not args.watch or terminal:
                if terminal and args.finalize:
                    finalize(args)
                return 0
            time.sleep(args.interval)
    finally:
        connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
