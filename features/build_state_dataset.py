#!/usr/bin/env python3
"""Export continuous world-model network states from labelled experiment runs."""

from __future__ import annotations

import argparse
import csv
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

from security_state import build_state_windows


ROOT = Path(__file__).resolve().parents[1]


def phase_for_time(
    phases: list[sqlite3.Row], timestamp: str
) -> tuple[str | None, str | None, int | None]:
    moment = datetime.fromisoformat(timestamp)
    for phase in phases:
        start = datetime.fromisoformat(phase["started_at"])
        end = datetime.fromisoformat(phase["ended_at"])
        if start <= moment <= end:
            return str(phase["phase"]), str(phase["label"]), int(phase["id"])
    return None, None, None


def export_states(
    connection: sqlite3.Connection,
    output: Path,
    *,
    campaign_id: str | None,
    window_seconds: float,
    stride_seconds: float,
    lookback_seconds: float,
) -> int:
    where = "WHERE status='COMPLETED'"
    parameters: tuple[Any, ...] = ()
    if campaign_id:
        where += " AND campaign_id=?"
        parameters = (campaign_id,)
    runs = connection.execute(
        f"""
        SELECT id,campaign_id,split,scenario,severity,started_at,ended_at
        FROM scenario_runs {where} ORDER BY id
        """,
        parameters,
    ).fetchall()
    if not runs:
        raise RuntimeError("no completed scenario runs matched the request")

    rows: list[dict[str, Any]] = []
    for run in runs:
        if not run["ended_at"]:
            continue
        phases = connection.execute(
            """
            SELECT id,phase,label,started_at,ended_at
            FROM scenario_phases
            WHERE run_id=? AND ended_at IS NOT NULL ORDER BY started_at
            """,
            (run["id"],),
        ).fetchall()
        if not phases:
            continue
        states = build_state_windows(
            connection,
            phases[0]["started_at"],
            phases[-1]["ended_at"],
            window_seconds=window_seconds,
            stride_seconds=stride_seconds,
            lookback_seconds=lookback_seconds,
        )
        for sequence_index, state in enumerate(states):
            phase, label, phase_id = phase_for_time(phases, state["window_end"])
            rows.append(
                {
                    "run_id": run["id"],
                    "campaign_id": run["campaign_id"],
                    "split": run["split"],
                    "scenario": run["scenario"],
                    "severity": run["severity"],
                    "sequence_index": sequence_index,
                    "phase_id": phase_id,
                    "phase": phase,
                    "label": label,
                    **state,
                }
            )

    if not rows:
        raise RuntimeError("matched runs contained no state windows")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--database", type=Path, default=ROOT / "outputs" / "telemetry.db"
    )
    parser.add_argument("--campaign-id")
    parser.add_argument(
        "--output", type=Path, default=ROOT / "dataset" / "network_states.csv"
    )
    parser.add_argument("--window-seconds", type=float, default=10.0)
    parser.add_argument("--stride-seconds", type=float, default=10.0)
    parser.add_argument("--lookback-seconds", type=float, default=60.0)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    uri = f"file:{args.database.as_posix()}?mode=ro"
    connection = sqlite3.connect(uri, uri=True)
    connection.row_factory = sqlite3.Row
    try:
        count = export_states(
            connection,
            args.output,
            campaign_id=args.campaign_id,
            window_seconds=args.window_seconds,
            stride_seconds=args.stride_seconds,
            lookback_seconds=args.lookback_seconds,
        )
    finally:
        connection.close()
    print(f"Exported {count} continuous network states to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
