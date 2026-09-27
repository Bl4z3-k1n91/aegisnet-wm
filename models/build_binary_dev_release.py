#!/usr/bin/env python3
"""Build a run-disjoint binary cyber-development release from all pre-acceptance EVE runs.

Explicit cyber stages are ATTACK. Every other labelled phase is a cyber BENIGN
negative, including routing/congestion/loss/outage conditions. This is deliberate:
the authority detector must distinguish cyber activity from network faults.
"""

from __future__ import annotations

import argparse
import bisect
import hashlib
import json
import sqlite3
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import numpy as np


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "features"))
from security_state import build_state  # noqa: E402
from state_vector import FLOW_FEATURES  # noqa: E402


ATTACK_LABELS = {
    "RECONNAISSANCE", "STATE_1",
    "INITIAL_ACCESS_PATTERN", "STATE_2",
    "LATERAL_MOVEMENT", "STATE_3",
    "C2_BEACON_PATTERN", "STATE_4",
    "EXFILTRATION_LIKE", "STATE_5", "STATE_X",
    "DDOS_LOW", "STATE_V1", "DDOS_MEDIUM", "STATE_V2", "DDOS_HIGH", "STATE_V3",
}


def utc(value: Any) -> datetime:
    result = datetime.fromisoformat(str(value))
    return result if result.tzinfo else result.replace(tzinfo=timezone.utc)


def run_hash(run_id: int, campaign_id: str) -> int:
    digest = hashlib.sha256(f"{campaign_id}:{run_id}".encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, default=ROOT / "outputs" / "telemetry.db")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "dataset" / "releases" / "eve-binary-dev-v1")
    parser.add_argument("--window-seconds", type=int, default=10)
    parser.add_argument("--validation-percent", type=int, default=20)
    parser.add_argument("--exclude-campaign", action="append", default=[])
    args = parser.parse_args()
    if not 5 <= args.validation_percent <= 50:
        parser.error("validation-percent must be between 5 and 50")

    connection = sqlite3.connect(f"file:{args.database.as_posix()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        query = """
            SELECT r.id run_id,r.scenario,COALESCE(r.campaign_id,'') campaign_id,
                   p.id phase_id,p.label,p.started_at,p.ended_at
            FROM scenario_runs r JOIN scenario_phases p ON p.run_id=r.id
            WHERE r.status IN ('COMPLETED','TRAFFIC_ONLY') AND p.ended_at IS NOT NULL
        """
        params: list[Any] = []
        if args.exclude_campaign:
            placeholders = ",".join("?" for _ in args.exclude_campaign)
            query += f" AND COALESCE(r.campaign_id,'') NOT IN ({placeholders})"
            params.extend(args.exclude_campaign)
        query += " ORDER BY r.id,p.started_at"
        phases = connection.execute(query, params).fetchall()
        if not phases:
            raise RuntimeError("no development phases found")
        earliest = min(utc(row["started_at"]) for row in phases) - timedelta(seconds=60)
        latest = max(utc(row["ended_at"]) for row in phases)
        cursor = connection.execute(
            """SELECT * FROM flows WHERE COALESCE(flow_end,timestamp)>=? AND COALESCE(flow_end,timestamp)<?
               ORDER BY COALESCE(flow_end,timestamp),id""",
            (earliest.isoformat(), latest.isoformat()),
        )
        columns = [item[0] for item in cursor.description]
        flows = [dict(zip(columns, values)) for values in cursor.fetchall()]
    finally:
        connection.close()

    run_labels: dict[tuple[int, str], set[str]] = {}
    for phase in phases:
        key = (int(phase["run_id"]), str(phase["campaign_id"]))
        run_labels.setdefault(key, set()).add(str(phase["label"] or "").strip().upper())
    attack_runs = sorted(
        [key for key, labels in run_labels.items() if labels & ATTACK_LABELS],
        key=lambda key: run_hash(*key),
    )
    benign_runs = sorted(
        [key for key, labels in run_labels.items() if not labels & ATTACK_LABELS],
        key=lambda key: run_hash(*key),
    )
    def val_count(items: list[tuple[int, str]], minimum: int = 1) -> int:
        return min(len(items), max(minimum, int(round(len(items) * args.validation_percent / 100.0))))
    validation_runs = set(attack_runs[:val_count(attack_runs, minimum=min(3, len(attack_runs)))])
    validation_runs.update(benign_runs[:val_count(benign_runs)])

    flow_times = [utc(row.get("flow_end") or row.get("timestamp")).timestamp() for row in flows]
    def flow_slice(start: datetime, end: datetime) -> list[dict[str, Any]]:
        left = bisect.bisect_left(flow_times, start.timestamp())
        right = bisect.bisect_left(flow_times, end.timestamp())
        return flows[left:right]

    buckets = {
        name: {"x": [], "y": [], "run_id": [], "phase_id": [], "phase_label": [], "scenario": []}
        for name in ("train", "val")
    }
    phase_labels: dict[str, Counter[str]] = {"train": Counter(), "val": Counter()}
    run_sets = {"train": set(), "val": set()}
    for phase in phases:
        run_key = (int(phase["run_id"]), str(phase["campaign_id"]))
        split = "val" if run_key in validation_runs else "train"
        raw = str(phase["label"] or "").strip().upper()
        truth = "ATTACK" if raw in ATTACK_LABELS else "BENIGN"
        phase_labels[split][raw] += 1
        run_sets[split].add(int(phase["run_id"]))
        start, end = utc(phase["started_at"]), utc(phase["ended_at"])
        cursor_time = start
        while cursor_time + timedelta(seconds=args.window_seconds) <= end:
            window_end = cursor_time + timedelta(seconds=args.window_seconds)
            state = build_state(
                flow_slice(cursor_time, window_end),
                previous_records=flow_slice(cursor_time - timedelta(seconds=60), cursor_time),
            )
            bucket = buckets[split]
            bucket["x"].append([float(state.get(name) or 0.0) for name in FLOW_FEATURES])
            bucket["y"].append(truth)
            bucket["run_id"].append(int(phase["run_id"]))
            bucket["phase_id"].append(int(phase["phase_id"]))
            bucket["phase_label"].append(raw)
            bucket["scenario"].append(str(phase["scenario"] or "unknown"))
            cursor_time = window_end

    summary: dict[str, Any] = {}
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for split, bucket in buckets.items():
        y = np.asarray(bucket["y"], dtype="U16")
        payload = {
            "x": np.asarray(bucket["x"], dtype=np.float32),
            "y": y,
            "run_id": np.asarray(bucket["run_id"], dtype=np.int64),
            "phase_id": np.asarray(bucket["phase_id"], dtype=np.int64),
            "phase_label": np.asarray(bucket["phase_label"], dtype="U64"),
            "scenario": np.asarray(bucket["scenario"], dtype="U64"),
        }
        np.savez_compressed(args.output_dir / f"{split}.npz", **payload)
        summary[split] = {
            "windows": int(len(y)),
            "benign_windows": int(np.sum(y == "BENIGN")),
            "attack_windows": int(np.sum(y == "ATTACK")),
            "runs": len(run_sets[split]),
            "phase_labels": dict(phase_labels[split]),
        }
    manifest = {
        "release": args.output_dir.name,
        "evidence_status": "real_local_eve_binary_development",
        "features": list(FLOW_FEATURES),
        "window_seconds": args.window_seconds,
        "split_strategy": "fresh SHA-256 run-level development split; final authority acceptance campaign excluded",
        "split_stratification": "attack-bearing runs and non-attack runs hashed separately; complete runs remain disjoint",
        "validation_percent": args.validation_percent,
        "excluded_campaigns": args.exclude_campaign,
        "attack_labels": sorted(ATTACK_LABELS),
        "benign_rule": "all other labelled network phases, including faults, are cyber BENIGN hard negatives",
        "splits": summary,
    }
    (args.output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
