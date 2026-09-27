#!/usr/bin/env python3
from __future__ import annotations

import argparse
import bisect
import json
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import numpy as np


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "features"))
sys.path.insert(0, str(ROOT / "models" / "world_model"))
from security_state import build_state  # noqa: E402
from state_vector import FLOW_FEATURES  # noqa: E402
from config import CLASS_TO_ID  # noqa: E402


BENIGN_LABELS = {
    "BENIGN", "BASELINE", "STATE_0", "RECOVERY", "STATE_R", "STATE_RECOVERY"
}
ATTACK_MAP = {
    "RECONNAISSANCE": "RECONNAISSANCE",
    "STATE_1": "RECONNAISSANCE",
    "INITIAL_ACCESS_PATTERN": "INITIAL_ACCESS_PATTERN",
    "STATE_2": "INITIAL_ACCESS_PATTERN",
    "LATERAL_MOVEMENT": "LATERAL_MOVEMENT",
    "STATE_3": "LATERAL_MOVEMENT",
    "C2_BEACON_PATTERN": "C2_BEACON_PATTERN",
    "STATE_4": "C2_BEACON_PATTERN",
    "EXFILTRATION_LIKE": "EXFILTRATION_LIKE",
    "STATE_5": "EXFILTRATION_LIKE",
    "STATE_X": "EXFILTRATION_LIKE",
    "DDOS_LOW": "DDOS_LOW",
    "STATE_V1": "DDOS_LOW",
    "DDOS_MEDIUM": "DDOS_MEDIUM",
    "STATE_V2": "DDOS_MEDIUM",
    "DDOS_HIGH": "DDOS_HIGH",
    "STATE_V3": "DDOS_HIGH",
}


def utc(value: Any) -> datetime:
    result = datetime.fromisoformat(str(value))
    return result if result.tzinfo else result.replace(tzinfo=timezone.utc)


def split_name(value: Any) -> str:
    raw = str(value or "train").lower()
    return "val" if raw in {"validation", "val"} else ("test" if raw == "test" else "train")


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a run-disjoint real EVE current-state cyber release.")
    parser.add_argument("--database", type=Path, default=ROOT / "outputs" / "telemetry.db")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "dataset" / "releases" / "eve-current-v2")
    parser.add_argument("--window-seconds", type=int, default=10)
    args = parser.parse_args()

    connection = sqlite3.connect(f"file:{args.database.as_posix()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        phases = connection.execute(
            """
            SELECT r.id run_id,r.scenario,r.campaign_id,COALESCE(r.split,'train') split,
                   p.id phase_id,p.label,p.started_at,p.ended_at
            FROM scenario_runs r
            JOIN scenario_phases p ON p.run_id=r.id
            WHERE r.status IN ('COMPLETED','TRAFFIC_ONLY')
              AND p.ended_at IS NOT NULL
            ORDER BY r.id,p.started_at
            """
        ).fetchall()
        selected = []
        for row in phases:
            raw = str(row["label"] or "").strip().upper()
            if raw in BENIGN_LABELS or raw in ATTACK_MAP:
                selected.append(row)
        if not selected:
            raise RuntimeError("no eligible EVE phases found")
        earliest = min(utc(row["started_at"]) for row in selected) - timedelta(seconds=60)
        latest = max(utc(row["ended_at"]) for row in selected)
        cursor = connection.execute(
            """
            SELECT * FROM flows
            WHERE COALESCE(flow_end,timestamp) >= ?
              AND COALESCE(flow_end,timestamp) < ?
            ORDER BY COALESCE(flow_end,timestamp),id
            """,
            (earliest.isoformat(), latest.isoformat()),
        )
        columns = [item[0] for item in cursor.description]
        flows = [dict(zip(columns, values)) for values in cursor.fetchall()]
    finally:
        connection.close()

    flow_times = [utc(row.get("flow_end") or row.get("timestamp")).timestamp() for row in flows]

    def flow_slice(start: datetime, end: datetime) -> list[dict[str, Any]]:
        left = bisect.bisect_left(flow_times, start.timestamp())
        right = bisect.bisect_left(flow_times, end.timestamp())
        return flows[left:right]

    by_split: dict[str, dict[str, list[Any]]] = {
        name: {"x": [], "current_label": [], "run_id": [], "phase_id": [], "scenario": [], "sample_time": []}
        for name in ("train", "val", "test")
    }
    phase_counts: dict[str, dict[str, int]] = {name: {"benign": 0, "attack": 0} for name in by_split}

    for row in selected:
        raw = str(row["label"] or "").strip().upper()
        canonical = "BENIGN" if raw in BENIGN_LABELS else ATTACK_MAP[raw]
        split = split_name(row["split"])
        phase_counts[split]["benign" if canonical == "BENIGN" else "attack"] += 1
        start = utc(row["started_at"])
        end = utc(row["ended_at"])
        cursor_time = start
        while cursor_time + timedelta(seconds=args.window_seconds) <= end:
            window_end = cursor_time + timedelta(seconds=args.window_seconds)
            current = flow_slice(cursor_time, window_end)
            previous = flow_slice(cursor_time - timedelta(seconds=60), cursor_time)
            state = build_state(current, previous_records=previous)
            values = np.asarray([float(state.get(name) or 0.0) for name in FLOW_FEATURES], dtype=np.float32)
            bucket = by_split[split]
            bucket["x"].append(values[None, :])
            bucket["current_label"].append(CLASS_TO_ID[canonical])
            bucket["run_id"].append(int(row["run_id"]))
            bucket["phase_id"].append(int(row["phase_id"]))
            bucket["scenario"].append(str(row["scenario"] or "unknown"))
            bucket["sample_time"].append(window_end.isoformat())
            cursor_time = window_end

    args.output_dir.mkdir(parents=True, exist_ok=True)
    summary: dict[str, Any] = {}
    for split, bucket in by_split.items():
        if not bucket["x"]:
            continue
        payload = {
            "x": np.asarray(bucket["x"], dtype=np.float32),
            "current_label": np.asarray(bucket["current_label"], dtype=np.int64),
            "run_id": np.asarray(bucket["run_id"], dtype=np.int64),
            "phase_id": np.asarray(bucket["phase_id"], dtype=np.int64),
            "scenario": np.asarray(bucket["scenario"], dtype="U64"),
            "sample_time": np.asarray(bucket["sample_time"], dtype="U40"),
        }
        np.savez_compressed(args.output_dir / f"{split}.npz", **payload)
        labels = payload["current_label"]
        benign = labels == CLASS_TO_ID["BENIGN"]
        summary[split] = {
            "windows": int(len(labels)),
            "benign_windows": int(benign.sum()),
            "attack_windows": int((~benign).sum()),
            "runs": int(len(set(payload["run_id"].tolist()))),
            "phases": phase_counts[split],
        }

    manifest = {
        "release": args.output_dir.name,
        "evidence_status": "real_local_eve_current_state",
        "features": list(FLOW_FEATURES),
        "feature_count": len(FLOW_FEATURES),
        "history_steps": 1,
        "window_seconds": args.window_seconds,
        "split_strategy": "scenario_runs split; complete phases/runs never cross train/validation/test",
        "benign_definition": sorted(BENIGN_LABELS),
        "attack_definition": ATTACK_MAP,
        "notes": [
            "Network-fault BASELINE/RECOVERY periods are intentionally benign cyber negatives.",
            "Fault-active labels that are not explicit cyber stages are excluded rather than relabelled as attacks.",
        ],
        "splits": summary,
    }
    (args.output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
