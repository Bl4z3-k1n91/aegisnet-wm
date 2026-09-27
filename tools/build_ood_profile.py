#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from bisect import bisect_left
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "features"))
from state_vector import FLOW_FEATURES, build_state_vector  # noqa: E402
from security_state import build_state  # noqa: E402


BENIGN_LABELS = {"BENIGN", "BASELINE", "RECOVERY", "STATE_0", "STATE_R"}
CONTROLLED_IPS = ("10.1.10.10", "10.2.10.10", "10.10.10.10", "10.20.10.10")


def profile_payload(values: np.ndarray, features: list[str], *, data_release: str, source: str) -> dict[str, object]:
    median = np.median(values, axis=0)
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "data_release": data_release,
        "split": "train",
        "source": source,
        "features": features,
        "sequence_count": None,
        "state_rows": int(values.shape[0]),
        "median": median.tolist(),
        "mad": np.median(np.abs(values - median), axis=0).tolist(),
        "q01": np.quantile(values, 0.01, axis=0).tolist(),
        "q99": np.quantile(values, 0.99, axis=0).tolist(),
        "minimum": np.min(values, axis=0).tolist(),
        "maximum": np.max(values, axis=0).tolist(),
        "evidence_status": "local_eve_train_envelope",
    }


def from_database(
    database: Path,
    *,
    window_seconds: int = 10,
    stride_seconds: int = 20,
    max_windows: int = 600,
) -> tuple[np.ndarray, list[str]]:
    features = list(FLOW_FEATURES)
    connection = sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    rows: list[list[float]] = []
    try:
        phases = connection.execute(
            """
            SELECT p.label,p.started_at,p.ended_at,r.id run_id,r.scenario
            FROM scenario_phases p
            JOIN scenario_runs r ON r.id=p.run_id
            WHERE lower(COALESCE(r.split,'train'))='train'
              AND r.status IN ('COMPLETED','TRAFFIC_ONLY')
              AND p.ended_at IS NOT NULL
            ORDER BY r.id DESC,p.started_at
            """
        ).fetchall()
        for phase in phases:
            if str(phase["label"] or "").strip().upper() not in BENIGN_LABELS:
                continue
            start = datetime.fromisoformat(str(phase["started_at"]))
            end = datetime.fromisoformat(str(phase["ended_at"]))
            lookback = timedelta(seconds=60)
            placeholders = ",".join("?" for _ in CONTROLLED_IPS)
            flow_rows = connection.execute(
                f"""
                SELECT * FROM flows
                WHERE src_ip IN ({placeholders})
                  AND dst_ip IN ({placeholders})
                  AND julianday(COALESCE(flow_end,timestamp))>=julianday(?)
                  AND julianday(COALESCE(flow_end,timestamp))<julianday(?)
                ORDER BY julianday(COALESCE(flow_end,timestamp)),id
                """,
                (*CONTROLLED_IPS, *CONTROLLED_IPS, (start - lookback).isoformat(), end.isoformat()),
            ).fetchall()
            records = [{key: row[key] for key in row.keys()} for row in flow_rows]
            record_times: list[datetime] = []
            valid_records: list[dict[str, object]] = []
            for record in records:
                raw_time = record.get("flow_end") or record.get("timestamp")
                if not raw_time:
                    continue
                try:
                    parsed = datetime.fromisoformat(str(raw_time))
                except ValueError:
                    continue
                record_times.append(parsed)
                valid_records.append(record)
            cursor = start
            while cursor + timedelta(seconds=window_seconds) <= end:
                window_end = cursor + timedelta(seconds=window_seconds)
                current_start = bisect_left(record_times, cursor)
                current_end = bisect_left(record_times, window_end)
                previous_start = bisect_left(record_times, cursor - lookback)
                current = valid_records[current_start:current_end]
                previous = valid_records[previous_start:current_start]
                state = build_state(current, previous_records=previous)
                rows.append([float(state.get(name) or 0.0) for name in features])
                if len(rows) >= max_windows:
                    return np.asarray(rows, dtype=np.float64), features
                cursor = cursor + timedelta(seconds=stride_seconds)
    finally:
        connection.close()
    if not rows:
        raise RuntimeError("no trusted benign train windows found in telemetry database")
    return np.asarray(rows, dtype=np.float64), features


def from_analysis_predictions(database: Path, *, max_rows: int = 2000) -> tuple[np.ndarray, list[str]]:
    """Use persisted real EVE states that fall inside trusted train benign phases.

    This avoids expensive flow re-aggregation while preserving the same 29-feature
    state representation consumed by live inference.
    """
    features = list(FLOW_FEATURES)
    connection = sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    rows: list[list[float]] = []
    try:
        benign_phases = connection.execute(
            """
            SELECT p.started_at,p.ended_at
            FROM scenario_phases p
            JOIN scenario_runs r ON r.id=p.run_id
            WHERE lower(COALESCE(r.split,'train'))='train'
              AND r.status IN ('COMPLETED','TRAFFIC_ONLY')
              AND p.ended_at IS NOT NULL
              AND upper(p.label) IN ('BENIGN','BASELINE','RECOVERY','STATE_0','STATE_R')
            ORDER BY r.id DESC,p.started_at
            """
        ).fetchall()
        for phase in benign_phases:
            states = connection.execute(
                """
                SELECT state_json
                FROM analysis_predictions
                WHERE source='LIVE'
                  AND julianday(event_time)>=julianday(?)
                  AND julianday(event_time)<=julianday(?)
                ORDER BY id
                """,
                (phase["started_at"], phase["ended_at"]),
            ).fetchall()
            for state_row in states:
                try:
                    state = json.loads(str(state_row["state_json"]))
                except json.JSONDecodeError:
                    continue
                if not isinstance(state, dict):
                    continue
                rows.append([float(state.get(name) or 0.0) for name in features])
                if len(rows) >= max_rows:
                    return np.asarray(rows, dtype=np.float64), features
    finally:
        connection.close()
    if not rows:
        raise RuntimeError("no persisted analysis states found in trusted benign train phases")
    return np.asarray(rows, dtype=np.float64), features


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a local EVE OOD envelope from the training split only.")
    parser.add_argument("--data-dir", type=Path, default=ROOT / "dataset" / "releases" / "eve-cyber-temporal-v1")
    parser.add_argument("--database", type=Path, default=ROOT / "outputs" / "telemetry.db")
    parser.add_argument("--source", choices=("npz", "db-benign", "analysis-benign"), default="analysis-benign")
    parser.add_argument("--max-windows", type=int, default=600)
    parser.add_argument("--stride-seconds", type=int, default=20)
    parser.add_argument("--output", type=Path, default=ROOT / "models" / "artifacts" / "eve-ood-profile-v1.json")
    args = parser.parse_args()
    if args.source == "analysis-benign":
        flat, features = from_analysis_predictions(args.database, max_rows=max(100, args.max_windows))
        profile = profile_payload(
            flat,
            features,
            data_release="telemetry.db/persisted-train-benign-states",
            source="analysis-benign",
        )
    elif args.source == "db-benign":
        flat, features = from_database(
            args.database,
            stride_seconds=max(10, args.stride_seconds),
            max_windows=max(100, args.max_windows),
        )
        profile = profile_payload(flat, features, data_release="telemetry.db/train-benign-phases", source="db-benign")
    else:
        manifest = json.loads((args.data_dir / "manifest.json").read_text(encoding="utf-8"))
        with np.load(args.data_dir / "train.npz", allow_pickle=False) as data:
            x = np.asarray(data["x"], dtype=np.float64)
        flat = x.reshape(-1, x.shape[-1])
        profile = profile_payload(flat, list(manifest["features"]), data_release=str(manifest.get("release", args.data_dir.name)), source="npz")
        profile["sequence_count"] = int(x.shape[0])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    temporary.write_text(json.dumps(profile, indent=2) + "\n", encoding="utf-8")
    temporary.replace(args.output)
    print(json.dumps({"output": str(args.output), "state_rows": int(flat.shape[0])}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
