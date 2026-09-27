#!/usr/bin/env python3
from __future__ import annotations

import argparse
import bisect
import json
import sqlite3
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "features"))
from state_vector import FLOW_FEATURES  # noqa: E402
from security_state import build_state  # noqa: E402


BENIGN_LABELS = {"BENIGN", "BASELINE", "STATE_0"}
ATTACK_LABELS = {
    "RECONNAISSANCE", "STATE_1",
    "INITIAL_ACCESS_PATTERN", "STATE_2",
    "LATERAL_MOVEMENT", "STATE_3",
    "C2_BEACON_PATTERN", "STATE_4",
    "EXFILTRATION_LIKE", "STATE_5", "STATE_X",
    "DDOS_LOW", "STATE_V1",
    "DDOS_MEDIUM", "STATE_V2",
    "DDOS_HIGH", "STATE_V3",
}


def utc(value: str) -> datetime:
    result = datetime.fromisoformat(value)
    return result if result.tzinfo else result.replace(tzinfo=timezone.utc)


def attack_probability(model: Any, x: np.ndarray) -> np.ndarray:
    raw = model.predict_proba(x)
    labels = [str(value) for value in model.classes_]
    return raw[:, labels.index("ATTACK")]


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate the binary challenger on independent historical EVE phases.")
    parser.add_argument("--database", type=Path, default=ROOT / "outputs" / "telemetry.db")
    parser.add_argument("--artifact", type=Path, default=ROOT / "models" / "artifacts" / "aegis-binary-v1-challenger")
    parser.add_argument("--window-seconds", type=int, default=10)
    parser.add_argument("--output", type=Path, default=ROOT / "outputs" / "binary-eve-acceptance.json")
    parser.add_argument(
        "--split",
        choices=("train", "validation", "val", "test"),
        help="Optional scenario_runs split restriction. Production acceptance should use --split test.",
    )
    args = parser.parse_args()

    metadata = json.loads((args.artifact / "metadata.json").read_text(encoding="utf-8"))
    threshold = float(metadata["attack_probability_threshold"])
    logistic = joblib.load(args.artifact / "logistic_pipeline.joblib")
    forest = joblib.load(args.artifact / "random_forest_pipeline.joblib")

    connection = sqlite3.connect(f"file:{args.database.as_posix()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    records: list[dict[str, Any]] = []
    try:
        query = """
            SELECT r.id run_id,r.scenario,r.campaign_id,r.split,p.id phase_id,p.label,p.started_at,p.ended_at
            FROM scenario_runs r
            JOIN scenario_phases p ON p.run_id=r.id
            WHERE r.status IN ('COMPLETED','TRAFFIC_ONLY')
              AND p.ended_at IS NOT NULL
              AND NOT (r.campaign_id='eve-cyber-v1' AND lower(COALESCE(r.split,'')) IN ('train','validation','val'))
        """
        params: list[Any] = []
        if args.split:
            if args.split in {"validation", "val"}:
                query += " AND lower(COALESCE(r.split,'')) IN ('validation','val')"
            else:
                query += " AND lower(COALESCE(r.split,''))=?"
                params.append(args.split)
        query += " ORDER BY r.id,p.started_at"
        rows = connection.execute(query, params).fetchall()
        if not rows:
            raise RuntimeError("no independent EVE evaluation phases found")

        earliest = min(utc(str(row["started_at"])) for row in rows) - timedelta(seconds=60)
        latest = max(utc(str(row["ended_at"])) for row in rows)
        flow_cursor = connection.execute(
            """
            SELECT * FROM flows
            WHERE COALESCE(flow_end,timestamp) >= ?
              AND COALESCE(flow_end,timestamp) < ?
            ORDER BY COALESCE(flow_end,timestamp),id
            """,
            (earliest.isoformat(), latest.isoformat()),
        )
        columns = [item[0] for item in flow_cursor.description]
        flow_rows = [dict(zip(columns, values)) for values in flow_cursor.fetchall()]
        flow_times = [
            utc(str(row.get("flow_end") or row.get("timestamp"))).timestamp()
            for row in flow_rows
        ]

        def flow_slice(start: datetime, end: datetime) -> list[dict[str, Any]]:
            left = bisect.bisect_left(flow_times, start.timestamp())
            right = bisect.bisect_left(flow_times, end.timestamp())
            return flow_rows[left:right]

        for row in rows:
            raw_label = str(row["label"] or "").strip().upper()
            if raw_label in BENIGN_LABELS:
                truth = "BENIGN"
            elif raw_label in ATTACK_LABELS:
                truth = "ATTACK"
            else:
                continue
            start = utc(str(row["started_at"]))
            end = utc(str(row["ended_at"]))
            cursor = start
            while cursor + timedelta(seconds=args.window_seconds) <= end:
                window_end = cursor + timedelta(seconds=args.window_seconds)
                current = flow_slice(cursor, window_end)
                previous = flow_slice(cursor - timedelta(seconds=60), cursor)
                state = build_state(current, previous_records=previous)
                records.append(
                    {
                        "run_id": int(row["run_id"]),
                        "phase_id": int(row["phase_id"]),
                        "scenario": str(row["scenario"]),
                        "campaign_id": str(row["campaign_id"] or ""),
                        "split": str(row["split"] or ""),
                        "phase_label": raw_label,
                        "truth": truth,
                        "window_end": window_end.isoformat(),
                        "features": [float(state.get(name) or 0.0) for name in FLOW_FEATURES],
                    }
                )
                cursor = window_end
    finally:
        connection.close()

    if not records:
        raise RuntimeError("no independent EVE evaluation windows found")
    x = np.asarray([row["features"] for row in records], dtype=np.float64)
    probability = (attack_probability(logistic, x) + attack_probability(forest, x)) / 2.0
    truth = np.asarray([row["truth"] == "ATTACK" for row in records], dtype=bool)
    pred = probability >= threshold
    negative = ~truth
    window_fpr = float(np.mean(pred[negative])) if negative.any() else 0.0
    window_recall = float(np.mean(pred[truth])) if truth.any() else 0.0

    by_phase: dict[int, list[int]] = defaultdict(list)
    for index, row in enumerate(records):
        by_phase[int(row["phase_id"])].append(index)
    false_episode_count = 0
    attack_phase_detected = 0
    attack_phase_count = 0
    confirmed_pred = np.zeros(len(records), dtype=bool)
    for indices in by_phase.values():
        ordered = sorted(indices, key=lambda idx: records[idx]["window_end"])
        previous = False
        previous_confirmed = False
        phase_truth = truth[ordered[0]]
        phase_hit = False
        for idx in ordered:
            current = bool(pred[idx])
            confirmed = current and previous
            confirmed_pred[idx] = confirmed
            if confirmed:
                phase_hit = True
            if not phase_truth and confirmed and not previous_confirmed:
                false_episode_count += 1
            previous = current
            previous_confirmed = confirmed
        if phase_truth:
            attack_phase_count += 1
            attack_phase_detected += int(phase_hit)

    confirmed_fpr = float(np.mean(confirmed_pred[negative])) if negative.any() else 0.0
    confirmed_recall = float(np.mean(confirmed_pred[truth])) if truth.any() else 0.0
    negative_hours = float(negative.sum() * args.window_seconds) / 3600.0
    result = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "artifact": metadata.get("model_release", args.artifact.name),
        "threshold": threshold,
        "selection_rule": "excludes eve-cyber-v1 train/validation runs; uses completed/traffic-only real EVE benign baseline and cyber attack phases",
        "split_restriction": args.split,
        "window_metrics": {
            "benign_windows": int(negative.sum()),
            "attack_windows": int(truth.sum()),
            "fpr": window_fpr,
            "recall": window_recall,
        },
        "two_window_confirmation": {
            "fpr": confirmed_fpr,
            "recall": confirmed_recall,
            "false_alert_episodes": int(false_episode_count),
            "false_alert_episodes_per_hour": float(false_episode_count / negative_hours) if negative_hours else 0.0,
            "attack_phases": int(attack_phase_count),
            "attack_phases_detected": int(attack_phase_detected),
            "attack_phase_detection_rate": float(attack_phase_detected / attack_phase_count) if attack_phase_count else 0.0,
        },
        "runs": sorted(set(int(row["run_id"]) for row in records)),
        "promotion_evidence_pass": (
            int(negative.sum()) >= 100
            and int(truth.sum()) >= 30
            and window_fpr <= 0.01
            and window_recall >= 0.90
            and (float(false_episode_count / negative_hours) if negative_hours else 0.0) <= 1.0
            and (attack_phase_detected / attack_phase_count if attack_phase_count else 0.0) >= 0.90
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
