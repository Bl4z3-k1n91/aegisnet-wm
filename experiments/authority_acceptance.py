#!/usr/bin/env python3
"""Strict production-authority acceptance for the present-state cyber detector.

The evaluator keeps three evidence sets separate:
1. run-disjoint held-out cyber test windows,
2. independent acceptance-campaign attack phases,
3. non-cyber infrastructure-fault hard negatives that the binary cyber model
   never saw as positive labels.

Promotion is fail-closed and policy driven. This script never changes authority.
"""

from __future__ import annotations

import argparse
import bisect
import json
import math
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
from security_state import build_state  # noqa: E402
from state_vector import FLOW_FEATURES  # noqa: E402


CYBER_ATTACK_LABELS = {
    "RECONNAISSANCE", "STATE_1",
    "INITIAL_ACCESS_PATTERN", "STATE_2",
    "LATERAL_MOVEMENT", "STATE_3",
    "C2_BEACON_PATTERN", "STATE_4",
    "EXFILTRATION_LIKE", "STATE_5", "STATE_X",
    "DDOS_LOW", "STATE_V1", "DDOS_MEDIUM", "STATE_V2", "DDOS_HIGH", "STATE_V3",
}
BENIGN_LABELS = {"BENIGN", "BASELINE", "STATE_0", "RECOVERY", "STATE_R", "STATE_RECOVERY"}
FAULT_NEGATIVE_LABELS = {
    "MPLS_JITTER", "MPLS_PACKET_LOSS", "MPLS_OUTAGE", "INTERNET_OUTAGE",
    "CORE_PATH_FAILURE", "POLICY_DRIFT", "BGP_FLAP",
    "MPLS_CONGESTION", "MPLS_CONGESTION_1", "MPLS_CONGESTION_2", "MPLS_CONGESTION_3",
}


def utc(value: Any) -> datetime:
    result = datetime.fromisoformat(str(value))
    return result if result.tzinfo else result.replace(tzinfo=timezone.utc)


def attack_probability(model: Any, x: np.ndarray) -> np.ndarray:
    raw = model.predict_proba(x)
    labels = [str(value) for value in model.classes_]
    return raw[:, labels.index("ATTACK")]


def class_probability(model: Any, x: np.ndarray, label: str) -> np.ndarray:
    raw = model.predict_proba(x)
    labels = [str(value) for value in model.classes_]
    return raw[:, labels.index(label)]


def wilson(successes: int, total: int, z: float = 1.96) -> dict[str, float | None]:
    if total <= 0:
        return {"low": None, "high": None}
    p = successes / total
    denom = 1.0 + z * z / total
    center = (p + z * z / (2 * total)) / denom
    radius = z * math.sqrt((p * (1 - p) + z * z / (4 * total)) / total) / denom
    return {"low": max(0.0, center - radius), "high": min(1.0, center + radius)}


def classify(label: str) -> str | None:
    label = label.strip().upper()
    if label in CYBER_ATTACK_LABELS:
        return "ATTACK"
    if label in BENIGN_LABELS:
        return "BENIGN"
    if label in FAULT_NEGATIVE_LABELS:
        return "HARD_NEGATIVE"
    return None


def score(
    records: list[dict[str, Any]],
    probability: np.ndarray,
    threshold: float,
    pred_override: np.ndarray | None = None,
) -> dict[str, Any]:
    truth = np.asarray([row["truth"] == "ATTACK" for row in records], dtype=bool)
    pred = np.asarray(pred_override, dtype=bool) if pred_override is not None else probability >= threshold
    negative = ~truth
    by_phase: dict[int, list[int]] = defaultdict(list)
    for index, row in enumerate(records):
        by_phase[int(row["phase_id"])].append(index)
    confirmed = np.zeros(len(records), dtype=bool)
    false_episodes = 0
    attack_phases = 0
    attack_phases_detected = 0
    attack_runs: set[int] = set()
    attack_runs_detected: set[int] = set()
    for indices in by_phase.values():
        ordered = sorted(indices, key=lambda idx: records[idx]["window_end"])
        phase_truth = bool(truth[ordered[0]])
        previous = False
        previous_confirmed = False
        phase_hit = False
        for idx in ordered:
            current = bool(pred[idx])
            this_confirmed = current and previous
            confirmed[idx] = this_confirmed
            phase_hit = phase_hit or this_confirmed
            if not phase_truth and this_confirmed and not previous_confirmed:
                false_episodes += 1
            previous = current
            previous_confirmed = this_confirmed
        if phase_truth:
            attack_phases += 1
            run_id = int(records[ordered[0]]["run_id"])
            attack_runs.add(run_id)
            if phase_hit:
                attack_phases_detected += 1
                attack_runs_detected.add(run_id)

    negatives = int(negative.sum())
    positives = int(truth.sum())
    fp = int(np.logical_and(pred, negative).sum())
    tp = int(np.logical_and(pred, truth).sum())
    confirmed_fp = int(np.logical_and(confirmed, negative).sum())
    confirmed_tp = int(np.logical_and(confirmed, truth).sum())
    negative_hours = negatives * 10.0 / 3600.0
    phase_details: list[dict[str, Any]] = []
    for indices in by_phase.values():
        ordered = sorted(indices, key=lambda idx: records[idx]["window_end"])
        probs = [float(probability[idx]) for idx in ordered]
        preds = [bool(pred[idx]) for idx in ordered]
        phase_details.append({
            "run_id": int(records[ordered[0]]["run_id"]),
            "phase_id": int(records[ordered[0]]["phase_id"]),
            "label": str(records[ordered[0]]["phase_label"]),
            "truth": str(records[ordered[0]]["truth"]),
            "windows": len(ordered),
            "probabilities": probs,
            "logistic_probabilities": [
                float(records[idx].get("logistic_attack_probability", 0.0)) for idx in ordered
            ],
            "forest_probabilities": [
                float(records[idx].get("forest_attack_probability", 0.0)) for idx in ordered
            ],
            "positive_windows": int(sum(preds)),
            "confirmed_hit": any(bool(confirmed[idx]) for idx in ordered),
        })
    return {
        "windows": len(records),
        "negative_windows": negatives,
        "attack_windows": positives,
        "window_fpr": fp / negatives if negatives else 0.0,
        "window_recall": tp / positives if positives else 0.0,
        "window_fpr_ci95": wilson(fp, negatives),
        "window_recall_ci95": wilson(tp, positives),
        "confirmed_fpr": confirmed_fp / negatives if negatives else 0.0,
        "confirmed_recall": confirmed_tp / positives if positives else 0.0,
        "false_alert_episodes": false_episodes,
        "negative_hours": negative_hours,
        "false_alert_episodes_per_hour": false_episodes / negative_hours if negative_hours else 0.0,
        "attack_phases": attack_phases,
        "attack_phases_detected": attack_phases_detected,
        "attack_phase_detection_rate": attack_phases_detected / attack_phases if attack_phases else 0.0,
        "attack_runs": len(attack_runs),
        "attack_runs_detected": len(attack_runs_detected),
        "attack_run_detection_rate": len(attack_runs_detected) / len(attack_runs) if attack_runs else 0.0,
        "phase_details": phase_details,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, default=ROOT / "outputs" / "telemetry.db")
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--training-release", type=Path, required=True)
    parser.add_argument("--fusion-config", type=Path)
    parser.add_argument("--acceptance-campaign", default="authority-acceptance-v1")
    parser.add_argument(
        "--exclude-campaign",
        action="append",
        default=[],
        help="Campaign IDs treated as development-contaminated and excluded from held-out evidence.",
    )
    parser.add_argument("--policy", type=Path, default=ROOT / "config" / "production_policy.json")
    parser.add_argument("--window-seconds", type=int, default=10)
    parser.add_argument("--output", type=Path, default=ROOT / "outputs" / "authority-acceptance.json")
    args = parser.parse_args()

    policy = json.loads(args.policy.read_text(encoding="utf-8"))
    gate = dict(policy.get("authority_acceptance") or {})
    metadata = json.loads((args.artifact / "metadata.json").read_text(encoding="utf-8"))
    threshold = float(metadata["attack_probability_threshold"])
    logistic = joblib.load(args.artifact / "logistic_pipeline.joblib")
    forest = joblib.load(args.artifact / "random_forest_pipeline.joblib")
    fusion: dict[str, Any] | None = None
    stage_logistic = stage_forest = None
    if args.fusion_config:
        fusion = json.loads(args.fusion_config.read_text(encoding="utf-8"))
        stage_artifact = Path(str(fusion["stage_artifact"]))
        stage_logistic = joblib.load(stage_artifact / "logistic_pipeline.joblib")
        stage_forest = joblib.load(stage_artifact / "random_forest_pipeline.joblib")

    excluded_runs: set[int] = set()
    for split in ("train", "val"):
        path = args.training_release / f"{split}.npz"
        if path.exists():
            with np.load(path, allow_pickle=False) as data:
                excluded_runs.update(int(v) for v in np.asarray(data["run_id"]).tolist())

    connection = sqlite3.connect(f"file:{args.database.as_posix()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        phases = connection.execute(
            """
            SELECT r.id run_id,r.scenario,r.campaign_id,COALESCE(r.split,'train') split,
                   p.id phase_id,p.label,p.started_at,p.ended_at
            FROM scenario_runs r JOIN scenario_phases p ON p.run_id=r.id
            WHERE r.status IN ('COMPLETED','TRAFFIC_ONLY') AND p.ended_at IS NOT NULL
            ORDER BY r.id,p.started_at
            """
        ).fetchall()
        selected = []
        for row in phases:
            run_id = int(row["run_id"])
            bucket = classify(str(row["label"] or ""))
            if bucket is None:
                continue
            campaign_id = str(row["campaign_id"] or "")
            is_new_campaign = campaign_id == args.acceptance_campaign
            is_held_out_test = (
                str(row["split"] or "").lower() == "test"
                and run_id not in excluded_runs
                and campaign_id not in set(args.exclude_campaign)
            )
            is_fault_stress = bucket == "HARD_NEGATIVE"
            if is_new_campaign or is_held_out_test or is_fault_stress:
                selected.append((row, bucket, is_new_campaign, is_held_out_test, is_fault_stress))
        if not selected:
            raise RuntimeError("no eligible production acceptance phases")
        earliest = min(utc(item[0]["started_at"]) for item in selected) - timedelta(seconds=60)
        latest = max(utc(item[0]["ended_at"]) for item in selected)
        cursor = connection.execute(
            """
            SELECT * FROM flows WHERE COALESCE(flow_end,timestamp)>=? AND COALESCE(flow_end,timestamp)<?
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
        return flows[bisect.bisect_left(flow_times, start.timestamp()):bisect.bisect_left(flow_times, end.timestamp())]

    records: list[dict[str, Any]] = []
    for row, bucket, is_new_campaign, is_held_out_test, is_fault_stress in selected:
        start, end = utc(row["started_at"]), utc(row["ended_at"])
        cursor_time = start
        while cursor_time + timedelta(seconds=args.window_seconds) <= end:
            window_end = cursor_time + timedelta(seconds=args.window_seconds)
            state = build_state(
                flow_slice(cursor_time, window_end),
                previous_records=flow_slice(cursor_time - timedelta(seconds=60), cursor_time),
            )
            records.append({
                "run_id": int(row["run_id"]), "phase_id": int(row["phase_id"]),
                "scenario": str(row["scenario"]), "campaign_id": str(row["campaign_id"] or ""),
                "split": str(row["split"] or ""), "phase_label": str(row["label"]),
                "truth": "ATTACK" if bucket == "ATTACK" else "BENIGN",
                "kind": "acceptance_campaign" if is_new_campaign else ("hard_negative_fault" if is_fault_stress else "held_out_test"),
                "window_end": window_end.isoformat(),
                "features": [float(state.get(name) or 0.0) for name in FLOW_FEATURES],
            })
            cursor_time = window_end

    x = np.asarray([row["features"] for row in records], dtype=np.float64)
    logistic_probability = attack_probability(logistic, x)
    forest_probability = attack_probability(forest, x)
    probability = (logistic_probability + forest_probability) / 2.0
    for index, row in enumerate(records):
        row["logistic_attack_probability"] = float(logistic_probability[index])
        row["forest_attack_probability"] = float(forest_probability[index])
    decision_pred: np.ndarray | None = None
    stage_probability: np.ndarray | None = None
    if fusion is not None and stage_logistic is not None and stage_forest is not None:
        stage_benign = (
            class_probability(stage_logistic, x, "BENIGN")
            + class_probability(stage_forest, x, "BENIGN")
        ) / 2.0
        stage_probability = 1.0 - stage_benign
        decision_pred = (
            (probability >= float(fusion["binary_threshold"]))
            | (stage_probability >= float(fusion["stage_threshold"]))
        )
        for index, row in enumerate(records):
            row["binary_attack_probability"] = float(probability[index])
            row["stage_attack_probability"] = float(stage_probability[index])

    groups: dict[str, tuple[list[dict[str, Any]], np.ndarray, np.ndarray | None]] = {}
    for kind in ("held_out_test", "acceptance_campaign", "hard_negative_fault"):
        indices = [i for i, row in enumerate(records) if row["kind"] == kind]
        groups[kind] = (
            [records[i] for i in indices],
            probability[indices],
            decision_pred[indices] if decision_pred is not None else None,
        )
    combined_records = [row for row in records if row["kind"] != "hard_negative_fault"]
    combined_indices = [i for i, row in enumerate(records) if row["kind"] != "hard_negative_fault"]
    combined = score(
        combined_records,
        probability[combined_indices],
        threshold,
        decision_pred[combined_indices] if decision_pred is not None else None,
    )
    hard_negative = score(
        groups["hard_negative_fault"][0], groups["hard_negative_fault"][1], threshold,
        groups["hard_negative_fault"][2],
    )
    acceptance = score(
        groups["acceptance_campaign"][0], groups["acceptance_campaign"][1], threshold,
        groups["acceptance_campaign"][2],
    )
    held_out = score(
        groups["held_out_test"][0], groups["held_out_test"][1], threshold,
        groups["held_out_test"][2],
    )

    gates = {
        "min_negative_windows": (
            combined["negative_windows"] + hard_negative["negative_windows"]
        ) >= int(gate.get("min_negative_windows", 750)),
        "min_attack_windows": combined["attack_windows"] >= int(gate.get("min_attack_windows", 100)),
        "min_attack_phases": combined["attack_phases"] >= int(gate.get("min_attack_phases", 30)),
        "min_attack_runs": combined["attack_runs"] >= int(gate.get("min_attack_runs", 15)),
        "max_raw_window_fpr": combined["window_fpr"] <= float(gate.get("max_raw_window_fpr", 0.03)),
        "max_confirmed_fpr": combined["confirmed_fpr"] <= float(gate.get("max_confirmed_fpr", 0.01)),
        "min_window_recall": combined["window_recall"] >= float(gate.get("min_window_recall", 0.90)),
        "max_false_alerts_per_hour": combined["false_alert_episodes_per_hour"] <= float(gate.get("max_false_alerts_per_hour", 0.10)),
        "min_attack_phase_detection": combined["attack_phase_detection_rate"] >= float(gate.get("min_attack_phase_detection", 0.90)),
        "min_hard_negative_windows": hard_negative["negative_windows"] >= int(gate.get("min_hard_negative_windows", 500)),
        "max_hard_negative_raw_fpr": hard_negative["window_fpr"] <= float(gate.get("max_hard_negative_raw_fpr", 0.01)),
        "max_hard_negative_confirmed_fpr": hard_negative["confirmed_fpr"] <= float(gate.get("max_hard_negative_confirmed_fpr", 0.005)),
    }
    result = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "artifact": metadata.get("model_release", args.artifact.name),
        "threshold": threshold,
        "fusion": fusion,
        "training_release": args.training_release.name,
        "excluded_training_validation_runs": sorted(excluded_runs),
        "acceptance_campaign": args.acceptance_campaign,
        "excluded_development_campaigns": list(args.exclude_campaign),
        "combined_cyber_acceptance": combined,
        "held_out_test": held_out,
        "acceptance_campaign_metrics": acceptance,
        "hard_negative_fault_stress": hard_negative,
        "negative_windows_total": combined["negative_windows"] + hard_negative["negative_windows"],
        "policy": gate,
        "gates": gates,
        "promotion_evidence_pass": all(gates.values()),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0 if result["promotion_evidence_pass"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
