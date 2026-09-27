#!/usr/bin/env python3
"""Evaluate a temporal authority challenger on one exact, locked EVE campaign."""

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
sys.path.insert(0, str(ROOT / "models"))
from security_state import build_state  # noqa: E402
from production_guard import load_policy  # noqa: E402


ATTACK_LABELS = {
    "RECONNAISSANCE", "STATE_1", "INITIAL_ACCESS_PATTERN", "STATE_2",
    "LATERAL_MOVEMENT", "STATE_3", "C2_BEACON_PATTERN", "STATE_4",
    "EXFILTRATION_LIKE", "STATE_5", "STATE_X", "DDOS_LOW", "STATE_V1",
    "DDOS_MEDIUM", "STATE_V2", "DDOS_HIGH", "STATE_V3",
}
EASY_BENIGN = {"BENIGN", "BASELINE", "RECOVERY", "STATE_0", "STATE_R", "STATE_RECOVERY"}


def utc(value: Any) -> datetime:
    result = datetime.fromisoformat(str(value))
    return result if result.tzinfo else result.replace(tzinfo=timezone.utc)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign-id", required=True)
    parser.add_argument("--database", type=Path, default=ROOT / "outputs" / "telemetry.db")
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "outputs" / "authority-acceptance.json")
    args = parser.parse_args()
    policy = load_policy()
    gates = policy["authority_acceptance"]
    metadata = json.loads((args.artifact / "metadata.json").read_text(encoding="utf-8"))
    if args.campaign_id in set(metadata.get("excluded_acceptance_campaigns") or []):
        pass
    else:
        raise RuntimeError("artifact does not declare this campaign excluded from development")
    features = list(metadata["features"])
    history_steps = int(metadata["history_steps"])
    window_seconds = int(metadata["window_seconds"])
    threshold = float(metadata["attack_probability_threshold"])
    model = joblib.load(args.artifact / "authority_model.joblib")

    connection = sqlite3.connect(f"file:{args.database.as_posix()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        phases = connection.execute(
            """SELECT r.id run_id,r.scenario,r.campaign_id,r.split,r.parameters_json,
                      p.id phase_id,p.label,p.started_at,p.ended_at
               FROM scenario_runs r JOIN scenario_phases p ON p.run_id=r.id
               WHERE r.campaign_id=? AND lower(COALESCE(r.split,''))='test'
                 AND r.status IN ('COMPLETED','TRAFFIC_ONLY') AND p.ended_at IS NOT NULL
               ORDER BY r.id,p.started_at""",
            (args.campaign_id,),
        ).fetchall()
        if not phases:
            raise RuntimeError("locked acceptance campaign has no completed test phases")
        earliest = min(utc(row["started_at"]) for row in phases) - timedelta(seconds=60)
        latest = max(utc(row["ended_at"]) for row in phases)
        cursor = connection.execute(
            """SELECT * FROM flows WHERE COALESCE(flow_end,timestamp)>=? AND COALESCE(flow_end,timestamp)<?
               ORDER BY COALESCE(flow_end,timestamp),id""",
            (earliest.isoformat(), latest.isoformat()),
        )
        columns = [item[0] for item in cursor.description]
        flows = [dict(zip(columns, row)) for row in cursor.fetchall()]
    finally:
        connection.close()
    flow_times = [utc(row.get("flow_end") or row.get("timestamp")).timestamp() for row in flows]
    def flow_slice(start: datetime, end: datetime) -> list[dict[str, Any]]:
        return flows[bisect.bisect_left(flow_times,start.timestamp()):bisect.bisect_left(flow_times,end.timestamp())]

    samples: list[dict[str, Any]] = []
    by_phase_states: dict[int, list[list[float]]] = defaultdict(list)
    phase_meta: dict[int, sqlite3.Row] = {}
    for phase in phases:
        phase_id = int(phase["phase_id"]); phase_meta[phase_id] = phase
        start,end = utc(phase["started_at"]),utc(phase["ended_at"]); cursor_time=start
        while cursor_time + timedelta(seconds=window_seconds) <= end:
            window_end=cursor_time+timedelta(seconds=window_seconds)
            state=build_state(flow_slice(cursor_time,window_end),previous_records=flow_slice(cursor_time-timedelta(seconds=60),cursor_time))
            by_phase_states[phase_id].append([float(state.get(name) or 0.0) for name in features])
            cursor_time=window_end
    for phase_id, states in by_phase_states.items():
        meta=phase_meta[phase_id]; raw=str(meta["label"] or "").upper(); truth=raw in ATTACK_LABELS
        try:
            parameters=json.loads(str(meta["parameters_json"] or "{}"))
        except json.JSONDecodeError:
            parameters={}
        profile=str(parameters.get("traffic_profile") or "").lower()
        stress_benign=(
            not truth
            and str(meta["scenario"] or "").lower()=="cyber-benign-soak"
            and profile in {"bulk","mixed","business","voice"}
        )
        for end in range(history_steps-1,len(states)):
            samples.append({
                "run_id":int(meta["run_id"]),"phase_id":phase_id,"phase_label":raw,
                "truth":truth,"hard_negative":(not truth and (raw not in EASY_BENIGN or stress_benign)),
                "features":np.asarray(states[end-history_steps+1:end+1],dtype=np.float64).reshape(-1),
            })
    if not samples: raise RuntimeError("campaign has no complete temporal sequences")
    x=np.asarray([s["features"] for s in samples]); classes=[str(v) for v in model.classes_]
    prob=model.predict_proba(np.log1p(np.clip(x,0.0,None)))[:,classes.index("ATTACK")]
    truth=np.asarray([s["truth"] for s in samples],dtype=bool); pred=prob>=threshold; neg=~truth
    hard=np.asarray([s["hard_negative"] for s in samples],dtype=bool)
    confirmed=np.zeros(len(samples),dtype=bool); false_episodes=0; phase_hit={}; by_phase=defaultdict(list)
    for i,s in enumerate(samples): by_phase[s["phase_id"]].append(i)
    for phase_id,indices in by_phase.items():
        previous=False; previous_confirmed=False; hit=False
        for idx in indices:
            current=bool(pred[idx]); c=current and previous; confirmed[idx]=c; hit|=c
            if not truth[idx] and c and not previous_confirmed: false_episodes+=1
            previous=current; previous_confirmed=c
        phase_hit[phase_id]=hit
    attack_phase_ids=[pid for pid,meta in phase_meta.items() if str(meta["label"] or "").upper() in ATTACK_LABELS]
    attack_runs=sorted({int(phase_meta[pid]["run_id"]) for pid in attack_phase_ids})
    negative_hours=float(neg.sum()*window_seconds)/3600.0
    result={
        "generated_at":datetime.now(timezone.utc).isoformat(),"campaign_id":args.campaign_id,
        "artifact":metadata["model_release"],"threshold":threshold,"history_steps":history_steps,
        "window_metrics":{"negative_windows":int(neg.sum()),"attack_windows":int(truth.sum()),"fpr":float(pred[neg].mean()) if neg.any() else 0.0,"recall":float(pred[truth].mean()) if truth.any() else 0.0},
        "confirmation":{"fpr":float(confirmed[neg].mean()) if neg.any() else 0.0,"recall":float(confirmed[truth].mean()) if truth.any() else 0.0,"false_alert_episodes":false_episodes,"false_alerts_per_hour":float(false_episodes/negative_hours) if negative_hours else 0.0},
        "attack_phases":{"count":len(attack_phase_ids),"detected":sum(bool(phase_hit.get(pid)) for pid in attack_phase_ids)},
        "attack_runs":len(attack_runs),
        "hard_negatives":{"windows":int(hard.sum()),"raw_fpr":float(pred[hard].mean()) if hard.any() else 0.0,"confirmed_fpr":float(confirmed[hard].mean()) if hard.any() else 0.0},
        "policy":gates,
    }
    phase_rate=(result["attack_phases"]["detected"]/result["attack_phases"]["count"]) if result["attack_phases"]["count"] else 0.0
    checks={
        "negative_windows":result["window_metrics"]["negative_windows"]>=gates["min_negative_windows"],
        "attack_windows":result["window_metrics"]["attack_windows"]>=gates["min_attack_windows"],
        "attack_phases":result["attack_phases"]["count"]>=gates["min_attack_phases"],
        "attack_runs":result["attack_runs"]>=gates["min_attack_runs"],
        "raw_fpr":result["window_metrics"]["fpr"]<=gates["max_raw_window_fpr"],
        "confirmed_fpr":result["confirmation"]["fpr"]<=gates["max_confirmed_fpr"],
        "recall":result["window_metrics"]["recall"]>=gates["min_window_recall"],
        "false_alerts_per_hour":result["confirmation"]["false_alerts_per_hour"]<=gates["max_false_alerts_per_hour"],
        "phase_detection":phase_rate>=gates["min_attack_phase_detection"],
        "hard_negative_windows":result["hard_negatives"]["windows"]>=gates["min_hard_negative_windows"],
        "hard_negative_raw_fpr":result["hard_negatives"]["raw_fpr"]<=gates["max_hard_negative_raw_fpr"],
        "hard_negative_confirmed_fpr":result["hard_negatives"]["confirmed_fpr"]<=gates["max_hard_negative_confirmed_fpr"],
    }
    result["phase_detection_rate"]=phase_rate; result["checks"]=checks; result["promotion_evidence_pass"]=all(checks.values())
    args.output.parent.mkdir(parents=True,exist_ok=True); args.output.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(result,indent=2)); return 0 if result["promotion_evidence_pass"] else 2


if __name__ == "__main__": raise SystemExit(main())
