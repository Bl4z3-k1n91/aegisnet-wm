#!/usr/bin/env python3
"""Run a resumable bounded EVE production-authority cyber acceptance campaign."""

from __future__ import annotations

import argparse
import json
import random
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "experiments" / "cyber_scenario_runner.py"


def completed_sequences(database: Path, campaign_id: str) -> set[int]:
    connection = sqlite3.connect(database)
    try:
        rows = connection.execute(
            "SELECT sequence_index FROM scenario_runs WHERE campaign_id=? AND status='COMPLETED' AND sequence_index IS NOT NULL",
            (campaign_id,),
        ).fetchall()
        return {int(row[0]) for row in rows}
    finally:
        connection.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign-id", default="authority-acceptance-v1")
    parser.add_argument("--runs", type=int, default=15)
    parser.add_argument("--seed", type=int, default=26153)
    parser.add_argument("--baseline-seconds", type=int, default=20)
    parser.add_argument("--recon-seconds", type=int, default=30)
    parser.add_argument("--attack-seconds", type=int, default=30)
    parser.add_argument("--recovery-seconds", type=int, default=20)
    parser.add_argument("--database", type=Path, default=ROOT / "outputs" / "telemetry.db")
    parser.add_argument("--plan-output", type=Path, default=ROOT / "outputs" / "authority-campaign-plan.json")
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs must be positive")

    rng = random.Random(args.seed)
    profiles = ["mixed", "business", "bulk", "ping", "voice"]
    scenarios = ["recon-initial-access", "recon-ddos-medium", "recon-ddos-high"]
    plan = []
    for index in range(1, args.runs + 1):
        plan.append({
            "sequence_index": index,
            "run_seed": rng.randrange(1, 2**31),
            "scenario": scenarios[(index - 1) % len(scenarios)],
            "traffic_profile": profiles[(index - 1) % len(profiles)],
        })
    args.plan_output.parent.mkdir(parents=True, exist_ok=True)
    args.plan_output.write_text(json.dumps({
        "campaign_id": args.campaign_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "seed": args.seed,
        "durations": {
            "baseline": args.baseline_seconds, "recon": args.recon_seconds,
            "attack": args.attack_seconds, "recovery": args.recovery_seconds,
        },
        "plan": plan,
    }, indent=2) + "\n", encoding="utf-8")

    done = completed_sequences(args.database, args.campaign_id)
    failures = 0
    for item in plan:
        if item["sequence_index"] in done:
            print(f"skip completed sequence {item['sequence_index']}", flush=True)
            continue
        command = [
            sys.executable, str(RUNNER), item["scenario"],
            "--campaign-id", args.campaign_id,
            "--sequence-index", str(item["sequence_index"]),
            "--run-seed", str(item["run_seed"]),
            "--split", "test",
            "--traffic-profile", item["traffic_profile"],
            "--baseline-seconds", str(args.baseline_seconds),
            "--recon-seconds", str(args.recon_seconds),
            "--attack-seconds", str(args.attack_seconds),
            "--recovery-seconds", str(args.recovery_seconds),
        ]
        print(f"authority run {item['sequence_index']}/{args.runs}: {item['scenario']} {item['traffic_profile']}", flush=True)
        result = subprocess.run(command, cwd=ROOT)
        if result.returncode != 0:
            failures += 1
            print(f"sequence {item['sequence_index']} failed rc={result.returncode}", file=sys.stderr, flush=True)
            break
    completed = completed_sequences(args.database, args.campaign_id)
    print(json.dumps({
        "campaign_id": args.campaign_id,
        "planned": args.runs,
        "completed": len(completed & {item['sequence_index'] for item in plan}),
        "failures": failures,
        "plan": str(args.plan_output),
    }, indent=2))
    return 0 if failures == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
