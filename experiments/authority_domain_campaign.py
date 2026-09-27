#!/usr/bin/env python3
"""Collect resumable train/validation EVE domain-expansion data for authority models."""

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


def completed(database: Path, campaign: str) -> set[int]:
    connection = sqlite3.connect(database)
    try:
        rows = connection.execute(
            "SELECT sequence_index FROM scenario_runs WHERE campaign_id=? AND status='COMPLETED' AND sequence_index IS NOT NULL",
            (campaign,),
        ).fetchall()
        return {int(row[0]) for row in rows}
    finally:
        connection.close()


def build_plan(seed: int) -> list[dict[str, object]]:
    rng = random.Random(seed)
    profiles = ["ping", "business", "bulk", "voice", "mixed"]
    plan: list[dict[str, object]] = []
    index = 1
    for split in ("train", "validation"):
        for profile in profiles:
            plan.append({
                "sequence_index": index,
                "split": split,
                "scenario": "benign-soak",
                "traffic_profile": profile,
                "run_seed": rng.randrange(1, 2**31),
            })
            index += 1
        attack_profiles = ("mixed", "business") if split == "train" else ("bulk", "voice")
        for scenario, profile in zip(("recon-ddos-medium", "recon-ddos-high"), attack_profiles):
            plan.append({
                "sequence_index": index,
                "split": split,
                "scenario": scenario,
                "traffic_profile": profile,
                "run_seed": rng.randrange(1, 2**31),
            })
            index += 1
    return plan


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign-id", default="authority-domain-v2")
    parser.add_argument("--seed", type=int, default=26154)
    parser.add_argument("--benign-seconds", type=int, default=30)
    parser.add_argument("--baseline-seconds", type=int, default=20)
    parser.add_argument("--recon-seconds", type=int, default=30)
    parser.add_argument("--attack-seconds", type=int, default=30)
    parser.add_argument("--recovery-seconds", type=int, default=20)
    parser.add_argument("--database", type=Path, default=ROOT / "outputs" / "telemetry.db")
    parser.add_argument("--plan-output", type=Path, default=ROOT / "outputs" / "authority-domain-plan.json")
    args = parser.parse_args()

    plan = build_plan(args.seed)
    args.plan_output.parent.mkdir(parents=True, exist_ok=True)
    args.plan_output.write_text(json.dumps({
        "campaign_id": args.campaign_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "seed": args.seed,
        "plan": plan,
    }, indent=2) + "\n", encoding="utf-8")

    done = completed(args.database, args.campaign_id)
    failures = 0
    for item in plan:
        sequence = int(item["sequence_index"])
        if sequence in done:
            print(f"skip completed domain sequence {sequence}", flush=True)
            continue
        command = [
            sys.executable, str(RUNNER), str(item["scenario"]),
            "--campaign-id", args.campaign_id,
            "--sequence-index", str(sequence),
            "--run-seed", str(item["run_seed"]),
            "--split", str(item["split"]),
            "--traffic-profile", str(item["traffic_profile"]),
            "--soak-seconds", str(args.benign_seconds),
            "--baseline-seconds", str(args.baseline_seconds),
            "--recon-seconds", str(args.recon_seconds),
            "--attack-seconds", str(args.attack_seconds),
            "--recovery-seconds", str(args.recovery_seconds),
        ]
        print(
            f"domain {sequence}/{len(plan)}: {item['split']} {item['scenario']} {item['traffic_profile']}",
            flush=True,
        )
        result = subprocess.run(command, cwd=ROOT)
        if result.returncode != 0:
            failures += 1
            print(f"domain sequence {sequence} failed rc={result.returncode}", file=sys.stderr, flush=True)
            break

    done = completed(args.database, args.campaign_id)
    planned = {int(item["sequence_index"]) for item in plan}
    print(json.dumps({
        "campaign_id": args.campaign_id,
        "planned": len(plan),
        "completed": len(done & planned),
        "failures": failures,
        "plan": str(args.plan_output),
    }, indent=2))
    return 0 if failures == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
