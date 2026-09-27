#!/usr/bin/env python3
"""Run a balanced, randomized and resumable labelled-fault campaign."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import re
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psutil


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from deploy_eve import EveClient, api_lab_path  # noqa: E402

SCHEMA = """
CREATE TABLE IF NOT EXISTS dataset_campaigns (
    campaign_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    status TEXT NOT NULL,
    seed INTEGER NOT NULL,
    plan_json TEXT NOT NULL,
    environment_json TEXT NOT NULL,
    completed_runs INTEGER NOT NULL DEFAULT 0,
    failed_runs INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS dataset_campaign_plan (
    campaign_id TEXT NOT NULL,
    sequence_index INTEGER NOT NULL,
    scenario TEXT NOT NULL,
    severity TEXT NOT NULL,
    traffic_profile TEXT NOT NULL,
    split TEXT NOT NULL,
    run_seed INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING',
    scenario_run_id INTEGER,
    attempts INTEGER NOT NULL DEFAULT 0,
    started_at TEXT,
    ended_at TEXT,
    error TEXT,
    PRIMARY KEY (campaign_id, sequence_index)
);
CREATE TABLE IF NOT EXISTS campaign_repair_events (
    id INTEGER PRIMARY KEY,
    campaign_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    reason TEXT NOT NULL,
    nodes_json TEXT NOT NULL
);
"""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def choose_split(run_seed: int) -> str:
    bucket = run_seed % 100
    if bucket < 70:
        return "train"
    if bucket < 85:
        return "validation"
    return "test"


def build_plan(args: argparse.Namespace) -> list[dict[str, Any]]:
    randomizer = random.Random(args.seed)
    plan: list[dict[str, Any]] = []
    severity_scenarios = {"jitter", "loss-burst"}
    profiles = [item.strip() for item in args.traffic_profiles.split(",") if item.strip()]
    for scenario in args.scenarios:
        severities = args.severities if scenario in severity_scenarios else ["moderate"]
        for severity in severities:
            for replicate in range(args.repeats):
                run_seed = randomizer.randrange(1, 2**31)
                plan.append(
                    {
                        "scenario": scenario,
                        "severity": severity,
                        "traffic_profile": profiles[len(plan) % len(profiles)],
                        "split": choose_split(run_seed),
                        "run_seed": run_seed,
                    }
                )
    randomizer.shuffle(plan)
    for index, item in enumerate(plan, start=1):
        item["sequence_index"] = index
    return plan


def environment_manifest(args: argparse.Namespace) -> dict[str, Any]:
    files = [
        ROOT / "lab" / "topology.json",
        ROOT / "experiments" / "scenario_runner.py",
        ROOT / "experiments" / "scenario_store.py",
        ROOT / "tools" / "fault_injector.py",
        ROOT / "telemetry" / "telemetry_service.py",
    ]
    return {
        "python": sys.version,
        "platform": sys.platform,
        "eve_url": args.eve_url,
        "eve_path": args.eve_path,
        "lab_name": args.lab_name,
        "telemetry_poll_seconds": args.expected_poll_interval,
        "file_sha256": {
            str(path.relative_to(ROOT)): sha256(path) for path in files
        },
    }


class Campaign:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.connection = sqlite3.connect(args.database, timeout=60)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA busy_timeout=60000")
        self.connection.executescript(SCHEMA)
        self.connection.commit()

    def initialize(self) -> None:
        existing = self.connection.execute(
            "SELECT 1 FROM dataset_campaigns WHERE campaign_id=?",
            (self.args.campaign_id,),
        ).fetchone()
        if existing:
            return
        plan = build_plan(self.args)
        now = utc_now()
        self.connection.execute(
            """
            INSERT INTO dataset_campaigns
            (campaign_id,created_at,updated_at,status,seed,plan_json,environment_json)
            VALUES (?,?,?,?,?,?,?)
            """,
            (
                self.args.campaign_id,
                now,
                now,
                "RUNNING",
                self.args.seed,
                json.dumps(plan, sort_keys=True),
                json.dumps(environment_manifest(self.args), sort_keys=True),
            ),
        )
        self.connection.executemany(
            """
            INSERT INTO dataset_campaign_plan
            (campaign_id,sequence_index,scenario,severity,traffic_profile,split,run_seed)
            VALUES (?,?,?,?,?,?,?)
            """,
            [
                (
                    self.args.campaign_id,
                    item["sequence_index"],
                    item["scenario"],
                    item["severity"],
                    item["traffic_profile"],
                    item["split"],
                    item["run_seed"],
                )
                for item in plan
            ],
        )
        self.connection.commit()

    def command(self, item: sqlite3.Row) -> list[str]:
        command = [
            sys.executable,
            str(ROOT / "experiments" / "scenario_runner.py"),
            item["scenario"],
            "--eve-url", self.args.eve_url,
            "--eve-username", self.args.eve_username,
            "--eve-path", self.args.eve_path,
            "--lab-name", self.args.lab_name,
            "--baseline-seconds", str(self.args.baseline_seconds),
            "--fault-seconds", str(self.args.fault_seconds),
            "--recovery-seconds", str(self.args.recovery_seconds),
            "--stage-seconds", str(self.args.stage_seconds),
            "--severity", item["severity"],
            "--traffic-profile", item["traffic_profile"],
            "--campaign-id", self.args.campaign_id,
            "--run-seed", str(item["run_seed"]),
            "--sequence-index", str(item["sequence_index"]),
            "--split", item["split"],
            "--window-seconds", str(self.args.window_seconds),
            "--stride-seconds", str(self.args.stride_seconds),
            "--database", str(self.args.database),
            "--status-file", str(self.args.status_file),
        ]
        return command

    def restore_all(self) -> None:
        subprocess.run(
            [
                sys.executable,
                str(ROOT / "tools" / "fault_injector.py"),
                "--eve-url", self.args.eve_url,
                "--username", self.args.eve_username,
                "--eve-path", self.args.eve_path,
                "--lab-name", self.args.lab_name,
                "restore-all",
            ],
            cwd=ROOT,
            env=os.environ.copy(),
            check=True,
            timeout=120,
        )

    def telemetry_healthy(self) -> tuple[bool, str]:
        if not self.args.status_file.is_file():
            return False, "status file missing"
        try:
            status = json.loads(
                self.args.status_file.read_text(encoding="utf-8")
            )
            pid = int(status.get("pid", 0))
            updated = datetime.fromisoformat(str(status["updated_at"]))
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            return False, f"invalid status file: {exc}"
        age = (datetime.now(timezone.utc) - updated).total_seconds()
        if not psutil.pid_exists(pid):
            return False, f"telemetry PID {pid} is not running"
        if age > self.args.telemetry_max_age:
            return False, f"telemetry heartbeat stale by {age:.0f}s"
        if status.get("fatal_errors"):
            return False, f"telemetry fatal errors: {status['fatal_errors']}"
        return True, "healthy"

    def restart_telemetry(self, reason: str) -> None:
        print(f"Restarting telemetry: {reason}", file=sys.stderr)
        manager = str(ROOT / "telemetry" / "manage_telemetry.py")
        subprocess.run(
            [sys.executable, manager, "stop"],
            cwd=ROOT,
            check=True,
            timeout=30,
        )
        subprocess.run(
            [
                sys.executable, manager, "start", "--",
                "--bind", self.args.telemetry_bind,
                "--poll-interval", str(self.args.expected_poll_interval),
            ],
            cwd=ROOT,
            check=True,
            timeout=30,
        )
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            healthy, _ = self.telemetry_healthy()
            if healthy:
                return
            time.sleep(2)
        raise RuntimeError("telemetry did not become healthy after restart")

    def ensure_telemetry(self) -> None:
        healthy, reason = self.telemetry_healthy()
        if not healthy:
            self.restart_telemetry(reason)

    def wait_for_convergence(self) -> None:
        expected = {
            "P1": {"ospf_full": 2},
            "P2": {"ospf_full": 2},
            "PE1": {"bgp_established": 3, "ospf_full": 2},
            "PE2": {"bgp_established": 3, "ospf_full": 2},
            "INET": {"bgp_established": 4},
            "HUB": {
                "bgp_established": 2, "eigrp_neighbors": 6,
                "dmvpn_up": 6, "ikev2_ready": 6,
            },
            "BR1": {
                "bgp_established": 2, "eigrp_neighbors": 2,
                "dmvpn_up": 4, "ikev2_ready": 4,
            },
            "BR2": {
                "bgp_established": 2, "eigrp_neighbors": 2,
                "dmvpn_up": 4, "ikev2_ready": 4,
            },
            "DC": {
                "bgp_established": 2, "eigrp_neighbors": 2,
                "dmvpn_up": 6, "ikev2_ready": 6,
            },
        }
        deadline = time.monotonic() + self.args.convergence_timeout
        last_problem = ""
        while time.monotonic() < deadline:
            stable = True
            problems = []
            for device, requirements in expected.items():
                samples = self.connection.execute(
                    """
                    SELECT * FROM device_samples
                    WHERE device=? AND reachable=1
                    ORDER BY id DESC LIMIT ?
                    """,
                    (device, self.args.stable_samples),
                ).fetchall()
                if len(samples) < self.args.stable_samples:
                    stable = False
                    problems.append(f"{device}:insufficient-samples")
                    continue
                for field, minimum in requirements.items():
                    if any(
                        sample[field] is None or sample[field] < minimum
                        for sample in samples
                    ):
                        stable = False
                        observed = [sample[field] for sample in samples]
                        problems.append(f"{device}:{field}={observed}<{minimum}")
            if stable:
                print(
                    f"Convergence gate passed with "
                    f"{self.args.stable_samples} consecutive samples."
                )
                return
            last_problem = "; ".join(problems)
            print(f"Waiting for convergence: {last_problem}")
            time.sleep(self.args.convergence_check_interval)
        raise RuntimeError(
            f"convergence gate timed out after {self.args.convergence_timeout}s: "
            f"{last_problem}"
        )

    def repair_access_plane(self, reason: str) -> None:
        nodes_to_restart = ("PE1", "NETEM-BR1-MPLS", "HUB", "BR1")
        client = EveClient(self.args.eve_url)
        client.login(
            self.args.eve_username,
            os.environ["EVE_PASSWORD"],
            native_console=True,
        )
        endpoint = api_lab_path(self.args.eve_path, self.args.lab_name)
        response = client.request("GET", f"/labs{endpoint}/nodes")
        node_ids = {
            value["name"]: int(key)
            for key, value in response["data"].items()
        }
        for name in nodes_to_restart:
            client.request(
                "GET", f"/labs{endpoint}/nodes/{node_ids[name]}/stop"
            )
        time.sleep(5)
        for name in ("NETEM-BR1-MPLS", "PE1", "HUB", "BR1"):
            client.request(
                "GET", f"/labs{endpoint}/nodes/{node_ids[name]}/start"
            )
        self.connection.execute(
            """
            INSERT INTO campaign_repair_events
            (campaign_id,timestamp,reason,nodes_json) VALUES (?,?,?,?)
            """,
            (
                self.args.campaign_id,
                utc_now(),
                reason,
                json.dumps(nodes_to_restart),
            ),
        )
        self.connection.commit()
        print(f"Recorded access-plane repair: {', '.join(nodes_to_restart)}")
        time.sleep(self.args.repair_boot_seconds)

    def ensure_converged(self) -> None:
        try:
            self.wait_for_convergence()
        except RuntimeError as first_error:
            print(f"Convergence repair triggered: {first_error}", file=sys.stderr)
            self.restore_all()
            self.repair_access_plane(str(first_error))
            self.restore_all()
            self.wait_for_convergence()

    def run(self) -> int:
        self.initialize()
        self.connection.execute(
            """
            UPDATE dataset_campaigns SET status='RUNNING',updated_at=?
            WHERE campaign_id=?
            """,
            (utc_now(), self.args.campaign_id),
        )
        self.connection.commit()
        pending = self.connection.execute(
            """
            SELECT * FROM dataset_campaign_plan
            WHERE campaign_id=? AND status!='COMPLETED'
            ORDER BY sequence_index
            """,
            (self.args.campaign_id,),
        ).fetchall()
        if not pending:
            print("Campaign already complete.")
            return 0
        self.ensure_telemetry()
        self.restore_all()
        self.ensure_converged()
        failures = 0
        infrastructure_paused = False
        for item in pending:
            self.ensure_telemetry()
            self.ensure_converged()
            index = item["sequence_index"]
            print(
                f"\\n[{index}] {item['scenario']} severity={item['severity']} "
                f"traffic={item['traffic_profile']} split={item['split']}"
            )
            self.connection.execute(
                """
                UPDATE dataset_campaign_plan
                SET status='RUNNING', attempts=attempts+1, started_at=?, error=NULL
                WHERE campaign_id=? AND sequence_index=?
                """,
                (utc_now(), self.args.campaign_id, index),
            )
            self.connection.commit()
            try:
                result = subprocess.run(
                    self.command(item),
                    cwd=ROOT,
                    env=os.environ.copy(),
                    text=True,
                    capture_output=True,
                    timeout=self.args.run_timeout,
                )
                stdout, stderr, returncode = (
                    result.stdout, result.stderr, result.returncode
                )
            except subprocess.TimeoutExpired as exc:
                stdout = exc.stdout if isinstance(exc.stdout, str) else ""
                stderr = exc.stderr if isinstance(exc.stderr, str) else ""
                stderr += f"\nRun timed out after {self.args.run_timeout}s"
                returncode = 124
                self.restore_all()
            print(stdout, end="")
            if stderr:
                print(stderr, file=sys.stderr, end="")
            match = re.search(r"run_id=(\d+)", stdout)
            run_id = int(match.group(1)) if match else None
            infrastructure_failure = returncode != 0 and run_id is None
            status = (
                "COMPLETED" if returncode == 0
                else "PENDING" if infrastructure_failure
                else "FAILED"
            )
            error = None if status == "COMPLETED" else (
                stderr[-4000:] or stdout[-4000:]
            )
            self.connection.execute(
                """
                UPDATE dataset_campaign_plan
                SET status=?, scenario_run_id=?, ended_at=?, error=?
                WHERE campaign_id=? AND sequence_index=?
                """,
                (status, run_id, utc_now(), error, self.args.campaign_id, index),
            )
            self.connection.commit()
            if infrastructure_failure:
                infrastructure_paused = True
                print(
                    "Campaign paused without consuming the run because the "
                    "scenario did not start.",
                    file=sys.stderr,
                )
                self.ensure_telemetry()
                break
            if status == "FAILED":
                failures += 1
                self.restore_all()
                if failures > self.args.max_failures:
                    break
            elif item["scenario"] == "progressive-congestion":
                # This Dynamips build can suffer a delayed PA-FE/tap wedge
                # after staged netem recovery even when the immediate ping
                # gate passes. Recreate the access plane between runs and
                # record it as collection provenance.
                self.restore_all()
                self.repair_access_plane(
                    "scheduled post-progressive Dynamips access-plane refresh"
                )
                self.restore_all()
                self.wait_for_convergence()
            time.sleep(self.args.cooldown_seconds)
        counts = dict(
            self.connection.execute(
                """
                SELECT SUM(status='COMPLETED') completed, SUM(status='FAILED') failed,
                       SUM(status='PENDING') pending
                FROM dataset_campaign_plan WHERE campaign_id=?
                """,
                (self.args.campaign_id,),
            ).fetchone()
        )
        final = "PAUSED" if infrastructure_paused else (
            "COMPLETED" if not counts["pending"] and not counts["failed"] else (
            "PARTIAL" if counts["completed"] else "FAILED"
            )
        )
        self.connection.execute(
            """
            UPDATE dataset_campaigns SET updated_at=?,status=?,
              completed_runs=?,failed_runs=? WHERE campaign_id=?
            """,
            (
                utc_now(), final, counts["completed"] or 0, counts["failed"] or 0,
                self.args.campaign_id,
            ),
        )
        self.connection.commit()
        self.restore_all()
        print(json.dumps({"campaign_id": self.args.campaign_id, **counts}, indent=2))
        return 0 if final == "COMPLETED" else 2


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--campaign-id",
        default=datetime.now().strftime("copilot-%Y%m%d-%H%M%S"),
    )
    parser.add_argument("--seed", type=int, default=20260701)
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument(
        "--scenarios",
        nargs="+",
        default=[
            "jitter", "loss-burst", "progressive-congestion", "mpls-outage",
            "internet-outage", "core-failure", "bgp-flap", "policy-drift",
        ],
    )
    parser.add_argument(
        "--severities", nargs="+", default=["light", "moderate", "severe"]
    )
    parser.add_argument(
        "--traffic-profiles", default="ping,bulk,business,voice,mixed"
    )
    parser.add_argument("--baseline-seconds", type=float, default=120)
    parser.add_argument("--fault-seconds", type=float, default=120)
    parser.add_argument("--recovery-seconds", type=float, default=90)
    parser.add_argument("--stage-seconds", type=float, default=60)
    parser.add_argument("--window-seconds", type=float, default=30)
    parser.add_argument("--stride-seconds", type=float, default=10)
    parser.add_argument("--cooldown-seconds", type=float, default=20)
    parser.add_argument("--run-timeout", type=float, default=600)
    parser.add_argument("--max-failures", type=int, default=2)
    parser.add_argument("--expected-poll-interval", type=float, default=5)
    parser.add_argument("--telemetry-max-age", type=float, default=45)
    parser.add_argument("--telemetry-bind", default="192.168.58.1")
    parser.add_argument("--convergence-timeout", type=float, default=90)
    parser.add_argument("--convergence-check-interval", type=float, default=10)
    parser.add_argument("--stable-samples", type=int, default=2)
    parser.add_argument("--repair-boot-seconds", type=float, default=75)
    parser.add_argument("--eve-url", default="http://192.168.58.128")
    parser.add_argument("--eve-username", default="admin")
    parser.add_argument("--eve-path", default="/RS")
    parser.add_argument("--lab-name", default="Air-Gapped Predictive Copilot")
    parser.add_argument(
        "--database", type=Path, default=ROOT / "outputs" / "telemetry.db"
    )
    parser.add_argument(
        "--status-file",
        type=Path,
        default=ROOT / "outputs" / "telemetry-status.json",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not os.environ.get("EVE_PASSWORD"):
        print("ERROR: set EVE_PASSWORD before starting a campaign", file=sys.stderr)
        return 2
    campaign = Campaign(args)
    try:
        return campaign.run()
    finally:
        try:
            campaign.restore_all()
        except BaseException as exc:
            print(f"WARNING: final restoration failed: {exc}", file=sys.stderr)
        campaign.connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
