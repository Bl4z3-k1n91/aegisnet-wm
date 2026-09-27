#!/usr/bin/env python3
"""Run labelled, reversible EVE fault scenarios and extract feature windows."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import threading
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import psutil


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "telemetry"))

from audit_lab import ios_local_secret, load_dotenv  # noqa: E402
from deploy_eve import EveClient, api_lab_path  # noqa: E402
from fault_injector import (  # noqa: E402
    ROUTER_ACTIONS,
    connect_router,
    run_netem,
    run_router_commands,
)
from ios_telemetry import IosSession  # noqa: E402
from push_configs import TelnetConsole, console_target  # noqa: E402
from scenario_store import ScenarioStore  # noqa: E402


SCENARIOS = {
    "jitter": "MPLS_JITTER",
    "loss-burst": "MPLS_PACKET_LOSS",
    "mpls-outage": "MPLS_OUTAGE",
    "internet-outage": "INTERNET_OUTAGE",
    "core-failure": "CORE_PATH_FAILURE",
    "policy-drift": "POLICY_DRIFT",
    "bgp-flap": "BGP_FLAP",
    "progressive-congestion": "MPLS_CONGESTION",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def wait_phase(seconds: float, stop_event: threading.Event | None = None) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        if stop_event and stop_event.wait(min(1.0, remaining)):
            return
        if not stop_event:
            time.sleep(min(1.0, remaining))


class ContinuousTraffic:
    def __init__(
        self,
        eve_url: str,
        eve_username: str,
        eve_password: str,
        eve_path: str,
        lab_name: str,
        profile: str,
        source_node: str = "CLIENT-BR1",
        rate_scale: int = 1,
    ) -> None:
        self.eve_url = eve_url
        self.eve_username = eve_username
        self.eve_password = eve_password
        self.eve_path = eve_path
        self.lab_name = lab_name
        self.profile = profile
        self.source_node = source_node
        self.rate_scale = max(1, min(int(rate_scale), 32))
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None
        self.error: str | None = None

    def start(self) -> None:
        self.thread = threading.Thread(
            target=self._run, name="scenario-traffic", daemon=True
        )
        self.thread.start()

    def _run(self) -> None:
        console: TelnetConsole | None = None
        try:
            client = EveClient(self.eve_url)
            client.login(
                self.eve_username, self.eve_password, native_console=True
            )
            endpoint = api_lab_path(self.eve_path, self.lab_name)
            response = client.request("GET", f"/labs{endpoint}/nodes")
            key, node = next(
                (key, node)
                for key, node in response["data"].items()  # type: ignore[index,union-attr]
                if node["name"] == self.source_node
            )
            eve_host = urllib.parse.urlparse(self.eve_url).hostname or "127.0.0.1"
            host, port = console_target({**node, "id": int(key)}, eve_host)
            console = TelnetConsole(host, port)
            console.send("\r")
            time.sleep(0.3)
            output = console.read_available(0.7)
            if "login:" in output:
                console.send("gns3\r")
                time.sleep(0.3)
                console.read_available(0.4)
                console.send("gns3\r")
                time.sleep(0.4)
                console.read_available(0.5)
            console.send(
                "ping 10.20.10.10 >/tmp/copilot-ping.log 2>&1 & "
                "echo $! >/tmp/copilot-ping.pid\r"
            )
            console.send(
                "sudo iptables -t mangle -D OUTPUT -p udp --dport 5202 "
                "-j DSCP --set-dscp 26 2>/dev/null || true; "
                "sudo iptables -t mangle -D OUTPUT -p udp --dport 5203 "
                "-j DSCP --set-dscp 46 2>/dev/null || true; "
                "sudo iptables -t mangle -A OUTPUT -p udp --dport 5202 "
                "-j DSCP --set-dscp 26; "
                "sudo iptables -t mangle -A OUTPUT -p udp --dport 5203 "
                "-j DSCP --set-dscp 46\r"
            )
            if self.profile in {"bulk", "mixed"}:
                bulk_count = 4 * self.rate_scale
                console.send(
                    f"(while true; do dd if=/dev/zero bs=1024 count={bulk_count} "
                    "2>/dev/null | nc -u -w 1 10.20.10.10 5201; sleep 1; "
                    "done) >/tmp/copilot-bulk.log 2>&1 & "
                    "echo $! >/tmp/copilot-bulk.pid\r"
                )
            if self.profile in {"business", "mixed"}:
                business_count = 2 * self.rate_scale
                console.send(
                    f"(while true; do dd if=/dev/zero bs=1024 count={business_count} "
                    "2>/dev/null | nc -u -w 1 10.20.10.10 5202; sleep 1; "
                    "done) >/tmp/copilot-business.log 2>&1 & "
                    "echo $! >/tmp/copilot-business.pid\r"
                )
            if self.profile in {"voice", "mixed"}:
                voice_count = 1 * self.rate_scale
                console.send(
                    f"(while true; do dd if=/dev/zero bs=1024 count={voice_count} "
                    "2>/dev/null | nc -u -w 1 10.20.10.10 5203; sleep 1; "
                    "done) >/tmp/copilot-voice.log 2>&1 & "
                    "echo $! >/tmp/copilot-voice.pid\r"
                )
            while not self.stop_event.wait(0.5):
                console.read_available(0.2)
            console.send(
                "for f in /tmp/copilot-*.pid; do "
                "test -f $f && kill $(cat $f) 2>/dev/null || true; done; "
                "pkill nc 2>/dev/null || true; pkill ping 2>/dev/null || true\r"
            )
            console.send(
                "sudo iptables -t mangle -D OUTPUT -p udp --dport 5202 "
                "-j DSCP --set-dscp 26 2>/dev/null || true; "
                "sudo iptables -t mangle -D OUTPUT -p udp --dport 5203 "
                "-j DSCP --set-dscp 46 2>/dev/null || true\r"
            )
            time.sleep(0.3)
            console.read_available(0.5)
        except BaseException as exc:
            self.error = f"{type(exc).__name__}: {exc}"
        finally:
            if console:
                console.close()

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=5)


class FaultController:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.eve_host = urllib.parse.urlparse(args.eve_url).hostname or "127.0.0.1"
        self.endpoint = api_lab_path(args.eve_path, args.lab_name)
        self.restore_action: Callable[[], None] | None = None
        self.flap_stop: threading.Event | None = None
        self.flap_thread: threading.Thread | None = None

    def client(self) -> EveClient:
        client = EveClient(self.args.eve_url)
        client.login(
            self.args.eve_username,
            self.args.eve_password,
            native_console=True,
        )
        return client

    def _router(self, definition: dict[str, object], restore: bool = False) -> None:
        client = self.client()
        console = connect_router(
            client,
            self.endpoint,
            str(definition["node"]),
            self.eve_host,
        )
        try:
            run_router_commands(
                console,
                definition["restore" if restore else "inject"],  # type: ignore[arg-type]
            )
        finally:
            console.close()

    def _netem(self, target: str, profile: str) -> None:
        run_netem(
            self.client(),
            self.endpoint,
            self.eve_host,
            target,
            profile,
        )

    def apply(self, scenario: str) -> None:
        if scenario == "jitter":
            self._netem("mpls", f"jitter-{self.args.severity}")
            self.restore_action = lambda: self._netem("mpls", "baseline")
        elif scenario == "loss-burst":
            self._netem("mpls", f"loss-burst-{self.args.severity}")
            self.restore_action = lambda: self._netem("mpls", "baseline")
        elif scenario == "internet-outage":
            self._netem("inet", "down")
            self.restore_action = lambda: self._netem("inet", "baseline")
        elif scenario == "mpls-outage":
            definition = {
                "node": "BR1",
                "inject": ROUTER_ACTIONS["br1-mpls-down"]["inject"],
                "restore": ROUTER_ACTIONS["br1-mpls-down"]["restore"],
            }
            self._router(definition)
            self.restore_action = lambda: self._router(definition, True)
        elif scenario in {"core-failure", "policy-drift"}:
            definition = ROUTER_ACTIONS[scenario]
            self._router(definition)
            self.restore_action = lambda: self._router(definition, True)
        elif scenario == "bgp-flap":
            self.flap_stop = threading.Event()
            self.flap_thread = threading.Thread(
                target=self._flap_loop, name="bgp-flap", daemon=True
            )
            self.flap_thread.start()
            self.restore_action = self._stop_flap
        else:
            raise ValueError(f"unsupported static scenario: {scenario}")

    def _flap_loop(self) -> None:
        assert self.flap_stop is not None
        client = self.client()
        console = connect_router(client, self.endpoint, "BR2", self.eve_host)
        try:
            while not self.flap_stop.is_set():
                run_router_commands(
                    console,
                    [
                        "configure terminal",
                        "router bgp 65102",
                        "neighbor 10.100.12.1 shutdown",
                        "end",
                    ],
                )
                if self.flap_stop.wait(self.args.flap_hold):
                    break
                run_router_commands(
                    console,
                    [
                        "configure terminal",
                        "router bgp 65102",
                        "no neighbor 10.100.12.1 shutdown",
                        "end",
                    ],
                )
                self.flap_stop.wait(self.args.flap_hold)
        finally:
            try:
                run_router_commands(
                    console,
                    [
                        "configure terminal",
                        "router bgp 65102",
                        "no neighbor 10.100.12.1 shutdown",
                        "end",
                    ],
                )
            finally:
                console.close()

    def _stop_flap(self) -> None:
        if self.flap_stop:
            self.flap_stop.set()
        if self.flap_thread:
            self.flap_thread.join(timeout=15)

    def progressive(self, profile: str) -> None:
        self._netem("mpls", profile)
        self.restore_action = lambda: self._netem("mpls", "baseline")

    def restore(self) -> None:
        if self.restore_action:
            action, self.restore_action = self.restore_action, None
            action()


def require_telemetry(status_file: Path) -> dict[str, object]:
    if not status_file.is_file():
        raise RuntimeError("telemetry status file is missing; start the service")
    status = json.loads(status_file.read_text(encoding="utf-8"))
    pid = int(status.get("pid", 0))
    if not psutil.pid_exists(pid):
        raise RuntimeError(f"telemetry PID {pid} is not running")
    updated = datetime.fromisoformat(str(status["updated_at"]))
    age = (datetime.now(timezone.utc) - updated).total_seconds()
    if age > 45:
        raise RuntimeError(f"telemetry heartbeat is stale ({age:.0f}s)")
    if status.get("fatal_errors"):
        raise RuntimeError(f"telemetry fatal errors: {status['fatal_errors']}")
    return status


def marker(
    address: str,
    username: str,
    password: str,
    run_id: int,
    phase: str,
    label: str,
) -> None:
    text = f"SCENARIO run={run_id} phase={phase} label={label}"
    try:
        with IosSession(address, username, password) as session:
            session.run(f"send log 6 {text}")
    except BaseException:
        pass


def run_phase(
    store: ScenarioStore,
    run_id: int,
    name: str,
    label: str,
    seconds: float,
    args: argparse.Namespace,
    details: dict[str, object] | None = None,
) -> None:
    phase_id = store.start_phase(run_id, name, label, details)
    marker(
        args.marker_address,
        args.ssh_username,
        args.ssh_password,
        run_id,
        name,
        label,
    )
    print(f"[{name}] {label} for {seconds:.0f}s")
    try:
        wait_phase(seconds)
    finally:
        store.end_phase(phase_id)


def validate_recovery(args: argparse.Namespace) -> None:
    with IosSession(
        args.marker_address, args.ssh_username, args.ssh_password
    ) as session:
        dmvpn = session.run("show dmvpn")
        ike = session.run("show crypto ikev2 sa")
        ping = session.run(
            "ping 10.20.10.10 source 10.1.10.1 repeat 5", timeout=20
        )
    if dmvpn.count(" UP ") < 2:
        raise RuntimeError("BR1 DMVPN did not recover")
    if ike.count("READY") < 2:
        raise RuntimeError("BR1 IKEv2 did not recover")
    if "Success rate is 100 percent" not in ping:
        raise RuntimeError("BR1-to-DC recovery ping failed")


def run_experiment(args: argparse.Namespace) -> int:
    require_telemetry(args.status_file)
    store = ScenarioStore(args.database)
    parameters = {
        "baseline_seconds": args.baseline_seconds,
        "fault_seconds": args.fault_seconds,
        "recovery_seconds": args.recovery_seconds,
        "stage_seconds": args.stage_seconds,
        "severity": args.severity,
        "campaign_id": args.campaign_id,
        "run_seed": args.run_seed,
        "sequence_index": args.sequence_index,
        "split": args.split,
        "traffic_profile": args.traffic_profile,
        "traffic_generator": "paced-udp-microflow-v2",
    }
    run_id = store.start_run(
        args.scenario,
        parameters,
        campaign_id=args.campaign_id,
        run_seed=args.run_seed,
        sequence_index=args.sequence_index,
        split=args.split,
        severity=args.severity,
    )
    traffic = ContinuousTraffic(
        args.eve_url,
        args.eve_username,
        args.eve_password,
        args.eve_path,
        args.lab_name,
        args.traffic_profile,
    )
    controller = FaultController(args)
    traffic.start()
    error: str | None = None
    try:
        run_phase(
            store,
            run_id,
            "baseline",
            "BASELINE",
            args.baseline_seconds,
            args,
        )
        if args.scenario == "progressive-congestion":
            for index, profile in enumerate(
                ("congestion-1", "congestion-2", "congestion-3"), start=1
            ):
                controller.progressive(profile)
                run_phase(
                    store,
                    run_id,
                    f"fault-{index}",
                    f"MPLS_CONGESTION_{index}",
                    args.stage_seconds,
                    args,
                    {"profile": profile},
                )
        else:
            controller.apply(args.scenario)
            run_phase(
                store,
                run_id,
                "fault",
                SCENARIOS[args.scenario],
                args.fault_seconds,
                args,
            )
        controller.restore()
        run_phase(
            store,
            run_id,
            "recovery",
            "RECOVERY",
            args.recovery_seconds,
            args,
        )
        validate_recovery(args)
        store.finish_run(run_id, "COMPLETED")
    except BaseException as exc:
        error = f"{type(exc).__name__}: {exc}"
        store.finish_run(run_id, "FAILED", error)
    finally:
        try:
            controller.restore()
        except BaseException as restore_exc:
            restore_error = f"{type(restore_exc).__name__}: {restore_exc}"
            error = f"{error}; restore={restore_error}" if error else restore_error
            store.finish_run(run_id, "FAILED", error)
        traffic.stop()
        rows = store.extract_features(run_id)
        rich_rows = store.extract_rich_features(
            run_id,
            window_seconds=args.window_seconds,
            stride_seconds=args.stride_seconds,
        )
        store.close()
    print(
        f"run_id={run_id} feature_rows={rows} "
        f"rich_device_rows={rich_rows['device']} rich_sla_rows={rich_rows['sla']} "
        f"rich_qos_rows={rich_rows['qos']}"
    )
    if traffic.error:
        print(f"traffic warning: {traffic.error}", file=sys.stderr)
    if error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    print("Scenario completed and recovery verified.")
    return 0


def parse_args() -> argparse.Namespace:
    load_dotenv(ROOT / ".env")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=sorted(SCENARIOS))
    parser.add_argument("--eve-url", default="http://192.168.58.128")
    parser.add_argument("--eve-username", default="admin")
    parser.add_argument("--eve-password", default=os.environ.get("EVE_PASSWORD"))
    parser.add_argument("--eve-path", default="/RS")
    parser.add_argument("--lab-name", default="Air-Gapped Predictive Copilot")
    parser.add_argument("--ssh-username", default="noc")
    parser.add_argument(
        "--ssh-password", default=os.environ.get("LAB_ADMIN_SECRET")
    )
    parser.add_argument("--marker-address", default="192.168.58.15")
    parser.add_argument("--baseline-seconds", type=float, default=30)
    parser.add_argument("--fault-seconds", type=float, default=60)
    parser.add_argument("--recovery-seconds", type=float, default=45)
    parser.add_argument("--stage-seconds", type=float, default=45)
    parser.add_argument("--flap-hold", type=float, default=5)
    parser.add_argument(
        "--severity",
        choices=("light", "moderate", "severe"),
        default="moderate",
    )
    parser.add_argument("--campaign-id")
    parser.add_argument("--run-seed", type=int)
    parser.add_argument("--sequence-index", type=int)
    parser.add_argument(
        "--split", choices=("train", "validation", "test"), default="train"
    )
    parser.add_argument("--window-seconds", type=float, default=30)
    parser.add_argument("--stride-seconds", type=float, default=10)
    parser.add_argument(
        "--traffic-profile",
        choices=("ping", "bulk", "business", "voice", "mixed"),
        default="mixed",
    )
    parser.add_argument(
        "--database", type=Path, default=ROOT / "outputs" / "telemetry.db"
    )
    parser.add_argument(
        "--status-file",
        type=Path,
        default=ROOT / "outputs" / "telemetry-status.json",
    )
    args = parser.parse_args()
    if not args.eve_password:
        args.eve_password = getpass.getpass("EVE API password: ")
    if not args.ssh_password:
        parser.error("LAB_ADMIN_SECRET is missing")
    args.ssh_password = ios_local_secret(args.ssh_password)
    return args


def main() -> int:
    return run_experiment(parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
