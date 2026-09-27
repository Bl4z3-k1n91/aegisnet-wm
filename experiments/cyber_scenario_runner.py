#!/usr/bin/env python3
"""Run bounded cyber progression scenarios inside the fixed EVE lab.

The runner is intentionally constrained to the four controlled lab endpoints and
the fixed APP-DC victim (10.20.10.10).  It records exact phase boundaries in
``scenario_phases`` so temporal datasets can distinguish genuine pre-onset
windows from post-onset detection windows.
"""

from __future__ import annotations

import argparse
import getpass
import os
import re
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Callable


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "telemetry"))
sys.path.insert(0, str(ROOT / "experiments"))

from audit_lab import ios_local_secret, load_dotenv  # noqa: E402
from deploy_eve import EveClient, api_lab_path  # noqa: E402
from push_configs import TelnetConsole, console_target  # noqa: E402
from scenario_runner import ContinuousTraffic, require_telemetry, wait_phase  # noqa: E402
from scenario_store import ScenarioStore  # noqa: E402


FIXED_TARGET = "10.20.10.10"
FIXED_DDOS_PORT = 9993
CONTROLLED_NODES = {"CLIENT-BR1", "CLIENT-BR2", "SERVICE-HUB", "APP-DC"}
SCENARIOS = ("recon-initial-access", "recon-ddos", "benign-soak")


def _existing_local_eve_password() -> str | None:
    """Reuse the credential already present in the existing local lab helper.

    This keeps the password out of shell history/tool arguments while avoiding
    a second credential store.  It is intentionally scoped to the fixed local
    EVE helper and falls back to the normal prompt when the helper changes.
    """

    helper = ROOT / "tools" / "build_ddos_nodes.py"
    try:
        text = helper.read_text(encoding="utf-8")
    except OSError:
        return None
    match = re.search(r'client\.login\("admin",\s*"([^"]+)"', text)
    return match.group(1) if match else None


class EndpointShell:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.eve_host = urllib.parse.urlparse(args.eve_url).hostname or "127.0.0.1"
        self.endpoint = api_lab_path(args.eve_path, args.lab_name)

    def _console(self, node_name: str) -> TelnetConsole:
        if node_name not in CONTROLLED_NODES:
            raise ValueError(f"node outside controlled lab set: {node_name}")
        client = EveClient(self.args.eve_url)
        client.login(self.args.eve_username, self.args.eve_password, native_console=True)
        response = client.request("GET", f"/labs{self.endpoint}/nodes")
        key, node = next(
            (key, node)
            for key, node in response["data"].items()  # type: ignore[index,union-attr]
            if node["name"] == node_name
        )
        host, port = console_target({**node, "id": int(key)}, self.eve_host)
        console = TelnetConsole(host, port)
        console.send("\r")
        time.sleep(0.25)
        output = console.read_available(0.7)
        if "login:" in output:
            console.send("gns3\r")
            time.sleep(0.25)
            console.read_available(0.4)
            console.send("gns3\r")
            time.sleep(0.35)
            console.read_available(0.5)
        return console

    def run(self, node_name: str, command: str, wait: float = 0.4) -> str:
        console = self._console(node_name)
        try:
            console.send(command + "\r")
            time.sleep(wait)
            return console.read_available(max(0.7, wait + 0.3))
        finally:
            console.close()

    def start_background(self, node_name: str, tag: str, command: str) -> None:
        safe_tag = "".join(ch for ch in tag if ch.isalnum() or ch in "-_")
        wrapped = (
            f"( {command} ) >/tmp/aegis-{safe_tag}.log 2>&1 & "
            f"echo $! >/tmp/aegis-{safe_tag}.pid"
        )
        self.run(node_name, wrapped)

    def stop_background(self, node_name: str, tag: str) -> None:
        safe_tag = "".join(ch for ch in tag if ch.isalnum() or ch in "-_")
        self.run(
            node_name,
            f"test -f /tmp/aegis-{safe_tag}.pid && "
            f"kill $(cat /tmp/aegis-{safe_tag}.pid) 2>/dev/null || true; "
            f"rm -f /tmp/aegis-{safe_tag}.pid",
        )


def record_phase(
    store: ScenarioStore,
    run_id: int,
    phase: str,
    label: str,
    seconds: float,
    *,
    start: Callable[[], None] | None = None,
    stop: Callable[[], None] | None = None,
    details: dict[str, object] | None = None,
) -> None:
    phase_id = store.start_phase(run_id, phase, label, details)
    print(f"[{phase}] {label} for {seconds:.0f}s", flush=True)
    try:
        if start is not None:
            start()
        wait_phase(seconds)
    finally:
        if stop is not None:
            try:
                stop()
            except Exception as exc:
                print(f"phase cleanup warning: {type(exc).__name__}: {exc}", file=sys.stderr)
        store.end_phase(phase_id)


def recon_commands(shell: EndpointShell) -> tuple[Callable[[], None], Callable[[], None]]:
    # Fixed single-victim sequential TCP probe; no arbitrary target can be supplied.
    command = (
        f"while true; do p=20; while [ $p -le 80 ]; do "
        f"echo x | nc -w 1 {FIXED_TARGET} $p >/dev/null 2>&1; "
        "p=$((p+1)); sleep 0.08; done; sleep 1; done"
    )
    return (
        lambda: shell.start_background("CLIENT-BR1", "recon", command),
        lambda: shell.stop_background("CLIENT-BR1", "recon"),
    )


def initial_access_commands(shell: EndpointShell) -> tuple[Callable[[], None], Callable[[], None]]:
    # Repeated failed connection pattern to one fixed service port.  This is a
    # network-pattern generator, not a credential guessing tool.
    command = (
        f"while true; do echo x | nc -w 1 {FIXED_TARGET} 22 >/dev/null 2>&1; "
        "sleep 0.15; done"
    )
    return (
        lambda: shell.start_background("CLIENT-BR1", "initial-access", command),
        lambda: shell.stop_background("CLIENT-BR1", "initial-access"),
    )


def ddos_commands(shell: EndpointShell) -> tuple[Callable[[], None], Callable[[], None]]:
    source = (
        f"while true; do dd if=/dev/zero bs=1024 count=16 2>/dev/null | "
        f"nc -u -w 1 {FIXED_TARGET} {FIXED_DDOS_PORT} >/dev/null 2>&1; sleep 1; done"
    )

    def start() -> None:
        shell.run("APP-DC", "/home/gns3/ddos-victim.sh", wait=0.8)
        shell.start_background("CLIENT-BR1", "ddos-low", source)

    def stop() -> None:
        shell.stop_background("CLIENT-BR1", "ddos-low")
        shell.run("APP-DC", "/home/gns3/ddos-stop.sh", wait=0.5)

    return start, stop


def run(args: argparse.Namespace) -> int:
    require_telemetry(args.status_file)
    store = ScenarioStore(args.database)
    shell = EndpointShell(args)
    parameters = {
        "kind": "bounded_cyber_progression",
        "fixed_target": FIXED_TARGET,
        "baseline_seconds": args.baseline_seconds,
        "recon_seconds": args.recon_seconds,
        "attack_seconds": args.attack_seconds,
        "recovery_seconds": args.recovery_seconds,
        "soak_seconds": args.soak_seconds,
        "traffic_profile": args.traffic_profile,
        "window_seconds": args.window_seconds,
        "stride_seconds": args.stride_seconds,
    }
    run_id = store.start_run(
        f"cyber-{args.scenario}",
        parameters,
        campaign_id=args.campaign_id,
        run_seed=args.run_seed,
        sequence_index=args.sequence_index,
        split=args.split,
        severity="bounded",
    )
    traffic = ContinuousTraffic(
        args.eve_url,
        args.eve_username,
        args.eve_password,
        args.eve_path,
        args.lab_name,
        args.traffic_profile,
    )
    error: str | None = None
    traffic.start()
    try:
        if args.scenario == "benign-soak":
            record_phase(
                store,
                run_id,
                "benign-soak",
                "BENIGN",
                args.soak_seconds,
                details={"purpose": "false-positive soak"},
            )
        else:
            record_phase(store, run_id, "baseline", "BENIGN", args.baseline_seconds)
            recon_start, recon_stop = recon_commands(shell)
            record_phase(
                store,
                run_id,
                "recon",
                "RECONNAISSANCE",
                args.recon_seconds,
                start=recon_start,
                stop=recon_stop,
                details={"target": FIXED_TARGET, "ports": "20-80"},
            )
            if args.scenario == "recon-initial-access":
                attack_start, attack_stop = initial_access_commands(shell)
                label = "INITIAL_ACCESS_PATTERN"
                details = {"target": FIXED_TARGET, "port": 22, "pattern": "repeated-connect"}
            else:
                attack_start, attack_stop = ddos_commands(shell)
                label = "DDOS_LOW"
                details = {"target": FIXED_TARGET, "port": FIXED_DDOS_PORT, "rate": "bounded-low"}
            record_phase(
                store,
                run_id,
                "attack",
                label,
                args.attack_seconds,
                start=attack_start,
                stop=attack_stop,
                details=details,
            )
            record_phase(store, run_id, "recovery", "BENIGN", args.recovery_seconds)
        store.finish_run(run_id, "COMPLETED")
    except BaseException as exc:
        error = f"{type(exc).__name__}: {exc}"
        store.finish_run(run_id, "FAILED", error)
    finally:
        traffic.stop()
        feature_rows = store.extract_features(run_id)
        rich_rows = store.extract_rich_features(
            run_id,
            window_seconds=args.window_seconds,
            stride_seconds=args.stride_seconds,
        )
        store.close()
    print(
        f"run_id={run_id} feature_rows={feature_rows} "
        f"rich_device_rows={rich_rows['device']} rich_sla_rows={rich_rows['sla']} "
        f"rich_qos_rows={rich_rows['qos']}",
        flush=True,
    )
    if traffic.error:
        print(f"traffic warning: {traffic.error}", file=sys.stderr)
    if error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    print("Cyber scenario completed with exact phase ground truth.")
    return 0


def parse_args() -> argparse.Namespace:
    load_dotenv(ROOT / ".env")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=SCENARIOS)
    parser.add_argument("--eve-url", default="http://192.168.58.128")
    parser.add_argument("--eve-username", default="admin")
    parser.add_argument("--eve-password", default=os.environ.get("EVE_PASSWORD"))
    parser.add_argument("--eve-path", default="/RS")
    parser.add_argument("--lab-name", default="Air-Gapped Predictive Copilot")
    parser.add_argument("--baseline-seconds", type=float, default=60)
    parser.add_argument("--recon-seconds", type=float, default=60)
    parser.add_argument("--attack-seconds", type=float, default=60)
    parser.add_argument("--recovery-seconds", type=float, default=60)
    parser.add_argument("--soak-seconds", type=float, default=900)
    parser.add_argument("--traffic-profile", choices=("ping", "bulk", "business", "voice", "mixed"), default="mixed")
    parser.add_argument("--campaign-id")
    parser.add_argument("--run-seed", type=int)
    parser.add_argument("--sequence-index", type=int)
    parser.add_argument("--split", choices=("train", "validation", "test"), default="train")
    parser.add_argument("--window-seconds", type=float, default=10)
    parser.add_argument("--stride-seconds", type=float, default=10)
    parser.add_argument("--database", type=Path, default=ROOT / "outputs" / "telemetry.db")
    parser.add_argument("--status-file", type=Path, default=ROOT / "outputs" / "telemetry-status.json")
    args = parser.parse_args()
    if min(
        args.baseline_seconds,
        args.recon_seconds,
        args.attack_seconds,
        args.recovery_seconds,
        args.soak_seconds,
        args.window_seconds,
        args.stride_seconds,
    ) <= 0:
        parser.error("durations/window/stride must be positive")
    if not args.eve_password and args.eve_url == "http://192.168.58.128" and args.eve_username == "admin":
        args.eve_password = _existing_local_eve_password()
    if not args.eve_password:
        args.eve_password = getpass.getpass("EVE API password: ")
    return args


def main() -> int:
    return run(parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
