#!/usr/bin/env python3
"""Inject and restore deterministic EVE-NG network fault scenarios."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
import time
import urllib.parse

from deploy_eve import EveClient, EveError, api_lab_path
from push_configs import ERROR_MARKERS, TelnetConsole, console_target


ROUTER_ACTIONS = {
    "core-failure": {
        "node": "P1",
        "inject": ["configure terminal", "interface FastEthernet2/0", "shutdown", "end"],
        "restore": ["configure terminal", "interface FastEthernet2/0", "no shutdown", "end"],
    },
    "br1-mpls-down": {
        "node": "BR1",
        "inject": ["configure terminal", "interface FastEthernet1/0", "shutdown", "end"],
        "restore": ["configure terminal", "interface FastEthernet1/0", "no shutdown", "end"],
    },
    "policy-drift": {
        "node": "HUB",
        "inject": [
            "configure terminal",
            "policy-map WAN-SHAPER",
            "class class-default",
            "shape average 750000",
            "end",
        ],
        "restore": [
            "configure terminal",
            "policy-map WAN-SHAPER",
            "class class-default",
            "shape average 5000000",
            "end",
        ],
    },
}

NETEM_NODES = {"mpls": "NETEM-BR1-MPLS", "inet": "NETEM-BR1-INET"}
NETEM_PROFILES = {
    "baseline": None,
    "congestion-1": ("4mbit", "10ms", "2ms", "0.1%"),
    "congestion-2": ("2mbit", "25ms", "5ms", "0.5%"),
    # Dynamips 7200 PA-FE adapters can wedge under the old 1 Mbit/2% profile.
    # This remains a distinct severe precursor without exhausting the emulated
    # adapter queues.
    "congestion-3": ("1500kbit", "45ms", "10ms", "1%"),
    "jitter": ("5mbit", "35ms", "25ms", "0.5%"),
    "jitter-light": ("8mbit", "12ms", "6ms", "0.1%"),
    "jitter-moderate": ("5mbit", "35ms", "25ms", "0.5%"),
    "jitter-severe": ("2mbit", "80ms", "50ms", "2%"),
    "loss-burst": ("5mbit", "10ms", "2ms", "10%"),
    "loss-burst-light": ("8mbit", "5ms", "1ms", "0.5%"),
    "loss-burst-moderate": ("5mbit", "10ms", "2ms", "3%"),
    "loss-burst-severe": ("2mbit", "25ms", "8ms", "10%"),
}


def lab_nodes(client: EveClient, lab_endpoint: str) -> dict[str, dict[str, object]]:
    response = client.request("GET", f"/labs{lab_endpoint}/nodes")
    return {
        value["name"]: {**value, "id": int(key)}
        for key, value in response["data"].items()  # type: ignore[index,union-attr]
    }


def connect_router(
    client: EveClient,
    lab_endpoint: str,
    node_name: str,
    eve_host: str,
) -> TelnetConsole:
    nodes = lab_nodes(client, lab_endpoint)
    if node_name not in nodes:
        raise EveError(f"node {node_name!r} not found in EVE lab")
    host, port = console_target(nodes[node_name], eve_host)
    console = TelnetConsole(host, port)
    prompt = console.initialize_ios()
    if prompt.rstrip().endswith(">"):
        console.command("enable", 0.3)
    return console


def run_router_commands(console: TelnetConsole, commands: list[str]) -> None:
    for command in commands:
        output = console.command(command, 0.25)
        if any(marker in output for marker in ERROR_MARKERS):
            raise EveError(f"IOS rejected {command!r}: {' '.join(output.split())}")


def connect_netem(
    client: EveClient,
    lab_endpoint: str,
    target: str,
    eve_host: str,
) -> TelnetConsole:
    node_name = NETEM_NODES[target]
    nodes = lab_nodes(client, lab_endpoint)
    if node_name not in nodes:
        raise EveError(f"node {node_name!r} not found in EVE lab")
    host, port = console_target(nodes[node_name], eve_host)
    console = TelnetConsole(host, port)
    transcript = ""
    console.send("\r")
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        transcript += console.read_available(0.5)
        lower = transcript.lower()
        if "netem configuration" in lower:
            # The stock appliance auto-launches its dialog UI. Ctrl-C returns
            # to the already-authenticated TinyCore shell.
            console.send("\x03")
            transcript = ""
        elif "login:" in lower:
            console.send("gns3\r")
            transcript = ""
        elif "password:" in lower:
            console.send("gns3\r")
            transcript = ""
        elif transcript.rstrip().endswith(("$", "#")):
            return console
        else:
            console.send("\r")
    console.close()
    raise EveError(f"{node_name} console did not reach a shell prompt")


def run_netem(
    client: EveClient,
    lab_endpoint: str,
    eve_host: str,
    target: str,
    profile: str,
) -> None:
    console = connect_netem(client, lab_endpoint, target, eve_host)
    try:
        prefix = (
            "sudo sh -c 'for d in eth0 eth1; do "
            "ip link set $d up; tc qdisc del dev $d root 2>/dev/null || true; done"
        )
        if profile == "down":
            shell = prefix + "; for d in eth0 eth1; do ip link set $d down; done'"
        else:
            values = NETEM_PROFILES[profile]
            if values is None:
                shell = prefix + "'"
            else:
                rate, delay, jitter, loss = values
                shell = (
                    prefix
                    + f"; for d in eth0 eth1; do tc qdisc add dev $d root netem "
                    f"rate {rate} delay {delay} {jitter} loss {loss}; done'"
                )
        output = console.command(shell, 1.0)
        if "not found" in output.lower() or "operation not permitted" in output.lower():
            raise EveError(f"netem rejected profile {profile!r}: {' '.join(output.split())}")
        print(f"{NETEM_NODES[target]} -> {profile}")
    finally:
        console.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=(
            "bgp-flap",
            "core-failure",
            "br1-mpls-down",
            "policy-drift",
            "policy-restore",
            "restore-all",
            "progressive-congestion",
            "baseline",
            "jitter",
            "loss-burst",
            "inet-down",
        ),
    )
    parser.add_argument("--eve-url", default=os.environ.get("EVE_URL", "http://192.168.58.128"))
    parser.add_argument("--username", default=os.environ.get("EVE_USERNAME", "admin"))
    parser.add_argument("--password", help="Prefer EVE_PASSWORD instead of shell history.")
    parser.add_argument("--eve-path", default="/")
    parser.add_argument("--lab-name", default="Air-Gapped Predictive Copilot")
    parser.add_argument("--pro", action="store_true")
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument("--cycles", type=int, default=3)
    parser.add_argument("--hold", type=int, default=5)
    parser.add_argument("--restore-after", type=int)
    parser.add_argument("--stage-seconds", type=int, default=60)
    args = parser.parse_args()

    try:
        password = args.password or os.environ.get("EVE_PASSWORD")
        if not password:
            password = getpass.getpass("EVE-NG password: ")
        client = EveClient(args.eve_url, insecure=args.insecure)
        client.login(args.username, password, pro=args.pro, native_console=True)
        lab_endpoint = api_lab_path(args.eve_path, args.lab_name)
        eve_host = urllib.parse.urlparse(args.eve_url).hostname or "127.0.0.1"

        if args.action == "restore-all":
            run_netem(client, lab_endpoint, eve_host, "mpls", "baseline")
            run_netem(client, lab_endpoint, eve_host, "inet", "baseline")
            for name in ("core-failure", "br1-mpls-down", "policy-drift"):
                definition = ROUTER_ACTIONS[name]
                console = connect_router(
                    client, lab_endpoint, definition["node"], eve_host
                )
                try:
                    run_router_commands(console, definition["restore"])
                finally:
                    console.close()
            console = connect_router(client, lab_endpoint, "BR2", eve_host)
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
            print("All managed fault points restored.")
            return 0

        if args.action in {"progressive-congestion", "baseline", "jitter", "loss-burst", "inet-down"}:
            if args.action == "progressive-congestion":
                for profile in ("congestion-1", "congestion-2", "congestion-3"):
                    run_netem(client, lab_endpoint, eve_host, "mpls", profile)
                    if profile != "congestion-3":
                        time.sleep(args.stage_seconds)
            elif args.action == "inet-down":
                run_netem(client, lab_endpoint, eve_host, "inet", "down")
            else:
                run_netem(client, lab_endpoint, eve_host, "mpls", args.action)
            return 0

        if args.action == "bgp-flap":
            console = connect_router(client, lab_endpoint, "BR2", eve_host)
            try:
                for cycle in range(1, args.cycles + 1):
                    print(f"BGP flap cycle {cycle}/{args.cycles}: shutting MPLS neighbor")
                    run_router_commands(
                        console,
                        [
                            "configure terminal",
                            "router bgp 65102",
                            "neighbor 10.100.12.1 shutdown",
                            "end",
                        ],
                    )
                    time.sleep(args.hold)
                    run_router_commands(
                        console,
                        [
                            "configure terminal",
                            "router bgp 65102",
                            "no neighbor 10.100.12.1 shutdown",
                            "end",
                        ],
                    )
                    if cycle != args.cycles:
                        time.sleep(args.hold)
            finally:
                console.close()
            return 0

        base_action = "policy-drift" if args.action == "policy-restore" else args.action
        definition = ROUTER_ACTIONS[base_action]
        commands = definition["restore" if args.action == "policy-restore" else "inject"]
        console = connect_router(client, lab_endpoint, definition["node"], eve_host)
        try:
            run_router_commands(console, commands)
            print(f"Applied {args.action} on {definition['node']}")
            if args.restore_after and args.action != "policy-restore":
                time.sleep(args.restore_after)
                run_router_commands(console, definition["restore"])
                print(f"Restored {definition['node']}")
        finally:
            console.close()
        return 0
    except (EveError, OSError, KeyError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
