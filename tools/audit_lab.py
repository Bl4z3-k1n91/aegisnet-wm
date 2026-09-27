#!/usr/bin/env python3
"""Audit EVE lab convergence and verify an SSH-derived IP-to-hostname map."""

from __future__ import annotations

import argparse
import concurrent.futures
import getpass
import ipaddress
import json
import os
import re
import socket
import sys
import time
import urllib.parse
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

import paramiko

from deploy_eve import EveClient, EveError, api_lab_path
from push_configs import TelnetConsole, console_target


ROOT = Path(__file__).resolve().parents[1]
ROUTERS = ("P1", "P2", "PE1", "PE2", "INET", "HUB", "BR1", "BR2", "DC")
PROVIDER = {"P1", "P2", "PE1", "PE2"}
SITES = {"HUB", "BR1", "BR2", "DC"}

EXPECTED_MINIMUMS = {
    "P1": {"ospf_full": 2, "ldp_peers": 2},
    "P2": {"ospf_full": 2, "ldp_peers": 2},
    "PE1": {"ospf_full": 2, "ldp_peers": 2, "bgp_established": 3},
    "PE2": {"ospf_full": 2, "ldp_peers": 2, "bgp_established": 3},
    "INET": {"bgp_established": 4},
    "HUB": {
        "bgp_established": 2,
        "eigrp_neighbors": 6,
        "dmvpn_up": 6,
        "ikev2_ready": 6,
    },
    "BR1": {
        "bgp_established": 2,
        "eigrp_neighbors": 2,
        "dmvpn_up": 2,
        "ikev2_ready": 2,
    },
    "BR2": {
        "bgp_established": 2,
        "eigrp_neighbors": 2,
        "dmvpn_up": 2,
        "ikev2_ready": 2,
    },
    "DC": {
        "bgp_established": 2,
        "eigrp_neighbors": 2,
        "dmvpn_up": 2,
        "ikev2_ready": 2,
    },
}


@dataclass
class RouterResult:
    hostname: str
    management_ip: str | None
    required_interfaces_up: bool
    ssh_enabled: bool
    metrics: dict[str, int]
    checks: dict[str, bool]
    errors: list[str]

    @property
    def passed(self) -> bool:
        return (
            self.required_interfaces_up
            and all(self.checks.values())
            and not self.errors
        )


def load_dotenv(path: Path) -> None:
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())


def ios_local_secret(value: str) -> str:
    """Match the legacy-IOS credential normalization used by config rendering."""
    return value[:25]


def required_interfaces() -> dict[str, set[str]]:
    topology = json.loads(
        (ROOT / "lab" / "topology.json").read_text(encoding="utf-8")
    )
    output = {name: set() for name in ROUTERS}
    for item in topology["connections"]:
        if item["node"] in output:
            slot = int(item["interface"])
            output[item["node"]].add(
                "FastEthernet0/0" if slot == 0 else f"FastEthernet{slot}/0"
            )
    return output


def run_console(console: TelnetConsole, command: str, wait: float = 0.8) -> str:
    console.read_available(0.1)
    console.send(command + "\r")
    output = ""
    deadline = time.monotonic() + max(3.0, wait * 3.0)
    prompt = re.compile(r"(?m)^[A-Za-z0-9_.-]+(?:\([^)]+\))?[>#]\s*$")
    while time.monotonic() < deadline:
        output += console.read_available(0.25)
        if prompt.search(output):
            return output
    return output


def read_until(
    console: TelnetConsole,
    patterns: tuple[str, ...],
    timeout: float,
) -> str:
    output = ""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        output += console.read_available(0.8)
        if any(pattern in output for pattern in patterns):
            return output
    return output


def repair_ssh_keys(console: TelnetConsole) -> tuple[bool, str]:
    run_console(console, "configure terminal", 0.3)
    console.send("crypto key generate rsa general-keys modulus 2048\r")
    output = read_until(
        console,
        ("[OK]", "% Invalid input", "% Failed", "replace them"),
        90.0,
    )
    if "replace them" in output.lower():
        run_console(console, "no", 0.3)
    run_console(console, "end", 0.3)
    console.send("write memory\r")
    output += read_until(console, ("[OK]", "#"), 15.0)
    ssh_output = run_console(console, "show ip ssh", 2.0)
    return "SSH Enabled" in ssh_output, output + ssh_output


def parse_interfaces(output: str) -> tuple[dict[str, tuple[str, str, str]], str | None]:
    interfaces: dict[str, tuple[str, str, str]] = {}
    management_ip = None
    for line in output.splitlines():
        match = re.match(
            r"^(FastEthernet\d+/\d+|Tunnel\d+|Loopback\d+)\s+"
            r"(\S+)\s+\S+\s+\S+\s+(.+?)\s{2,}(\S+)\s*$",
            line.strip(),
        )
        if not match:
            continue
        name, address, status, protocol = match.groups()
        interfaces[name] = (address, status.strip(), protocol)
        if name == "FastEthernet0/0" and address != "unassigned":
            management_ip = address
    return interfaces, management_ip


def count_bgp_established(*outputs: str) -> int:
    peers: set[tuple[str, str]] = set()
    for output in outputs:
        for line in output.splitlines():
            fields = line.split()
            if len(fields) < 10:
                continue
            try:
                ipaddress.ip_address(fields[0])
                int(fields[-1])
            except ValueError:
                continue
            peers.add((fields[0], fields[2]))
    return len(peers)


def count_eigrp_neighbors(output: str) -> int:
    neighbors = set()
    for line in output.splitlines():
        match = re.match(r"^\s*\d+\s+(\d+\.\d+\.\d+\.\d+)\s+", line)
        if match:
            neighbors.add(match.group(1))
    return len(neighbors)


def count_dmvpn_up(output: str) -> int:
    legacy = sum(
        1
        for line in output.splitlines()
        if re.search(r"\sUP\s+\d", line) and re.search(r"\d+\.\d+\.\d+\.\d+", line)
    )
    nhrp_dynamic = len(re.findall(r"(?m)^\s*Type:\s+dynamic,", output))
    return max(legacy, nhrp_dynamic)


def count_crypto_up(output: str) -> int:
    """Support both legacy IKEv2 READY output and current crypto sessions."""

    return max(
        len(re.findall(r"\bREADY\b", output)),
        len(re.findall(r"Session status:\s+UP-ACTIVE", output)),
    )


def audit_router(
    node: dict[str, Any],
    eve_host: str,
    required: set[str],
    repair_ssh: bool,
    ssh_username: str,
    ssh_password: str,
) -> RouterResult:
    hostname = str(node["name"])
    metrics: dict[str, int] = {}
    checks: dict[str, bool] = {}
    errors: list[str] = []
    management_ip = None
    required_up = False
    ssh_enabled = False
    host, port = console_target(node, eve_host)
    console = TelnetConsole(host, port)
    try:
        console.initialize_ios()
        run_console(console, "terminal length 0", 0.2)
        interface_output = run_console(console, "show ip interface brief")
        interfaces, management_ip = parse_interfaces(interface_output)
        down = [
            name
            for name in sorted(required)
            if name not in interfaces
            or interfaces[name][1] != "up"
            or interfaces[name][2] != "up"
        ]
        required_up = not down
        if down:
            errors.append(f"required interfaces not up/up: {', '.join(down)}")

        ssh_output = run_console(console, "show ip ssh")
        ssh_enabled = "SSH Enabled" in ssh_output
        if repair_ssh and not ssh_enabled:
            ssh_enabled, repair_output = repair_ssh_keys(console)
            if not ssh_enabled:
                compact = " ".join(repair_output.split())
                errors.append(f"RSA repair failed: {compact[-300:]}")
        if repair_ssh:
            run_console(console, "configure terminal", 0.3)
            # Do not retain or print the command output: it echoes the secret.
            run_console(
                console,
                f"username {ssh_username} privilege 15 secret 0 {ssh_password}",
                0.8,
            )
            run_console(console, "aaa authentication login default local", 0.3)
            run_console(console, "aaa authorization exec default local", 0.3)
            run_console(console, "line vty 0 4", 0.3)
            run_console(console, "login local", 0.3)
            run_console(console, "transport input ssh", 0.3)
            run_console(console, "end", 0.3)
            console.send("write memory\r")
            read_until(console, ("[OK]", "#"), 15.0)
        if not ssh_enabled:
            errors.append("SSH disabled (use --repair-ssh)")

        bgp = run_console(console, "show ip bgp summary")
        vpnv4 = (
            run_console(console, "show ip bgp vpnv4 all summary")
            if hostname in {"PE1", "PE2"}
            else ""
        )
        metrics["bgp_established"] = count_bgp_established(bgp, vpnv4)

        if hostname in PROVIDER:
            ospf = run_console(console, "show ip ospf neighbor")
            ldp = run_console(console, "show mpls ldp neighbor")
            metrics["ospf_full"] = len(re.findall(r"\bFULL/", ospf))
            metrics["ldp_peers"] = len(re.findall(r"Peer LDP Ident:", ldp))

        if hostname in SITES:
            eigrp = run_console(console, "show ip eigrp neighbors", 1.2)
            dmvpn = run_console(console, "show ip nhrp", 2.0)
            ike = run_console(console, "show crypto session", 2.0)
            metrics["eigrp_neighbors"] = count_eigrp_neighbors(eigrp)
            metrics["dmvpn_up"] = count_dmvpn_up(dmvpn)
            metrics["ikev2_ready"] = count_crypto_up(ike)
            for _ in range(2):
                if (
                    metrics["dmvpn_up"]
                    >= EXPECTED_MINIMUMS[hostname]["dmvpn_up"]
                    and metrics["ikev2_ready"]
                    >= EXPECTED_MINIMUMS[hostname]["ikev2_ready"]
                ):
                    break
                time.sleep(0.5)
                dmvpn = run_console(console, "show ip nhrp", 2.0)
                ike = run_console(console, "show crypto session", 2.0)
                metrics["dmvpn_up"] = count_dmvpn_up(dmvpn)
                metrics["ikev2_ready"] = count_crypto_up(ike)

        for metric, expected in EXPECTED_MINIMUMS[hostname].items():
            checks[metric] = metrics.get(metric, 0) >= expected
    except (OSError, EveError) as exc:
        errors.append(str(exc))
    finally:
        console.close()
    return RouterResult(
        hostname=hostname,
        management_ip=management_ip,
        required_interfaces_up=required_up,
        ssh_enabled=ssh_enabled,
        metrics=metrics,
        checks=checks,
        errors=errors,
    )


def port_open(address: str, port: int = 22, timeout: float = 0.35) -> bool:
    try:
        with socket.create_connection((address, port), timeout=timeout):
            return True
    except OSError:
        return False


def ssh_hostname(
    address: str,
    username: str,
    password: str,
    timeout: float = 6.0,
) -> tuple[str, str | None, str | None]:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            address,
            username=username,
            password=password,
            timeout=timeout,
            auth_timeout=timeout,
            banner_timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        channel = client.invoke_shell(width=120, height=40)
        channel.settimeout(0.4)
        channel.send("terminal length 0\r")
        time.sleep(0.3)
        channel.send("show running-config | include ^hostname\r")
        chunks = []
        deadline = time.monotonic() + 4.0
        while time.monotonic() < deadline:
            try:
                chunks.append(channel.recv(65535).decode("utf-8", errors="replace"))
            except socket.timeout:
                continue
            if re.search(r"(?m)^hostname\s+\S+", "".join(chunks)):
                break
        text = "".join(chunks)
        match = re.search(r"(?m)^hostname\s+(\S+)", text)
        if not match:
            return address, None, "SSH succeeded but hostname was not returned"
        return address, match.group(1), None
    except (OSError, paramiko.SSHException) as exc:
        return address, None, str(exc)
    finally:
        client.close()


def ssh_ios_commands(
    address: str,
    username: str,
    password: str,
    commands: list[str],
) -> dict[str, str]:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    output: dict[str, str] = {}
    try:
        client.connect(
            address,
            username=username,
            password=password,
            timeout=8,
            auth_timeout=8,
            banner_timeout=8,
            look_for_keys=False,
            allow_agent=False,
        )
        channel = client.invoke_shell(width=160, height=80)
        channel.settimeout(0.3)
        prompt = re.compile(r"(?m)^[A-Za-z0-9_.-]+[>#]\s*$")

        def read_prompt(timeout: float) -> str:
            collected = ""
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                try:
                    collected += channel.recv(65535).decode(
                        "utf-8", errors="replace"
                    )
                except socket.timeout:
                    continue
                if prompt.search(collected):
                    break
            return collected

        def command(text: str, timeout: float = 12.0) -> str:
            while channel.recv_ready():
                channel.recv(65535)
            channel.send(text + "\r")
            return read_prompt(timeout)

        read_prompt(8.0)
        command("terminal length 0")
        for item in commands:
            output[item] = command(item, 20.0 if item.startswith("ping ") else 12.0)
        return output
    finally:
        client.close()


def scan_ssh(
    candidates: set[str],
    username: str,
    password: str,
    priority: set[str] | None = None,
) -> tuple[dict[str, str], dict[str, str]]:
    priority = priority or set()
    probe_candidates = candidates - priority
    with concurrent.futures.ThreadPoolExecutor(max_workers=48) as pool:
        open_results = dict(
            zip(probe_candidates, pool.map(port_open, sorted(probe_candidates)))
        )
    open_addresses = set(priority)
    open_addresses.update(
        address for address, opened in open_results.items() if opened
    )
    mapping: dict[str, str] = {}
    errors: dict[str, str] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        futures = [
            pool.submit(ssh_hostname, address, username, password)
            for address in sorted(open_addresses)
        ]
        for future in concurrent.futures.as_completed(futures):
            address, hostname, error = future.result()
            if hostname:
                mapping[address] = hostname
            elif error:
                errors[address] = error
    return mapping, errors


def subnet_candidates(value: str | None) -> set[str]:
    if not value:
        return set()
    network = ipaddress.ip_network(value, strict=False)
    if network.num_addresses > 1024:
        raise ValueError("refusing to scan more than 1024 addresses")
    return {str(address) for address in network.hosts()}


def main() -> int:
    load_dotenv(ROOT / ".env")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--eve-url", default=os.environ.get("EVE_URL", "http://192.168.58.128")
    )
    parser.add_argument("--eve-username", default=os.environ.get("EVE_USERNAME", "admin"))
    parser.add_argument("--eve-password", help="Prefer EVE_PASSWORD.")
    parser.add_argument("--eve-path", default="/RS")
    parser.add_argument("--lab-name", default="Air-Gapped Predictive Copilot")
    parser.add_argument("--ssh-username", default="noc")
    parser.add_argument("--ssh-password", help="Prefer LAB_ADMIN_SECRET in .env.")
    parser.add_argument("--subnet", help="Optionally scan this subnet for extra IOS SSH hosts.")
    parser.add_argument("--repair-ssh", action="store_true")
    parser.add_argument("--skip-ssh-map", action="store_true")
    parser.add_argument(
        "--output", type=Path, default=ROOT / "outputs" / "lab-audit.json"
    )
    args = parser.parse_args()

    eve_password = args.eve_password or os.environ.get("EVE_PASSWORD")
    if not eve_password:
        eve_password = getpass.getpass("EVE GUI/API password: ")
    ssh_password = args.ssh_password or os.environ.get("LAB_ADMIN_SECRET")
    if not args.skip_ssh_map and not ssh_password:
        ssh_password = getpass.getpass("IOS SSH password: ")
    ssh_password = ios_local_secret(ssh_password or "")

    client = EveClient(args.eve_url)
    try:
        client.login(
            args.eve_username,
            eve_password,
            native_console=True,
        )
        endpoint = api_lab_path(args.eve_path, args.lab_name)
        response = client.request("GET", f"/labs{endpoint}/nodes")
        nodes = {
            value["name"]: {**value, "id": int(key)}
            for key, value in response["data"].items()  # type: ignore[index,union-attr]
        }
        missing = [name for name in ROUTERS if name not in nodes]
        if missing:
            raise EveError(f"missing routers: {', '.join(missing)}")
        stopped = [name for name in ROUTERS if int(nodes[name].get("status", 0)) == 0]
        if stopped:
            raise EveError(f"routers are stopped: {', '.join(stopped)}")

        eve_host = urllib.parse.urlparse(args.eve_url).hostname or "127.0.0.1"
        required = required_interfaces()
        results = [
            audit_router(
                nodes[name],
                eve_host,
                required[name],
                args.repair_ssh,
                args.ssh_username,
                ssh_password or "",
            )
            for name in ROUTERS
        ]

        ip_map: dict[str, str] = {}
        ssh_errors: dict[str, str] = {}
        expected_map = {
            item.management_ip: item.hostname
            for item in results
            if item.management_ip
        }
        if not args.skip_ssh_map:
            candidates = set(expected_map)
            candidates.update(subnet_candidates(args.subnet))
            ip_map, ssh_errors = scan_ssh(
                candidates,
                args.ssh_username,
                ssh_password or "",
                priority=set(expected_map),
            )

            # Treat direct SSH as the authoritative fallback when an EVE
            # console returns an empty show-command response under load.
            by_name = {item.hostname: item for item in results}
            for hostname in SITES:
                address = next(
                    (
                        ip
                        for ip, mapped_hostname in ip_map.items()
                        if mapped_hostname == hostname
                    ),
                    None,
                )
                item = by_name[hostname]
                if not address or (
                    item.metrics.get("dmvpn_up", 0)
                    >= EXPECTED_MINIMUMS[hostname]["dmvpn_up"]
                    and item.metrics.get("ikev2_ready", 0)
                    >= EXPECTED_MINIMUMS[hostname]["ikev2_ready"]
                ):
                    continue
                try:
                    shows = ssh_ios_commands(
                        address,
                        args.ssh_username,
                        ssh_password,
                        ["show ip nhrp", "show crypto session"],
                    )
                    item.metrics["dmvpn_up"] = count_dmvpn_up(shows["show ip nhrp"])
                    item.metrics["ikev2_ready"] = count_crypto_up(
                        shows["show crypto session"]
                    )
                    item.checks["dmvpn_up"] = (
                        item.metrics["dmvpn_up"]
                        >= EXPECTED_MINIMUMS[hostname]["dmvpn_up"]
                    )
                    item.checks["ikev2_ready"] = (
                        item.metrics["ikev2_ready"]
                        >= EXPECTED_MINIMUMS[hostname]["ikev2_ready"]
                    )
                except (OSError, paramiko.SSHException) as exc:
                    ssh_errors[address] = f"convergence fallback failed: {exc}"

        endpoint_test = ""
        br1_host, br1_port = console_target(nodes["BR1"], eve_host)
        br1_console = TelnetConsole(br1_host, br1_port)
        try:
            br1_console.initialize_ios()
            for _ in range(3):
                endpoint_test = run_console(
                    br1_console,
                    "ping 10.20.10.10 repeat 5",
                    7.0,
                )
                if "Success rate is 100 percent" in endpoint_test:
                    break
        finally:
            br1_console.close()
        endpoint_reachable = "Success rate is 100 percent" in endpoint_test
        if not endpoint_reachable and not args.skip_ssh_map:
            br1_address = next(
                (
                    ip
                    for ip, mapped_hostname in ip_map.items()
                    if mapped_hostname == "BR1"
                ),
                None,
            )
            if br1_address:
                try:
                    ping_output = ssh_ios_commands(
                        br1_address,
                        args.ssh_username,
                        ssh_password,
                        ["ping 10.20.10.10 repeat 5"],
                    )
                    endpoint_reachable = "Success rate is 100 percent" in next(
                        iter(ping_output.values())
                    )
                except (OSError, paramiko.SSHException) as exc:
                    ssh_errors[br1_address] = f"endpoint fallback failed: {exc}"

        identity_ok = all(
            ip_map.get(address) == hostname
            for address, hostname in expected_map.items()
        ) if not args.skip_ssh_map else True
        passed = all(item.passed for item in results) and endpoint_reachable and identity_ok
        report = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "eve_url": args.eve_url,
            "lab": args.lab_name,
            "passed": passed,
            "endpoint_br1_to_dc": endpoint_reachable,
            "routers": [asdict(item) | {"passed": item.passed} for item in results],
            "expected_ip_map": expected_map,
            "ssh_ip_map": ip_map,
            "ssh_errors": ssh_errors,
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

        for item in results:
            status = "PASS" if item.passed else "FAIL"
            metrics = " ".join(f"{key}={value}" for key, value in item.metrics.items())
            print(
                f"[{status}] {item.hostname:<4} mgmt={item.management_ip or '-':<15} "
                f"ssh={'up' if item.ssh_enabled else 'down'} {metrics}"
            )
            for error in item.errors:
                print(f"       {error}")
        print(f"[{'PASS' if endpoint_reachable else 'FAIL'}] CLIENT-BR1 -> APP-DC")
        for address, hostname in sorted(ip_map.items(), key=lambda item: ipaddress.ip_address(item[0])):
            print(f"[MAP]  {address:<15} -> {hostname}")
        print(f"Report: {args.output}")
        return 0 if passed else 2
    except (EveError, OSError, KeyError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
