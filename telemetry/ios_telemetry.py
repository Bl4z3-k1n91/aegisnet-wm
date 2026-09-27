"""IOS SSH polling and parsers for SLA, interfaces and control-plane state."""

from __future__ import annotations

import ipaddress
import re
import socket
import time
from dataclasses import dataclass, field
from typing import Any

import paramiko


PROMPT_RE = re.compile(r"(?m)^[A-Za-z0-9_.-]+[>#]\s*$")


class IosSession:
    def __init__(self, host: str, username: str, password: str) -> None:
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(
            host,
            username=username,
            password=password,
            timeout=8,
            auth_timeout=8,
            banner_timeout=8,
            look_for_keys=False,
            allow_agent=False,
        )
        self.channel = self.client.invoke_shell(width=180, height=100)
        self.channel.settimeout(0.3)
        self._read_until_prompt(8.0)
        self.run("terminal length 0")

    def _read_until_prompt(self, timeout: float) -> str:
        output = ""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                output += self.channel.recv(65535).decode(
                    "utf-8", errors="replace"
                )
            except socket.timeout:
                continue
            if PROMPT_RE.search(output):
                return output
        return output

    def run(self, command: str, timeout: float = 12.0) -> str:
        time.sleep(0.05)
        while self.channel.recv_ready():
            self.channel.recv(65535)
        self.channel.send(command + "\r")
        return self._read_until_prompt(timeout)

    def close(self) -> None:
        self.client.close()

    def __enter__(self) -> "IosSession":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def established_bgp(output: str) -> int:
    peers = set()
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 10:
            continue
        try:
            ipaddress.ip_address(fields[0])
            int(fields[-1])
        except ValueError:
            continue
        peers.add(fields[0])
    return len(peers)


def parse_sla(output: str, track_output: str) -> list[dict[str, Any]]:
    track_states: dict[int, str] = {}
    for line in track_output.splitlines():
        match = re.match(
            r"^\s*(\d+)\s+ip sla\s+\d+\s+reachability\s+(\S+)", line
        )
        if match:
            track_states[int(match.group(1))] = match.group(2)

    records: list[dict[str, Any]] = []
    parts = re.split(r"(?=IPSLA operation id:\s*\d+)", output)
    for part in parts:
        operation = re.search(r"IPSLA operation id:\s*(\d+)", part)
        if not operation:
            continue
        operation_id = int(operation.group(1))
        rtt = re.search(r"Latest RTT:\s*(\d+)\s+milliseconds", part)
        return_code = re.search(r"Latest operation return code:\s*(.+)", part)
        successes = re.search(r"Number of successes:\s*(\d+)", part)
        failures = re.search(r"Number of failures:\s*(\d+)", part)
        records.append(
            {
                "operation_id": operation_id,
                "rtt_ms": int(rtt.group(1)) if rtt else None,
                "return_code": return_code.group(1).strip() if return_code else None,
                "successes": int(successes.group(1)) if successes else 0,
                "failures": int(failures.group(1)) if failures else 0,
                "track_state": track_states.get(operation_id),
            }
        )
    return records


def parse_interfaces(output: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None

    def finish() -> None:
        if current is not None:
            records.append(current.copy())

    for raw in output.splitlines():
        line = raw.strip()
        header = re.match(r"^(\S+) is (.*?), line protocol is (\S+)", line)
        if header:
            finish()
            current = {
                "interface": header.group(1),
                "admin_state": header.group(2),
                "protocol_state": header.group(3),
                "input_bps": 0,
                "output_bps": 0,
                "input_pps": 0,
                "output_pps": 0,
                "input_errors": 0,
                "output_errors": 0,
                "input_drops": 0,
                "output_drops": 0,
            }
            continue
        if current is None:
            continue
        match = re.search(r"Input queue: \d+/\d+/(\d+)/", line)
        if match:
            current["input_drops"] = int(match.group(1))
        match = re.search(r"Total output drops:\s*(\d+)", line)
        if match:
            current["output_drops"] = int(match.group(1))
        match = re.search(
            r"5 minute input rate\s+(\d+) bits/sec,\s+(\d+) packets/sec", line
        )
        if match:
            current["input_bps"], current["input_pps"] = map(int, match.groups())
        match = re.search(
            r"5 minute output rate\s+(\d+) bits/sec,\s+(\d+) packets/sec", line
        )
        if match:
            current["output_bps"], current["output_pps"] = map(int, match.groups())
        match = re.search(r"(\d+) input errors", line)
        if match:
            current["input_errors"] = int(match.group(1))
        match = re.search(r"(\d+) output errors", line)
        if match:
            current["output_errors"] = int(match.group(1))
    finish()
    return records


def parse_qos(output: str) -> list[dict[str, Any]]:
    """Parse hierarchical MQC class counters from show policy-map interface."""
    records: list[dict[str, Any]] = []
    interface: str | None = None
    policies: dict[int, str] = {}
    current: dict[str, Any] | None = None

    def finish() -> None:
        nonlocal current
        if current is not None:
            records.append(current)
            current = None

    for raw in output.splitlines():
        line = raw.strip()
        interface_match = re.match(r"^(FastEthernet\S+|Tunnel\S+)\s*$", line)
        if interface_match and " " not in line:
            finish()
            interface = interface_match.group(1)
            policies.clear()
            continue
        policy_match = re.match(r"^Service-policy\s+(?:output:|:)\s*(\S+)", line)
        if policy_match:
            indent = len(raw) - len(raw.lstrip())
            policies[indent] = policy_match.group(1)
            continue
        class_match = re.match(r"^Class-map:\s*(\S+)", line)
        if class_match and interface:
            finish()
            indent = len(raw) - len(raw.lstrip())
            parent_policies = [
                (depth, name) for depth, name in policies.items() if depth < indent
            ]
            policy = max(parent_policies, default=(0, "unknown"))[1]
            current = {
                "interface": interface,
                "policy": policy,
                "class_name": class_match.group(1),
                "offered_bps": 0,
                "drop_bps": 0,
                "total_drops": 0,
                "packets": 0,
                "bytes": 0,
                "shape_rate": None,
            }
            continue
        if current is None:
            continue
        counters = re.match(r"^(\d+)\s+packets,\s+(\d+)\s+bytes", line)
        if counters and current["packets"] == 0:
            current["packets"], current["bytes"] = map(int, counters.groups())
        rates = re.match(
            r"^5 minute offered rate\s+(\d+)\s+bps,\s+drop rate\s+(\d+)\s+bps",
            line,
        )
        if rates:
            current["offered_bps"], current["drop_bps"] = map(int, rates.groups())
        drops = re.search(
            r"\(queue depth/total drops/no-buffer drops(?:/flowdrops)?\)"
            r"\s+\d+/(\d+)/",
            line,
        )
        if drops:
            current["total_drops"] = int(drops.group(1))
        shape = re.search(r"target shape rate\s+(\d+)", line)
        if shape:
            current["shape_rate"] = int(shape.group(1))
    finish()
    return records


def parse_device_state(outputs: dict[str, str]) -> dict[str, Any]:
    nhrp_output = outputs.get("nhrp", "") or outputs.get("dmvpn", "")
    crypto_output = outputs.get("crypto_session", "") or outputs.get("ikev2", "")
    legacy_dmvpn_up = sum(
        1
        for line in outputs.get("dmvpn", "").splitlines()
        if re.search(r"\sUP\s+\d", line)
    )
    nhrp_dynamic = len(
        re.findall(r"(?m)^\s*Type:\s+dynamic,", nhrp_output)
    )
    crypto_up = len(re.findall(r"Session status:\s+UP-ACTIVE", crypto_output))
    legacy_ike_ready = len(re.findall(r"\bREADY\b", outputs.get("ikev2", "")))
    state: dict[str, Any] = {
        "cpu_5s": None,
        "cpu_1m": None,
        "cpu_5m": None,
        "memory_total": None,
        "memory_used": None,
        "memory_free": None,
        "bgp_established": established_bgp(
            outputs.get("bgp", "") + "\n" + outputs.get("bgp_vpnv4", "")
        ),
        "ospf_full": len(re.findall(r"\bFULL/", outputs.get("ospf", ""))),
        "eigrp_neighbors": len(
            set(
                re.findall(
                    r"(?m)^\s*\d+\s+(\d+\.\d+\.\d+\.\d+)\s+",
                    outputs.get("eigrp", ""),
                )
            )
        ),
        # Keep the existing field names so the historical dataset and quality
        # gates remain compatible.  On the current IOS image, `show dmvpn` and
        # `show crypto ikev2 sa` are unavailable, so dynamic NHRP mappings and
        # UP-ACTIVE crypto sessions are the authoritative equivalents.
        "dmvpn_up": max(legacy_dmvpn_up, nhrp_dynamic),
        "ikev2_ready": max(legacy_ike_ready, crypto_up),
    }
    cpu = re.search(
        r"five seconds:\s*(\d+)%/\d+%; one minute:\s*(\d+)%; "
        r"five minutes:\s*(\d+)%",
        outputs.get("cpu", ""),
    )
    if cpu:
        state["cpu_5s"], state["cpu_1m"], state["cpu_5m"] = map(
            int, cpu.groups()
        )
    memory = re.search(
        r"(?m)^Processor\s+\S+\s+(\d+)\s+(\d+)\s+(\d+)", outputs.get("memory", "")
    )
    if memory:
        (
            state["memory_total"],
            state["memory_used"],
            state["memory_free"],
        ) = map(int, memory.groups())
    return state


POLL_COMMANDS = {
    "sla": "show ip sla statistics",
    "track": "show track brief",
    "interfaces": (
        "show interfaces | include ^FastEthernet|^Tunnel|^Loopback|"
        "line protocol|input rate|output rate|drops|errors"
    ),
    "cpu": "show processes cpu | include CPU utilization",
    "memory": "show memory statistics | include Processor",
    "bgp": "show ip bgp summary",
    "bgp_vpnv4": "show ip bgp vpnv4 all summary",
    "ospf": "show ip ospf neighbor",
    "eigrp": "show ip eigrp neighbors",
    "nhrp": "show ip nhrp",
    "crypto_session": "show crypto session",
    "qos": "show policy-map interface",
}


@dataclass
class PollResult:
    device: str
    management_ip: str
    poll_ms: int
    sla: list[dict[str, Any]]
    interfaces: list[dict[str, Any]]
    state: dict[str, Any]
    qos: list[dict[str, Any]] = field(default_factory=list)


def poll_device(
    device: str,
    management_ip: str,
    username: str,
    password: str,
) -> PollResult:
    started = time.monotonic()
    outputs: dict[str, str] = {}
    with IosSession(management_ip, username, password) as session:
        for key, command in POLL_COMMANDS.items():
            outputs[key] = session.run(command)
    return PollResult(
        device=device,
        management_ip=management_ip,
        poll_ms=round((time.monotonic() - started) * 1000),
        sla=parse_sla(outputs["sla"], outputs["track"]),
        interfaces=parse_interfaces(outputs["interfaces"]),
        qos=parse_qos(outputs["qos"]),
        state=parse_device_state(outputs),
    )
