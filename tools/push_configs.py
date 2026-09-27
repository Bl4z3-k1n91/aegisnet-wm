#!/usr/bin/env python3
"""Start EVE routers and paste rendered IOS configurations over their consoles."""

from __future__ import annotations

import argparse
import getpass
import os
import re
import socket
import sys
import time
import urllib.parse
from pathlib import Path

from deploy_eve import EveClient, EveError, api_lab_path


ROOT = Path(__file__).resolve().parents[1]
ROUTER_NAMES = ("P1", "P2", "PE1", "PE2", "INET", "HUB", "BR1", "BR2", "DC")
ERROR_MARKERS = (
    "% Invalid input",
    "% Ambiguous command",
    "% Incomplete command",
    "% Unrecognized command",
)


class TelnetConsole:
    IAC = 255
    DO = 253
    DONT = 254
    WILL = 251
    WONT = 252
    SB = 250
    SE = 240

    def __init__(self, host: str, port: int) -> None:
        self.sock = socket.create_connection((host, port), timeout=15)
        self.sock.settimeout(0.2)

    def close(self) -> None:
        self.sock.close()

    def send(self, text: str) -> None:
        self.sock.sendall(text.encode("ascii", errors="ignore"))

    def _negotiate(self, data: bytes) -> bytes:
        output = bytearray()
        i = 0
        while i < len(data):
            if data[i] != self.IAC:
                output.append(data[i])
                i += 1
                continue
            if i + 1 >= len(data):
                break
            command = data[i + 1]
            if command == self.IAC:
                output.append(self.IAC)
                i += 2
            elif command in (self.DO, self.DONT, self.WILL, self.WONT):
                if i + 2 >= len(data):
                    break
                option = data[i + 2]
                if command in (self.DO, self.DONT):
                    reply = bytes((self.IAC, self.WONT, option))
                else:
                    reply = bytes((self.IAC, self.DONT, option))
                self.sock.sendall(reply)
                i += 3
            elif command == self.SB:
                end = data.find(bytes((self.IAC, self.SE)), i + 2)
                i = len(data) if end == -1 else end + 2
            else:
                i += 2
        return bytes(output)

    def read_available(self, duration: float = 0.4) -> str:
        end = time.monotonic() + duration
        chunks: list[bytes] = []
        while time.monotonic() < end:
            try:
                chunk = self.sock.recv(65535)
                if not chunk:
                    break
                chunks.append(self._negotiate(chunk))
            except socket.timeout:
                time.sleep(0.03)
        return b"".join(chunks).decode("utf-8", errors="replace")

    def initialize_ios(self, timeout: float = 30) -> str:
        transcript = ""
        deadline = time.monotonic() + timeout
        self.send("\r")
        while time.monotonic() < deadline:
            transcript += self.read_available(0.5)
            lower = transcript.lower()
            if "initial configuration dialog" in lower:
                self.send("no\r")
                transcript = ""
                continue
            if "press return to get started" in lower:
                self.send("\r")
                transcript = ""
                continue
            if re.search(r"[A-Za-z0-9_-]+[>#]\s*$", transcript):
                return transcript
            self.send("\r")
        raise EveError("IOS console did not reach a command prompt")

    def command(self, command: str, wait: float = 0.08) -> str:
        self.send(command + "\r")
        time.sleep(wait)
        return self.read_available(max(wait, 0.12))


def cli_commands(config: str) -> list[str]:
    """Convert indentation-based running config into console-paste commands."""
    parsed: list[tuple[int, str]] = []
    for raw in config.splitlines():
        stripped = raw.strip()
        if (
            not stripped
            or stripped == "!"
            or stripped == "end"
            or stripped.startswith("version ")
            or stripped in {"boot-start-marker", "boot-end-marker"}
            or stripped.startswith("exit-")
        ):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        parsed.append((indent, stripped))

    commands: list[str] = []
    depth = 0
    for index, (indent, command) in enumerate(parsed):
        while depth > indent:
            commands.append("exit")
            depth -= 1
        commands.append(command)
        next_indent = parsed[index + 1][0] if index + 1 < len(parsed) else 0
        if next_indent > indent:
            depth = next_indent
    while depth:
        commands.append("exit")
        depth -= 1
    return commands


def console_target(node: dict[str, object], eve_host: str) -> tuple[str, int]:
    url = str(node.get("url", ""))
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "telnet" or not parsed.port:
        raise EveError(f"node {node.get('name')} has no usable telnet console URL: {url!r}")
    host = parsed.hostname or eve_host
    if host in {"127.0.0.1", "localhost", "::1"}:
        host = eve_host
    return host, parsed.port


def push_one(
    name: str,
    node: dict[str, object],
    config_path: Path,
    eve_host: str,
    line_delay: float,
) -> list[str]:
    config = config_path.read_text(encoding="utf-8")
    if "CHANGEME" in config:
        raise EveError(
            f"{config_path} still contains CHANGEME values; render it from a populated .env"
        )
    host, port = console_target(node, eve_host)
    console = TelnetConsole(host, port)
    errors: list[str] = []
    try:
        prompt = console.initialize_ios()
        if prompt.rstrip().endswith(">"):
            console.command("enable", 0.2)
        console.command("configure terminal", 0.3)
        for command in cli_commands(config):
            output = console.command(command, line_delay)
            if any(marker in output for marker in ERROR_MARKERS):
                compact = " ".join(output.split())
                errors.append(f"{command!r}: {compact}")
        console.command("end", 0.2)
        console.command("configure terminal", 0.2)
        rsa_output = console.command(
            "crypto key generate rsa general-keys modulus 2048", 18.0
        )
        if "Do you really want to replace them" in rsa_output:
            console.command("no", 0.3)
        console.command("end", 0.2)
        console.command("write memory", 1.5)
    finally:
        console.close()
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--eve-url", default=os.environ.get("EVE_URL", "http://192.168.58.128"))
    parser.add_argument("--username", default=os.environ.get("EVE_USERNAME", "admin"))
    parser.add_argument("--password", help="Prefer EVE_PASSWORD instead of shell history.")
    parser.add_argument("--eve-path", default="/")
    parser.add_argument("--lab-name", default="Air-Gapped Predictive Copilot")
    parser.add_argument("--configs", type=Path, default=ROOT / "configs" / "routers")
    parser.add_argument("--pro", action="store_true")
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument("--start", action="store_true", help="Start all routers before waiting.")
    parser.add_argument("--boot-wait", type=int, default=90)
    parser.add_argument("--line-delay", type=float, default=0.08)
    parser.add_argument("--only", choices=ROUTER_NAMES, action="append")
    args = parser.parse_args()

    password = args.password or os.environ.get("EVE_PASSWORD")
    if not password:
        password = getpass.getpass("EVE-NG password: ")
    client = EveClient(args.eve_url, insecure=args.insecure)
    try:
        client.login(args.username, password, pro=args.pro, native_console=True)
        lab_endpoint = api_lab_path(args.eve_path, args.lab_name)
        response = client.request("GET", f"/labs{lab_endpoint}/nodes")
        nodes = {
            value["name"]: {**value, "id": int(key)}
            for key, value in response["data"].items()  # type: ignore[index,union-attr]
        }
        selected = tuple(args.only or ROUTER_NAMES)
        missing = [name for name in selected if name not in nodes]
        if missing:
            raise EveError(f"router nodes missing from EVE lab: {', '.join(missing)}")

        if args.start:
            for name in selected:
                if int(nodes[name].get("status", 0)) == 0:
                    client.request(
                        "GET", f"/labs{lab_endpoint}/nodes/{nodes[name]['id']}/start"
                    )
            print(f"Waiting {args.boot_wait}s for IOS to boot...")
            time.sleep(args.boot_wait)

        total_errors: list[str] = []
        eve_host = urllib.parse.urlparse(args.eve_url).hostname or "127.0.0.1"
        for name in selected:
            print(f"[{name}] pushing {args.configs / f'{name}.cfg'}")
            errors = push_one(
                name,
                nodes[name],
                args.configs / f"{name}.cfg",
                eve_host,
                args.line_delay,
            )
            for error in errors:
                total_errors.append(f"{name}: {error}")
            print(f"[{name}] complete ({len(errors)} rejected commands)")

        if total_errors:
            print("\nIOS rejected the following commands:", file=sys.stderr)
            for error in total_errors:
                print(f"- {error}", file=sys.stderr)
            return 2
        print("All selected configurations were applied and saved.")
        return 0
    except (EveError, OSError, KeyError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
