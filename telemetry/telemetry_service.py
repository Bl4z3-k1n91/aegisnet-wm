#!/usr/bin/env python3
"""Unified NetFlow v9, syslog, IP SLA and IOS health telemetry service."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import logging
import os
import signal
import socket
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flow_collector import FlowParser, NbarTable, RecordWriter
from ios_telemetry import poll_device
from syslog_collector import parse_message
from telemetry_store import TelemetryStore


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DEVICES = {
    "P1": "192.168.58.10",
    "P2": "192.168.58.11",
    "PE1": "192.168.58.12",
    "PE2": "192.168.58.13",
    "INET": "192.168.58.14",
    "BR1": "192.168.58.15",
    "BR2": "192.168.58.16",
    "HUB": "192.168.58.17",
    "DC": "192.168.58.18",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_json_status(path: Path, payload: dict[str, Any]) -> None:
    """Publish a status snapshot without letting transient Windows readers kill the heartbeat.

    ``os.replace`` can raise ``PermissionError`` on Windows when another process
    briefly has the destination open.  Health/status readers are expected to be
    concurrent, so retry the atomic replace and keep the heartbeat thread alive.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    last_error: OSError | None = None
    for attempt in range(20):
        try:
            temporary.replace(path)
            return
        except PermissionError as exc:
            last_error = exc
            time.sleep(0.05 * (attempt + 1))
    if last_error is not None:
        raise last_error


def load_dotenv(path: Path) -> None:
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        stripped = raw.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key, value = stripped.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip())


def ios_local_secret(value: str) -> str:
    return value[:25]


def load_devices(path: Path | None) -> dict[str, str]:
    if path and path.is_file():
        body = json.loads(path.read_text(encoding="utf-8"))
        ip_map = body.get("ssh_ip_map") or body.get("expected_ip_map") or {}
        mapped = {str(hostname): str(address) for address, hostname in ip_map.items()}
        if mapped:
            return mapped
    return DEFAULT_DEVICES.copy()


class RuntimeState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.started_at = utc_now()
        self.last_flow_at: str | None = None
        self.last_syslog_at: str | None = None
        self.last_poll_at: dict[str, str] = {}
        self.poll_errors: dict[str, str] = {}
        self.fatal_errors: list[str] = []

    def snapshot(self, counts: dict[str, int]) -> dict[str, Any]:
        with self.lock:
            health = "HEALTHY"
            if self.fatal_errors:
                health = "FAILED"
            elif self.poll_errors:
                health = "DEGRADED"
            return {
                "state": "RUNNING",
                "health": health,
                "pid": os.getpid(),
                "started_at": self.started_at,
                "updated_at": utc_now(),
                "last_flow_at": self.last_flow_at,
                "last_syslog_at": self.last_syslog_at,
                "last_poll_at": dict(self.last_poll_at),
                "poll_errors": dict(self.poll_errors),
                "fatal_errors": list(self.fatal_errors),
                "counts": counts,
            }


class TelemetryService:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.stop_event = threading.Event()
        self.store = TelemetryStore(args.database)
        self.state = RuntimeState()
        self.devices = load_devices(args.device_map)
        self.exporter_devices = {address: name for name, address in self.devices.items()}
        self.flow_parser = FlowParser(NbarTable(args.nbar_table))
        self.flow_writer = RecordWriter(args.flow_csv, args.flow_jsonl)
        args.syslog_jsonl.parent.mkdir(parents=True, exist_ok=True)
        self.syslog_output = args.syslog_jsonl.open("a", encoding="utf-8")
        self.threads: list[threading.Thread] = []

    def stop(self) -> None:
        self.stop_event.set()

    def _fatal(self, component: str, exc: BaseException) -> None:
        message = f"{component}: {exc}"
        logging.exception(message)
        with self.state.lock:
            self.state.fatal_errors.append(message)
        self.store.event("ERROR", component, str(exc))
        self.stop_event.set()

    def flow_loop(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        try:
            sock.bind((self.args.bind, self.args.flow_port))
            logging.info("NetFlow v9/IPFIX listening on %s:%d", self.args.bind, self.args.flow_port)
            while not self.stop_event.is_set():
                try:
                    packet, address = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                records = self.flow_parser.parse_packet(packet, address[0])
                if not records:
                    continue
                self.store.write_flows(records, self.exporter_devices)
                self.flow_writer.write(records)
                with self.state.lock:
                    self.state.last_flow_at = utc_now()
        except BaseException as exc:
            self._fatal("netflow", exc)
        finally:
            sock.close()

    def syslog_loop(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        try:
            sock.bind((self.args.bind, self.args.syslog_port))
            logging.info("Syslog listening on %s:%d", self.args.bind, self.args.syslog_port)
            while not self.stop_event.is_set():
                try:
                    payload, address = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                record = parse_message(payload, address[0])
                self.store.write_syslog(record, self.exporter_devices)
                self.syslog_output.write(json.dumps(record, sort_keys=True) + "\n")
                self.syslog_output.flush()
                with self.state.lock:
                    self.state.last_syslog_at = utc_now()
        except BaseException as exc:
            self._fatal("syslog", exc)
        finally:
            sock.close()

    def _poll_one(self, device: str, address: str) -> None:
        try:
            result = poll_device(
                device,
                address,
                self.args.ssh_username,
                self.args.ssh_password,
            )
            self.store.write_poll(result)
            with self.state.lock:
                self.state.last_poll_at[device] = utc_now()
                self.state.poll_errors.pop(device, None)
        except BaseException as exc:
            message = f"{type(exc).__name__}: {exc}"
            logging.warning("Poll failed for %s (%s): %s", device, address, message)
            self.store.write_poll_error(device, address, message)
            with self.state.lock:
                self.state.poll_errors[device] = message

    def poll_loop(self) -> None:
        logging.info(
            "IOS polling every %.1fs for %d devices",
            self.args.poll_interval,
            len(self.devices),
        )
        while not self.stop_event.is_set():
            started = time.monotonic()
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.args.poll_workers
            ) as pool:
                futures = [
                    pool.submit(self._poll_one, device, address)
                    for device, address in self.devices.items()
                ]
                concurrent.futures.wait(futures)
            elapsed = time.monotonic() - started
            remaining = max(0.0, self.args.poll_interval - elapsed)
            self.stop_event.wait(remaining)

    def status_loop(self) -> None:
        counts: dict[str, int] = {}
        while not self.stop_event.wait(2.0):
            try:
                current = self.store.try_counts()
                if current is not None:
                    counts = current
                snapshot = self.state.snapshot(counts)
                write_json_status(self.args.status_file, snapshot)
            except BaseException as exc:
                # A status-publish failure must never silently terminate the
                # heartbeat thread.  Keep retrying on the next cycle and leave
                # an explicit diagnostic in the service log.
                logging.warning("status heartbeat publish failed: %s: %s", type(exc).__name__, exc)

    def run(self) -> int:
        self.args.pid_file.parent.mkdir(parents=True, exist_ok=True)
        self.args.pid_file.write_text(str(os.getpid()), encoding="ascii")
        self.store.event(
            "INFO",
            "service",
            "telemetry service started",
            {"devices": self.devices},
        )
        self.threads = [
            threading.Thread(target=self.flow_loop, name="netflow", daemon=True),
            threading.Thread(target=self.syslog_loop, name="syslog", daemon=True),
            threading.Thread(target=self.poll_loop, name="poller", daemon=True),
            threading.Thread(target=self.status_loop, name="status", daemon=True),
        ]
        for thread in self.threads:
            thread.start()
        deadline = (
            None
            if self.args.run_seconds <= 0
            else time.monotonic() + self.args.run_seconds
        )
        try:
            while not self.stop_event.wait(0.5):
                if deadline is not None and time.monotonic() >= deadline:
                    self.stop()
        finally:
            for thread in self.threads:
                thread.join(timeout=5)
            self.store.event("INFO", "service", "telemetry service stopped")
            final_status = self.state.snapshot(self.store.counts())
            final_status["state"] = "FAILED" if self.state.fatal_errors else "STOPPED"
            final_status["health"] = "FAILED" if self.state.fatal_errors else "STOPPED"
            write_json_status(self.args.status_file, final_status)
            self.flow_writer.close()
            self.syslog_output.close()
            self.store.close()
            self.args.pid_file.unlink(missing_ok=True)
        return 1 if self.state.fatal_errors else 0


def parse_args() -> argparse.Namespace:
    load_dotenv(ROOT / ".env")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--flow-port", type=int, default=2055)
    parser.add_argument("--syslog-port", type=int, default=5514)
    parser.add_argument("--poll-interval", type=float, default=15.0)
    parser.add_argument("--poll-workers", type=int, default=6)
    parser.add_argument("--ssh-username", default="noc")
    parser.add_argument("--ssh-password", default=os.environ.get("LAB_ADMIN_SECRET"))
    parser.add_argument(
        "--device-map",
        type=Path,
        default=None,
        help=(
            "Optional audit/device-map JSON. When omitted, use the repository's "
            "current static OOB inventory instead of a possibly stale audit file."
        ),
    )
    parser.add_argument(
        "--database", type=Path, default=ROOT / "outputs" / "telemetry.db"
    )
    parser.add_argument(
        "--flow-csv", type=Path, default=ROOT / "outputs" / "flows-live.csv"
    )
    parser.add_argument(
        "--flow-jsonl", type=Path, default=ROOT / "outputs" / "flows-live.jsonl"
    )
    parser.add_argument(
        "--syslog-jsonl", type=Path, default=ROOT / "outputs" / "syslog-live.jsonl"
    )
    default_nbar = Path(__file__).with_name("nbar_table.txt")
    parser.add_argument(
        "--nbar-table",
        type=Path,
        default=default_nbar if default_nbar.is_file() else None,
    )
    parser.add_argument(
        "--status-file",
        type=Path,
        default=ROOT / "outputs" / "telemetry-status.json",
    )
    parser.add_argument(
        "--pid-file",
        type=Path,
        default=ROOT / "outputs" / "telemetry-service.pid",
    )
    parser.add_argument("--run-seconds", type=float, default=0)
    args = parser.parse_args()
    if not args.ssh_password:
        parser.error("LAB_ADMIN_SECRET is missing; set it in .env or use --ssh-password")
    args.ssh_password = ios_local_secret(args.ssh_password)
    return args


def main() -> int:
    args = parse_args()
    args.database.parent.mkdir(parents=True, exist_ok=True)
    log_path = ROOT / "outputs" / "telemetry-service.log"
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(threadName)s %(message)s",
        handlers=[
            logging.FileHandler(log_path, encoding="utf-8"),
            logging.StreamHandler(),
        ],
    )
    service = TelemetryService(args)
    signal.signal(signal.SIGINT, lambda *_: service.stop())
    signal.signal(signal.SIGTERM, lambda *_: service.stop())
    return service.run()


if __name__ == "__main__":
    raise SystemExit(main())
