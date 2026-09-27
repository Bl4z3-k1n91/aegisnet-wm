"""SQLite storage for normalized telemetry records."""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS flows (
    id INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,
    exporter TEXT NOT NULL,
    device TEXT,
    version INTEGER,
    observation_domain INTEGER,
    template_id INTEGER,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    protocol INTEGER,
    tcp_flags INTEGER,
    dscp INTEGER,
    input_if INTEGER,
    output_if INTEGER,
    direction INTEGER,
    next_hop TEXT,
    application TEXT,
    application_engine INTEGER,
    application_selector INTEGER,
    bytes INTEGER,
    packets INTEGER,
    flow_start TEXT,
    flow_end TEXT,
    flow_start_uptime_ms INTEGER,
    flow_end_uptime_ms INTEGER,
    raw_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_flows_timestamp ON flows(timestamp);
CREATE INDEX IF NOT EXISTS idx_flows_device ON flows(device, timestamp);

CREATE TABLE IF NOT EXISTS syslog_events (
    id INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,
    exporter TEXT NOT NULL,
    device TEXT,
    facility INTEGER,
    severity INTEGER,
    priority INTEGER,
    message TEXT NOT NULL,
    raw_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_syslog_timestamp ON syslog_events(timestamp);

CREATE TABLE IF NOT EXISTS sla_samples (
    id INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,
    device TEXT NOT NULL,
    management_ip TEXT NOT NULL,
    operation_id INTEGER NOT NULL,
    transport TEXT,
    target_role TEXT,
    rtt_ms INTEGER,
    return_code TEXT,
    successes INTEGER,
    failures INTEGER,
    success_delta INTEGER,
    failure_delta INTEGER,
    track_state TEXT
);
CREATE INDEX IF NOT EXISTS idx_sla_device_time
    ON sla_samples(device, operation_id, timestamp);

CREATE TABLE IF NOT EXISTS interface_samples (
    id INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,
    device TEXT NOT NULL,
    management_ip TEXT NOT NULL,
    interface TEXT NOT NULL,
    admin_state TEXT,
    protocol_state TEXT,
    input_bps INTEGER,
    output_bps INTEGER,
    input_pps INTEGER,
    output_pps INTEGER,
    input_errors INTEGER,
    output_errors INTEGER,
    input_drops INTEGER,
    output_drops INTEGER,
    input_error_delta INTEGER,
    output_error_delta INTEGER,
    input_drop_delta INTEGER,
    output_drop_delta INTEGER
);
CREATE INDEX IF NOT EXISTS idx_interface_device_time
    ON interface_samples(device, interface, timestamp);

CREATE TABLE IF NOT EXISTS qos_samples (
    id INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,
    device TEXT NOT NULL,
    management_ip TEXT NOT NULL,
    interface TEXT NOT NULL,
    policy TEXT NOT NULL,
    class_name TEXT NOT NULL,
    offered_bps INTEGER,
    drop_bps INTEGER,
    packets INTEGER,
    bytes INTEGER,
    total_drops INTEGER,
    drop_delta INTEGER,
    shape_rate INTEGER
);
CREATE INDEX IF NOT EXISTS idx_qos_device_time
    ON qos_samples(device, interface, policy, class_name, timestamp);

CREATE TABLE IF NOT EXISTS device_samples (
    id INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,
    device TEXT NOT NULL,
    management_ip TEXT NOT NULL,
    reachable INTEGER NOT NULL,
    poll_ms INTEGER,
    cpu_5s INTEGER,
    cpu_1m INTEGER,
    cpu_5m INTEGER,
    memory_total INTEGER,
    memory_used INTEGER,
    memory_free INTEGER,
    bgp_established INTEGER,
    ospf_full INTEGER,
    eigrp_neighbors INTEGER,
    dmvpn_up INTEGER,
    ikev2_ready INTEGER,
    error TEXT
);
CREATE INDEX IF NOT EXISTS idx_device_samples_time
    ON device_samples(device, timestamp);

CREATE TABLE IF NOT EXISTS service_events (
    id INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,
    level TEXT NOT NULL,
    component TEXT NOT NULL,
    message TEXT NOT NULL,
    details_json TEXT
);
"""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class TelemetryStore:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(
            path, check_same_thread=False, timeout=60
        )
        self.connection.execute("PRAGMA busy_timeout=60000")
        self.connection.executescript(SCHEMA)
        self._ensure_columns(
            "sla_samples",
            {"transport": "TEXT", "target_role": "TEXT"},
        )
        self._ensure_columns(
            "interface_samples",
            {
                "input_error_delta": "INTEGER",
                "output_error_delta": "INTEGER",
                "input_drop_delta": "INTEGER",
                "output_drop_delta": "INTEGER",
            },
        )
        self._ensure_columns(
            "flows",
            {
                "tcp_flags": "INTEGER",
                "direction": "INTEGER",
                "next_hop": "TEXT",
                "flow_start": "TEXT",
                "flow_end": "TEXT",
                "flow_start_uptime_ms": "INTEGER",
                "flow_end_uptime_ms": "INTEGER",
            },
        )
        self.lock = threading.Lock()
        self.previous_sla: dict[tuple[str, int], tuple[int, int]] = {}
        self.previous_interfaces: dict[
            tuple[str, str], tuple[int, int, int, int]
        ] = {}
        self.previous_qos: dict[tuple[str, str, str, str], int] = {}

    def _ensure_columns(self, table: str, columns: dict[str, str]) -> None:
        existing = {
            row[1]
            for row in self.connection.execute(f"PRAGMA table_info({table})")
        }
        for name, data_type in columns.items():
            if name not in existing:
                self.connection.execute(
                    f"ALTER TABLE {table} ADD COLUMN {name} {data_type}"
                )
        self.connection.commit()

    def close(self) -> None:
        with self.lock:
            self.connection.close()

    def write_flows(
        self, records: list[dict[str, Any]], exporter_devices: dict[str, str]
    ) -> None:
        rows = []
        for record in records:
            rows.append(
                (
                    record.get("timestamp", utc_now()),
                    record.get("exporter"),
                    exporter_devices.get(str(record.get("exporter"))),
                    record.get("version"),
                    record.get("observation_domain"),
                    record.get("template_id"),
                    record.get("src_ip"),
                    record.get("dst_ip"),
                    record.get("src_port"),
                    record.get("dst_port"),
                    record.get("protocol"),
                    record.get("tcp_flags"),
                    record.get("dscp"),
                    record.get("input_if"),
                    record.get("output_if"),
                    record.get("direction"),
                    record.get("next_hop"),
                    record.get("application"),
                    record.get("application_engine"),
                    record.get("application_selector"),
                    record.get("bytes"),
                    record.get("packets"),
                    record.get("flow_start"),
                    record.get("flow_end"),
                    record.get("flow_start_uptime_ms"),
                    record.get("flow_end_uptime_ms"),
                    json.dumps(record, sort_keys=True),
                )
            )
        with self.lock:
            self.connection.executemany(
                """
                INSERT INTO flows (
                    timestamp, exporter, device, version, observation_domain,
                    template_id, src_ip, dst_ip, src_port, dst_port, protocol,
                    tcp_flags, dscp, input_if, output_if, direction, next_hop,
                    application, application_engine, application_selector, bytes,
                    packets, flow_start, flow_end, flow_start_uptime_ms,
                    flow_end_uptime_ms, raw_json
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                rows,
            )
            self.connection.commit()

    def write_syslog(
        self, record: dict[str, Any], exporter_devices: dict[str, str]
    ) -> None:
        exporter = str(record["exporter"])
        with self.lock:
            self.connection.execute(
                """
                INSERT INTO syslog_events (
                    timestamp, exporter, device, facility, severity, priority,
                    message, raw_json
                ) VALUES (?,?,?,?,?,?,?,?)
                """,
                (
                    record["timestamp"],
                    exporter,
                    exporter_devices.get(exporter),
                    record.get("facility"),
                    record.get("severity"),
                    record.get("priority"),
                    record.get("message", ""),
                    json.dumps(record, sort_keys=True),
                ),
            )
            self.connection.commit()

    def write_poll(self, poll: Any) -> None:
        timestamp = utc_now()
        sla_rows = []
        for sample in poll.sla:
            key = (poll.device, sample["operation_id"])
            previous = self.previous_sla.get(key)
            successes = int(sample.get("successes", 0))
            failures = int(sample.get("failures", 0))
            success_delta = 0 if previous is None else max(0, successes - previous[0])
            failure_delta = 0 if previous is None else max(0, failures - previous[1])
            self.previous_sla[key] = (successes, failures)
            operation_id = int(sample["operation_id"])
            transport = "MPLS" if operation_id in {101, 111} else "INTERNET"
            target_role = "HUB" if operation_id in {101, 102} else "DC"
            sla_rows.append(
                (
                    timestamp,
                    poll.device,
                    poll.management_ip,
                    operation_id,
                    transport,
                    target_role,
                    sample.get("rtt_ms"),
                    sample.get("return_code"),
                    successes,
                    failures,
                    success_delta,
                    failure_delta,
                    sample.get("track_state"),
                )
            )
        interface_rows = []
        for sample in poll.interfaces:
            interface = str(sample["interface"])
            counters = (
                int(sample.get("input_errors", 0)),
                int(sample.get("output_errors", 0)),
                int(sample.get("input_drops", 0)),
                int(sample.get("output_drops", 0)),
            )
            key = (poll.device, interface)
            previous = self.previous_interfaces.get(key)
            deltas = (
                (0, 0, 0, 0)
                if previous is None
                else tuple(max(0, value - old) for value, old in zip(counters, previous))
            )
            self.previous_interfaces[key] = counters
            interface_rows.append(
                (
                    timestamp,
                    poll.device,
                    poll.management_ip,
                    interface,
                    sample.get("admin_state"),
                    sample.get("protocol_state"),
                    sample.get("input_bps"),
                    sample.get("output_bps"),
                    sample.get("input_pps"),
                    sample.get("output_pps"),
                    *counters,
                    *deltas,
                )
            )
        state = poll.state
        qos_rows = []
        for sample in getattr(poll, "qos", []):
            key = (
                poll.device,
                str(sample["interface"]),
                str(sample["policy"]),
                str(sample["class_name"]),
            )
            total_drops = int(sample.get("total_drops", 0))
            previous = self.previous_qos.get(key)
            drop_delta = (
                0 if previous is None else max(0, total_drops - previous)
            )
            self.previous_qos[key] = total_drops
            qos_rows.append(
                (
                    timestamp,
                    poll.device,
                    poll.management_ip,
                    sample["interface"],
                    sample["policy"],
                    sample["class_name"],
                    sample.get("offered_bps"),
                    sample.get("drop_bps"),
                    sample.get("packets"),
                    sample.get("bytes"),
                    total_drops,
                    drop_delta,
                    sample.get("shape_rate"),
                )
            )
        device_row = (
            timestamp,
            poll.device,
            poll.management_ip,
            1,
            poll.poll_ms,
            state.get("cpu_5s"),
            state.get("cpu_1m"),
            state.get("cpu_5m"),
            state.get("memory_total"),
            state.get("memory_used"),
            state.get("memory_free"),
            state.get("bgp_established"),
            state.get("ospf_full"),
            state.get("eigrp_neighbors"),
            state.get("dmvpn_up"),
            state.get("ikev2_ready"),
            None,
        )
        with self.lock:
            if sla_rows:
                self.connection.executemany(
                    """
                    INSERT INTO sla_samples (
                        timestamp, device, management_ip, operation_id,
                        transport, target_role, rtt_ms, return_code, successes,
                        failures, success_delta, failure_delta, track_state
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    sla_rows,
                )
            if interface_rows:
                self.connection.executemany(
                    """
                    INSERT INTO interface_samples (
                        timestamp, device, management_ip, interface,
                        admin_state, protocol_state, input_bps, output_bps,
                        input_pps, output_pps, input_errors, output_errors,
                        input_drops, output_drops, input_error_delta,
                        output_error_delta, input_drop_delta, output_drop_delta
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    interface_rows,
                )
            if qos_rows:
                self.connection.executemany(
                    """
                    INSERT INTO qos_samples (
                        timestamp, device, management_ip, interface, policy,
                        class_name, offered_bps, drop_bps, packets, bytes,
                        total_drops, drop_delta, shape_rate
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    qos_rows,
                )
            self.connection.execute(
                "INSERT INTO device_samples VALUES "
                "(NULL,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                device_row,
            )
            self.connection.commit()

    def write_poll_error(self, device: str, address: str, error: str) -> None:
        with self.lock:
            self.connection.execute(
                """
                INSERT INTO device_samples (
                    timestamp, device, management_ip, reachable, error
                ) VALUES (?,?,?,?,?)
                """,
                (utc_now(), device, address, 0, error),
            )
            self.connection.commit()

    def event(
        self,
        level: str,
        component: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        with self.lock:
            self.connection.execute(
                """
                INSERT INTO service_events (
                    timestamp, level, component, message, details_json
                ) VALUES (?,?,?,?,?)
                """,
                (
                    utc_now(),
                    level,
                    component,
                    message,
                    None if details is None else json.dumps(details, sort_keys=True),
                ),
            )
            self.connection.commit()

    def counts(self) -> dict[str, int]:
        tables = (
            "flows",
            "syslog_events",
            "sla_samples",
            "interface_samples",
            "qos_samples",
            "device_samples",
            "service_events",
        )
        with self.lock:
            return {
                table: int(
                    self.connection.execute(
                        f"SELECT COUNT(*) FROM {table}"
                    ).fetchone()[0]
                )
                for table in tables
            }

    def try_counts(self, timeout: float = 0.1) -> dict[str, int] | None:
        """Return fast append-only row counters for status heartbeats.

        Telemetry tables are append-only during normal service operation.  Using
        ``MAX(id)`` avoids repeated full ``COUNT(*)`` scans as the database grows;
        exact counts remain available through :meth:`counts` for offline/reporting
        use.  The primary-key lookup is important because this method runs from the
        two-second health-heartbeat loop.
        """
        acquired = self.lock.acquire(timeout=timeout)
        if not acquired:
            return None
        try:
            tables = (
                "flows",
                "syslog_events",
                "sla_samples",
                "interface_samples",
                "qos_samples",
                "device_samples",
                "service_events",
            )
            return {
                table: int(
                    self.connection.execute(
                        f"SELECT COALESCE(MAX(id),0) FROM {table}"
                    ).fetchone()[0]
                )
                for table in tables
            }
        finally:
            self.lock.release()
