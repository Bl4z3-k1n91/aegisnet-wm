"""Scenario metadata and labelled feature extraction for telemetry.db."""

from __future__ import annotations

import json
import math
import sqlite3
import statistics
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = """
CREATE TABLE IF NOT EXISTS scenario_runs (
    id INTEGER PRIMARY KEY,
    scenario TEXT NOT NULL,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    status TEXT NOT NULL,
    parameters_json TEXT,
    error TEXT
);

CREATE TABLE IF NOT EXISTS scenario_phases (
    id INTEGER PRIMARY KEY,
    run_id INTEGER NOT NULL REFERENCES scenario_runs(id),
    phase TEXT NOT NULL,
    label TEXT NOT NULL,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    details_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_scenario_phases_run ON scenario_phases(run_id);

CREATE TABLE IF NOT EXISTS feature_windows (
    id INTEGER PRIMARY KEY,
    run_id INTEGER NOT NULL,
    phase_id INTEGER NOT NULL,
    phase TEXT NOT NULL,
    label TEXT NOT NULL,
    device TEXT NOT NULL,
    window_start TEXT NOT NULL,
    window_end TEXT NOT NULL,
    duration_seconds REAL,
    sla_mpls_rtt_avg REAL,
    sla_mpls_rtt_max REAL,
    sla_inet_rtt_avg REAL,
    sla_inet_rtt_max REAL,
    sla_mpls_failures INTEGER,
    sla_inet_failures INTEGER,
    input_bps_avg REAL,
    input_bps_max INTEGER,
    output_bps_avg REAL,
    output_bps_max INTEGER,
    input_drop_delta INTEGER,
    output_drop_delta INTEGER,
    input_error_delta INTEGER,
    output_error_delta INTEGER,
    flow_records INTEGER,
    flow_bytes INTEGER,
    flow_packets INTEGER,
    syslog_count INTEGER,
    syslog_warning_count INTEGER,
    cpu_avg REAL,
    cpu_max INTEGER,
    reachable_ratio REAL,
    bgp_min INTEGER,
    ospf_min INTEGER,
    eigrp_min INTEGER,
    dmvpn_min INTEGER,
    ikev2_min INTEGER
);
CREATE INDEX IF NOT EXISTS idx_feature_windows_run ON feature_windows(run_id);
CREATE INDEX IF NOT EXISTS idx_feature_windows_label ON feature_windows(label);

CREATE TABLE IF NOT EXISTS device_feature_windows (
    id INTEGER PRIMARY KEY,
    run_id INTEGER NOT NULL,
    phase_id INTEGER NOT NULL,
    campaign_id TEXT,
    split TEXT NOT NULL,
    scenario TEXT NOT NULL,
    severity TEXT,
    phase TEXT NOT NULL,
    label TEXT NOT NULL,
    device TEXT NOT NULL,
    window_start TEXT NOT NULL,
    window_end TEXT NOT NULL,
    duration_seconds REAL NOT NULL,
    seconds_from_phase_start REAL NOT NULL,
    time_to_fault_seconds REAL,
    fault_within_30s INTEGER NOT NULL,
    fault_within_60s INTEGER NOT NULL,
    sample_count INTEGER NOT NULL,
    cpu_mean REAL,
    cpu_std REAL,
    cpu_p95 REAL,
    cpu_max REAL,
    memory_util_mean REAL,
    reachable_ratio REAL,
    bgp_min INTEGER,
    ospf_min INTEGER,
    eigrp_min INTEGER,
    dmvpn_min INTEGER,
    ikev2_min INTEGER,
    interface_sample_count INTEGER NOT NULL,
    input_bps_mean REAL,
    input_bps_p95 REAL,
    input_bps_max REAL,
    output_bps_mean REAL,
    output_bps_p95 REAL,
    output_bps_max REAL,
    input_drop_delta INTEGER NOT NULL,
    output_drop_delta INTEGER NOT NULL,
    input_error_delta INTEGER NOT NULL,
    output_error_delta INTEGER NOT NULL,
    flow_records INTEGER NOT NULL,
    flow_bytes INTEGER NOT NULL,
    flow_packets INTEGER NOT NULL,
    ef_bytes INTEGER NOT NULL,
    af31_bytes INTEGER NOT NULL,
    best_effort_bytes INTEGER NOT NULL,
    distinct_applications INTEGER NOT NULL,
    syslog_count INTEGER NOT NULL,
    syslog_warning_count INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_device_features_run
    ON device_feature_windows(run_id, phase_id, device);
CREATE INDEX IF NOT EXISTS idx_device_features_split
    ON device_feature_windows(split, scenario, severity);

CREATE TABLE IF NOT EXISTS sla_feature_windows (
    id INTEGER PRIMARY KEY,
    run_id INTEGER NOT NULL,
    phase_id INTEGER NOT NULL,
    campaign_id TEXT,
    split TEXT NOT NULL,
    scenario TEXT NOT NULL,
    severity TEXT,
    phase TEXT NOT NULL,
    label TEXT NOT NULL,
    device TEXT NOT NULL,
    operation_id INTEGER NOT NULL,
    transport TEXT,
    target_role TEXT,
    window_start TEXT NOT NULL,
    window_end TEXT NOT NULL,
    duration_seconds REAL NOT NULL,
    seconds_from_phase_start REAL NOT NULL,
    time_to_fault_seconds REAL,
    fault_within_30s INTEGER NOT NULL,
    fault_within_60s INTEGER NOT NULL,
    sample_count INTEGER NOT NULL,
    rtt_mean REAL,
    rtt_std REAL,
    rtt_min REAL,
    rtt_p50 REAL,
    rtt_p95 REAL,
    rtt_max REAL,
    rtt_mad REAL,
    rtt_cv REAL,
    rtt_slope_per_second REAL,
    success_delta INTEGER NOT NULL,
    failure_delta INTEGER NOT NULL,
    successful_sample_ratio REAL
);
CREATE INDEX IF NOT EXISTS idx_sla_features_run
    ON sla_feature_windows(run_id, phase_id, device, operation_id);
CREATE INDEX IF NOT EXISTS idx_sla_features_split
    ON sla_feature_windows(split, scenario, severity);

CREATE TABLE IF NOT EXISTS qos_feature_windows (
    id INTEGER PRIMARY KEY,
    run_id INTEGER NOT NULL,
    phase_id INTEGER NOT NULL,
    campaign_id TEXT,
    split TEXT NOT NULL,
    scenario TEXT NOT NULL,
    severity TEXT,
    phase TEXT NOT NULL,
    label TEXT NOT NULL,
    device TEXT NOT NULL,
    interface TEXT NOT NULL,
    policy TEXT NOT NULL,
    class_name TEXT NOT NULL,
    window_start TEXT NOT NULL,
    window_end TEXT NOT NULL,
    duration_seconds REAL NOT NULL,
    seconds_from_phase_start REAL NOT NULL,
    time_to_fault_seconds REAL,
    fault_within_30s INTEGER NOT NULL,
    fault_within_60s INTEGER NOT NULL,
    sample_count INTEGER NOT NULL,
    offered_bps_mean REAL,
    offered_bps_p95 REAL,
    offered_bps_max REAL,
    drop_bps_mean REAL,
    drop_bps_max REAL,
    drop_delta INTEGER NOT NULL,
    packet_delta INTEGER NOT NULL,
    byte_delta INTEGER NOT NULL,
    shape_rate_min INTEGER,
    shape_rate_max INTEGER
);
CREATE INDEX IF NOT EXISTS idx_qos_features_run
    ON qos_feature_windows(run_id, phase_id, device, interface, policy, class_name);
"""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ScenarioStore:
    def __init__(self, database: Path) -> None:
        self.connection = sqlite3.connect(database, timeout=60)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA busy_timeout=60000")
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.executescript(SCHEMA)
        self._migrate()
        self.connection.commit()

    def _migrate(self) -> None:
        existing = {
            row[1] for row in self.connection.execute("PRAGMA table_info(scenario_runs)")
        }
        additions = {
            "campaign_id": "TEXT",
            "run_seed": "INTEGER",
            "sequence_index": "INTEGER",
            "split": "TEXT NOT NULL DEFAULT 'train'",
            "severity": "TEXT",
        }
        for column, definition in additions.items():
            if column not in existing:
                self.connection.execute(
                    f"ALTER TABLE scenario_runs ADD COLUMN {column} {definition}"
                )

    def close(self) -> None:
        self.connection.close()

    def start_run(
        self,
        scenario: str,
        parameters: dict[str, Any],
        *,
        campaign_id: str | None = None,
        run_seed: int | None = None,
        sequence_index: int | None = None,
        split: str = "train",
        severity: str | None = None,
    ) -> int:
        cursor = self.connection.execute(
            """
            INSERT INTO scenario_runs (
                scenario, started_at, status, parameters_json, campaign_id,
                run_seed, sequence_index, split, severity
            ) VALUES (?,?,?,?,?,?,?,?,?)
            """,
            (
                scenario,
                utc_now(),
                "RUNNING",
                json.dumps(parameters, sort_keys=True),
                campaign_id,
                run_seed,
                sequence_index,
                split,
                severity,
            ),
        )
        self.connection.commit()
        return int(cursor.lastrowid)

    def finish_run(self, run_id: int, status: str, error: str | None = None) -> None:
        self.connection.execute(
            """
            UPDATE scenario_runs
            SET ended_at=?, status=?, error=?
            WHERE id=?
            """,
            (utc_now(), status, error, run_id),
        )
        self.connection.commit()

    def start_phase(
        self,
        run_id: int,
        phase: str,
        label: str,
        details: dict[str, Any] | None = None,
    ) -> int:
        cursor = self.connection.execute(
            """
            INSERT INTO scenario_phases (
                run_id, phase, label, started_at, details_json
            ) VALUES (?,?,?,?,?)
            """,
            (
                run_id,
                phase,
                label,
                utc_now(),
                None if details is None else json.dumps(details, sort_keys=True),
            ),
        )
        self.connection.commit()
        return int(cursor.lastrowid)

    def end_phase(self, phase_id: int) -> None:
        self.connection.execute(
            "UPDATE scenario_phases SET ended_at=? WHERE id=?",
            (utc_now(), phase_id),
        )
        self.connection.commit()

    def _one(self, query: str, parameters: tuple[Any, ...]) -> dict[str, Any]:
        row = self.connection.execute(query, parameters).fetchone()
        return {} if row is None else dict(row)

    def extract_features(self, run_id: int) -> int:
        phases = self.connection.execute(
            """
            SELECT id, phase, label, started_at, ended_at
            FROM scenario_phases
            WHERE run_id=? AND ended_at IS NOT NULL
            ORDER BY id
            """,
            (run_id,),
        ).fetchall()
        devices = [
            row[0]
            for row in self.connection.execute(
                """
                SELECT DISTINCT device FROM device_samples
                WHERE device IS NOT NULL ORDER BY device
                """
            )
        ]
        self.connection.execute("DELETE FROM feature_windows WHERE run_id=?", (run_id,))
        inserted = 0
        for phase in phases:
            start, end = phase["started_at"], phase["ended_at"]
            duration = (
                datetime.fromisoformat(end) - datetime.fromisoformat(start)
            ).total_seconds()
            for device in devices:
                period = (device, start, end)
                sla = self._one(
                    """
                    SELECT
                      AVG(CASE WHEN transport='MPLS' THEN rtt_ms END) sla_mpls_rtt_avg,
                      MAX(CASE WHEN transport='MPLS' THEN rtt_ms END) sla_mpls_rtt_max,
                      AVG(CASE WHEN transport='INTERNET' THEN rtt_ms END) sla_inet_rtt_avg,
                      MAX(CASE WHEN transport='INTERNET' THEN rtt_ms END) sla_inet_rtt_max,
                      COALESCE(SUM(CASE WHEN transport='MPLS' THEN failure_delta ELSE 0 END),0) sla_mpls_failures,
                      COALESCE(SUM(CASE WHEN transport='INTERNET' THEN failure_delta ELSE 0 END),0) sla_inet_failures
                    FROM sla_samples
                    WHERE device=? AND julianday(timestamp)
                      BETWEEN julianday(?) AND julianday(?)
                    """,
                    period,
                )
                interface = self._one(
                    """
                    SELECT AVG(input_bps) input_bps_avg, MAX(input_bps) input_bps_max,
                           AVG(output_bps) output_bps_avg, MAX(output_bps) output_bps_max,
                           COALESCE(SUM(input_drop_delta),0) input_drop_delta,
                           COALESCE(SUM(output_drop_delta),0) output_drop_delta,
                           COALESCE(SUM(input_error_delta),0) input_error_delta,
                           COALESCE(SUM(output_error_delta),0) output_error_delta
                    FROM interface_samples
                    WHERE device=? AND julianday(timestamp)
                      BETWEEN julianday(?) AND julianday(?)
                    """,
                    period,
                )
                flow = self._one(
                    """
                    SELECT COUNT(*) flow_records, COALESCE(SUM(bytes),0) flow_bytes,
                           COALESCE(SUM(packets),0) flow_packets
                    FROM flows
                    WHERE device=? AND julianday(timestamp)
                      BETWEEN julianday(?) AND julianday(?)
                    """,
                    period,
                )
                syslog = self._one(
                    """
                    SELECT COUNT(*) syslog_count,
                           COALESCE(SUM(CASE WHEN severity <= 4 THEN 1 ELSE 0 END),0)
                             syslog_warning_count
                    FROM syslog_events
                    WHERE device=? AND julianday(timestamp)
                      BETWEEN julianday(?) AND julianday(?)
                    """,
                    period,
                )
                health = self._one(
                    """
                    SELECT AVG(cpu_5s) cpu_avg, MAX(cpu_5s) cpu_max,
                           AVG(reachable) reachable_ratio,
                           MIN(bgp_established) bgp_min, MIN(ospf_full) ospf_min,
                           MIN(eigrp_neighbors) eigrp_min, MIN(dmvpn_up) dmvpn_min,
                           MIN(ikev2_ready) ikev2_min
                    FROM device_samples
                    WHERE device=? AND julianday(timestamp)
                      BETWEEN julianday(?) AND julianday(?)
                    """,
                    period,
                )
                values = {
                    **sla,
                    **interface,
                    **flow,
                    **syslog,
                    **health,
                }
                columns = [
                    "sla_mpls_rtt_avg", "sla_mpls_rtt_max",
                    "sla_inet_rtt_avg", "sla_inet_rtt_max",
                    "sla_mpls_failures", "sla_inet_failures",
                    "input_bps_avg", "input_bps_max",
                    "output_bps_avg", "output_bps_max",
                    "input_drop_delta", "output_drop_delta",
                    "input_error_delta", "output_error_delta",
                    "flow_records", "flow_bytes", "flow_packets",
                    "syslog_count", "syslog_warning_count",
                    "cpu_avg", "cpu_max", "reachable_ratio",
                    "bgp_min", "ospf_min", "eigrp_min", "dmvpn_min", "ikev2_min",
                ]
                self.connection.execute(
                    f"""
                    INSERT INTO feature_windows (
                        run_id, phase_id, phase, label, device,
                        window_start, window_end, duration_seconds,
                        {", ".join(columns)}
                    ) VALUES ({", ".join("?" for _ in range(8 + len(columns)))})
                    """,
                    (
                        run_id,
                        phase["id"],
                        phase["phase"],
                        phase["label"],
                        device,
                        start,
                        end,
                        duration,
                        *(values.get(column) for column in columns),
                    ),
                )
                inserted += 1
        self.connection.commit()
        return inserted

    @staticmethod
    def _percentile(values: list[float], percentile: float) -> float | None:
        if not values:
            return None
        ordered = sorted(values)
        position = (len(ordered) - 1) * percentile
        low = math.floor(position)
        high = math.ceil(position)
        if low == high:
            return float(ordered[low])
        weight = position - low
        return float(ordered[low] * (1 - weight) + ordered[high] * weight)

    @classmethod
    def _summary(cls, values: list[float]) -> dict[str, float | None]:
        if not values:
            return {
                "mean": None, "std": None, "min": None, "p50": None,
                "p95": None, "max": None, "mad": None, "cv": None,
            }
        mean = statistics.fmean(values)
        std = statistics.stdev(values) if len(values) > 1 else 0.0
        median = statistics.median(values)
        mad = statistics.median(abs(value - median) for value in values)
        return {
            "mean": mean,
            "std": std,
            "min": min(values),
            "p50": median,
            "p95": cls._percentile(values, 0.95),
            "max": max(values),
            "mad": mad,
            "cv": None if mean == 0 else std / mean,
        }

    @staticmethod
    def _slope(points: list[tuple[str, float]]) -> float | None:
        if len(points) < 2:
            return None
        origin = datetime.fromisoformat(points[0][0])
        xs = [
            (datetime.fromisoformat(timestamp) - origin).total_seconds()
            for timestamp, _ in points
        ]
        ys = [value for _, value in points]
        x_mean, y_mean = statistics.fmean(xs), statistics.fmean(ys)
        denominator = sum((value - x_mean) ** 2 for value in xs)
        if denominator == 0:
            return 0.0
        return sum(
            (x - x_mean) * (y - y_mean) for x, y in zip(xs, ys)
        ) / denominator

    @staticmethod
    def _windows(
        start: datetime,
        end: datetime,
        window_seconds: float,
        stride_seconds: float,
    ) -> list[tuple[datetime, datetime]]:
        from datetime import timedelta

        duration = (end - start).total_seconds()
        if duration <= window_seconds:
            return [(start, end)]
        windows: list[tuple[datetime, datetime]] = []
        cursor = start
        width = timedelta(seconds=window_seconds)
        stride = timedelta(seconds=stride_seconds)
        while cursor + width <= end:
            windows.append((cursor, cursor + width))
            cursor += stride
        tail = (end - width, end)
        if not windows or windows[-1] != tail:
            windows.append(tail)
        return windows

    def extract_rich_features(
        self,
        run_id: int,
        *,
        window_seconds: float = 30,
        stride_seconds: float = 10,
    ) -> dict[str, int]:
        run = self.connection.execute(
            """
            SELECT scenario, campaign_id, split, severity
            FROM scenario_runs WHERE id=?
            """,
            (run_id,),
        ).fetchone()
        if run is None:
            raise ValueError(f"scenario run {run_id} does not exist")
        phases = self.connection.execute(
            """
            SELECT id, phase, label, started_at, ended_at
            FROM scenario_phases
            WHERE run_id=? AND ended_at IS NOT NULL ORDER BY id
            """,
            (run_id,),
        ).fetchall()
        fault_start = next(
            (
                datetime.fromisoformat(row["started_at"])
                for row in phases
                if row["phase"].startswith("fault")
            ),
            None,
        )
        self.connection.execute(
            "DELETE FROM device_feature_windows WHERE run_id=?", (run_id,)
        )
        self.connection.execute(
            "DELETE FROM sla_feature_windows WHERE run_id=?", (run_id,)
        )
        self.connection.execute(
            "DELETE FROM qos_feature_windows WHERE run_id=?", (run_id,)
        )
        self.connection.commit()
        counts = {"device": 0, "sla": 0, "qos": 0}
        for phase in phases:
            phase_start = datetime.fromisoformat(phase["started_at"])
            phase_end = datetime.fromisoformat(phase["ended_at"])
            for start_dt, end_dt in self._windows(
                phase_start, phase_end, window_seconds, stride_seconds
            ):
                start, end = start_dt.isoformat(), end_dt.isoformat()
                duration = (end_dt - start_dt).total_seconds()
                offset = (start_dt - phase_start).total_seconds()
                time_to_fault = (
                    (fault_start - end_dt).total_seconds()
                    if fault_start is not None and end_dt <= fault_start
                    else None
                )
                forecast_30 = int(
                    time_to_fault is not None and 0 <= time_to_fault <= 30
                )
                forecast_60 = int(
                    time_to_fault is not None and 0 <= time_to_fault <= 60
                )
                devices = [
                    row[0]
                    for row in self.connection.execute(
                        """
                        SELECT DISTINCT device FROM device_samples
                        WHERE julianday(timestamp) BETWEEN julianday(?) AND julianday(?)
                        ORDER BY device
                        """,
                        (start, end),
                    )
                ]
                for device in devices:
                    self._insert_device_window(
                        run_id, phase, run, device, start, end, duration, offset,
                        time_to_fault, forecast_30, forecast_60,
                    )
                    counts["device"] += 1
                operations = self.connection.execute(
                    """
                    SELECT DISTINCT device, operation_id, transport, target_role
                    FROM sla_samples
                    WHERE julianday(timestamp) BETWEEN julianday(?) AND julianday(?)
                    ORDER BY device, operation_id
                    """,
                    (start, end),
                ).fetchall()
                for operation in operations:
                    self._insert_sla_window(
                        run_id, phase, run, operation, start, end, duration, offset,
                        time_to_fault, forecast_30, forecast_60,
                    )
                    counts["sla"] += 1
                qos_classes = self.connection.execute(
                    """
                    SELECT DISTINCT device, interface, policy, class_name
                    FROM qos_samples
                    WHERE julianday(timestamp) BETWEEN julianday(?) AND julianday(?)
                    ORDER BY device, interface, policy, class_name
                    """,
                    (start, end),
                ).fetchall()
                for qos_class in qos_classes:
                    self._insert_qos_window(
                        run_id, phase, run, qos_class, start, end, duration, offset,
                        time_to_fault, forecast_30, forecast_60,
                    )
                    counts["qos"] += 1
            self.connection.commit()
        self.connection.commit()
        return counts

    def _base_values(
        self,
        run_id: int,
        phase: sqlite3.Row,
        run: sqlite3.Row,
        start: str,
        end: str,
        duration: float,
        offset: float,
        time_to_fault: float | None,
        forecast_30: int,
        forecast_60: int,
    ) -> tuple[Any, ...]:
        return (
            run_id, phase["id"], run["campaign_id"], run["split"],
            run["scenario"], run["severity"], phase["phase"], phase["label"],
            start, end, duration, offset, time_to_fault, forecast_30, forecast_60,
        )

    def _insert_device_window(
        self,
        run_id: int,
        phase: sqlite3.Row,
        run: sqlite3.Row,
        device: str,
        start: str,
        end: str,
        duration: float,
        offset: float,
        time_to_fault: float | None,
        forecast_30: int,
        forecast_60: int,
    ) -> None:
        samples = self.connection.execute(
            """
            SELECT * FROM device_samples WHERE device=? AND
            julianday(timestamp) BETWEEN julianday(?) AND julianday(?)
            ORDER BY timestamp
            """,
            (device, start, end),
        ).fetchall()
        cpu = [float(row["cpu_5s"]) for row in samples if row["cpu_5s"] is not None]
        cpu_summary = self._summary(cpu)
        memory = [
            100.0 * row["memory_used"] / row["memory_total"]
            for row in samples
            if row["memory_used"] is not None and row["memory_total"]
        ]
        interfaces = self.connection.execute(
            """
            SELECT * FROM interface_samples WHERE device=? AND
            julianday(timestamp) BETWEEN julianday(?) AND julianday(?)
            """,
            (device, start, end),
        ).fetchall()
        input_rates = [
            float(row["input_bps"]) for row in interfaces
            if row["input_bps"] is not None
        ]
        output_rates = [
            float(row["output_bps"]) for row in interfaces
            if row["output_bps"] is not None
        ]
        input_summary = self._summary(input_rates)
        output_summary = self._summary(output_rates)
        flow = self.connection.execute(
            """
            SELECT COUNT(*) records, COALESCE(SUM(bytes),0) bytes,
              COALESCE(SUM(packets),0) packets,
              COALESCE(SUM(CASE WHEN dscp=46 THEN bytes ELSE 0 END),0) ef_bytes,
              COALESCE(SUM(CASE WHEN dscp=26 THEN bytes ELSE 0 END),0) af31_bytes,
              COALESCE(SUM(CASE WHEN dscp NOT IN (26,46) OR dscp IS NULL
                           THEN bytes ELSE 0 END),0) best_effort_bytes,
              COUNT(DISTINCT application) applications
            FROM flows WHERE device=? AND
            julianday(timestamp) BETWEEN julianday(?) AND julianday(?)
            """,
            (device, start, end),
        ).fetchone()
        syslog = self.connection.execute(
            """
            SELECT COUNT(*) records,
              COALESCE(SUM(CASE WHEN severity<=4 THEN 1 ELSE 0 END),0) warnings
            FROM syslog_events WHERE device=? AND
            julianday(timestamp) BETWEEN julianday(?) AND julianday(?)
            """,
            (device, start, end),
        ).fetchone()
        minima = lambda column: min(
            (row[column] for row in samples if row[column] is not None),
            default=None,
        )
        values = (
            *self._base_values(
                run_id, phase, run, start, end, duration, offset,
                time_to_fault, forecast_30, forecast_60,
            )[:8],
            device,
            *self._base_values(
                run_id, phase, run, start, end, duration, offset,
                time_to_fault, forecast_30, forecast_60,
            )[8:],
            len(samples), cpu_summary["mean"], cpu_summary["std"],
            cpu_summary["p95"], cpu_summary["max"],
            statistics.fmean(memory) if memory else None,
            statistics.fmean(row["reachable"] for row in samples) if samples else None,
            minima("bgp_established"), minima("ospf_full"),
            minima("eigrp_neighbors"), minima("dmvpn_up"), minima("ikev2_ready"),
            len(interfaces), input_summary["mean"], input_summary["p95"],
            input_summary["max"], output_summary["mean"], output_summary["p95"],
            output_summary["max"],
            sum((row["input_drop_delta"] or 0) for row in interfaces),
            sum((row["output_drop_delta"] or 0) for row in interfaces),
            sum((row["input_error_delta"] or 0) for row in interfaces),
            sum((row["output_error_delta"] or 0) for row in interfaces),
            flow["records"], flow["bytes"], flow["packets"], flow["ef_bytes"],
            flow["af31_bytes"], flow["best_effort_bytes"], flow["applications"],
            syslog["records"], syslog["warnings"],
        )
        columns = [
            "run_id", "phase_id", "campaign_id", "split", "scenario", "severity",
            "phase", "label", "device", "window_start", "window_end",
            "duration_seconds", "seconds_from_phase_start", "time_to_fault_seconds",
            "fault_within_30s", "fault_within_60s", "sample_count", "cpu_mean",
            "cpu_std", "cpu_p95", "cpu_max", "memory_util_mean", "reachable_ratio",
            "bgp_min", "ospf_min", "eigrp_min", "dmvpn_min", "ikev2_min",
            "interface_sample_count", "input_bps_mean", "input_bps_p95",
            "input_bps_max", "output_bps_mean", "output_bps_p95", "output_bps_max",
            "input_drop_delta", "output_drop_delta", "input_error_delta",
            "output_error_delta", "flow_records", "flow_bytes", "flow_packets",
            "ef_bytes", "af31_bytes", "best_effort_bytes", "distinct_applications",
            "syslog_count", "syslog_warning_count",
        ]
        self.connection.execute(
            f"INSERT INTO device_feature_windows ({','.join(columns)}) "
            f"VALUES ({','.join('?' for _ in columns)})",
            values,
        )

    def _insert_sla_window(
        self,
        run_id: int,
        phase: sqlite3.Row,
        run: sqlite3.Row,
        operation: sqlite3.Row,
        start: str,
        end: str,
        duration: float,
        offset: float,
        time_to_fault: float | None,
        forecast_30: int,
        forecast_60: int,
    ) -> None:
        rows = self.connection.execute(
            """
            SELECT timestamp, rtt_ms, return_code, success_delta, failure_delta
            FROM sla_samples WHERE device=? AND operation_id=? AND
            julianday(timestamp) BETWEEN julianday(?) AND julianday(?)
            ORDER BY timestamp
            """,
            (operation["device"], operation["operation_id"], start, end),
        ).fetchall()
        rtt = [float(row["rtt_ms"]) for row in rows if row["rtt_ms"] is not None]
        summary = self._summary(rtt)
        successful = sum(
            1 for row in rows
            if row["return_code"] and "OK" in row["return_code"].upper()
        )
        points = [
            (row["timestamp"], float(row["rtt_ms"]))
            for row in rows if row["rtt_ms"] is not None
        ]
        base = self._base_values(
            run_id, phase, run, start, end, duration, offset,
            time_to_fault, forecast_30, forecast_60,
        )
        values = (
            *base[:8], operation["device"], operation["operation_id"],
            operation["transport"], operation["target_role"], *base[8:],
            len(rows), summary["mean"], summary["std"], summary["min"],
            summary["p50"], summary["p95"], summary["max"], summary["mad"],
            summary["cv"], self._slope(points),
            sum((row["success_delta"] or 0) for row in rows),
            sum((row["failure_delta"] or 0) for row in rows),
            successful / len(rows) if rows else None,
        )
        columns = [
            "run_id", "phase_id", "campaign_id", "split", "scenario", "severity",
            "phase", "label", "device", "operation_id", "transport", "target_role",
            "window_start", "window_end", "duration_seconds",
            "seconds_from_phase_start", "time_to_fault_seconds",
            "fault_within_30s", "fault_within_60s", "sample_count", "rtt_mean",
            "rtt_std", "rtt_min", "rtt_p50", "rtt_p95", "rtt_max", "rtt_mad",
            "rtt_cv", "rtt_slope_per_second", "success_delta", "failure_delta",
            "successful_sample_ratio",
        ]
        self.connection.execute(
            f"INSERT INTO sla_feature_windows ({','.join(columns)}) "
            f"VALUES ({','.join('?' for _ in columns)})",
            values,
        )

    def _insert_qos_window(
        self,
        run_id: int,
        phase: sqlite3.Row,
        run: sqlite3.Row,
        qos_class: sqlite3.Row,
        start: str,
        end: str,
        duration: float,
        offset: float,
        time_to_fault: float | None,
        forecast_30: int,
        forecast_60: int,
    ) -> None:
        rows = self.connection.execute(
            """
            SELECT * FROM qos_samples
            WHERE device=? AND interface=? AND policy=? AND class_name=?
              AND julianday(timestamp) BETWEEN julianday(?) AND julianday(?)
            ORDER BY timestamp
            """,
            (
                qos_class["device"], qos_class["interface"], qos_class["policy"],
                qos_class["class_name"], start, end,
            ),
        ).fetchall()
        offered = [
            float(row["offered_bps"]) for row in rows
            if row["offered_bps"] is not None
        ]
        drops = [
            float(row["drop_bps"]) for row in rows if row["drop_bps"] is not None
        ]
        offered_summary = self._summary(offered)
        drop_summary = self._summary(drops)
        packets = [row["packets"] for row in rows if row["packets"] is not None]
        byte_counts = [row["bytes"] for row in rows if row["bytes"] is not None]
        shape_rates = [
            row["shape_rate"] for row in rows if row["shape_rate"] is not None
        ]
        base = self._base_values(
            run_id, phase, run, start, end, duration, offset,
            time_to_fault, forecast_30, forecast_60,
        )
        values = (
            *base[:8], qos_class["device"], qos_class["interface"],
            qos_class["policy"], qos_class["class_name"], *base[8:], len(rows),
            offered_summary["mean"], offered_summary["p95"],
            offered_summary["max"], drop_summary["mean"], drop_summary["max"],
            sum((row["drop_delta"] or 0) for row in rows),
            max(packets) - min(packets) if len(packets) > 1 else 0,
            max(byte_counts) - min(byte_counts) if len(byte_counts) > 1 else 0,
            min(shape_rates) if shape_rates else None,
            max(shape_rates) if shape_rates else None,
        )
        columns = [
            "run_id", "phase_id", "campaign_id", "split", "scenario", "severity",
            "phase", "label", "device", "interface", "policy", "class_name",
            "window_start", "window_end", "duration_seconds",
            "seconds_from_phase_start", "time_to_fault_seconds",
            "fault_within_30s", "fault_within_60s", "sample_count",
            "offered_bps_mean", "offered_bps_p95", "offered_bps_max",
            "drop_bps_mean", "drop_bps_max", "drop_delta", "packet_delta",
            "byte_delta", "shape_rate_min", "shape_rate_max",
        ]
        self.connection.execute(
            f"INSERT INTO qos_feature_windows ({','.join(columns)}) "
            f"VALUES ({','.join('?' for _ in columns)})",
            values,
        )
