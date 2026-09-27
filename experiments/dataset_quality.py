#!/usr/bin/env python3
"""Audit and export a campaign as a versioned, checksummed dataset release."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def export_query(
    connection: sqlite3.Connection,
    path: Path,
    query: str,
    parameters: tuple[Any, ...],
) -> int:
    cursor = connection.execute(query, parameters)
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow([column[0] for column in cursor.description])
        for row in cursor:
            writer.writerow(row)
            count += 1
    return count


def latest_campaign(connection: sqlite3.Connection) -> str:
    row = connection.execute(
        "SELECT campaign_id FROM dataset_campaigns ORDER BY created_at DESC LIMIT 1"
    ).fetchone()
    if row is None:
        raise RuntimeError("no dataset campaign exists")
    return str(row[0])


def quality_report(
    connection: sqlite3.Connection, campaign_id: str
) -> dict[str, Any]:
    campaign = dict(
        connection.execute(
            "SELECT * FROM dataset_campaigns WHERE campaign_id=?", (campaign_id,)
        ).fetchone()
    )
    plan = [
        dict(row)
        for row in connection.execute(
            """
            SELECT scenario,severity,traffic_profile,split,status,scenario_run_id
            FROM dataset_campaign_plan WHERE campaign_id=?
            ORDER BY sequence_index
            """,
            (campaign_id,),
        )
    ]
    completed_ids = [
        row["scenario_run_id"]
        for row in plan
        if row["status"] == "COMPLETED" and row["scenario_run_id"] is not None
    ]
    report: dict[str, Any] = {
        "campaign_id": campaign_id,
        "generated_at": utc_now(),
        "campaign_status": campaign["status"],
        "planned_runs": len(plan),
        "completed_runs": len(completed_ids),
        "failed_runs": sum(row["status"] == "FAILED" for row in plan),
        "pending_runs": sum(row["status"] in {"PENDING", "RUNNING"} for row in plan),
        "runs_by_scenario": {},
        "runs_by_severity": {},
        "runs_by_traffic_profile": {},
        "runs_by_split": {},
        "quality_gates": {},
    }
    for field, output in (
        ("scenario", "runs_by_scenario"),
        ("severity", "runs_by_severity"),
        ("traffic_profile", "runs_by_traffic_profile"),
        ("split", "runs_by_split"),
    ):
        for row in plan:
            if row["status"] == "COMPLETED":
                key = str(row[field])
                report[output][key] = report[output].get(key, 0) + 1
    if completed_ids:
        placeholders = ",".join("?" for _ in completed_ids)
        device = connection.execute(
            f"""
            SELECT COUNT(*) rows, AVG(sample_count) mean_samples,
              AVG(sample_count>=3) sufficient_ratio,
              AVG(reachable_ratio) reachability,
              SUM(CASE WHEN phase='recovery' AND reachable_ratio<1 THEN 1 ELSE 0 END)
                bad_recovery_windows
            FROM device_feature_windows WHERE run_id IN ({placeholders})
            """,
            completed_ids,
        ).fetchone()
        sla = connection.execute(
            f"""
            SELECT COUNT(*) rows, AVG(sample_count) mean_samples,
              AVG(sample_count>=3) sufficient_ratio,
              AVG(successful_sample_ratio) successful_ratio,
              SUM(rtt_std IS NULL) missing_std
            FROM sla_feature_windows WHERE run_id IN ({placeholders})
            """,
            completed_ids,
        ).fetchone()
        report["device_windows"] = dict(device)
        report["sla_windows"] = dict(sla)
        qos = connection.execute(
            f"""
            SELECT COUNT(*) rows, AVG(sample_count) mean_samples,
              AVG(sample_count>=3) sufficient_ratio,
              SUM(drop_delta) drop_packets
            FROM qos_feature_windows WHERE run_id IN ({placeholders})
            """,
            completed_ids,
        ).fetchone()
        report["qos_windows"] = dict(qos)
    else:
        report["device_windows"] = {}
        report["sla_windows"] = {}
        report["qos_windows"] = {}
    gates = {
        "no_failed_runs": report["failed_runs"] == 0,
        "campaign_complete": report["pending_runs"] == 0,
        "minimum_30_runs": report["completed_runs"] >= 30,
        "minimum_5_runs_per_class": bool(report["runs_by_scenario"])
        and min(report["runs_by_scenario"].values()) >= 5,
        "train_validation_test_present": all(
            report["runs_by_split"].get(split, 0) > 0
            for split in ("train", "validation", "test")
        ),
        "sla_windows_have_3_samples": (
            report.get("sla_windows", {}).get("sufficient_ratio") or 0
        ) >= 0.95,
        "recovery_is_clean": (
            report.get("device_windows", {}).get("bad_recovery_windows") or 0
        ) == 0,
        "qos_telemetry_present": (
            report.get("qos_windows", {}).get("rows") or 0
        ) > 0,
        "license_selected": False,
        "persistent_identifier_assigned": False,
        "external_replication_complete": False,
    }
    report["quality_gates"] = gates
    report["publication_ready"] = all(gates.values())
    return report


def export_release(
    connection: sqlite3.Connection,
    campaign_id: str,
    output: Path,
    report: dict[str, Any],
) -> None:
    output.mkdir(parents=True, exist_ok=True)
    queries = {
        "campaign_plan.csv": (
            "SELECT * FROM dataset_campaign_plan WHERE campaign_id=? "
            "ORDER BY sequence_index",
            (campaign_id,),
        ),
        "scenario_runs.csv": (
            "SELECT * FROM scenario_runs WHERE campaign_id=? ORDER BY id",
            (campaign_id,),
        ),
        "scenario_phases.csv": (
            """
            SELECT p.* FROM scenario_phases p JOIN scenario_runs r ON r.id=p.run_id
            WHERE r.campaign_id=? ORDER BY p.id
            """,
            (campaign_id,),
        ),
        "device_features.csv": (
            "SELECT * FROM device_feature_windows WHERE campaign_id=? ORDER BY id",
            (campaign_id,),
        ),
        "sla_features.csv": (
            "SELECT * FROM sla_feature_windows WHERE campaign_id=? ORDER BY id",
            (campaign_id,),
        ),
        "qos_features.csv": (
            "SELECT * FROM qos_feature_windows WHERE campaign_id=? ORDER BY id",
            (campaign_id,),
        ),
        "raw_sla.csv": (
            """
            SELECT p.run_id,p.id phase_id,p.phase,p.label,s.*
            FROM scenario_phases p JOIN scenario_runs r ON r.id=p.run_id
            JOIN sla_samples s ON julianday(s.timestamp)
              BETWEEN julianday(p.started_at) AND julianday(p.ended_at)
            WHERE r.campaign_id=? ORDER BY s.id
            """,
            (campaign_id,),
        ),
        "raw_device.csv": (
            """
            SELECT p.run_id,p.id phase_id,p.phase,p.label,s.*
            FROM scenario_phases p JOIN scenario_runs r ON r.id=p.run_id
            JOIN device_samples s ON julianday(s.timestamp)
              BETWEEN julianday(p.started_at) AND julianday(p.ended_at)
            WHERE r.campaign_id=? ORDER BY s.id
            """,
            (campaign_id,),
        ),
        "raw_interfaces.csv": (
            """
            SELECT p.run_id,p.id phase_id,p.phase,p.label,s.*
            FROM scenario_phases p JOIN scenario_runs r ON r.id=p.run_id
            JOIN interface_samples s ON julianday(s.timestamp)
              BETWEEN julianday(p.started_at) AND julianday(p.ended_at)
            WHERE r.campaign_id=? ORDER BY s.id
            """,
            (campaign_id,),
        ),
        "raw_qos.csv": (
            """
            SELECT p.run_id,p.id phase_id,p.phase,p.label,s.*
            FROM scenario_phases p JOIN scenario_runs r ON r.id=p.run_id
            JOIN qos_samples s ON julianday(s.timestamp)
              BETWEEN julianday(p.started_at) AND julianday(p.ended_at)
            WHERE r.campaign_id=? ORDER BY s.id
            """,
            (campaign_id,),
        ),
        "raw_flows.csv": (
            """
            SELECT p.run_id,p.id phase_id,p.phase,p.label,s.*
            FROM scenario_phases p JOIN scenario_runs r ON r.id=p.run_id
            JOIN flows s ON julianday(s.timestamp)
              BETWEEN julianday(p.started_at) AND julianday(p.ended_at)
            WHERE r.campaign_id=? ORDER BY s.id
            """,
            (campaign_id,),
        ),
        "raw_syslog.csv": (
            """
            SELECT p.run_id,p.id phase_id,p.phase,p.label,s.*
            FROM scenario_phases p JOIN scenario_runs r ON r.id=p.run_id
            JOIN syslog_events s ON julianday(s.timestamp)
              BETWEEN julianday(p.started_at) AND julianday(p.ended_at)
            WHERE r.campaign_id=? ORDER BY s.id
            """,
            (campaign_id,),
        ),
    }
    row_counts = {
        filename: export_query(connection, output / filename, query, parameters)
        for filename, (query, parameters) in queries.items()
    }
    (output / "quality_report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    croissant = {
        "@context": {
            "@language": "en",
            "@vocab": "https://schema.org/",
            "cr": "http://mlcommons.org/croissant/",
            "rai": "http://mlcommons.org/croissant/RAI/",
        },
        "@type": "Dataset",
        "name": "Air-Gapped Predictive Copilot Telemetry Dataset",
        "description": (
            "Controlled dual-transport MPLS/Internet DMVPN telemetry with "
            "reversible network faults and run-grouped labels."
        ),
        "version": "0.1.0-pilot",
        "license": "LICENSE-PENDING",
        "datePublished": utc_now(),
        "keywords": [
            "network telemetry", "NetFlow v9", "IP SLA", "DMVPN", "MPLS",
            "fault detection", "fault prediction",
        ],
        "rai:dataCollection": (
            "Generated in a local EVE-NG lab using deterministic and randomized "
            "fault injection; contains no human-subject or public-user traffic."
        ),
        "rai:dataLimitations": (
            "Cisco 7200 emulation and one topology do not establish production "
            "network generalization. Management addresses are synthetic/private."
        ),
    }
    (output / "croissant.json").write_text(
        json.dumps(croissant, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    card = f"""# Air-Gapped Predictive Copilot Dataset

Campaign: `{campaign_id}`

This release contains controlled telemetry from an emulated dual-transport
MPLS/Internet DMVPN network. Labels are assigned from exact fault-controller
phase boundaries. Train, validation and test membership is assigned at the
complete-run level to prevent overlapping-window leakage.

## Intended tasks

- Current-state fault detection and fault-family diagnosis.
- Recovery verification.
- Forecasting only from rows carrying `fault_within_30s` or
  `fault_within_60s`; post-fault rows must not be presented as prediction.

## Limitations

- One emulated topology and one IOS family.
- Synthetic workload; not representative of all enterprise traffic.
- EVE/Cisco images are not redistributed.
- The release license and persistent DOI are pending owner selection.
- External replication on an independently rebuilt lab is still required.

See `quality_report.json`, `croissant.json` and `manifest.json`.
"""
    (output / "DATASET_CARD.md").write_text(card, encoding="utf-8")
    files = sorted(path for path in output.iterdir() if path.is_file())
    manifest = {
        "campaign_id": campaign_id,
        "created_at": utc_now(),
        "row_counts": row_counts,
        "files": {
            path.name: {"bytes": path.stat().st_size, "sha256": sha256(path)}
            for path in files
        },
    }
    (output / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign-id")
    parser.add_argument(
        "--database", type=Path, default=ROOT / "outputs" / "telemetry.db"
    )
    parser.add_argument("--export", action="store_true")
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    connection = sqlite3.connect(args.database)
    connection.row_factory = sqlite3.Row
    try:
        campaign_id = args.campaign_id or latest_campaign(connection)
        report = quality_report(connection, campaign_id)
        print(json.dumps(report, indent=2, sort_keys=True))
        if args.export:
            output = args.output or ROOT / "dataset" / "releases" / campaign_id
            export_release(connection, campaign_id, output, report)
            print(f"Release exported to {output}")
        return 0 if report["publication_ready"] else 1
    finally:
        connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
