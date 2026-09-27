#!/usr/bin/env python3
"""Continuous local inference engine for AegisNet-WM.

Reads controlled endpoint NetFlow from telemetry.db, builds a 10-second
behavioral state, runs the trained prototype ensemble, and persists each new
prediction.  This process is intentionally independent of Streamlit.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import joblib
import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "features"))
sys.path.insert(0, str(ROOT / "models" / "world_model"))
sys.path.insert(0, str(ROOT / "intelligence"))

from security_state import build_state  # noqa: E402
from state_vector import FLOW_FEATURES  # noqa: E402
from inference import StateHistory, WorldForecaster  # noqa: E402
from open_world import OpenWorldAttackForecaster  # noqa: E402
from eve_shadow_calibration import EveShadowCalibrator  # noqa: E402
from next_stage import NextStageForecaster  # noqa: E402
from markov_fallback import MarkovFallback  # noqa: E402
from mitre import enrich_forecast as enrich_mitre  # noqa: E402
from topology import dominant_source_site, enrich_forecast as enrich_topology  # noqa: E402
from audit_chain import append_event as append_audit_event  # noqa: E402
from reporting import write_report  # noqa: E402
from playbook import enrich_forecast as enrich_playbook  # noqa: E402
from knowledge import enrich_forecast as enrich_knowledge  # noqa: E402
from artifact_integrity import verify_manifest  # noqa: E402
from production_guard import (  # noqa: E402
    DecisionStateMachine,
    OODGuard,
    advisory_gate,
    atomic_json_write,
    load_policy,
    telemetry_health,
    verify_file_sha256,
)


DATABASE = ROOT / "outputs" / "telemetry.db"
MODEL_DIR = ROOT / "models" / "artifacts" / "ntro-clean-traffic-v1"
DATASET = ROOT / "dataset" / "releases" / "ntro-clean-traffic-v1" / "training_states.csv"
STATUS_FILE = ROOT / "outputs" / "analysis-status.json"
PID_FILE = ROOT / "outputs" / "analysis-service.pid"
TELEMETRY_STATUS_FILE = ROOT / "outputs" / "telemetry-status.json"
DECISION_STATE_FILE = ROOT / "outputs" / "production-decision-state.json"
PRODUCTION_POLICY_FILE = ROOT / "config" / "production_policy.json"
CONTROLLED_IPS = ("10.1.10.10", "10.2.10.10", "10.10.10.10", "10.20.10.10")
CURRENT_CONFIDENCE_THRESHOLD = 0.60

SHADOW_OPEN_WORLD_ARTIFACTS = {
    "GENIS": ROOT / "models" / "artifacts" / "genis-open-world-v1",
    "CTU13": ROOT / "models" / "artifacts" / "ctu13-open-world-v1",
    "CICIDS2017": ROOT / "models" / "artifacts" / "cicids2017-open-world-v1",
}
EVE_SHADOW_CALIBRATION_ARTIFACT = (
    ROOT / "models" / "artifacts" / "eve-shadow-calibration-v1"
)
NEXT_STAGE_ARTIFACT = ROOT / "models" / "artifacts" / "genis-next-stage-v1"

SCHEMA = """
CREATE TABLE IF NOT EXISTS analysis_predictions (
    id INTEGER PRIMARY KEY,
    created_at TEXT NOT NULL,
    event_time TEXT NOT NULL,
    window_start TEXT NOT NULL,
    window_end TEXT NOT NULL,
    predicted_label TEXT NOT NULL,
    confidence REAL NOT NULL,
    cyber_risk REAL NOT NULL,
    risk_band TEXT NOT NULL,
    model_release TEXT NOT NULL,
    probabilities_json TEXT NOT NULL,
    state_json TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'LIVE',
    ground_truth TEXT,
    simulation_id INTEGER,
    operator_state TEXT,
    operator_reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_analysis_event_time
    ON analysis_predictions(event_time);

CREATE TABLE IF NOT EXISTS analysis_simulations (
    id INTEGER PRIMARY KEY,
    requested_at TEXT NOT NULL,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    label TEXT NOT NULL,
    state TEXT NOT NULL,
    row_index INTEGER NOT NULL DEFAULT 0,
    error TEXT
);
CREATE INDEX IF NOT EXISTS idx_analysis_sim_state
    ON analysis_simulations(state,id);

CREATE TABLE IF NOT EXISTS forecast_predictions (
    id INTEGER PRIMARY KEY,
    created_at TEXT NOT NULL,
    event_time TEXT NOT NULL,
    current_label TEXT NOT NULL,
    current_confidence REAL NOT NULL,
    source_site TEXT,
    model_release TEXT NOT NULL,
    evidence_status TEXT NOT NULL,
    forecast_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_forecast_event_time
    ON forecast_predictions(event_time);
"""


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def risk_band(risk: float) -> str:
    if risk >= 0.85:
        return "CRITICAL"
    if risk >= 0.65:
        return "HIGH"
    if risk >= 0.40:
        return "ELEVATED"
    return "LOW"


def flow_rows(connection: sqlite3.Connection, start: datetime, end: datetime) -> list[dict[str, Any]]:
    placeholders = ",".join("?" for _ in CONTROLLED_IPS)
    query = f"""
        SELECT * FROM flows
        WHERE src_ip IN ({placeholders})
          AND dst_ip IN ({placeholders})
          AND julianday(COALESCE(flow_end,timestamp)) >= julianday(?)
          AND julianday(COALESCE(flow_end,timestamp)) < julianday(?)
        ORDER BY julianday(COALESCE(flow_end,timestamp)),id
    """
    params = (*CONTROLLED_IPS, *CONTROLLED_IPS, start.isoformat(), end.isoformat())
    cursor = connection.execute(query, params)
    columns = [item[0] for item in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


def latest_event_time(connection: sqlite3.Connection) -> datetime | None:
    placeholders = ",".join("?" for _ in CONTROLLED_IPS)
    row = connection.execute(
        f"""
        SELECT MAX(COALESCE(flow_end,timestamp)) latest
        FROM flows
        WHERE src_ip IN ({placeholders}) AND dst_ip IN ({placeholders})
        """,
        (*CONTROLLED_IPS, *CONTROLLED_IPS),
    ).fetchone()
    if not row or not row[0]:
        return None
    value = datetime.fromisoformat(str(row[0]))
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def model_frame(state: dict[str, Any]) -> pd.DataFrame:
    return pd.DataFrame(
        [[float(state.get(feature) or 0.0) for feature in FLOW_FEATURES]],
        columns=list(FLOW_FEATURES),
    )


def predict(state: dict[str, Any], logistic: Any, forest: Any) -> tuple[str, float, float, dict[str, float]]:
    x = model_frame(state)
    lp = logistic.predict_proba(x)[0]
    fp = forest.predict_proba(x)[0]
    logistic_map = {str(label): float(value) for label, value in zip(logistic.classes_, lp)}
    forest_map = {str(label): float(value) for label, value in zip(forest.classes_, fp)}
    labels = sorted(set(logistic_map) | set(forest_map))
    probabilities = {
        label: (logistic_map.get(label, 0.0) + forest_map.get(label, 0.0)) / 2.0
        for label in labels
    }
    label = max(probabilities, key=probabilities.get)
    confidence = float(probabilities[label])
    risk = float(max(0.0, min(1.0, 1.0 - probabilities.get("BENIGN", 0.0))))
    return label, confidence, risk, probabilities


def binary_predict(
    state: dict[str, Any],
    logistic: Any,
    forest: Any,
    threshold: float,
) -> dict[str, Any]:
    x = model_frame(state)
    probabilities: list[float] = []
    for model in (logistic, forest):
        values = model.predict_proba(x)[0]
        classes = [str(value) for value in model.classes_]
        if "ATTACK" not in classes:
            raise RuntimeError("binary detector artifact does not expose ATTACK class")
        probabilities.append(float(values[classes.index("ATTACK")]))
    attack_probability = float(sum(probabilities) / len(probabilities))
    attack = attack_probability >= threshold
    return {
        "label": "ATTACK" if attack else "BENIGN",
        "attack_probability": attack_probability,
        "confidence": attack_probability if attack else 1.0 - attack_probability,
        "threshold": threshold,
        "model_votes": probabilities,
    }


def calibrated_current_decision(
    label: str,
    confidence: float,
    risk: float,
    threshold: float = CURRENT_CONFIDENCE_THRESHOLD,
) -> tuple[str, float, str]:
    """Convert the prototype classifier output into an operator-facing decision.

    The present-state detector is trained on a deliberately small clean seed set.
    Low-confidence samples are therefore surfaced as UNKNOWN rather than forced
    into an attack class.  This is an abstention policy, not a benign override.
    """

    if confidence < threshold:
        return "UNKNOWN", risk, "abstain_low_confidence"
    return label, risk, "model_classification"


def shadow_open_world_forecast(
    forecasters: dict[str, Any],
    history: list[dict[str, Any]],
) -> dict[str, Any]:
    """Run public-dataset forecasters without granting them alert authority.

    Cross-dataset calibration is not assumed to transfer to the EVE lab.  The
    resulting probabilities are therefore evidence/shadow signals only.
    """

    models: dict[str, Any] = {}
    by_seconds: dict[int, list[dict[str, Any]]] = {}
    for name, forecaster in forecasters.items():
        try:
            result = forecaster.forecast(history)
        except Exception as exc:
            models[name] = {"error": f"{type(exc).__name__}: {exc}"}
            continue
        horizons: dict[str, Any] = {}
        for _, item in result.get("horizons", {}).items():
            seconds = int(item.get("seconds") or 0)
            probability = float(item.get("future_attack_probability") or 0.0)
            threshold = float(item.get("threshold") or 0.0)
            alert = bool(item.get("alert"))
            record = {
                "seconds": seconds,
                "future_attack_probability": probability,
                "native_threshold": threshold,
                "native_alert": alert,
            }
            horizons[str(seconds)] = record
            by_seconds.setdefault(seconds, []).append({"model": name, **record})
        models[name] = {
            "model_release": result.get("model_release"),
            "evidence_status": result.get("evidence_status"),
            "history_steps_observed": result.get("history_steps_observed"),
            "history_steps_required": result.get("history_steps_required"),
            "horizons": horizons,
        }

    consensus: dict[str, Any] = {}
    for seconds, items in sorted(by_seconds.items()):
        probabilities = [float(item["future_attack_probability"]) for item in items]
        alert_votes = sum(bool(item["native_alert"]) for item in items)
        consensus[str(seconds)] = {
            "seconds": seconds,
            "models": [str(item["model"]) for item in items],
            "model_count": len(items),
            "mean_probability": sum(probabilities) / len(probabilities),
            "max_probability": max(probabilities),
            "native_alert_votes": alert_votes,
            "native_alert_fraction": alert_votes / len(items),
            "shadow_only": True,
        }
    return {
        "mode": "SHADOW_ONLY",
        "alert_authority": False,
        "reason": "public-dataset thresholds are not assumed to transfer across domains into EVE",
        "models": models,
        "consensus": consensus,
    }


def write_status(payload: dict[str, Any]) -> None:
    body = dict(payload)
    body["updated_at"] = utcnow().isoformat()
    atomic_json_write(STATUS_FILE, body)


def resolve_repo_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def checked_artifact(path: Path, *, require_manifest: bool) -> dict[str, Any]:
    result = verify_manifest(path, require=require_manifest)
    result["path"] = str(path)
    return result


def ensure_column(connection: sqlite3.Connection, table: str, name: str, sql_type: str) -> None:
    columns = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
    if name not in columns:
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {name} {sql_type}")
        connection.commit()


def insert_prediction(
    connection: sqlite3.Connection,
    *,
    event_time: datetime,
    start: datetime,
    end: datetime,
    state: dict[str, Any],
    label: str,
    confidence: float,
    risk: float,
    probabilities: dict[str, float],
    source: str,
    model_release: str,
    risk_band_override: str | None = None,
    ground_truth: str | None = None,
    simulation_id: int | None = None,
    operator_state: str | None = None,
    operator_reason: str | None = None,
) -> str:
    created_at = utcnow().isoformat()
    connection.execute(
        """
        INSERT INTO analysis_predictions (
            created_at,event_time,window_start,window_end,predicted_label,
            confidence,cyber_risk,risk_band,model_release,probabilities_json,state_json,
            source,ground_truth,simulation_id,operator_state,operator_reason
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            created_at,
            event_time.isoformat(),
            start.isoformat(),
            end.isoformat(),
            label,
            confidence,
            risk,
            risk_band_override or risk_band(risk),
            model_release,
            json.dumps(probabilities, sort_keys=True),
            json.dumps(state, sort_keys=True, default=str),
            source,
            ground_truth,
            simulation_id,
            operator_state,
            operator_reason,
        ),
    )
    connection.commit()
    return created_at


def run(poll_seconds: float) -> int:
    policy = load_policy(PRODUCTION_POLICY_FILE)
    require_manifests = bool(policy.get("require_artifact_manifests", True))
    current_artifact = resolve_repo_path(str(policy.get("current_detector_artifact", MODEL_DIR)))
    current_integrity = checked_artifact(current_artifact, require_manifest=require_manifests)
    if not current_integrity.get("valid"):
        write_status(
            {
                "state": "FAILED_CLOSED",
                "pid": os.getpid(),
                "error": "authoritative detector artifact integrity check failed",
                "artifact_integrity": {"current_detector": current_integrity},
            }
        )
        raise RuntimeError("authoritative detector artifact integrity check failed")
    logistic = joblib.load(current_artifact / "logistic_pipeline.joblib")
    forest = joblib.load(current_artifact / "random_forest_pipeline.joblib")
    current_metadata = json.loads((current_artifact / "metadata.json").read_text(encoding="utf-8"))
    current_confidence_threshold = float(
        current_metadata.get("confidence_threshold", CURRENT_CONFIDENCE_THRESHOLD)
    )
    world_artifact = resolve_repo_path(
        str(policy.get("world_model_artifact", "models/artifacts/genis-world-v1"))
    )
    world_integrity = checked_artifact(world_artifact, require_manifest=require_manifests)
    world_forecaster = None
    world_load_error = None
    if not world_integrity.get("valid"):
        world_load_error = "artifact integrity verification failed"
    elif (world_artifact / "world_model.pt").exists():
        try:
            world_forecaster = WorldForecaster(world_artifact)
            allowed_evidence = set(policy.get("world_model_allowed_evidence") or [])
            if allowed_evidence and world_forecaster.metadata.get("evidence_status") not in allowed_evidence:
                world_load_error = (
                    f"evidence status {world_forecaster.metadata.get('evidence_status')} is not production-allowed"
                )
                world_forecaster = None
        except Exception as exc:
            world_load_error = f"{type(exc).__name__}: {exc}"
    markov_fallback = None
    try:
        markov_fallback = MarkovFallback(world_artifact)
    except Exception:
        markov_fallback = None
    shadow_forecasters: dict[str, Any] = {}
    shadow_load_errors: dict[str, str] = {}
    artifact_integrity: dict[str, Any] = {
        "current_detector": current_integrity,
        "world_model": world_integrity,
    }
    binary_detector = None
    binary_load_error = None
    binary_artifact = resolve_repo_path(str(policy.get("binary_detector_challenger", "")))
    if str(policy.get("binary_detector_challenger", "")):
        binary_integrity = checked_artifact(binary_artifact, require_manifest=require_manifests)
        artifact_integrity["binary_detector"] = binary_integrity
        try:
            if not binary_integrity.get("valid"):
                raise RuntimeError("artifact integrity verification failed")
            binary_metadata = json.loads((binary_artifact / "metadata.json").read_text(encoding="utf-8"))
            binary_detector = {
                "logistic": joblib.load(binary_artifact / "logistic_pipeline.joblib"),
                "forest": joblib.load(binary_artifact / "random_forest_pipeline.joblib"),
                "metadata": binary_metadata,
                "threshold": float(binary_metadata["attack_probability_threshold"]),
            }
        except Exception as exc:
            binary_load_error = f"{type(exc).__name__}: {exc}"
    for name, artifact_dir in SHADOW_OPEN_WORLD_ARTIFACTS.items():
        if not (artifact_dir / "metadata.json").exists():
            continue
        integrity = checked_artifact(artifact_dir, require_manifest=require_manifests)
        artifact_integrity[f"shadow_{name.lower()}"] = integrity
        if not integrity.get("valid"):
            shadow_load_errors[name] = "artifact integrity verification failed"
            continue
        try:
            shadow_forecasters[name] = OpenWorldAttackForecaster(artifact_dir)
        except Exception as exc:
            shadow_load_errors[name] = f"{type(exc).__name__}: {exc}"
    eve_shadow_calibrator = None
    eve_shadow_calibration_error = None
    if (EVE_SHADOW_CALIBRATION_ARTIFACT / "metadata.json").exists():
        calibration_integrity = checked_artifact(
            EVE_SHADOW_CALIBRATION_ARTIFACT,
            require_manifest=require_manifests,
        )
        artifact_integrity["eve_calibration"] = calibration_integrity
        try:
            if not calibration_integrity.get("valid"):
                raise RuntimeError("artifact integrity verification failed")
            eve_shadow_calibrator = EveShadowCalibrator(EVE_SHADOW_CALIBRATION_ARTIFACT)
        except Exception as exc:
            eve_shadow_calibration_error = f"{type(exc).__name__}: {exc}"
    next_stage_forecaster = None
    next_stage_load_error = None
    if (NEXT_STAGE_ARTIFACT / "metadata.json").exists():
        next_integrity = checked_artifact(NEXT_STAGE_ARTIFACT, require_manifest=require_manifests)
        artifact_integrity["next_stage"] = next_integrity
        try:
            if not next_integrity.get("valid"):
                raise RuntimeError("artifact integrity verification failed")
            next_stage_forecaster = NextStageForecaster(NEXT_STAGE_ARTIFACT)
        except Exception as exc:
            next_stage_load_error = f"{type(exc).__name__}: {exc}"
    ood_guard = None
    ood_load_error = None
    ood_path = resolve_repo_path(str(policy["ood"]["profile"]))
    try:
        ood_integrity = verify_file_sha256(ood_path, policy["ood"].get("profile_sha256"))
        artifact_integrity["ood_profile"] = ood_integrity
        if not ood_integrity.get("valid"):
            raise RuntimeError("OOD profile integrity verification failed")
        ood_guard = OODGuard(ood_path, policy)
    except Exception as exc:
        ood_load_error = f"{type(exc).__name__}: {exc}"
    decision_machine = DecisionStateMachine(DECISION_STATE_FILE, policy)
    state_history = StateHistory(maxlen=12)
    PID_FILE.write_text(str(os.getpid()), encoding="ascii")

    connection = sqlite3.connect(DATABASE, timeout=60)
    connection.execute("PRAGMA busy_timeout=60000")
    connection.execute("PRAGMA journal_mode=WAL")
    connection.executescript(SCHEMA)
    ensure_column(connection, "analysis_predictions", "source", "TEXT NOT NULL DEFAULT 'LIVE'")
    ensure_column(connection, "analysis_predictions", "ground_truth", "TEXT")
    ensure_column(connection, "analysis_predictions", "simulation_id", "INTEGER")
    ensure_column(connection, "analysis_predictions", "operator_state", "TEXT")
    ensure_column(connection, "analysis_predictions", "operator_reason", "TEXT")
    connection.commit()

    training = pd.read_csv(DATASET)

    last_event: str | None = None
    last_world_bin: str | None = None
    inference_count = 0
    service_started_at = utcnow().isoformat()
    write_status(
        {
            "state": "RUNNING",
            "pid": os.getpid(),
            "started_at": service_started_at,
            "last_inference_at": None,
            "last_event_time": None,
            "inference_count": 0,
            "error": None,
        }
    )

    try:
        while True:
            try:
                simulation = connection.execute(
                    "SELECT * FROM analysis_simulations WHERE state='RUNNING' ORDER BY id DESC LIMIT 1"
                ).fetchone()
                if simulation:
                    sim_id = int(simulation[0])
                    started_at = datetime.fromisoformat(str(simulation[2]))
                    sim_label = str(simulation[4])
                    current_index = int(simulation[6])
                    subset = training.loc[training["label"] == sim_label].reset_index(drop=True)
                    if subset.empty:
                        connection.execute(
                            "UPDATE analysis_simulations SET state='FAILED',ended_at=?,error=? WHERE id=?",
                            (utcnow().isoformat(), "No replay rows for label", sim_id),
                        )
                        connection.commit()
                        time.sleep(poll_seconds)
                        continue

                    elapsed = max(0.0, (utcnow() - started_at).total_seconds())
                    desired_index = min(int(elapsed // 3.0), len(subset) - 1)
                    if desired_index != current_index or inference_count == 0:
                        row = subset.iloc[desired_index]
                        state = {feature: float(row.get(feature, 0.0) or 0.0) for feature in FLOW_FEATURES}
                        label, confidence, risk, probabilities = predict(state, logistic, forest)
                        now = utcnow()
                        created_at = insert_prediction(
                            connection,
                            event_time=now,
                            start=now - timedelta(seconds=10),
                            end=now,
                            state=state,
                            label=label,
                            confidence=confidence,
                            risk=risk,
                            probabilities=probabilities,
                            source="SIMULATION",
                            model_release=str(current_metadata.get("model_release", current_artifact.name)),
                            ground_truth=sim_label,
                        simulation_id=sim_id,
                        operator_state="SIMULATION",
                        operator_reason="simulation replay",
                        )
                        connection.execute(
                            "UPDATE analysis_simulations SET row_index=? WHERE id=?",
                            (desired_index, sim_id),
                        )
                        connection.commit()
                        inference_count += 1
                        write_status(
                            {
                                "state": "RUNNING",
                                "mode": "SIMULATION",
                                "pid": os.getpid(),
                                "started_at": service_started_at,
                                "last_inference_at": created_at,
                                "last_event_time": now.isoformat(),
                                "inference_count": inference_count,
                                "predicted_label": label,
                                "ground_truth": sim_label,
                                "confidence": confidence,
                                "cyber_risk": risk,
                                "risk_band": risk_band(risk),
                                "simulation_id": sim_id,
                                "simulation_row": desired_index,
                                "error": None,
                            }
                        )
                    if elapsed >= max(6.0, len(subset) * 3.0):
                        connection.execute(
                            "UPDATE analysis_simulations SET state='COMPLETED',ended_at=? WHERE id=?",
                            (utcnow().isoformat(), sim_id),
                        )
                        connection.commit()
                    time.sleep(poll_seconds)
                    continue

                latest = latest_event_time(connection)
                telemetry = telemetry_health(
                    TELEMETRY_STATUS_FILE,
                    heartbeat_max_age_seconds=float(policy["telemetry"]["heartbeat_max_age_seconds"]),
                    max_poll_error_fraction=float(policy["telemetry"]["max_poll_error_fraction"]),
                )
                flow_age = (utcnow() - latest).total_seconds() if latest is not None else None
                flow_fresh = latest is not None and flow_age <= float(policy["telemetry"]["flow_max_age_seconds"])
                if not flow_fresh:
                    state_history.clear()
                    operator = decision_machine.update(
                        label="UNKNOWN",
                        confidence=None,
                        data_valid=False,
                    )
                    write_status(
                        {
                            "state": "RUNNING",
                            "mode": "NO_DATA",
                            "pid": os.getpid(),
                            "started_at": service_started_at,
                            "last_inference_at": None,
                            "last_event_time": latest.isoformat() if latest else None,
                            "inference_count": inference_count,
                            "predicted_label": "UNKNOWN",
                            "confidence": None,
                            "cyber_risk": 0.0,
                            "risk_band": "NO_DATA",
                            "operator_state": operator.state,
                            "operator_reason": operator.reason,
                            "telemetry_health": telemetry,
                            "flow_age_seconds": flow_age,
                            "world_model": (
                                "READY_NEURAL"
                                if world_forecaster is not None
                                else ("READY_MARKOV" if markov_fallback is not None else "UNAVAILABLE")
                            ),
                            "world_model_load_error": world_load_error,
                            "shadow_models": sorted(shadow_forecasters),
                            "shadow_model_load_errors": shadow_load_errors,
                            "eve_shadow_calibration": (
                                "READY"
                                if eve_shadow_calibrator is not None
                                else "UNTRAINED"
                            ),
                            "eve_shadow_calibration_load_error": eve_shadow_calibration_error,
                            "next_stage_model": (
                                "READY"
                                if next_stage_forecaster is not None
                                else "UNAVAILABLE"
                            ),
                            "next_stage_load_error": next_stage_load_error,
                            "ood_guard": {
                                "status": "READY" if ood_guard is not None else "UNAVAILABLE",
                                "error": ood_load_error,
                            },
                            "artifact_integrity": artifact_integrity,
                            "binary_detector": (
                                "READY_CHALLENGER" if binary_detector is not None else "UNAVAILABLE"
                            ),
                            "binary_detector_load_error": binary_load_error,
                            "decision_source": "visibility_lost",
                            "error": None,
                        }
                    )
                    time.sleep(poll_seconds)
                    continue
                if latest is not None and latest.isoformat() != last_event:
                    end = latest + timedelta(milliseconds=1)
                    start = end - timedelta(seconds=10)
                    current = flow_rows(connection, start, end)
                    previous = flow_rows(connection, start - timedelta(seconds=60), start)
                    state = build_state(current, previous_records=previous)
                    raw_label, confidence, risk, probabilities = predict(state, logistic, forest)
                    label, risk, decision_source = calibrated_current_decision(
                        raw_label,
                        confidence,
                        risk,
                        current_confidence_threshold,
                    )
                    authority_enabled = bool(policy.get("current_detector_authority_enabled", False))
                    binary_result = None
                    if binary_detector is not None:
                        binary_result = binary_predict(
                            state,
                            binary_detector["logistic"],
                            binary_detector["forest"],
                            binary_detector["threshold"],
                        )
                    authority_label = (
                        str(binary_result["label"])
                        if authority_enabled and binary_result is not None
                        else "UNKNOWN"
                    )
                    authority_confidence = (
                        float(binary_result["confidence"])
                        if authority_enabled and binary_result is not None
                        else confidence
                    )
                    data_valid_for_authority = bool(telemetry.get("healthy")) and (
                        binary_result is not None or not authority_enabled
                    )
                    operator = decision_machine.update(
                        label=authority_label,
                        confidence=authority_confidence,
                        data_valid=data_valid_for_authority,
                    )
                    if not authority_enabled and telemetry.get("healthy"):
                        operator.reason = "authoritative detector promotion pending; current classification is advisory only"
                    decision_band = (
                        "DEGRADED"
                        if operator.state == "DEGRADED"
                        else ("UNVERIFIED" if label == "UNKNOWN" else risk_band(risk))
                    )
                    forecast = None
                    ood_result: dict[str, Any] = {
                        "status": "UNAVAILABLE",
                        "in_domain": False,
                        "reason": ood_load_error or "OOD profile unavailable",
                    }
                    if world_forecaster is not None or markov_fallback is not None:
                        bin_seconds = (
                            world_forecaster.config.window_seconds
                            if world_forecaster is not None
                            else 10
                        )
                        bin_epoch = int(latest.timestamp() // bin_seconds) * bin_seconds
                        world_end = datetime.fromtimestamp(bin_epoch, tz=timezone.utc)
                        world_bin = world_end.isoformat()
                        if world_end > datetime.fromtimestamp(0, tz=timezone.utc) and world_bin != last_world_bin:
                            world_start = world_end - timedelta(seconds=bin_seconds)
                            world_rows = flow_rows(connection, world_start, world_end)
                            world_previous = flow_rows(
                                connection,
                                world_start - timedelta(seconds=60),
                                world_start,
                            )
                            world_state = build_state(world_rows, previous_records=world_previous)
                            state_history.append(world_state)
                            if ood_guard is not None:
                                ood_result = ood_guard.evaluate(state_history.values())
                            if world_forecaster is not None:
                                forecast = world_forecaster.forecast(state_history.values())
                            else:
                                forecast = markov_fallback.forecast(raw_label)
                            if shadow_forecasters:
                                shadow_result = shadow_open_world_forecast(
                                    shadow_forecasters,
                                    state_history.values(),
                                )
                                if eve_shadow_calibrator is not None:
                                    shadow_result["eve_calibration"] = eve_shadow_calibrator.enrich(
                                        shadow_result
                                    )
                                elif eve_shadow_calibration_error:
                                    shadow_result["eve_calibration"] = {
                                        "mode": "UNAVAILABLE",
                                        "alert_authority": False,
                                        "error": eve_shadow_calibration_error,
                                    }
                                forecast["shadow_real_models"] = shadow_result
                            if next_stage_forecaster is not None:
                                forecast["next_stage_forecast"] = next_stage_forecaster.forecast(
                                    state_history.values(),
                                    label,
                                )
                            elif next_stage_load_error:
                                forecast["next_stage_forecast"] = {
                                    "alert_authority": False,
                                    "error": next_stage_load_error,
                                }
                            history_fill = float(forecast.get("history_fill_ratio") or 0.0)
                            production_gate = advisory_gate(
                                telemetry=telemetry,
                                ood=ood_result,
                                history_fill_ratio=history_fill,
                                policy=policy,
                            )
                            production_gate["telemetry"] = telemetry
                            production_gate["ood"] = ood_result
                            production_gate["artifact_integrity_valid"] = all(
                                bool(item.get("valid"))
                                for item in artifact_integrity.values()
                            )
                            if not production_gate["artifact_integrity_valid"]:
                                production_gate["advisory_eligible"] = False
                                production_gate["status"] = "WITHHELD"
                                production_gate["reasons"].append("artifact integrity failure")
                            forecast["production_guard"] = production_gate
                            eve_cal = ((forecast.get("shadow_real_models") or {}).get("eve_calibration") or {})
                            for item in (eve_cal.get("horizons") or {}).values():
                                item["operator_advisory"] = bool(
                                    item.get("shadow_alert") and production_gate["advisory_eligible"]
                                )
                                item["operator_advisory_authority"] = False
                            source_site = dominant_source_site(world_rows or current)
                            forecast = enrich_topology(forecast, source_site)
                            forecast = enrich_mitre(forecast)
                            forecast = enrich_knowledge(forecast)
                            forecast = enrich_playbook(forecast)
                            audit_payload = {
                                "event_time": world_end.isoformat(),
                                "current_label": label,
                                "raw_current_label": raw_label,
                                "current_confidence": confidence,
                                "source_site": source_site,
                                "forecast": forecast,
                            }
                            audit_record = append_audit_event("forecast", audit_payload)
                            forecast["audit_hash"] = audit_record["hash"]
                            forecast["audit_previous_hash"] = audit_record["previous_hash"]
                            report_path = write_report(
                                {"label": label, "confidence": confidence, "risk": risk},
                                forecast,
                            )
                            forecast["report_path"] = str(report_path)
                            connection.execute(
                                """
                                INSERT INTO forecast_predictions (
                                    created_at,event_time,current_label,current_confidence,source_site,
                                    model_release,evidence_status,forecast_json
                                ) VALUES (?,?,?,?,?,?,?,?)
                                """,
                                (
                                    utcnow().isoformat(),
                                    world_end.isoformat(),
                                    label,
                                    confidence,
                                    source_site,
                                    str(forecast.get("model_release", "unknown")),
                                    str(forecast.get("evidence_status", "unknown")),
                                    json.dumps(forecast, sort_keys=True),
                                ),
                            )
                            connection.commit()
                            last_world_bin = world_bin
                    created_at = insert_prediction(
                        connection,
                        event_time=latest,
                        start=start,
                        end=end,
                        state=state,
                        label=label,
                        confidence=confidence,
                        risk=risk,
                        probabilities=probabilities,
                        source="LIVE",
                        model_release=str(current_metadata.get("model_release", current_artifact.name)),
                        risk_band_override=decision_band,
                        operator_state=operator.state,
                        operator_reason=operator.reason,
                    )
                    last_event = latest.isoformat()
                    inference_count += 1
                    write_status(
                        {
                            "state": "RUNNING",
                            "mode": "LIVE",
                            "pid": os.getpid(),
                            "started_at": service_started_at,
                            "last_inference_at": created_at,
                            "last_event_time": last_event,
                            "inference_count": inference_count,
                            "predicted_label": label,
                            "raw_predicted_label": raw_label,
                            "confidence": confidence,
                            "cyber_risk": risk,
                            "risk_band": decision_band,
                            "decision_source": decision_source,
                            "current_detector_authority_enabled": authority_enabled,
                            "current_detector_release": current_metadata.get("model_release", current_artifact.name),
                            "current_detector_evidence_status": current_metadata.get("evidence_status"),
                            "current_detector_confidence_threshold": current_confidence_threshold,
                            "binary_detector": binary_result,
                            "binary_detector_status": (
                                "AUTHORITY"
                                if authority_enabled and binary_result is not None
                                else ("CHALLENGER" if binary_result is not None else "UNAVAILABLE")
                            ),
                            "binary_detector_load_error": binary_load_error,
                            "operator_state": operator.state,
                            "operator_reason": operator.reason,
                            "operator_previous_state": operator.previous_state,
                            "operator_attack_streak": operator.attack_streak,
                            "operator_benign_streak": operator.benign_streak,
                            "telemetry_health": telemetry,
                            "ood": ood_result,
                            "artifact_integrity": artifact_integrity,
                            "eve_shadow_calibration": (
                                "ACTIVE_SHADOW"
                                if eve_shadow_calibrator is not None
                                else "UNTRAINED"
                            ),
                            "next_stage_model": (
                                "ACTIVE_SHADOW"
                                if next_stage_forecaster is not None
                                else "UNAVAILABLE"
                            ),
                            "world_model": (
                                "ACTIVE_NEURAL"
                                if forecast is not None and world_forecaster is not None
                                else (
                                    "ACTIVE_MARKOV"
                                    if forecast is not None and markov_fallback is not None
                                    else (
                                        "WAITING_BIN"
                                        if world_forecaster is not None or markov_fallback is not None
                                        else "UNAVAILABLE"
                                    )
                                )
                            ),
                            "forecast": forecast,
                            "error": None,
                        }
                    )
                elif STATUS_FILE.exists():
                    try:
                        heartbeat = json.loads(STATUS_FILE.read_text(encoding="utf-8"))
                        write_status(heartbeat)
                    except Exception:
                        pass
                time.sleep(poll_seconds)
            except KeyboardInterrupt:
                raise
            except Exception as exc:
                write_status(
                    {
                        "state": "RUNNING_WITH_ERROR",
                        "pid": os.getpid(),
                        "updated_at": utcnow().isoformat(),
                        "last_inference_at": None,
                        "last_event_time": last_event,
                        "inference_count": inference_count,
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )
                time.sleep(max(2.0, poll_seconds))
    finally:
        connection.close()
        PID_FILE.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--poll-seconds", type=float, default=2.0)
    args = parser.parse_args()
    if not 0.5 <= args.poll_seconds <= 30:
        parser.error("--poll-seconds must be between 0.5 and 30")
    return run(args.poll_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
