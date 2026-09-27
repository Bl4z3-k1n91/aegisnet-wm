from __future__ import annotations

import json
import hashlib
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import numpy as np


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY = ROOT / "config" / "production_policy.json"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        result = datetime.fromisoformat(str(value))
        return result if result.tzinfo else result.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def atomic_json_write(path: Path, payload: dict[str, Any]) -> None:
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


def load_policy(path: Path = DEFAULT_POLICY) -> dict[str, Any]:
    policy = json.loads(path.read_text(encoding="utf-8"))
    if int(policy.get("schema_version", 0)) != 1:
        raise ValueError("unsupported production policy schema")
    return policy


def verify_file_sha256(path: Path, expected: str | None) -> dict[str, Any]:
    if not path.exists():
        return {"valid": False, "status": "MISSING", "path": str(path), "sha256": None}
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if not expected:
        return {"valid": True, "status": "UNPINNED", "path": str(path), "sha256": digest}
    valid = digest.lower() == str(expected).lower()
    return {
        "valid": valid,
        "status": "VALID" if valid else "TAMPERED",
        "path": str(path),
        "sha256": digest,
        "expected_sha256": str(expected).lower(),
    }


def telemetry_health(
    status_file: Path,
    *,
    heartbeat_max_age_seconds: float,
    max_poll_error_fraction: float,
) -> dict[str, Any]:
    if not status_file.exists():
        return {"healthy": False, "status": "MISSING", "reason": "telemetry status file missing"}
    try:
        status = json.loads(status_file.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"healthy": False, "status": "INVALID", "reason": f"{type(exc).__name__}: {exc}"}
    updated = parse_time(status.get("updated_at"))
    age = (utcnow() - updated).total_seconds() if updated else float("inf")
    fatal = list(status.get("fatal_errors") or [])
    polls = dict(status.get("last_poll_at") or {})
    poll_errors = dict(status.get("poll_errors") or {})
    poll_error_fraction = len(poll_errors) / max(len(polls) + len(poll_errors), 1)
    reasons: list[str] = []
    if age > heartbeat_max_age_seconds:
        reasons.append(f"heartbeat stale ({age:.1f}s)")
    if fatal:
        reasons.append(f"fatal telemetry errors: {len(fatal)}")
    if poll_error_fraction > max_poll_error_fraction:
        reasons.append(f"poll error fraction {poll_error_fraction:.2f}")
    healthy = not reasons
    return {
        "healthy": healthy,
        "status": "HEALTHY" if healthy else "DEGRADED",
        "reason": "; ".join(reasons) if reasons else "ok",
        "heartbeat_age_seconds": None if not np.isfinite(age) else float(age),
        "poll_error_fraction": float(poll_error_fraction),
        "fatal_error_count": len(fatal),
        "last_flow_at": status.get("last_flow_at"),
        "updated_at": status.get("updated_at"),
    }


@dataclass
class DecisionResult:
    state: str
    reason: str
    attack_streak: int
    benign_streak: int
    previous_state: str


class DecisionStateMachine:
    def __init__(self, state_file: Path, policy: dict[str, Any]) -> None:
        self.state_file = Path(state_file)
        cfg = policy["decision_hysteresis"]
        self.alert_confirm = int(cfg["alert_confirm_windows"])
        self.clear_confirm = int(cfg["clear_confirm_windows"])
        self.minimum_alert_confidence = float(cfg["minimum_alert_confidence"])
        self.state = "NORMAL"
        self.attack_streak = 0
        self.benign_streak = 0
        self.last_label: str | None = None
        if self.state_file.exists():
            try:
                saved = json.loads(self.state_file.read_text(encoding="utf-8"))
                self.state = str(saved.get("state") or "NORMAL")
                self.attack_streak = int(saved.get("attack_streak") or 0)
                self.benign_streak = int(saved.get("benign_streak") or 0)
                self.last_label = saved.get("last_label")
            except Exception:
                pass

    def _save(self, reason: str) -> None:
        atomic_json_write(
            self.state_file,
            {
                "state": self.state,
                "attack_streak": self.attack_streak,
                "benign_streak": self.benign_streak,
                "last_label": self.last_label,
                "reason": reason,
                "updated_at": utcnow().isoformat(),
            },
        )

    def update(
        self,
        *,
        label: str,
        confidence: float | None,
        data_valid: bool,
    ) -> DecisionResult:
        previous = self.state
        if not data_valid:
            self.state = "DEGRADED"
            self.attack_streak = 0
            self.benign_streak = 0
            reason = "telemetry/data quality invalid; operator decision withheld"
        elif label == "UNKNOWN":
            self.state = "UNVERIFIED"
            self.attack_streak = 0
            self.benign_streak = 0
            reason = "current detector abstained"
        elif label == "BENIGN":
            self.attack_streak = 0
            self.benign_streak += 1
            if previous in {"ALERT", "RECOVERING"} and self.benign_streak < self.clear_confirm:
                self.state = "RECOVERING"
                reason = f"waiting for {self.clear_confirm} consecutive benign windows"
            else:
                self.state = "NORMAL"
                reason = "benign current-state evidence"
        else:
            self.benign_streak = 0
            self.attack_streak += 1
            if (
                self.attack_streak >= self.alert_confirm
                and confidence is not None
                and confidence >= self.minimum_alert_confidence
            ):
                self.state = "ALERT"
                reason = f"confirmed {self.attack_streak} consecutive attack windows"
            else:
                self.state = "WATCH"
                reason = f"attack evidence pending confirmation ({self.attack_streak}/{self.alert_confirm})"
        self.last_label = label
        self._save(reason)
        return DecisionResult(self.state, reason, self.attack_streak, self.benign_streak, previous)


class OODGuard:
    def __init__(self, profile_path: Path, policy: dict[str, Any]) -> None:
        self.profile_path = Path(profile_path)
        self.profile = json.loads(self.profile_path.read_text(encoding="utf-8"))
        self.features = list(self.profile["features"])
        cfg = policy["ood"]
        self.max_outside = float(cfg["max_feature_outside_fraction"])
        self.max_robust_z = float(cfg["max_robust_z"])
        self.minimum_rows = int(cfg["minimum_profile_rows"])

    def evaluate(self, states: Iterable[dict[str, Any]]) -> dict[str, Any]:
        rows = list(states)
        if not rows:
            return {"status": "NO_HISTORY", "in_domain": False, "reason": "no temporal history"}
        med = np.asarray(self.profile["median"], dtype=np.float64)
        mad = np.asarray(self.profile["mad"], dtype=np.float64)
        q01 = np.asarray(self.profile["q01"], dtype=np.float64)
        q99 = np.asarray(self.profile["q99"], dtype=np.float64)
        values = np.asarray(
            [[float(row.get(name) or 0.0) for name in self.features] for row in rows],
            dtype=np.float64,
        )
        span = np.maximum(q99 - q01, 1e-6)
        lower = q01 - 0.5 * span
        upper = q99 + 0.5 * span
        outside = (values < lower) | (values > upper)
        outside_fraction = float(np.mean(outside))
        robust_scale = np.maximum.reduce([mad * 1.4826, span / 4.0, np.full_like(span, 1e-6)])
        robust_z = np.abs((values - med) / robust_scale)
        max_z = float(np.max(robust_z))
        profile_rows = int(self.profile.get("state_rows") or 0)
        enough_profile = profile_rows >= self.minimum_rows
        in_domain = outside_fraction <= self.max_outside and max_z <= self.max_robust_z
        reasons: list[str] = []
        if outside_fraction > self.max_outside:
            reasons.append(f"outside-feature fraction {outside_fraction:.3f} > {self.max_outside:.3f}")
        if max_z > self.max_robust_z:
            reasons.append(f"robust z {max_z:.1f} > {self.max_robust_z:.1f}")
        if not enough_profile:
            reasons.append(f"limited profile rows ({profile_rows} < {self.minimum_rows})")
        return {
            "status": "IN_DOMAIN" if in_domain else "OUT_OF_DOMAIN",
            "in_domain": bool(in_domain),
            "profile_quality": "ADEQUATE" if enough_profile else "LIMITED",
            "profile_rows": profile_rows,
            "outside_feature_fraction": outside_fraction,
            "max_robust_z": max_z,
            "reason": "; ".join(reasons) if reasons else "within local training envelope",
        }


def advisory_gate(
    *,
    telemetry: dict[str, Any],
    ood: dict[str, Any],
    history_fill_ratio: float,
    policy: dict[str, Any],
) -> dict[str, Any]:
    cfg = policy["advisory"]
    reasons: list[str] = []
    if cfg.get("require_telemetry_healthy", True) and not telemetry.get("healthy"):
        reasons.append("telemetry unhealthy")
    if cfg.get("require_in_domain", True) and not ood.get("in_domain"):
        reasons.append("out-of-domain input")
    minimum_history = float(cfg.get("minimum_history_fill_ratio", 1.0))
    if history_fill_ratio < minimum_history:
        reasons.append(f"history fill {history_fill_ratio:.2f} < {minimum_history:.2f}")
    eligible = not reasons
    return {
        "advisory_eligible": eligible,
        "status": "ELIGIBLE" if eligible else "WITHHELD",
        "reasons": reasons,
    }
