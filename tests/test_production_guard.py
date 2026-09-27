from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "models"))
sys.path.insert(0, str(ROOT / "intelligence"))

from artifact_integrity import verify_manifest, write_manifest  # noqa: E402
from production_guard import DecisionStateMachine, OODGuard, telemetry_health, verify_file_sha256  # noqa: E402


POLICY = {
    "decision_hysteresis": {
        "alert_confirm_windows": 2,
        "clear_confirm_windows": 3,
        "minimum_alert_confidence": 0.6,
    },
    "ood": {
        "max_feature_outside_fraction": 0.25,
        "max_robust_z": 15.0,
        "minimum_profile_rows": 4,
    },
}


class ProductionGuardTests(unittest.TestCase):
    def test_decision_hysteresis_requires_confirmation_and_clearance(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            machine = DecisionStateMachine(Path(folder) / "state.json", POLICY)
            first = machine.update(label="RECONNAISSANCE", confidence=0.9, data_valid=True)
            self.assertEqual(first.state, "WATCH")
            second = machine.update(label="RECONNAISSANCE", confidence=0.9, data_valid=True)
            self.assertEqual(second.state, "ALERT")
            b1 = machine.update(label="BENIGN", confidence=0.95, data_valid=True)
            self.assertEqual(b1.state, "RECOVERING")
            b2 = machine.update(label="BENIGN", confidence=0.95, data_valid=True)
            self.assertEqual(b2.state, "RECOVERING")
            b3 = machine.update(label="BENIGN", confidence=0.95, data_valid=True)
            self.assertEqual(b3.state, "NORMAL")

    def test_visibility_loss_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            machine = DecisionStateMachine(Path(folder) / "state.json", POLICY)
            result = machine.update(label="BENIGN", confidence=0.99, data_valid=False)
            self.assertEqual(result.state, "DEGRADED")
            self.assertIn("withheld", result.reason)

    def test_ood_guard_rejects_extreme_input(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            profile = Path(folder) / "profile.json"
            profile.write_text(
                json.dumps(
                    {
                        "features": ["a", "b"],
                        "state_rows": 10,
                        "median": [1.0, 1.0],
                        "mad": [0.5, 0.5],
                        "q01": [0.0, 0.0],
                        "q99": [2.0, 2.0],
                    }
                ),
                encoding="utf-8",
            )
            guard = OODGuard(profile, POLICY)
            normal = guard.evaluate([{"a": 1.0, "b": 1.5}])
            self.assertTrue(normal["in_domain"])
            extreme = guard.evaluate([{"a": 100.0, "b": 100.0}])
            self.assertFalse(extreme["in_domain"])

    def test_artifact_manifest_detects_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            artifact = Path(folder)
            model = artifact / "model.bin"
            model.write_bytes(b"known-good")
            write_manifest(artifact)
            self.assertTrue(verify_manifest(artifact)["valid"])
            model.write_bytes(b"tampered")
            result = verify_manifest(artifact)
            self.assertFalse(result["valid"])
            self.assertEqual(result["status"], "TAMPERED")

    def test_telemetry_health_detects_stale_heartbeat(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            status = Path(folder) / "telemetry-status.json"
            status.write_text(
                json.dumps(
                    {
                        "updated_at": (datetime.now(timezone.utc) - timedelta(seconds=30)).isoformat(),
                        "fatal_errors": [],
                        "last_poll_at": {},
                        "poll_errors": {},
                    }
                ),
                encoding="utf-8",
            )
            result = telemetry_health(
                status,
                heartbeat_max_age_seconds=10,
                max_poll_error_fraction=0.5,
            )
            self.assertFalse(result["healthy"])
            self.assertEqual(result["status"], "DEGRADED")

    def test_pinned_file_hash_detects_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "profile.json"
            path.write_text("trusted", encoding="utf-8")
            import hashlib
            expected = hashlib.sha256(b"trusted").hexdigest()
            self.assertTrue(verify_file_sha256(path, expected)["valid"])
            path.write_text("changed", encoding="utf-8")
            self.assertFalse(verify_file_sha256(path, expected)["valid"])


if __name__ == "__main__":
    unittest.main()
