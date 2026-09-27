from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "telemetry"))
sys.path.insert(0, str(ROOT / "experiments"))

from scenario_store import ScenarioStore  # noqa: E402
from telemetry_store import TelemetryStore  # noqa: E402


class ScenarioPipelineTests(unittest.TestCase):
    def test_phase_feature_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "telemetry.db"
            telemetry = TelemetryStore(database)
            telemetry.close()
            scenarios = ScenarioStore(database)
            run_id = scenarios.start_run("jitter", {"fault_seconds": 30})
            phase_id = scenarios.start_phase(
                run_id, "fault", "MPLS_JITTER", {"profile": "jitter"}
            )
            scenarios.connection.execute(
                """
                UPDATE scenario_phases
                SET started_at='2026-07-01T10:00:00+00:00',
                    ended_at='2026-07-01T10:00:30+00:00'
                WHERE id=?
                """,
                (phase_id,),
            )
            for statement, values in (
                (
                    """INSERT INTO device_samples
                    (timestamp,device,management_ip,reachable,cpu_5s,
                     bgp_established,ospf_full,eigrp_neighbors,dmvpn_up,ikev2_ready)
                    VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (
                        "2026-07-01T10:00:10+00:00", "BR1", "192.0.2.1",
                        1, 20, 2, 0, 2, 4, 4,
                    ),
                ),
                (
                    """INSERT INTO sla_samples
                    (timestamp,device,management_ip,operation_id,transport,
                     rtt_ms,success_delta,failure_delta)
                    VALUES (?,?,?,?,?,?,?,?)""",
                    (
                        "2026-07-01T10:00:10+00:00", "BR1", "192.0.2.1",
                        101, "MPLS", 80, 1, 2,
                    ),
                ),
                (
                    """INSERT INTO interface_samples
                    (timestamp,device,management_ip,interface,input_bps,output_bps,
                     input_error_delta,output_error_delta,input_drop_delta,
                     output_drop_delta)
                    VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (
                        "2026-07-01T10:00:10+00:00", "BR1", "192.0.2.1",
                        "Fa1/0", 1000, 2000, 1, 2, 3, 4,
                    ),
                ),
                (
                    """INSERT INTO flows
                    (timestamp,exporter,device,bytes,packets,raw_json)
                    VALUES (?,?,?,?,?,?)""",
                    (
                        "2026-07-01T10:00:10+00:00", "192.0.2.1", "BR1",
                        1200, 12, "{}",
                    ),
                ),
                (
                    """INSERT INTO syslog_events
                    (timestamp,exporter,device,severity,message,raw_json)
                    VALUES (?,?,?,?,?,?)""",
                    (
                        "2026-07-01T10:00:10+00:00", "192.0.2.1", "BR1",
                        4, "test warning", "{}",
                    ),
                ),
            ):
                scenarios.connection.execute(statement, values)
            scenarios.connection.commit()

            self.assertEqual(scenarios.extract_features(run_id), 1)
            row = scenarios.connection.execute(
                "SELECT * FROM feature_windows WHERE run_id=?", (run_id,)
            ).fetchone()
            self.assertEqual(row["label"], "MPLS_JITTER")
            self.assertEqual(row["duration_seconds"], 30)
            self.assertEqual(row["sla_mpls_rtt_avg"], 80)
            self.assertEqual(row["sla_mpls_failures"], 2)
            self.assertEqual(row["input_drop_delta"], 3)
            self.assertEqual(row["flow_bytes"], 1200)
            self.assertEqual(row["syslog_warning_count"], 1)
            self.assertEqual(row["dmvpn_min"], 4)

            rich = scenarios.extract_rich_features(
                run_id, window_seconds=30, stride_seconds=10
            )
            self.assertEqual(rich, {"device": 1, "sla": 1, "qos": 0})
            device = scenarios.connection.execute(
                "SELECT * FROM device_feature_windows WHERE run_id=?", (run_id,)
            ).fetchone()
            self.assertEqual(device["scenario"], "jitter")
            self.assertEqual(device["flow_bytes"], 1200)
            self.assertEqual(device["input_drop_delta"], 3)
            sla = scenarios.connection.execute(
                "SELECT * FROM sla_feature_windows WHERE run_id=?", (run_id,)
            ).fetchone()
            self.assertEqual(sla["operation_id"], 101)
            self.assertEqual(sla["rtt_mean"], 80)
            self.assertEqual(sla["rtt_p95"], 80)
            self.assertEqual(sla["failure_delta"], 2)
            scenarios.close()


if __name__ == "__main__":
    unittest.main()
