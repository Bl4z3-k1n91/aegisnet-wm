from __future__ import annotations

import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "features"))
sys.path.insert(0, str(ROOT / "telemetry"))

from state_vector import MODEL_FEATURES, STATE_SCHEMA_VERSION, build_state_vector, model_row  # noqa: E402
from telemetry_store import TelemetryStore  # noqa: E402


class StateVectorTests(unittest.TestCase):
    def test_fused_state_v1(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "telemetry.db"
            store = TelemetryStore(path)
            store.write_flows(
                [
                    {
                        "timestamp": "2026-09-15T00:00:02+00:00",
                        "exporter": "192.168.58.15",
                        "src_ip": "10.1.10.10",
                        "dst_ip": "10.20.10.10",
                        "src_port": 40000,
                        "dst_port": 445,
                        "protocol": 6,
                        "tcp_flags": 0x02,
                        "bytes": 60,
                        "packets": 1,
                    }
                ],
                {"192.168.58.15": "BR1"},
            )
            store.close()

            connection = sqlite3.connect(path)
            connection.execute(
                """
                INSERT INTO device_samples
                (timestamp,device,management_ip,reachable,poll_ms,cpu_5s,
                 memory_total,memory_used,bgp_established,ospf_full,
                 eigrp_neighbors,dmvpn_up,ikev2_ready)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    "2026-09-15T00:00:03+00:00", "BR1", "192.168.58.15", 1,
                    100, 20, 1000, 400, 2, 0, 2, 4, 4,
                ),
            )
            connection.execute(
                """
                INSERT INTO sla_samples
                (timestamp,device,management_ip,operation_id,transport,target_role,
                 rtt_ms,success_delta,failure_delta)
                VALUES (?,?,?,?,?,?,?,?,?)
                """,
                (
                    "2026-09-15T00:00:04+00:00", "BR1", "192.168.58.15", 111,
                    "MPLS", "DC", 50, 1, 0,
                ),
            )
            connection.execute(
                """
                INSERT INTO interface_samples
                (timestamp,device,management_ip,interface,input_bps,output_bps,
                 input_drop_delta,output_drop_delta,input_error_delta,output_error_delta)
                VALUES (?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    "2026-09-15T00:00:05+00:00", "BR1", "192.168.58.15",
                    "FastEthernet1/0", 1000, 2000, 1, 2, 0, 0,
                ),
            )
            connection.commit()

            packets = [
                {
                    "timestamp": 1789430406.0,
                    "src_ip": "10.1.10.10",
                    "dst_ip": "10.20.10.10",
                    "protocol": 6,
                    "ttl": 64,
                    "ip_flags": 2,
                    "dont_fragment": 1,
                    "more_fragments": 0,
                    "fragment_offset": 0,
                    "src_port": 40000,
                    "dst_port": 445,
                    "tcp_flags": 2,
                    "tcp_window": 4096,
                    "tcp_seq": 1,
                    "tcp_ack": 0,
                    "payload_bytes": 0,
                }
            ]
            state = build_state_vector(
                connection,
                "2026-09-15T00:00:00+00:00",
                "2026-09-15T00:00:10+00:00",
                packet_events=packets,
            )
            connection.close()

        self.assertEqual(state["schema_version"], STATE_SCHEMA_VERSION)
        self.assertEqual(state["flow_count"], 1)
        self.assertEqual(state["syn_count"], 1)
        self.assertEqual(state["packet_event_count"], 1)
        self.assertEqual(state["packet_capture_present"], 1)
        self.assertEqual(state["packet_ttl_mean"], 64.0)
        self.assertEqual(state["health_reachable_ratio"], 1.0)
        self.assertEqual(state["health_dmvpn_total"], 4)
        self.assertEqual(state["sla_mpls_rtt_mean"], 50.0)
        self.assertEqual(state["interface_output_drop_delta"], 2)
        self.assertEqual(len(model_row(state)), len(MODEL_FEATURES))

    def test_missing_pcap_is_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "telemetry.db"
            store = TelemetryStore(path)
            store.close()
            connection = sqlite3.connect(path)
            state = build_state_vector(
                connection,
                "2026-09-15T00:00:00+00:00",
                "2026-09-15T00:00:10+00:00",
            )
            connection.close()
        self.assertEqual(state["packet_capture_present"], 0)
        self.assertEqual(state["packet_event_count"], 0)

    def test_model_row_rejects_wrong_schema(self) -> None:
        with self.assertRaises(ValueError):
            model_row({"schema_version": "other"})


if __name__ == "__main__":
    unittest.main()
