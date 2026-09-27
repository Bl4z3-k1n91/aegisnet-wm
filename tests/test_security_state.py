from __future__ import annotations

import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "telemetry"))

from features.security_state import build_state, build_state_windows  # noqa: E402
from telemetry_store import TelemetryStore  # noqa: E402


class SecurityStateTests(unittest.TestCase):
    def test_scan_like_flow_state(self) -> None:
        flows = [
            {
                "timestamp": f"2026-09-15T00:00:0{index}+00:00",
                "src_ip": "10.1.10.10",
                "dst_ip": "10.20.10.10",
                "src_port": 40000 + index,
                "dst_port": 20 + index,
                "protocol": 6,
                "tcp_flags": 0x02,
                "bytes": 60,
                "packets": 1,
                "flow_start_uptime_ms": index * 1000,
                "flow_end_uptime_ms": index * 1000 + 25,
            }
            for index in range(5)
        ]
        previous = [
            {
                "timestamp": "2026-09-14T23:59:59+00:00",
                "src_ip": "10.1.10.10",
                "dst_ip": "10.20.10.10",
                "dst_port": 443,
                "protocol": 6,
                "tcp_flags": 0x12,
            }
        ]

        state = build_state(flows, previous_records=previous)

        self.assertEqual(state["flow_count"], 5)
        self.assertEqual(state["syn_count"], 5)
        self.assertEqual(state["ack_count"], 0)
        self.assertEqual(state["syn_only_count"], 5)
        self.assertEqual(state["max_port_fanout"], 5)
        self.assertEqual(state["new_dst_hosts"], 0)
        self.assertEqual(state["new_dst_ports"], 5)
        self.assertEqual(state["east_west_flows"], 5)
        self.assertEqual(state["north_south_flows"], 0)
        self.assertAlmostEqual(state["sequential_port_score"], 1.0)
        self.assertGreater(state["port_entropy"], 0.99)
        self.assertEqual(state["flow_duration_mean_ms"], 25.0)

    def test_raw_json_backfills_legacy_flow_columns(self) -> None:
        state = build_state(
            [
                {
                    "timestamp": "2026-09-15T00:00:01+00:00",
                    "src_ip": "10.1.10.10",
                    "dst_ip": "10.20.10.10",
                    "dst_port": 445,
                    "protocol": 6,
                    "raw_json": (
                        '{"tcp_flags": 2, "flow_start_uptime_ms": 1000, '
                        '"flow_end_uptime_ms": 1040}'
                    ),
                }
            ]
        )
        self.assertEqual(state["syn_count"], 1)
        self.assertEqual(state["ack_count"], 0)
        self.assertEqual(state["flow_duration_mean_ms"], 40.0)

    def test_state_windows_are_continuous_across_time(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "telemetry.db"
            store = TelemetryStore(database)
            records = []
            for second, port in ((1, 80), (6, 81), (11, 82), (16, 83)):
                records.append(
                    {
                        "timestamp": f"2026-09-15T00:00:{second:02d}+00:00",
                        "exporter": "10.0.0.1",
                        "src_ip": "10.1.10.10",
                        "dst_ip": "10.20.10.10",
                        "src_port": 45000 + second,
                        "dst_port": port,
                        "protocol": 6,
                        "tcp_flags": 0x02,
                        "bytes": 60,
                        "packets": 1,
                    }
                )
            store.write_flows(records, {"10.0.0.1": "BR1"})
            store.close()

            connection = sqlite3.connect(database)
            connection.row_factory = sqlite3.Row
            states = build_state_windows(
                connection,
                "2026-09-15T00:00:00+00:00",
                "2026-09-15T00:00:20+00:00",
                window_seconds=5,
                stride_seconds=5,
                lookback_seconds=10,
            )
            connection.close()

        self.assertEqual(len(states), 4)
        self.assertEqual([state["flow_count"] for state in states], [1, 1, 1, 1])
        self.assertEqual(states[0]["new_dst_ports"], 1)
        self.assertEqual(states[1]["new_dst_ports"], 1)
        self.assertEqual(states[2]["new_dst_ports"], 1)
        self.assertEqual(states[3]["new_dst_ports"], 1)


if __name__ == "__main__":
    unittest.main()
