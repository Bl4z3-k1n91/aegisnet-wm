from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "telemetry"))

from syslog_collector import parse_message  # noqa: E402


class SyslogCollectorTests(unittest.TestCase):
    def test_priority_is_decoded(self) -> None:
        record = parse_message(
            b"<189>Jun 27 12:00:00 BR2 %BGP-5-ADJCHANGE: neighbor down",
            "172.31.255.102",
        )
        self.assertEqual(record["priority"], 189)
        self.assertEqual(record["facility"], 23)
        self.assertEqual(record["severity"], 5)
        self.assertIn("%BGP-5-ADJCHANGE", record["message"])

    def test_message_without_priority_is_preserved(self) -> None:
        record = parse_message(b"plain message", "127.0.0.1")
        self.assertIsNone(record["priority"])
        self.assertEqual(record["message"], "plain message")


if __name__ == "__main__":
    unittest.main()
