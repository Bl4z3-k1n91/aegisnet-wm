from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "experiments"))

from cyber_scenario_runner import (  # noqa: E402
    SCENARIOS,
    c2_beacon_commands,
    exfiltration_like_commands,
    initial_access_commands,
    lateral_movement_commands,
)


class _DummyShell:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str]] = []

    def start_background(self, node: str, tag: str, command: str) -> None:
        self.calls.append(("start", node, f"{tag}:{command}"))

    def stop_background(self, node: str, tag: str) -> None:
        self.calls.append(("stop", node, tag))


class CyberRunnerTests(unittest.TestCase):
    def test_full_kill_chain_is_exposed(self) -> None:
        self.assertIn("full-kill-chain", SCENARIOS)

    def test_stage_factories_return_bounded_start_stop_pairs(self) -> None:
        shell = _DummyShell()
        for factory in (
            initial_access_commands,
            lateral_movement_commands,
            c2_beacon_commands,
            exfiltration_like_commands,
        ):
            start, stop = factory(shell)  # type: ignore[arg-type]
            self.assertTrue(callable(start))
            self.assertTrue(callable(stop))
            start()
            stop()
        joined = "\n".join(value for _, _, value in shell.calls)
        self.assertIn("10.20.10.10", joined)
        self.assertIn("10.2.10.10", joined)
        self.assertNotIn("10.0.0.0/0", joined)


if __name__ == "__main__":
    unittest.main()
