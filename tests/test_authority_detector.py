from __future__ import annotations

import sys
import unittest
from pathlib import Path

import numpy as np


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "models"))
from live_analysis_service import temporal_binary_predict  # noqa: E402


class _DummyTemporalModel:
    classes_ = np.asarray(["ATTACK", "BENIGN"])

    def predict_proba(self, x: np.ndarray) -> np.ndarray:
        # Deterministic high attack probability once history is complete.
        return np.asarray([[0.8, 0.2] for _ in range(len(x))], dtype=np.float64)


class AuthorityDetectorTests(unittest.TestCase):
    def test_temporal_detector_withholds_until_history_complete(self) -> None:
        result = temporal_binary_predict(
            [{"a": 1.0}, {"a": 2.0}],
            _DummyTemporalModel(),
            features=["a"],
            history_steps=3,
            threshold=0.67,
        )
        self.assertEqual(result["label"], "UNKNOWN")
        self.assertEqual(result["status"], "WARMING_UP")

    def test_temporal_detector_scores_complete_history(self) -> None:
        result = temporal_binary_predict(
            [{"a": 1.0}, {"a": 2.0}, {"a": 3.0}],
            _DummyTemporalModel(),
            features=["a"],
            history_steps=3,
            threshold=0.67,
        )
        self.assertEqual(result["label"], "ATTACK")
        self.assertAlmostEqual(float(result["attack_probability"]), 0.8)
        self.assertEqual(result["status"], "READY")


if __name__ == "__main__":
    unittest.main()
