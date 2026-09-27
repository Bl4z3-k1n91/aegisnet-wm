from __future__ import annotations

import sys
import unittest
from pathlib import Path

import numpy as np


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'models' / 'world_model'))
sys.path.insert(0, str(ROOT / 'experiments'))

from config import CLASS_TO_ID, WorldModelConfig  # noqa: E402
from eve_shadow_calibration import choose_guarded_threshold, stacking_vector  # noqa: E402
from forecast_evaluator import signal_item  # noqa: E402
from lab_temporal_dataset import windows  # noqa: E402
from train_next_stage import derive_next_stage  # noqa: E402


class ForecastHardeningTests(unittest.TestCase):
    def test_guarded_threshold_can_hold_zero_validation_fpr(self) -> None:
        y = np.asarray([0, 0, 0, 1, 1], dtype=np.int64)
        p = np.asarray([0.10, 0.20, 0.30, 0.80, 0.90], dtype=np.float64)
        result = choose_guarded_threshold(y, p, max_fpr=0.0)
        self.assertTrue(result['met_fpr_target'])
        self.assertEqual(result['validation_fpr'], 0.0)
        self.assertEqual(result['validation_recall'], 1.0)

    def test_stacking_vector_marks_missing_models_explicitly(self) -> None:
        shadow = {
            'models': {
                'GENIS': {
                    'horizons': {
                        '60': {
                            'future_attack_probability': 0.8,
                            'native_alert': True,
                        }
                    }
                }
            }
        }
        vector = stacking_vector(shadow, 60)
        self.assertEqual(vector.shape, (12,))
        self.assertAlmostEqual(float(vector[0]), 0.8)
        self.assertEqual(float(vector[1]), 1.0)
        self.assertEqual(float(vector[3]), 0.0)

    def test_lab_temporal_windows_keep_run_identity_and_next_stage(self) -> None:
        config = WorldModelConfig()
        states = [np.asarray([float(index)], dtype=np.float32) for index in range(12)]
        labels = ['BENIGN'] * 7 + ['RECONNAISSANCE'] * 5
        sample_times = [f'2026-09-26T00:00:{index:02d}+00:00' for index in range(12)]
        result = windows(
            states,
            labels,
            sample_times,
            77,
            config,
            scenario='cyber-recon-ddos',
            campaign_id='campaign-a',
        )
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(int(result['run_id'][0]), 77)
        self.assertEqual(str(result['campaign_id'][0]), 'run-77')
        self.assertEqual(str(result['source_campaign_id'][0]), 'campaign-a')
        self.assertEqual(str(result['scenario'][0]), 'cyber-recon-ddos')
        self.assertEqual(int(result['next_stage'][0]), CLASS_TO_ID['RECONNAISSANCE'])

    def test_next_stage_target_uses_first_changed_horizon(self) -> None:
        arrays = {
            'current_label': np.asarray([0, 1], dtype=np.int64),
            'future_label': np.asarray([[0, 1, 8], [1, 1, 1]], dtype=np.int64),
        }
        target = derive_next_stage(arrays)
        self.assertEqual(target.tolist(), [1, 1])

    def test_eve_calibrated_signal_never_changes_authority_contract(self) -> None:
        forecast = {
            'shadow_real_models': {
                'eve_calibration': {
                    'alert_authority': False,
                    'horizons': {
                        '60': {
                            'calibrated_attack_probability': 0.9,
                            'threshold': 0.7,
                            'shadow_alert': True,
                        }
                    },
                }
            }
        }
        item = signal_item(forecast, 60, 'eve-calibrated', 0.5)
        self.assertIsNotNone(item)
        assert item is not None
        probability, threshold, alert, _ = item
        self.assertAlmostEqual(probability, 0.9)
        self.assertAlmostEqual(threshold, 0.7)
        self.assertTrue(alert)
        self.assertFalse(forecast['shadow_real_models']['eve_calibration']['alert_authority'])


if __name__ == '__main__':
    unittest.main()
