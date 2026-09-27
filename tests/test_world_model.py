from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

import numpy as np
import torch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'models' / 'world_model'))
sys.path.insert(0, str(ROOT / 'intelligence'))
sys.path.insert(0, str(ROOT / 'models'))

from config import CLASSES, HORIZONS, VICTIMS, WorldModelConfig
from model import LatentWorldModel
from inference import WorldForecaster
from topology import shortest_path
from mitre import mitre_for_class
from audit_chain import append_event, verify
from public_dataset import canonical_label
from live_analysis_service import calibrated_current_decision, shadow_open_world_forecast
from markov_fallback import MarkovFallback
from knowledge import enrich_forecast as enrich_knowledge


class WorldModelTests(unittest.TestCase):
    def test_rollout_shapes(self):
        config = WorldModelConfig()
        model = LatentWorldModel(29, config)
        x = torch.randn(4, config.history_steps, 29)
        out = model(x)
        self.assertEqual(set(out.class_logits), set(HORIZONS))
        for horizon in HORIZONS:
            self.assertEqual(tuple(out.class_logits[horizon].shape), (4, len(CLASSES)))
            self.assertEqual(tuple(out.attack_logits[horizon].shape), (4,))
            self.assertEqual(tuple(out.change_logits[horizon].shape), (4,))
            self.assertEqual(tuple(out.onset_logits[horizon].shape), (4,))
            self.assertEqual(tuple(out.victim_logits[horizon].shape), (4, len(VICTIMS)))
            self.assertEqual(tuple(out.state_by_horizon[horizon].shape), (4, 29))

    def test_free_running_rollout_changes_latent(self):
        model = LatentWorldModel(29)
        x = torch.randn(2, 6, 29)
        out = model(x)
        self.assertFalse(torch.allclose(out.latent_by_horizon[1], out.latent_by_horizon[6]))

    def test_bootstrap_split_campaigns_are_disjoint(self):
        release = ROOT / 'dataset' / 'releases' / 'ntro-world-bootstrap-v1'
        sets = []
        for split in ('train', 'val', 'test'):
            with np.load(release / f'{split}.npz') as data:
                sets.append(set(data['campaign_id'].tolist()))
        self.assertTrue(sets[0].isdisjoint(sets[1]))
        self.assertTrue(sets[0].isdisjoint(sets[2]))
        self.assertTrue(sets[1].isdisjoint(sets[2]))

    def test_saved_forecaster_contract(self):
        forecaster = WorldForecaster()
        state = {feature: 0.0 for feature in forecaster.features}
        result = forecaster.forecast([state] * 6)
        self.assertEqual(set(result['horizons']), {'1', '3', '6'})
        for item in result['horizons'].values():
            self.assertIn(item['predicted_class'], CLASSES)
            self.assertIn(item['predicted_victim'], VICTIMS)
            self.assertIn('future_attack_probability', item)
            self.assertIn('state_change_probability', item)
            self.assertIn('attack_onset_probability', item)
            self.assertIn('top_features', item)

    def test_topology_path(self):
        self.assertEqual(shortest_path('BR1', 'DC'), ['BR1', 'CORE', 'DC'])
        self.assertEqual(shortest_path('HUB', 'BR2'), ['HUB', 'CORE', 'BR2'])

    def test_mitre_mapping(self):
        self.assertEqual(mitre_for_class('DDOS_HIGH')['technique_id'], 'T1498')
        self.assertEqual(mitre_for_class('RECONNAISSANCE')['technique_id'], 'T1046')

    def test_audit_chain_detects_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'audit.jsonl'
            append_event('forecast', {'x': 1}, path)
            append_event('forecast', {'x': 2}, path)
            self.assertTrue(verify(path)['valid'])
            lines = path.read_text(encoding='utf-8').splitlines()
            record = json.loads(lines[0]); record['payload']['x'] = 999
            lines[0] = json.dumps(record, separators=(',', ':'))
            path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
            self.assertFalse(verify(path)['valid'])

    def test_public_label_mapping(self):
        self.assertEqual(canonical_label('BENIGN'), 'BENIGN')
        self.assertEqual(canonical_label('PortScan'), 'RECONNAISSANCE')
        self.assertEqual(canonical_label('DDoS'), 'DDOS_HIGH')
        self.assertEqual(canonical_label('Bot'), 'C2_BEACON_PATTERN')

    def test_current_detector_abstains_on_low_confidence(self):
        label, risk, source = calibrated_current_decision('DDOS_MEDIUM', 0.45, 0.91)
        self.assertEqual(label, 'UNKNOWN')
        self.assertEqual(risk, 0.91)
        self.assertEqual(source, 'abstain_low_confidence')
        label, risk, source = calibrated_current_decision('RECONNAISSANCE', 0.82, 0.95)
        self.assertEqual(label, 'RECONNAISSANCE')
        self.assertEqual(source, 'model_classification')

    def test_markov_fallback_contract(self):
        fallback = MarkovFallback()
        result = fallback.forecast('RECONNAISSANCE')
        self.assertTrue(result['fallback'])
        self.assertEqual(set(result['horizons']), {'1', '3', '6'})
        for item in result['horizons'].values():
            self.assertIn(item['predicted_class'], CLASSES)
            self.assertIn('class_probabilities', item)

    def test_missing_knowledge_cache_is_explicit(self):
        sample = {
            'horizons': {
                '1': {
                    'predicted_class': 'DDOS_HIGH',
                    'predicted_victim': 'DC',
                    'mitre': {'technique_id': 'T1498'},
                }
            }
        }
        enriched = enrich_knowledge(sample)
        knowledge = enriched['horizons']['1']['knowledge']
        self.assertIn(knowledge['capec_status'], {'cache_missing', 'available'})
        self.assertIn(knowledge['cve_status'], {'cache_missing', 'available'})

    def test_shadow_forecast_never_has_alert_authority(self):
        class FakeForecaster:
            def forecast(self, history):
                return {
                    'model_release': 'fake-real-model',
                    'evidence_status': 'real_public_dataset',
                    'history_steps_observed': 6,
                    'history_steps_required': 6,
                    'horizons': {
                        '1': {
                            'seconds': 10,
                            'future_attack_probability': 0.99,
                            'threshold': 0.10,
                            'alert': True,
                        }
                    },
                }

        result = shadow_open_world_forecast({'FAKE': FakeForecaster()}, [{}] * 6)
        self.assertEqual(result['mode'], 'SHADOW_ONLY')
        self.assertFalse(result['alert_authority'])
        self.assertTrue(result['models']['FAKE']['horizons']['10']['native_alert'])
        self.assertTrue(result['consensus']['10']['shadow_only'])


if __name__ == '__main__':
    unittest.main()
