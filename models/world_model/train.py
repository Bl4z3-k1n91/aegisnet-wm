from __future__ import annotations

import argparse
import json
import math
import random
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any

import numpy as np
import torch
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, average_precision_score, f1_score, log_loss, roc_auc_score
from torch import nn
from torch.utils.data import DataLoader, Dataset, WeightedRandomSampler

from config import CLASSES, HORIZONS, VICTIMS, WorldModelConfig
from model import DirectGRUForecaster, LatentWorldModel

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATA_DIR = ROOT / 'dataset' / 'releases' / 'ntro-world-bootstrap-v1'
DEFAULT_OUTPUT_DIR = ROOT / 'models' / 'artifacts' / 'ntro-world-bootstrap-v1'


def feature_transform(values: np.ndarray, mode: str) -> np.ndarray:
    values = np.asarray(values, dtype=np.float32)
    if mode == 'identity':
        return values
    if mode == 'log1p':
        return np.log1p(np.clip(values, 0.0, None)).astype(np.float32)
    raise ValueError(f'unsupported feature transform: {mode}')


def transformed_arrays(arrays: dict[str, np.ndarray], mode: str) -> dict[str, np.ndarray]:
    result = dict(arrays)
    result['x'] = feature_transform(arrays['x'], mode)
    result['future_state'] = feature_transform(arrays['future_state'], mode)
    return result


class ArrayDataset(Dataset):
    def __init__(self, arrays: dict[str, np.ndarray], mean: np.ndarray, std: np.ndarray) -> None:
        self.x = ((arrays['x'] - mean) / std).astype(np.float32)
        self.future_state = ((arrays['future_state'] - mean) / std).astype(np.float32)
        self.future_label = arrays['future_label'].astype(np.int64)
        self.attack = arrays['attack'].astype(np.float32)
        self.change = arrays['change'].astype(np.float32)
        self.onset = arrays['onset'].astype(np.float32)
        self.infiltration = arrays['infiltration'].astype(np.float32)
        self.victim = arrays['victim'].astype(np.int64)
        self.current_label = arrays['current_label'].astype(np.int64)

    def __len__(self) -> int:
        return len(self.x)

    def __getitem__(self, index: int) -> dict[str, torch.Tensor]:
        return {
            'x': torch.from_numpy(self.x[index]),
            'future_state': torch.from_numpy(self.future_state[index]),
            'future_label': torch.from_numpy(self.future_label[index]),
            'attack': torch.from_numpy(self.attack[index]),
            'change': torch.from_numpy(self.change[index]),
            'onset': torch.from_numpy(self.onset[index]),
            'infiltration': torch.from_numpy(self.infiltration[index]),
            'victim': torch.from_numpy(self.victim[index]),
            'current_label': torch.tensor(self.current_label[index], dtype=torch.long),
        }


def load_npz(split: str, data_dir: Path) -> dict[str, np.ndarray]:
    with np.load(data_dir / f'{split}.npz', allow_pickle=False) as loaded:
        return {name: loaded[name] for name in loaded.files}


def seed_everything(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)


def world_loss(
    output: Any,
    batch: dict[str, torch.Tensor],
    config: WorldModelConfig,
    class_weights: torch.Tensor | None = None,
    attack_pos_weight: torch.Tensor | None = None,
    change_pos_weight: torch.Tensor | None = None,
    onset_pos_weight: torch.Tensor | None = None,
    infiltration_pos_weight: torch.Tensor | None = None,
) -> tuple[torch.Tensor, dict[str, float]]:
    ce = nn.CrossEntropyLoss(weight=class_weights)
    attack_bce = nn.BCEWithLogitsLoss(pos_weight=attack_pos_weight)
    change_bce = nn.BCEWithLogitsLoss(pos_weight=change_pos_weight)
    onset_bce = nn.BCEWithLogitsLoss(pos_weight=onset_pos_weight)
    infiltration_bce = nn.BCEWithLogitsLoss(pos_weight=infiltration_pos_weight)
    victim_ce = nn.CrossEntropyLoss()
    mse = nn.MSELoss()
    class_loss = torch.zeros((), device=batch['x'].device)
    attack_loss = torch.zeros_like(class_loss)
    change_loss = torch.zeros_like(class_loss)
    onset_loss = torch.zeros_like(class_loss)
    infiltration_loss = torch.zeros_like(class_loss)
    victim_loss = torch.zeros_like(class_loss)
    state_loss = torch.zeros_like(class_loss)
    for horizon_index, horizon in enumerate(config.horizons):
        class_loss = class_loss + ce(output.class_logits[horizon], batch['future_label'][:, horizon_index])
        attack_loss = attack_loss + attack_bce(output.attack_logits[horizon], batch['attack'][:, horizon_index])
        change_loss = change_loss + change_bce(output.change_logits[horizon], batch['change'][:, horizon_index])
        onset_loss = onset_loss + onset_bce(output.onset_logits[horizon], batch['onset'][:, horizon_index])
        infiltration_loss = infiltration_loss + infiltration_bce(
            output.infiltration_logits[horizon], batch['infiltration'][:, horizon_index]
        )
        victim_loss = victim_loss + victim_ce(output.victim_logits[horizon], batch['victim'][:, horizon_index])
        state_loss = state_loss + mse(output.state_by_horizon[horizon], batch['future_state'][:, horizon_index])
    divisor = float(len(config.horizons))
    class_loss = class_loss / divisor
    attack_loss = attack_loss / divisor
    change_loss = change_loss / divisor
    onset_loss = onset_loss / divisor
    infiltration_loss = infiltration_loss / divisor
    victim_loss = victim_loss / divisor
    state_loss = state_loss / divisor
    total = (
        class_loss
        + config.attack_loss_weight * attack_loss
        + config.change_loss_weight * change_loss
        + config.onset_loss_weight * onset_loss
        + config.infiltration_loss_weight * infiltration_loss
        + config.victim_loss_weight * victim_loss
        + config.state_loss_weight * state_loss
    )
    return total, {
        'total': float(total.detach().cpu()),
        'class': float(class_loss.detach().cpu()),
        'attack': float(attack_loss.detach().cpu()),
        'change': float(change_loss.detach().cpu()),
        'onset': float(onset_loss.detach().cpu()),
        'infiltration': float(infiltration_loss.detach().cpu()),
        'victim': float(victim_loss.detach().cpu()),
        'transition_state': float(state_loss.detach().cpu()),
    }


def epoch(
    model: LatentWorldModel,
    loader: DataLoader,
    optimizer: torch.optim.Optimizer | None,
    config: WorldModelConfig,
    device: torch.device,
    class_weights: torch.Tensor | None = None,
    attack_pos_weight: torch.Tensor | None = None,
    change_pos_weight: torch.Tensor | None = None,
    onset_pos_weight: torch.Tensor | None = None,
    infiltration_pos_weight: torch.Tensor | None = None,
) -> dict[str, float]:
    train = optimizer is not None
    model.train(train)
    totals: dict[str, float] = {}
    batches = 0
    for raw in loader:
        batch = {key: value.to(device) for key, value in raw.items()}
        with torch.set_grad_enabled(train):
            output = model(batch['x'])
            loss, parts = world_loss(
                output,
                batch,
                config,
                class_weights=class_weights,
                attack_pos_weight=attack_pos_weight,
                change_pos_weight=change_pos_weight,
                onset_pos_weight=onset_pos_weight,
                infiltration_pos_weight=infiltration_pos_weight,
            )
            if train:
                optimizer.zero_grad(set_to_none=True)
                loss.backward()
                nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                optimizer.step()
        for key, value in parts.items():
            totals[key] = totals.get(key, 0.0) + value
        batches += 1
    return {key: value / max(batches, 1) for key, value in totals.items()}


def collect_predictions(model: LatentWorldModel, loader: DataLoader, device: torch.device, config: WorldModelConfig) -> dict[int, dict[str, np.ndarray]]:
    model.eval()
    storage = {
        horizon: {
            'prob': [], 'truth': [],
            'attack_prob': [], 'attack_truth': [],
            'change_prob': [], 'change_truth': [],
            'onset_prob': [], 'onset_truth': [],
            'infiltration_prob': [], 'infiltration_truth': [],
            'victim_pred': [], 'victim_truth': [],
        }
        for horizon in config.horizons
    }
    with torch.no_grad():
        for raw in loader:
            batch = {key: value.to(device) for key, value in raw.items()}
            output = model(batch['x'])
            for hi, horizon in enumerate(config.horizons):
                prob = torch.softmax(output.class_logits[horizon], dim=-1).cpu().numpy()
                attack_prob = torch.sigmoid(output.attack_logits[horizon]).cpu().numpy()
                change_prob = torch.sigmoid(output.change_logits[horizon]).cpu().numpy()
                onset_prob = torch.sigmoid(output.onset_logits[horizon]).cpu().numpy()
                infiltration_prob = torch.sigmoid(output.infiltration_logits[horizon]).cpu().numpy()
                victim_pred = output.victim_logits[horizon].argmax(dim=-1).cpu().numpy()
                storage[horizon]['prob'].append(prob)
                storage[horizon]['truth'].append(batch['future_label'][:, hi].cpu().numpy())
                storage[horizon]['attack_prob'].append(attack_prob)
                storage[horizon]['attack_truth'].append(batch['attack'][:, hi].cpu().numpy())
                storage[horizon]['change_prob'].append(change_prob)
                storage[horizon]['change_truth'].append(batch['change'][:, hi].cpu().numpy())
                storage[horizon]['onset_prob'].append(onset_prob)
                storage[horizon]['onset_truth'].append(batch['onset'][:, hi].cpu().numpy())
                storage[horizon]['infiltration_prob'].append(infiltration_prob)
                storage[horizon]['infiltration_truth'].append(batch['infiltration'][:, hi].cpu().numpy())
                storage[horizon]['victim_pred'].append(victim_pred)
                storage[horizon]['victim_truth'].append(batch['victim'][:, hi].cpu().numpy())
    return {
        horizon: {key: np.concatenate(value, axis=0) for key, value in values.items()}
        for horizon, values in storage.items()
    }


def threshold_for_confidence(prob: np.ndarray, truth: np.ndarray) -> dict[str, float]:
    pred = prob.argmax(axis=1)
    conf = prob.max(axis=1)
    correct = pred == truth
    best = {'threshold': 0.0, 'coverage': 1.0, 'retained_accuracy': float(correct.mean())}
    for threshold in np.linspace(0.35, 0.90, 23):
        keep = conf >= threshold
        if not keep.any():
            continue
        retained = float(correct[keep].mean())
        coverage = float(keep.mean())
        if retained >= 0.80 and coverage > best['coverage'] * (1 if best['retained_accuracy'] >= 0.80 else 0):
            best = {'threshold': float(threshold), 'coverage': coverage, 'retained_accuracy': retained}
    if best['retained_accuracy'] < 0.80:
        candidates = []
        for threshold in np.linspace(0.35, 0.95, 25):
            keep = conf >= threshold
            if keep.any():
                candidates.append((float(correct[keep].mean()), float(keep.mean()), float(threshold)))
        if candidates:
            accuracy, coverage, threshold = max(candidates)
            best = {'threshold': threshold, 'coverage': coverage, 'retained_accuracy': accuracy}
    return best


def horizon_metrics(
    values: dict[str, np.ndarray],
    threshold: float | None = None,
    seen_class_ids: set[int] | None = None,
) -> dict[str, Any]:
    prob = values['prob']
    truth = values['truth']
    pred = prob.argmax(axis=1)
    benign = CLASSES.index('BENIGN')
    onehot = np.eye(len(CLASSES), dtype=np.float64)[truth]
    result: dict[str, Any] = {
        'accuracy': float(accuracy_score(truth, pred)),
        'macro_f1': float(f1_score(truth, pred, average='macro', zero_division=0)),
        'brier_multiclass': float(np.mean(np.sum((prob - onehot) ** 2, axis=1))),
        'nll': float(log_loss(truth, prob, labels=list(range(len(CLASSES))))),
        'benign_false_positive_rate': float(np.mean(pred[truth == benign] != benign)) if np.any(truth == benign) else 0.0,
        'victim_accuracy': float(accuracy_score(values['victim_truth'], values['victim_pred'])),
    }
    class_attack_truth = (truth != benign).astype(np.int64)
    class_attack_prob = 1.0 - prob[:, benign]
    attack_truth = values['attack_truth'].astype(np.int64)
    attack_prob = values['attack_prob']
    if len(np.unique(class_attack_truth)) > 1:
        result['class_attack_auroc'] = float(roc_auc_score(class_attack_truth, class_attack_prob))
        result['class_attack_auprc'] = float(average_precision_score(class_attack_truth, class_attack_prob))
    if len(np.unique(attack_truth)) > 1:
        result['attack_auroc'] = float(roc_auc_score(attack_truth, attack_prob))
        result['attack_auprc'] = float(average_precision_score(attack_truth, attack_prob))
        result['attack_recall_at_0_5'] = float(np.mean(attack_prob[attack_truth == 1] >= 0.5)) if np.any(attack_truth == 1) else 0.0
    change_truth = values['change_truth'].astype(np.int64)
    change_prob = values['change_prob']
    if len(np.unique(change_truth)) > 1:
        result['change_auroc'] = float(roc_auc_score(change_truth, change_prob))
        result['change_auprc'] = float(average_precision_score(change_truth, change_prob))
        result['change_recall_at_0_5'] = float(
            np.mean(change_prob[change_truth == 1] >= 0.5)
        ) if np.any(change_truth == 1) else 0.0
    transition_mask = change_truth == 1
    result['transition_samples'] = int(transition_mask.sum())
    if transition_mask.any():
        result['transition_exact_class_accuracy'] = float(
            accuracy_score(truth[transition_mask], pred[transition_mask])
        )
        result['transition_exact_class_macro_f1'] = float(
            f1_score(
                truth[transition_mask],
                pred[transition_mask],
                average='macro',
                zero_division=0,
            )
        )
    if seen_class_ids is not None:
        seen_mask = np.asarray([int(value) in seen_class_ids for value in truth], dtype=bool)
        unseen_mask = ~seen_mask
        result['seen_class_samples'] = int(seen_mask.sum())
        result['unseen_class_samples'] = int(unseen_mask.sum())
        if seen_mask.any():
            result['seen_class_accuracy'] = float(accuracy_score(truth[seen_mask], pred[seen_mask]))
            result['seen_class_macro_f1'] = float(
                f1_score(truth[seen_mask], pred[seen_mask], average='macro', zero_division=0)
            )
        if unseen_mask.any():
            result['unseen_exact_class_accuracy'] = float(
                accuracy_score(truth[unseen_mask], pred[unseen_mask])
            )
            result['unseen_attack_detection_recall_at_0_5'] = float(
                np.mean(values['attack_prob'][unseen_mask] >= 0.5)
            )
    infil_truth = values['infiltration_truth']
    onset_truth = values['onset_truth']
    if len(np.unique(onset_truth)) > 1:
        result['onset_auroc'] = float(roc_auc_score(onset_truth, values['onset_prob']))
        result['onset_auprc'] = float(average_precision_score(onset_truth, values['onset_prob']))
    if len(np.unique(infil_truth)) > 1:
        result['infiltration_auroc'] = float(roc_auc_score(infil_truth, values['infiltration_prob']))
        result['infiltration_auprc'] = float(average_precision_score(infil_truth, values['infiltration_prob']))
    if threshold is not None:
        confidence = prob.max(axis=1)
        keep = confidence >= threshold
        result['abstention_threshold'] = float(threshold)
        result['coverage'] = float(keep.mean())
        result['retained_accuracy'] = float(accuracy_score(truth[keep], pred[keep])) if keep.any() else None
    return result


def train_direct_gru(
    train_loader: DataLoader,
    val_loader: DataLoader,
    feature_count: int,
    config: WorldModelConfig,
    device: torch.device,
    class_weights: torch.Tensor | None = None,
    epochs: int = 8,
) -> DirectGRUForecaster:
    model = DirectGRUForecaster(feature_count, config).to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=1e-3, weight_decay=1e-4)
    best = None
    best_loss = math.inf
    ce = nn.CrossEntropyLoss(weight=class_weights)
    for _ in range(epochs):
        model.train()
        for raw in train_loader:
            x = raw['x'].to(device)
            truth = raw['future_label'].to(device)
            outputs = model(x)
            loss = sum(ce(outputs[h], truth[:, hi]) for hi, h in enumerate(config.horizons)) / len(config.horizons)
            optimizer.zero_grad(set_to_none=True)
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
        model.eval()
        losses = []
        with torch.no_grad():
            for raw in val_loader:
                x = raw['x'].to(device); truth = raw['future_label'].to(device); outputs = model(x)
                losses.append(float((sum(ce(outputs[h], truth[:, hi]) for hi, h in enumerate(config.horizons)) / len(config.horizons)).cpu()))
        current = float(np.mean(losses))
        if current < best_loss:
            best_loss = current
            best = deepcopy(model.state_dict())
    if best is not None:
        model.load_state_dict(best)
    return model


def direct_gru_metrics(model: DirectGRUForecaster, loader: DataLoader, device: torch.device, config: WorldModelConfig) -> dict[str, Any]:
    model.eval(); store = {h: [[], []] for h in config.horizons}
    with torch.no_grad():
        for raw in loader:
            outputs = model(raw['x'].to(device))
            for hi, h in enumerate(config.horizons):
                store[h][0].append(outputs[h].argmax(dim=-1).cpu().numpy())
                store[h][1].append(raw['future_label'][:, hi].numpy())
    result = {}
    for h, (preds, truths) in store.items():
        pred = np.concatenate(preds); truth = np.concatenate(truths)
        result[str(h)] = {'accuracy': float(accuracy_score(truth, pred)), 'macro_f1': float(f1_score(truth, pred, average='macro', zero_division=0))}
    return result


def classical_baselines(train: dict[str, np.ndarray], test: dict[str, np.ndarray], mean: np.ndarray, std: np.ndarray, config: WorldModelConfig) -> dict[str, Any]:
    x_train = ((train['x'][:, -1, :] - mean.reshape(-1)) / std.reshape(-1)).astype(np.float64)
    x_test = ((test['x'][:, -1, :] - mean.reshape(-1)) / std.reshape(-1)).astype(np.float64)
    result: dict[str, Any] = {'persistence': {}, 'logistic_forecast': {}, 'markov': {}}
    current_train = train['current_label']; current_test = test['current_label']
    for hi, h in enumerate(config.horizons):
        truth_train = train['future_label'][:, hi]; truth_test = test['future_label'][:, hi]
        persistence = current_test
        result['persistence'][str(h)] = {
            'accuracy': float(accuracy_score(truth_test, persistence)),
            'macro_f1': float(f1_score(truth_test, persistence, average='macro', zero_division=0)),
        }
        lr = LogisticRegression(max_iter=2000, class_weight='balanced', solver='lbfgs')
        lr.fit(x_train, truth_train)
        lr_pred = lr.predict(x_test)
        result['logistic_forecast'][str(h)] = {
            'accuracy': float(accuracy_score(truth_test, lr_pred)),
            'macro_f1': float(f1_score(truth_test, lr_pred, average='macro', zero_division=0)),
        }
        matrix = np.ones((len(CLASSES), len(CLASSES)), dtype=np.float64)
        for source, target in zip(current_train, truth_train):
            matrix[source, target] += 1.0
        markov_pred = matrix[current_test].argmax(axis=1)
        result['markov'][str(h)] = {
            'accuracy': float(accuracy_score(truth_test, markov_pred)),
            'macro_f1': float(f1_score(truth_test, markov_pred, average='macro', zero_division=0)),
            'transition_matrix': (matrix / matrix.sum(axis=1, keepdims=True)).tolist(),
        }
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--epochs', type=int, default=18)
    parser.add_argument('--batch-size', type=int, default=128)
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--data-dir', type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument('--output-dir', type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument(
        '--feature-transform',
        choices=('auto', 'identity', 'log1p'),
        default='auto',
        help='Feature transform before train-only standardisation. auto uses log1p for real public data.',
    )
    args = parser.parse_args()
    seed_everything(args.seed)
    manifest = json.loads((args.data_dir / 'manifest.json').read_text(encoding='utf-8'))
    config = WorldModelConfig(
        history_steps=int(manifest.get('history_steps', 6)),
        horizons=tuple(int(value) for value in manifest.get('horizons_steps', (1, 3, 6))),
        window_seconds=int(manifest.get('window_seconds', 10)),
        victim_loss_weight=(
            0.0
            if str(manifest.get('victim_supervision', '')).startswith('generic only')
            else 0.35
        ),
    )
    features = list(manifest['features'])
    train = load_npz('train', args.data_dir); val = load_npz('val', args.data_dir); test = load_npz('test', args.data_dir)
    transform_mode = args.feature_transform
    if transform_mode == 'auto':
        transform_mode = 'log1p' if manifest.get('evidence_status') == 'real_public_dataset' else 'identity'
    train = transformed_arrays(train, transform_mode)
    val = transformed_arrays(val, transform_mode)
    test = transformed_arrays(test, transform_mode)
    flat_labels = train['future_label'].reshape(-1)
    class_counts = np.bincount(flat_labels, minlength=len(CLASSES)).astype(np.float64)
    present = class_counts > 0
    class_weights_np = np.zeros(len(CLASSES), dtype=np.float32)
    if present.any():
        class_weights_np[present] = (
            class_counts[present].sum()
            / (float(present.sum()) * class_counts[present])
        ).astype(np.float32)
        class_weights_np[present] /= max(float(class_weights_np[present].mean()), 1e-6)

    def positive_weight(values: np.ndarray) -> float:
        positives = float(values.sum())
        negatives = float(values.size - positives)
        if positives <= 0:
            return 1.0
        return min(50.0, max(1.0, negatives / positives))

    onset_weight_value = positive_weight(train['onset'])
    attack_weight_value = positive_weight(train['attack'])
    change_weight_value = positive_weight(train['change'])
    infiltration_weight_value = positive_weight(train['infiltration'])
    mean = train['x'].mean(axis=(0, 1), keepdims=True).astype(np.float32)
    std = train['x'].std(axis=(0, 1), keepdims=True).astype(np.float32)
    std[std < 1e-6] = 1.0
    train_ds = ArrayDataset(train, mean, std); val_ds = ArrayDataset(val, mean, std); test_ds = ArrayDataset(test, mean, std)
    transition_sequence = train['change'].max(axis=1).astype(np.float64)
    onset_sequence = train['onset'].max(axis=1).astype(np.float64)
    sample_weights = 1.0 + 6.0 * transition_sequence + 3.0 * onset_sequence
    sampler_generator = torch.Generator().manual_seed(args.seed)
    train_sampler = WeightedRandomSampler(
        weights=torch.as_tensor(sample_weights, dtype=torch.double),
        num_samples=len(train_ds),
        replacement=True,
        generator=sampler_generator,
    )
    train_loader = DataLoader(train_ds, batch_size=args.batch_size, sampler=train_sampler)
    val_loader = DataLoader(val_ds, batch_size=args.batch_size, shuffle=False)
    test_loader = DataLoader(test_ds, batch_size=args.batch_size, shuffle=False)
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    class_weights = torch.tensor(class_weights_np, dtype=torch.float32, device=device)
    attack_pos_weight = torch.tensor(attack_weight_value, dtype=torch.float32, device=device)
    change_pos_weight = torch.tensor(change_weight_value, dtype=torch.float32, device=device)
    onset_pos_weight = torch.tensor(onset_weight_value, dtype=torch.float32, device=device)
    infiltration_pos_weight = torch.tensor(infiltration_weight_value, dtype=torch.float32, device=device)
    model = LatentWorldModel(len(features), config).to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=1e-3, weight_decay=1e-4)
    best_state = None; best_val = math.inf; patience = 0; history = []
    for epoch_index in range(1, args.epochs + 1):
        train_loss = epoch(
            model, train_loader, optimizer, config, device,
            class_weights, attack_pos_weight, change_pos_weight, onset_pos_weight, infiltration_pos_weight,
        )
        val_loss = epoch(
            model, val_loader, None, config, device,
            class_weights, attack_pos_weight, change_pos_weight, onset_pos_weight, infiltration_pos_weight,
        )
        history.append({'epoch': epoch_index, 'train': train_loss, 'val': val_loss})
        print(f"epoch={epoch_index:02d} train={train_loss['total']:.4f} val={val_loss['total']:.4f}")
        if val_loss['total'] < best_val - 1e-4:
            best_val = val_loss['total']; best_state = deepcopy(model.state_dict()); patience = 0
        else:
            patience += 1
            if patience >= 5:
                break
    if best_state is not None:
        model.load_state_dict(best_state)

    val_predictions = collect_predictions(model, val_loader, device, config)
    calibration = {str(h): threshold_for_confidence(val_predictions[h]['prob'], val_predictions[h]['truth']) for h in config.horizons}
    test_predictions = collect_predictions(model, test_loader, device, config)
    seen_class_ids = set(int(value) for value in np.unique(flat_labels))
    world_metrics = {
        str(h): horizon_metrics(
            test_predictions[h],
            calibration[str(h)]['threshold'],
            seen_class_ids=seen_class_ids,
        )
        for h in config.horizons
    }

    direct = train_direct_gru(
        train_loader,
        val_loader,
        len(features),
        config,
        device,
        class_weights=class_weights,
    )
    direct_metrics = direct_gru_metrics(direct, test_loader, device, config)
    baselines = classical_baselines(train, test, mean, std, config)

    warning_candidates = []
    generic_warning_candidates = []
    benign_id = CLASSES.index('BENIGN')
    for index in range(len(test['x'])):
        if int(test['current_label'][index]) != benign_id:
            continue
        valid = []
        for hi, h in enumerate(config.horizons):
            truth = int(test['future_label'][index, hi])
            pred = int(test_predictions[h]['prob'][index].argmax())
            if truth != benign_id and pred == truth:
                valid.append(h * config.window_seconds)
            if truth != benign_id and float(test_predictions[h]['attack_prob'][index]) >= 0.5:
                generic_warning_candidates.append(h * config.window_seconds)
        if valid:
            warning_candidates.append(max(valid))
    lead_time = {
        'samples_with_correct_early_warning': len(warning_candidates),
        'median_warning_seconds': float(np.median(warning_candidates)) if warning_candidates else 0.0,
        'p95_warning_seconds': float(np.percentile(warning_candidates, 95)) if warning_candidates else 0.0,
        'generic_attack_warning_samples': len(generic_warning_candidates),
        'generic_attack_median_warning_seconds': (
            float(np.median(generic_warning_candidates)) if generic_warning_candidates else 0.0
        ),
        'generic_attack_p95_warning_seconds': (
            float(np.percentile(generic_warning_candidates, 95)) if generic_warning_candidates else 0.0
        ),
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    torch.save({'state_dict': model.state_dict(), 'feature_count': len(features)}, args.output_dir / 'world_model.pt')
    torch.save({'state_dict': direct.state_dict(), 'feature_count': len(features)}, args.output_dir / 'direct_gru_baseline.pt')
    np.savez(args.output_dir / 'scaler.npz', mean=mean.reshape(-1), std=std.reshape(-1))
    metadata = {
        'model_release': args.output_dir.name,
        'evidence_status': manifest['evidence_status'],
        'data_release': manifest.get('release', args.data_dir.name),
        'features': features,
        'classes': list(CLASSES),
        'victims': list(VICTIMS),
        'history_steps': config.history_steps,
        'window_seconds': config.window_seconds,
        'horizons_steps': list(config.horizons),
        'horizons_seconds': [h * config.window_seconds for h in config.horizons],
        'latent_dim': config.latent_dim,
        'device_trained': str(device),
        'seed': args.seed,
        'feature_transform': transform_mode,
        'class_counts_train': {CLASSES[index]: int(value) for index, value in enumerate(class_counts) if value > 0},
        'class_weights_train': {CLASSES[index]: float(value) for index, value in enumerate(class_weights_np) if value > 0},
        'attack_pos_weight': attack_weight_value,
        'change_pos_weight': change_weight_value,
        'onset_pos_weight': onset_weight_value,
        'infiltration_pos_weight': infiltration_weight_value,
        'delta_encoding': True,
        'transition_sampler': {
            'transition_sequence_weight': 6.0,
            'onset_sequence_weight': 3.0,
            'transition_sequences': int(transition_sequence.sum()),
            'onset_sequences': int(onset_sequence.sum()),
        },
        'victim_supervision': manifest.get('victim_supervision', 'lab_specific'),
    }
    (args.output_dir / 'metadata.json').write_text(json.dumps(metadata, indent=2) + '\n', encoding='utf-8')
    (args.output_dir / 'calibration.json').write_text(json.dumps(calibration, indent=2) + '\n', encoding='utf-8')
    metrics = {
        'evidence_status': manifest['evidence_status'],
        'warning': manifest.get('warning'),
        'unseen_test_classes': manifest.get('unseen_test_classes', []),
        'world_model': world_metrics,
        'direct_gru_baseline': direct_metrics,
        'classical_baselines': baselines,
        'lead_time': lead_time,
        'best_val_loss': best_val,
        'training_history': history,
    }
    (args.output_dir / 'metrics.json').write_text(json.dumps(metrics, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'output': str(args.output_dir), 'world_model': world_metrics, 'lead_time': lead_time}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
