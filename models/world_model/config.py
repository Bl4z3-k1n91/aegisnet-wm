from __future__ import annotations

from dataclasses import dataclass

CLASSES = (
    'BENIGN',
    'RECONNAISSANCE',
    'INITIAL_ACCESS_PATTERN',
    'LATERAL_MOVEMENT',
    'C2_BEACON_PATTERN',
    'EXFILTRATION_LIKE',
    'DDOS_LOW',
    'DDOS_MEDIUM',
    'DDOS_HIGH',
)
CLASS_TO_ID = {name: index for index, name in enumerate(CLASSES)}
VICTIMS = ('NONE', 'BR1', 'BR2', 'HUB', 'DC', 'MULTI')
VICTIM_TO_ID = {name: index for index, name in enumerate(VICTIMS)}
HORIZONS = (1, 3, 6)
WINDOW_SECONDS = 10
HISTORY_STEPS = 6
INFILTRATION_CLASSES = {
    'INITIAL_ACCESS_PATTERN',
    'LATERAL_MOVEMENT',
    'C2_BEACON_PATTERN',
    'EXFILTRATION_LIKE',
}
VICTIM_BY_CLASS = {
    'BENIGN': 'NONE',
    'RECONNAISSANCE': 'MULTI',
    'INITIAL_ACCESS_PATTERN': 'DC',
    'LATERAL_MOVEMENT': 'MULTI',
    'C2_BEACON_PATTERN': 'BR2',
    'EXFILTRATION_LIKE': 'BR2',
    'DDOS_LOW': 'DC',
    'DDOS_MEDIUM': 'DC',
    'DDOS_HIGH': 'DC',
}

ATTACK_CHAINS = (
    ('BENIGN', 'RECONNAISSANCE', 'INITIAL_ACCESS_PATTERN', 'LATERAL_MOVEMENT', 'C2_BEACON_PATTERN', 'EXFILTRATION_LIKE'),
    ('BENIGN', 'RECONNAISSANCE', 'INITIAL_ACCESS_PATTERN', 'C2_BEACON_PATTERN', 'EXFILTRATION_LIKE'),
    ('BENIGN', 'DDOS_LOW', 'DDOS_MEDIUM', 'DDOS_HIGH'),
    ('BENIGN', 'RECONNAISSANCE', 'DDOS_LOW', 'DDOS_MEDIUM', 'DDOS_HIGH'),
)

@dataclass(frozen=True)
class WorldModelConfig:
    history_steps: int = HISTORY_STEPS
    horizons: tuple[int, ...] = HORIZONS
    window_seconds: int = WINDOW_SECONDS
    encoder_dim: int = 64
    latent_dim: int = 64
    transition_hidden: int = 128
    dropout: float = 0.10
    state_loss_weight: float = 0.25
    attack_loss_weight: float = 0.50
    change_loss_weight: float = 0.60
    onset_loss_weight: float = 0.50
    infiltration_loss_weight: float = 0.50
    victim_loss_weight: float = 0.35
