from __future__ import annotations

from dataclasses import dataclass

import torch
from torch import nn

from config import CLASSES, HORIZONS, VICTIMS, WorldModelConfig


@dataclass
class WorldModelOutput:
    z0: torch.Tensor
    latent_by_horizon: dict[int, torch.Tensor]
    state_by_horizon: dict[int, torch.Tensor]
    class_logits: dict[int, torch.Tensor]
    attack_logits: dict[int, torch.Tensor]
    change_logits: dict[int, torch.Tensor]
    onset_logits: dict[int, torch.Tensor]
    infiltration_logits: dict[int, torch.Tensor]
    victim_logits: dict[int, torch.Tensor]


class LatentWorldModel(nn.Module):
    def __init__(self, feature_count: int, config: WorldModelConfig | None = None) -> None:
        super().__init__()
        self.config = config or WorldModelConfig()
        self.feature_count = int(feature_count)
        self.step_encoder = nn.Sequential(
            nn.Linear(self.feature_count * 2, self.config.encoder_dim),
            nn.ReLU(),
            nn.LayerNorm(self.config.encoder_dim),
            nn.Dropout(self.config.dropout),
        )
        self.gru = nn.GRU(
            input_size=self.config.encoder_dim,
            hidden_size=self.config.latent_dim,
            num_layers=1,
            batch_first=True,
        )
        self.transition = nn.Sequential(
            nn.Linear(self.config.latent_dim, self.config.transition_hidden),
            nn.ReLU(),
            nn.Linear(self.config.transition_hidden, self.config.latent_dim),
        )
        self.transition_norm = nn.LayerNorm(self.config.latent_dim)
        self.state_decoder = nn.Sequential(
            nn.Linear(self.config.latent_dim, self.config.encoder_dim),
            nn.ReLU(),
            nn.Linear(self.config.encoder_dim, self.feature_count),
        )
        self.class_head = nn.Linear(self.config.latent_dim, len(CLASSES))
        self.attack_head = nn.Linear(self.config.latent_dim, 1)
        self.change_head = nn.Linear(self.config.latent_dim, 1)
        self.onset_head = nn.Linear(self.config.latent_dim, 1)
        self.infiltration_head = nn.Linear(self.config.latent_dim, 1)
        self.victim_head = nn.Linear(self.config.latent_dim, len(VICTIMS))

    def encode(self, x: torch.Tensor) -> torch.Tensor:
        if x.ndim != 3 or x.shape[-1] != self.feature_count:
            raise ValueError(
                f'expected [batch,time,{self.feature_count}] input, received {tuple(x.shape)}'
            )
        delta = torch.diff(x, dim=1, prepend=x[:, :1, :])
        encoded = self.step_encoder(torch.cat([x, delta], dim=-1))
        _, hidden = self.gru(encoded)
        return hidden[-1]

    def transition_once(self, z: torch.Tensor) -> torch.Tensor:
        return self.transition_norm(z + self.transition(z))

    def rollout(self, z0: torch.Tensor, steps: int) -> torch.Tensor:
        z = z0
        for _ in range(int(steps)):
            z = self.transition_once(z)
        return z

    def forward(self, x: torch.Tensor, horizons: tuple[int, ...] = HORIZONS) -> WorldModelOutput:
        z0 = self.encode(x)
        wanted = set(int(item) for item in horizons)
        maximum = max(wanted)
        latent: dict[int, torch.Tensor] = {}
        state: dict[int, torch.Tensor] = {}
        class_logits: dict[int, torch.Tensor] = {}
        attack_logits: dict[int, torch.Tensor] = {}
        change_logits: dict[int, torch.Tensor] = {}
        onset_logits: dict[int, torch.Tensor] = {}
        infiltration_logits: dict[int, torch.Tensor] = {}
        victim_logits: dict[int, torch.Tensor] = {}
        z = z0
        for step in range(1, maximum + 1):
            z = self.transition_once(z)
            if step not in wanted:
                continue
            latent[step] = z
            state[step] = self.state_decoder(z)
            class_logits[step] = self.class_head(z)
            attack_logits[step] = self.attack_head(z).squeeze(-1)
            change_logits[step] = self.change_head(z).squeeze(-1)
            onset_logits[step] = self.onset_head(z).squeeze(-1)
            infiltration_logits[step] = self.infiltration_head(z).squeeze(-1)
            victim_logits[step] = self.victim_head(z)
        return WorldModelOutput(
            z0=z0,
            latent_by_horizon=latent,
            state_by_horizon=state,
            class_logits=class_logits,
            attack_logits=attack_logits,
            change_logits=change_logits,
            onset_logits=onset_logits,
            infiltration_logits=infiltration_logits,
            victim_logits=victim_logits,
        )


class DirectGRUForecaster(nn.Module):
    """Sequence baseline with no learned latent transition/rollout."""

    def __init__(self, feature_count: int, config: WorldModelConfig | None = None) -> None:
        super().__init__()
        self.config = config or WorldModelConfig()
        self.encoder = nn.GRU(feature_count, self.config.latent_dim, batch_first=True)
        self.heads = nn.ModuleDict({
            str(horizon): nn.Linear(self.config.latent_dim, len(CLASSES))
            for horizon in self.config.horizons
        })

    def forward(self, x: torch.Tensor) -> dict[int, torch.Tensor]:
        _, hidden = self.encoder(x)
        z = hidden[-1]
        return {int(key): head(z) for key, head in self.heads.items()}
