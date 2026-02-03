from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Tuple

import numpy as np


@dataclass(frozen=True)
class ActionSpec:
    """Action in the *environment's* MultiDiscrete index space."""

    k_idx: int
    r0_idx: int
    rstep_idx: int

    def to_env_action(self) -> np.ndarray:
        return np.asarray([self.k_idx, self.r0_idx, self.rstep_idx], dtype=np.int64)


class ActionSet:
    """Candidate action set for contextual bandit.

    Notes on discretization:
    - The existing env uses MultiDiscrete indices:
        K = 20 + 2*k_idx, R0 = r0_idx, RSTEP = 1 + rstep_idx.
    """

    def __init__(
        self,
        *,
        k_values: Iterable[int] | None = None,
        r0_values: Iterable[int] | None = None,
        rstep_values: Iterable[int] | None = None,
    ):
        # Defaults: representable, moderately sized, aligned with bandit.md intent.
        if k_values is None:
            k_values = list(range(20, 61, 2))
        if r0_values is None:
            r0_values = list(range(0, 21))
        if rstep_values is None:
            rstep_values = list(range(1, 21))

        self.k_values = sorted({int(x) for x in k_values})
        self.r0_values = sorted({int(x) for x in r0_values})
        self.rstep_values = sorted({int(x) for x in rstep_values})

        self.actions: List[ActionSpec] = []
        for K in self.k_values:
            k_idx = (int(K) - 20) // 2
            if int(K) != int(20 + 2 * k_idx):
                continue
            if not (0 <= k_idx <= 20):
                continue
            for R0 in self.r0_values:
                r0_idx = int(np.clip(int(R0), 0, 20))
                for RSTEP in self.rstep_values:
                    rstep_idx = int(np.clip(int(RSTEP) - 1, 0, 19))
                    self.actions.append(ActionSpec(k_idx=k_idx, r0_idx=r0_idx, rstep_idx=rstep_idx))

        if not self.actions:
            raise ValueError("ActionSet is empty; check discretization values")

        # Factor levels for one-hot encoding (sizes are small).
        self._k_levels = sorted({a.k_idx for a in self.actions})
        self._r0_levels = sorted({a.r0_idx for a in self.actions})
        self._rstep_levels = sorted({a.rstep_idx for a in self.actions})

        self._k_index = {v: i for i, v in enumerate(self._k_levels)}
        self._r0_index = {v: i for i, v in enumerate(self._r0_levels)}
        self._rstep_index = {v: i for i, v in enumerate(self._rstep_levels)}

        # Precompute factor one-hot vectors for each action.
        self._a_onehots: List[np.ndarray] = [self._encode_onehot(a) for a in self.actions]

    @property
    def onehot_dim(self) -> int:
        return len(self._k_levels) + len(self._r0_levels) + len(self._rstep_levels)

    def __len__(self) -> int:
        return len(self.actions)

    def iter_actions(self) -> Iterable[Tuple[int, ActionSpec]]:
        for i, a in enumerate(self.actions):
            yield i, a

    def get_action(self, idx: int) -> ActionSpec:
        return self.actions[int(idx)]

    def get_onehot(self, idx: int) -> np.ndarray:
        return self._a_onehots[int(idx)]

    def _encode_onehot(self, a: ActionSpec) -> np.ndarray:
        k_dim = len(self._k_levels)
        r0_dim = len(self._r0_levels)
        rs_dim = len(self._rstep_levels)

        v = np.zeros((k_dim + r0_dim + rs_dim,), dtype=np.float32)
        off = 0
        v[off + self._k_index[a.k_idx]] = 1.0
        off += k_dim
        v[off + self._r0_index[a.r0_idx]] = 1.0
        off += r0_dim
        v[off + self._rstep_index[a.rstep_idx]] = 1.0
        return v
