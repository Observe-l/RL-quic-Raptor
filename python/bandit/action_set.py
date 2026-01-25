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
    ddl_idx: int

    def to_env_action(self) -> np.ndarray:
        return np.asarray([self.k_idx, self.r0_idx, self.rstep_idx, self.ddl_idx], dtype=np.int64)


class ActionSet:
    """Candidate action set for contextual bandit.

    Notes on discretization:
    - The existing env uses MultiDiscrete indices:
            K = 10 + k_idx, R0_pct = 0.05*r0_idx, RSTEP = 1+rstep_idx, ddl_ms in {100,150,200,250,300,350}.
    """

    def __init__(
        self,
        *,
        k_values: Iterable[int] | None = None,
        r0_pct_values: Iterable[float] | None = None,
        rstep_values: Iterable[int] | None = None,
        ddl_ms_values: Iterable[int] | None = None,
    ):
        # Defaults: representable, moderately sized, aligned with bandit.md intent.
        if k_values is None:
            k_values = list(range(10, 65, 4))  # 10..62 step 4
            if 64 not in k_values:
                k_values = list(k_values) + [64]
        if r0_pct_values is None:
            # Env supports 0.0..1.0 step 0.05; choose a smaller subset.
            r0_pct_values = [0.05, 0.1, 0.15, 0.2, 0.25]
        if rstep_values is None:
            rstep_values = [1, 2, 3, 4, 5, 6, 7, 8]
        if ddl_ms_values is None:
            ddl_ms_values = [100, 150, 200, 250, 300, 350]

        self.k_values = sorted({int(x) for x in k_values})
        self.r0_pct_values = sorted({float(x) for x in r0_pct_values})
        self.rstep_values = sorted({int(x) for x in rstep_values})
        self.ddl_ms_values = sorted({int(x) for x in ddl_ms_values})

        self.actions: List[ActionSpec] = []
        ddl_levels = [100, 150, 200, 250, 300, 350]
        ddl_to_idx = {v: i for i, v in enumerate(ddl_levels)}
        for K in self.k_values:
            k_idx = int(K) - 10
            if not (0 <= k_idx <= 54):
                continue
            for r0 in self.r0_pct_values:
                r0_idx = int(round(float(r0) / 0.05))
                r0_idx = int(np.clip(r0_idx, 0, 20))
                for RSTEP in self.rstep_values:
                    rstep_idx = int(np.clip(int(RSTEP) - 1, 0, 7))
                    for ddl_ms in self.ddl_ms_values:
                        ddl_idx = ddl_to_idx.get(int(ddl_ms))
                        if ddl_idx is None:
                            # Backward-compat: map unsupported values to nearest level.
                            target = int(ddl_ms)
                            ddl_idx = int(min(range(len(ddl_levels)), key=lambda i: abs(int(ddl_levels[i]) - target)))
                        self.actions.append(ActionSpec(k_idx=k_idx, r0_idx=r0_idx, rstep_idx=rstep_idx, ddl_idx=ddl_idx))

        if not self.actions:
            raise ValueError("ActionSet is empty; check discretization values")

        # Factor levels for one-hot encoding (sizes are small).
        self._k_levels = sorted({a.k_idx for a in self.actions})
        self._r0_levels = sorted({a.r0_idx for a in self.actions})
        self._rstep_levels = sorted({a.rstep_idx for a in self.actions})
        self._ddl_levels = sorted({a.ddl_idx for a in self.actions})

        self._k_index = {v: i for i, v in enumerate(self._k_levels)}
        self._r0_index = {v: i for i, v in enumerate(self._r0_levels)}
        self._rstep_index = {v: i for i, v in enumerate(self._rstep_levels)}
        self._ddl_index = {v: i for i, v in enumerate(self._ddl_levels)}

        # Precompute factor one-hot vectors for each action.
        self._a_onehots: List[np.ndarray] = [self._encode_onehot(a) for a in self.actions]

    @property
    def onehot_dim(self) -> int:
        return len(self._k_levels) + len(self._r0_levels) + len(self._rstep_levels) + len(self._ddl_levels)

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
        ddl_dim = len(self._ddl_levels)

        v = np.zeros((k_dim + r0_dim + rs_dim + ddl_dim,), dtype=np.float32)
        off = 0
        v[off + self._k_index[a.k_idx]] = 1.0
        off += k_dim
        v[off + self._r0_index[a.r0_idx]] = 1.0
        off += r0_dim
        v[off + self._rstep_index[a.rstep_idx]] = 1.0
        off += rs_dim
        v[off + self._ddl_index[a.ddl_idx]] = 1.0
        return v
