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
    - This project uses a discrete MultiDiscrete action space.
    - Indices are *factor level indices* (0..n-1), and are mapped by `FecEnv`
      using the exact factor level arrays (K/R0/RSTEP/DDL).
    """

    def __init__(
        self,
        *,
        k_values: Iterable[int] | None = None,
        r0_values: Iterable[int] | None = None,
        # Backward-compat: older checkpoints called this r0_pct_values and used ratios.
        # We still accept it, but new training should use r0_values (symbols).
        r0_pct_values: Iterable[float] | None = None,
        rstep_values: Iterable[int] | None = None,
        ddl_ms_values: Iterable[int] | None = None,
    ):
        # Defaults: representable, moderately sized, aligned with bandit.md intent.
        if k_values is None:
            # Requested discretization: K in [20, 60] step 2.
            k_values = list(range(20, 61, 2))

        # Requested discretization: R0 in [0, 20] step 2 (symbols).
        if r0_values is None and r0_pct_values is None:
            r0_values = list(range(0, 21, 2))

        # If caller passed legacy r0_pct_values, approximate to symbol counts using a
        # conservative reference K (30). This keeps old checkpoints loadable, but note
        # that the intended semantics changed, so old models won't be comparable.
        if r0_values is None and r0_pct_values is not None:
            ref_k = 30
            r0_values = sorted({int(round(float(p) * float(ref_k))) for p in r0_pct_values})

        if rstep_values is None:
            # Requested discretization: RSTEP in [0, 20] step 2.
            rstep_values = list(range(0, 21, 2))
        if ddl_ms_values is None:
            # Requested discretization: receiver ARQ soft deadline in ms.
            ddl_ms_values = [40, 55, 70]

        self.k_values = sorted({int(x) for x in k_values})
        self.r0_values = sorted({int(x) for x in (r0_values or [])})
        self.rstep_values = sorted({int(x) for x in rstep_values})
        self.ddl_ms_values = sorted({int(x) for x in ddl_ms_values})

        if not self.r0_values:
            raise ValueError("r0_values must be non-empty")

        self.actions: List[ActionSpec] = []
        k_levels = list(self.k_values)
        r0_levels = list(self.r0_values)
        rs_levels = list(self.rstep_values)
        ddl_levels = list(self.ddl_ms_values)

        k_to_idx = {int(v): int(i) for i, v in enumerate(k_levels)}
        r0_to_idx = {int(v): int(i) for i, v in enumerate(r0_levels)}
        rs_to_idx = {int(v): int(i) for i, v in enumerate(rs_levels)}
        ddl_to_idx = {int(v): int(i) for i, v in enumerate(ddl_levels)}

        for K in k_levels:
            k_idx = k_to_idx[int(K)]
            for R0 in r0_levels:
                r0_idx = r0_to_idx[int(R0)]
                for RSTEP in rs_levels:
                    rstep_idx = rs_to_idx[int(RSTEP)]
                    for ddl_ms in ddl_levels:
                        ddl_idx = ddl_to_idx[int(ddl_ms)]
                        self.actions.append(
                            ActionSpec(
                                k_idx=int(k_idx),
                                r0_idx=int(r0_idx),
                                rstep_idx=int(rstep_idx),
                                ddl_idx=int(ddl_idx),
                            )
                        )

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
