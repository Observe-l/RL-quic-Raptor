from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

import numpy as np


@dataclass
class ContextConfig:
    # EWMA smoothing
    ewma_alpha: float = 0.2
    # Sliding window for rates/trends
    window: int = 50

    # Normalization references (bandit.md suggests aligning scales)
    goodput_ref_mbps: float = 20.0
    # Kept for checkpoint compatibility; delay is no longer part of the context.
    delay_ref_ms: float = 600.0
    # Overhead is now a ratio (repairs/source). Keep the field name for
    # checkpoint compatibility, but default the scale to 1.0.
    overhead_ref_pct: float = 1.0
    nack_ref: float = 50.0
    residual_ref: float = 5.0
    arq_ref: float = 10.0


class ContextBuilder:
    """Builds a smoothed, normalized context vector x_t from env outputs.

    Uses only step() outputs (obs/info/reward) and keeps internal history.
    """

    def __init__(self, cfg: ContextConfig):
        self.cfg = cfg
        self._t = 0

        self._ewma_goodput = 0.0
        self._ewma_overhead = 0.0
        self._ewma_nack = 0.0
        self._ewma_arq = 0.0
        self._ewma_residual = 0.0

        self._last_fec_rate = 0.0

        self._residual_hist = []  # 1 if residual>0 else 0
        self._timeout_hist = []
        self._residual_value_hist = []

    def reset(self) -> None:
        self._t = 0
        self._ewma_goodput = 0.0
        self._ewma_overhead = 0.0
        self._ewma_nack = 0.0
        self._ewma_arq = 0.0
        self._ewma_residual = 0.0
        self._last_fec_rate = 0.0
        self._residual_hist.clear()
        self._timeout_hist.clear()
        self._residual_value_hist.clear()

    def get_context(self) -> np.ndarray:
        """Return current context vector x_t for action selection."""

        cfg = self.cfg
        res_rate = float(np.mean(self._residual_hist)) if self._residual_hist else 0.0
        to_rate = float(np.mean(self._timeout_hist)) if self._timeout_hist else 0.0
        residual_mean = float(np.mean(self._residual_value_hist)) if self._residual_value_hist else 0.0

        # Backward-compat: older checkpoints used percent scaling (100.0).
        overhead_ref = float(cfg.overhead_ref_pct)
        if overhead_ref > 10.0:
            overhead_ref = overhead_ref / 100.0

        x = np.asarray(
            [
                # 5 x EWMA metrics
                self._ewma_goodput / max(1e-6, cfg.goodput_ref_mbps),
                self._ewma_overhead / max(1e-6, overhead_ref),
                self._ewma_nack / max(1e-6, cfg.nack_ref),
                self._ewma_arq / max(1e-6, cfg.arq_ref),
                self._ewma_residual / max(1e-6, cfg.residual_ref),
                # Current fec_rate (from obs)
                float(self._last_fec_rate),
                # 3 x history features
                res_rate,
                to_rate,
                residual_mean / max(1e-6, cfg.residual_ref),
            ],
            dtype=np.float32,
        )
        return np.clip(x, 0.0, 10.0)

    def update_from_obs(self, *, obs: np.ndarray) -> None:
        """Update context state using ONLY the environment observation vector.

        This is the bandit-safe path: it does not depend on `info`, which may
        contain debugging or leakage-prone fields.

                Expected obs layout (from `FecEnv._obs_keys`):
                    0: goodput
                    1: fec_overhead
                    2: ctrl_tx_nack_msgs
                    3: arq_attempts_mean
                    4: residual_erasures
                    5: fec_rate
        """

        cfg = self.cfg
        alpha = float(cfg.ewma_alpha)

        v = np.asarray(obs, dtype=np.float64).reshape(-1)

        def _get(i: int) -> float:
            if 0 <= int(i) < int(v.size):
                try:
                    return float(v[int(i)])
                except Exception:
                    return 0.0
            return 0.0

        goodput = _get(0)
        overhead = _get(1)
        nack = _get(2)
        arq = _get(3)
        residual = _get(4)
        fec_rate = float(np.clip(_get(5), 0.0, 1.0))
        # No explicit timeout flag in obs; treat zero-goodput as timeout/failure.
        is_timeout = 1.0 if float(goodput) <= 1e-6 else 0.0
        res_flag = 1.0 if float(residual) > 0.0 else 0.0

        self._ewma_goodput = (1.0 - alpha) * self._ewma_goodput + alpha * goodput
        self._ewma_overhead = (1.0 - alpha) * self._ewma_overhead + alpha * overhead
        self._ewma_nack = (1.0 - alpha) * self._ewma_nack + alpha * nack
        self._ewma_arq = (1.0 - alpha) * self._ewma_arq + alpha * arq
        self._ewma_residual = (1.0 - alpha) * self._ewma_residual + alpha * residual
        self._last_fec_rate = fec_rate

        self._push(self._residual_hist, res_flag)
        self._push(self._timeout_hist, is_timeout)
        self._push(self._residual_value_hist, residual)

        self._t += 1

    def update(self, *, info: Dict[str, Any]) -> None:
        """Backward-compatible update path.

        New training/evaluation should call `update_from_obs()`.
        """

        # Best-effort: if caller provided raw_obs (policy-safe), map it to a
        # minimal obs vector and then use the obs-only path.
        raw_obs = info.get("raw_obs") if isinstance(info, dict) else None
        if isinstance(raw_obs, dict):
            obs_vec = np.asarray(
                [
                    float(raw_obs.get("goodput", raw_obs.get("goodput_mbps", raw_obs.get("goodput_arrival_mbps", raw_obs.get("goodput_decode_mbps", 0.0))))),
                    float(raw_obs.get("fec_overhead", raw_obs.get("fec_overhead_pct_arrival", 0.0))),
                    float(raw_obs.get("ctrl_tx_nack_msgs", 0.0)),
                    float(raw_obs.get("arq_attempts_mean", 0.0)),
                    float(raw_obs.get("residual_erasures", 0.0)),
                    float(raw_obs.get("fec_rate", 0.0)),
                ],
                dtype=np.float64,
            )
            self.update_from_obs(obs=obs_vec)
            return

        # Fall back to the minimal safe behavior.
        self.update_from_obs(obs=np.zeros((6,), dtype=np.float64))

    def _push(self, xs: list, v: float) -> None:
        xs.append(float(v))
        if len(xs) > int(self.cfg.window):
            del xs[0]
