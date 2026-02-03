from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

import numpy as np


@dataclass
class ContextConfig:
    # EWMA smoothing
    ewma_alpha: float = 0.2
    # Sliding window for rates/trends
    window: int = 50

    # Normalization references (keep scales roughly aligned)
    goodput_ref_mbps: float = 20.0
    # Overhead is a ratio (repairs/source). Keep the field name for compatibility.
    overhead_ref_pct: float = 1.0
    # Sender-side retransmission trigger count (repair rounds appended in a transfer)
    # Used to normalize tx_retx_rounds into a similar scale as other features.
    retx_ref: float = 10.0
    residual_ref: float = 5.0


class ContextBuilder:
    """Builds a smoothed, normalized context vector x_t from env outputs.

    Uses only step() outputs (obs/info/reward) and keeps internal history.
    """

    def __init__(self, cfg: ContextConfig):
        self.cfg = cfg
        self._t = 0

        self._ewma_goodput = 0.0
        self._ewma_overhead = 0.0
        self._ewma_retx = 0.0
        self._ewma_residual = 0.0

        self._last_fec_rate = 0.0

        self._residual_hist = []  # 1 if residual>0 else 0

    def reset(self) -> None:
        self._t = 0
        self._ewma_goodput = 0.0
        self._ewma_overhead = 0.0
        self._ewma_retx = 0.0
        self._ewma_residual = 0.0
        self._last_fec_rate = 0.0
        self._residual_hist.clear()

    def get_context(self) -> np.ndarray:
        """Return current context vector x_t for action selection."""

        cfg = self.cfg
        res_rate = float(np.mean(self._residual_hist)) if self._residual_hist else 0.0

        # Backward-compat: older checkpoints used percent scaling (100.0).
        overhead_ref = float(cfg.overhead_ref_pct)
        if overhead_ref > 10.0:
            overhead_ref = overhead_ref / 100.0

        x = np.asarray(
            [
                # 4 x EWMA metrics
                self._ewma_goodput / max(1e-6, cfg.goodput_ref_mbps),
                self._ewma_overhead / max(1e-6, overhead_ref),
                self._ewma_retx / max(1e-6, cfg.retx_ref),
                self._ewma_residual / max(1e-6, cfg.residual_ref),
                # Current fec_rate (from obs)
                float(self._last_fec_rate),
                # history feature
                res_rate,
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
                    2: tx_retx_rounds
                    3: residual_erasures
                    4: fec_rate
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
        retx = _get(2)
        residual = _get(3)
        fec_rate = float(np.clip(_get(4), 0.0, 1.0))
        res_flag = 1.0 if float(residual) > 0.0 else 0.0

        self._ewma_goodput = (1.0 - alpha) * self._ewma_goodput + alpha * goodput
        self._ewma_overhead = (1.0 - alpha) * self._ewma_overhead + alpha * overhead
        self._ewma_retx = (1.0 - alpha) * self._ewma_retx + alpha * retx
        self._ewma_residual = (1.0 - alpha) * self._ewma_residual + alpha * residual
        self._last_fec_rate = fec_rate

        self._push(self._residual_hist, res_flag)

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
                    float(raw_obs.get("residual_erasures", 0.0)),
                    float(raw_obs.get("fec_rate", 0.0)),
                ],
                dtype=np.float64,
            )
            # Insert tx_retx_rounds at index 2 (new layout).
            try:
                tx_retx = float(raw_obs.get("tx_retx_rounds", raw_obs.get("tx_retx_rounds_mean", 0.0)))
            except Exception:
                tx_retx = 0.0
            obs_vec = np.insert(obs_vec, 2, tx_retx)
            self.update_from_obs(obs=obs_vec)
            return

        # Fall back to the minimal safe behavior.
        self.update_from_obs(obs=np.zeros((5,), dtype=np.float64))

    def _push(self, xs: list, v: float) -> None:
        xs.append(float(v))
        if len(xs) > int(self.cfg.window):
            del xs[0]
