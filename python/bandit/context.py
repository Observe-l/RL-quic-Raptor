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
    delay_ref_ms: float = 600.0
    overhead_ref_pct: float = 100.0
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
        self._ewma_d95 = 0.0
        self._ewma_overhead = 0.0
        self._ewma_nack = 0.0
        self._ewma_arq = 0.0

        self._residual_hist = []  # 1 if residual>0 else 0
        self._timeout_hist = []
        self._delay_violate_hist = []  # 1 if d95>ddl else 0
        self._residual_value_hist = []

    def reset(self) -> None:
        self._t = 0
        self._ewma_goodput = 0.0
        self._ewma_d95 = 0.0
        self._ewma_overhead = 0.0
        self._ewma_nack = 0.0
        self._ewma_arq = 0.0
        self._residual_hist.clear()
        self._timeout_hist.clear()
        self._delay_violate_hist.clear()
        self._residual_value_hist.clear()

    def get_context(self) -> np.ndarray:
        """Return current context vector x_t for action selection."""

        cfg = self.cfg
        res_rate = float(np.mean(self._residual_hist)) if self._residual_hist else 0.0
        to_rate = float(np.mean(self._timeout_hist)) if self._timeout_hist else 0.0
        delay_violate_rate = float(np.mean(self._delay_violate_hist)) if self._delay_violate_hist else 0.0
        residual_mean = float(np.mean(self._residual_value_hist)) if self._residual_value_hist else 0.0

        x = np.asarray(
            [
                self._ewma_goodput / max(1e-6, cfg.goodput_ref_mbps),
                self._ewma_d95 / max(1e-6, cfg.delay_ref_ms),
                self._ewma_overhead / max(1e-6, cfg.overhead_ref_pct),
                self._ewma_nack / max(1e-6, cfg.nack_ref),
                res_rate,
                to_rate,
                delay_violate_rate,
                residual_mean / max(1e-6, cfg.residual_ref),
                self._ewma_arq / max(1e-6, cfg.arq_ref),
            ],
            dtype=np.float32,
        )
        return np.clip(x, 0.0, 10.0)

    def update(self, *, info: Dict[str, Any], ddl_ms: int) -> None:
        """Update context state based on env info from the last step."""

        cfg = self.cfg
        alpha = float(cfg.ewma_alpha)

        raw_obs = info.get("raw_obs") if isinstance(info, dict) else None
        if not isinstance(raw_obs, dict):
            raw_obs = {}

        # Prefer the env-provided goodput metric (it is part of reward computation).
        goodput = float(info.get("goodput_mbps", 0.0))
        d95 = float(raw_obs.get("decode_latency_p95_ms", info.get("decode_latency_p95_ms", 0.0)))
        overhead = float(raw_obs.get("fec_overhead_pct_arrival", 0.0))
        nack = float(raw_obs.get("ctrl_tx_nack_msgs", 0.0))
        residual = float(raw_obs.get("residual_erasures", 0.0))
        arq = float(raw_obs.get("arq_attempts_mean", 0.0))

        # Timeout detection: env uses info["error"] containing "timeout".
        err = info.get("error") if isinstance(info, dict) else None
        is_timeout = 0.0
        if isinstance(err, str) and err.lower().startswith("timeout"):
            is_timeout = 1.0

        violate = 1.0 if float(d95) > float(max(1, int(ddl_ms))) else 0.0
        res_flag = 1.0 if float(residual) > 0.0 else 0.0

        # EWMA updates
        self._ewma_goodput = (1.0 - alpha) * self._ewma_goodput + alpha * goodput
        self._ewma_d95 = (1.0 - alpha) * self._ewma_d95 + alpha * d95
        self._ewma_overhead = (1.0 - alpha) * self._ewma_overhead + alpha * overhead
        self._ewma_nack = (1.0 - alpha) * self._ewma_nack + alpha * nack
        self._ewma_arq = (1.0 - alpha) * self._ewma_arq + alpha * arq

        # Windowed stats
        self._push(self._residual_hist, res_flag)
        self._push(self._timeout_hist, is_timeout)
        self._push(self._delay_violate_hist, violate)
        self._push(self._residual_value_hist, residual)

        self._t += 1

    def _push(self, xs: list, v: float) -> None:
        xs.append(float(v))
        if len(xs) > int(self.cfg.window):
            del xs[0]
