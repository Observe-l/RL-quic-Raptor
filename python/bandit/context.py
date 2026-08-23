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
        self._ewma_done_flag = 0.0

        # Backward-compat fields (older checkpoints may contain these).
        self._ewma_arq = 0.0
        self._ewma_residual = 0.0

        self._last_fec_rate = 0.0

        # New history feature: failure/late history (1 - done_flag).
        self._fail_hist: list[float] = []

        # Backward-compat hists
        self._residual_hist = []  # 1 if residual>0 else 0
        self._timeout_hist = []
        self._residual_value_hist = []

    def reset(self) -> None:
        self._t = 0
        self._ewma_goodput = 0.0
        self._ewma_overhead = 0.0
        self._ewma_nack = 0.0
        self._ewma_done_flag = 0.0
        self._ewma_arq = 0.0
        self._ewma_residual = 0.0
        self._last_fec_rate = 0.0
        self._fail_hist.clear()
        self._residual_hist.clear()
        self._timeout_hist.clear()
        self._residual_value_hist.clear()

    def get_context(self) -> np.ndarray:
        """Return current context vector x_t for action selection."""

        cfg = self.cfg
        fail_rate = float(np.mean(self._fail_hist)) if self._fail_hist else 0.0

        # Backward-compat: older checkpoints used percent scaling (100.0).
        overhead_ref = float(cfg.overhead_ref_pct)
        if overhead_ref > 10.0:
            overhead_ref = overhead_ref / 100.0

        # Requested context features:
        #   _ewma_goodput,_ewma_overhead,_ewma_nack,_ewma_done_flag,fec_rate,_fail_hist
        x = np.asarray(
            [
                self._ewma_goodput / max(1e-6, cfg.goodput_ref_mbps),
                self._ewma_overhead / max(1e-6, overhead_ref),
                self._ewma_nack / max(1e-6, cfg.nack_ref),
                float(np.clip(self._ewma_done_flag, 0.0, 1.0)),
                float(np.clip(self._last_fec_rate, 0.0, 1.0)),
                float(np.clip(fail_rate, 0.0, 1.0)),
            ],
            dtype=np.float32,
        )
        return np.clip(x, 0.0, 10.0)

    def update_from_obs(self, *, obs: np.ndarray, ddl_ms: Optional[int] = None) -> None:
        """Update context state using ONLY the environment observation vector.

        This is the bandit-safe path: it does not depend on `info`, which may
        contain debugging or leakage-prone fields.

                Expected obs layout (from `FecEnv._obs_keys`):
                    0: goodput
                    1: fec_overhead
                    2: ctrl_tx_nack_msgs
                    3: done_flag
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
        nack = _get(2)
        done_flag = float(np.clip(_get(3), 0.0, 1.0))
        fec_rate = float(np.clip(_get(4), 0.0, 1.0))
        # Failure/late history: 1 - done_flag.
        fail_flag = 1.0 - float(done_flag)

        self._ewma_goodput = (1.0 - alpha) * self._ewma_goodput + alpha * goodput
        self._ewma_overhead = (1.0 - alpha) * self._ewma_overhead + alpha * overhead
        self._ewma_nack = (1.0 - alpha) * self._ewma_nack + alpha * nack
        self._ewma_done_flag = (1.0 - alpha) * self._ewma_done_flag + alpha * float(done_flag)
        self._last_fec_rate = fec_rate

        self._push(self._fail_hist, float(fail_flag))

        self._t += 1

    def update(self, *, info: Dict[str, Any], ddl_ms: Optional[int] = None) -> None:
        """Backward-compatible update path.

        New training/evaluation should call `update_from_obs()`.
        """

        # Best-effort: if caller provided raw_obs (policy-safe), map it to a
        # minimal obs vector and then use the obs-only path.
        raw_obs = info.get("raw_obs") if isinstance(info, dict) else None
        if isinstance(raw_obs, dict):
            # Expected obs layout (new):
            #   0 goodput, 1 overhead, 2 nack, 3 done_flag, 4 fec_rate
            # If done_flag is missing (older logs), fall back to (1 - timeout_flag).
            goodput = float(
                raw_obs.get(
                    "goodput",
                    raw_obs.get("goodput_mbps", raw_obs.get("goodput_arrival_mbps", raw_obs.get("goodput_decode_mbps", 0.0))),
                )
            )
            overhead = float(raw_obs.get("fec_overhead", raw_obs.get("fec_overhead_pct_arrival", 0.0)))
            nack = float(raw_obs.get("ctrl_tx_nack_msgs", 0.0))
            done_flag = raw_obs.get("done_flag")
            if done_flag is None:
                timeout_flag = float(raw_obs.get("timeout_flag", 0.0))
                done_flag = 1.0 - float(np.clip(timeout_flag, 0.0, 1.0))
            fec_rate = float(raw_obs.get("fec_rate", 0.0))
            obs_vec = np.asarray(
                [
                    goodput,
                    overhead,
                    nack,
                    float(done_flag),
                    fec_rate,
                ],
                dtype=np.float64,
            )
            self.update_from_obs(obs=obs_vec)
            return

        # Fall back to the minimal safe behavior.
        self.update_from_obs(obs=np.zeros((5,), dtype=np.float64))

    def _push(self, xs: list, v: float) -> None:
        xs.append(float(v))
        if len(xs) > int(self.cfg.window):
            del xs[0]
