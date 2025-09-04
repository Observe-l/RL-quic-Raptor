from typing import List, Tuple, Dict, Any
import os
import sys
import numpy as np

try:
    from .multiagentenv import MultiAgentEnv
except Exception:
    # Allow running as a script without package context
    here = os.path.dirname(__file__)
    src_root = os.path.abspath(os.path.join(here, ".."))
    if src_root not in sys.path:
        sys.path.insert(0, src_root)
    from multiagentenv import MultiAgentEnv  # type: ignore
try:
    from quicfec_rl.env import QuicFecEnv, EnvConfig, Action
except ModuleNotFoundError:
    # Allow running from python/src where quicfec_rl lives one level up
    this_dir = os.path.dirname(__file__)
    python_root = os.path.abspath(os.path.join(this_dir, "..", ".."))
    if python_root not in sys.path:
        sys.path.insert(0, python_root)
    from quicfec_rl.env import QuicFecEnv, EnvConfig, Action


class QuicFecWrapper(MultiAgentEnv):
    """
    EPyMARL-compatible single-agent wrapper around the QUIC-FEC episode runner.
    One episode == one file transfer == one step.
    Uses an independent 10-D continuous action space per v2 doc (Box).
    """

    def __init__(
        self,
        rtt_ms: int = 100,
        loss_pct: int = 5,
        bitrate_mbps: int = 10,
        K: int = 40,
        symbol_bytes: int = 1200,
        prefer_local: bool = True,
        common_reward: bool = True,
        reward_scalarisation: str = "sum",
        **kwargs,
    ) -> None:
        self._rtt_ms = int(rtt_ms)
        self._loss_pct = int(loss_pct)
        self._bitrate = int(bitrate_mbps) * 1_000_000

        # Underlying single-episode environment; prefer local smoke script to avoid sudo
        self._env = QuicFecEnv(prefer_local=prefer_local)
        self._env.reset(
            EnvConfig(
                datagrams_enabled=True,
                num_connections=1,
                cc_mode="bypass",
                target_bitrate_bps=self._bitrate,
                loss_profile=f"iid:{self._loss_pct}",
                K=K,
                symbol_bytes=symbol_bytes,
            )
        )
        # Continuous action Box per v2 doc (length 10)
        self._act_low = np.array([8, 256, 0.10, 2, 4, 50, 0.3, 0, 0, 0.8], dtype=np.float32)
        self._act_high = np.array([64, 1300, 0.30, 8, 16, 150, 1.2, 3, 8, 1.2], dtype=np.float32)

        # Observation mapping: project the server Observation dict to a numeric vector
        self._obs_keys = [
            "goodput_decode_mbps",
            "duration_decode_ms",
            "residual_erasures",
            "fec_overhead_pct_arrival",
            "arq_attempts_mean",
            "arq_attempts_p95",
            "rx_unique_at_ddl_mean",
            "rx_unique_at_ddl_p95",
            "decode_latency_p50_ms",
            "decode_latency_p95_ms",
            "estimated_available_bw_mbps_p95",
            "estimated_available_bw_mbps_peak",
        ]

        self.n_agents = 1
        self.episode_limit = 1  # 1 step per episode
        self._last_obs_vec = np.zeros(len(self._obs_keys), dtype=np.float32)

    # --- MultiAgentEnv API ---
    def step(self, actions):
        """Returns obss, reward, terminated, truncated, info"""
        # Accept either a 10-D vector (preferred) or a scalar (fallback for discrete controllers)
        if isinstance(actions, (list, tuple, np.ndarray)):
            a = np.asarray(actions[0], dtype=np.float32).reshape(-1)
        else:
            a = np.asarray(actions, dtype=np.float32).reshape(-1)
        if a.size == 1:
            # Fallback: use midpoints as a neutral independent action vector
            a = (self._act_low + self._act_high) / 2.0
        if a.shape[0] != 10:
            raise ValueError("Action must be a 10-D vector per v2 action space or a scalar for fallback mode")
        a = np.clip(a, self._act_low, self._act_high)

        # Map → quantize → guard (PMTU safety and simple guards)
        K = int(round(float(a[0])))
        symbol_bytes = int(round(float(a[1])))
        R0_pct = float(a[2])
        R_step = int(round(float(a[3])))
        W = int(round(float(a[4])))
        ddl_ms = int(round(float(a[5])))
        alpha = float(a[6])
        epsilon = int(round(float(a[7])))
        interleaver_span = int(round(float(a[8])))
        pacing_gain = float(a[9])

        # PMTU guard with safety and alignment
        safety = 12
        align = 4
        max_payload = 1300 - safety
        symbol_bytes = min(symbol_bytes, max_payload)
        symbol_bytes = symbol_bytes - (symbol_bytes % align)

        R0 = int(round(K * R0_pct))
        R_step = max(1, min(R_step, 16))
        W = max(1, min(W, 32))

        act = Action(R0=R0, R_step=R_step, window_W=W, ddl_ms=ddl_ms, alpha=alpha, epsilon=epsilon,
                      interleaver_span=interleaver_span, pacing_gain=pacing_gain, K=K, symbol_bytes=symbol_bytes)

        obs_dict, reward, done, info = self._env.step(act, rtt_ms=self._rtt_ms, loss_pct=self._loss_pct)
        self._last_obs_vec = self._obs_to_vec(obs_dict)
        terminated = bool(done)
        truncated = False
        return [self._last_obs_vec], float(reward), terminated, truncated, {"raw_obs": obs_dict, **info, "applied_action": {
            "K": K, "symbol_bytes": symbol_bytes, "R0": R0, "R_step": R_step, "W": W, "ddl_ms": ddl_ms,
            "alpha": alpha, "epsilon": epsilon, "interleaver_span": interleaver_span, "pacing_gain": pacing_gain
        }}

    def get_obs(self):
        return [self._last_obs_vec]

    def get_obs_agent(self, agent_id):
        return self._last_obs_vec

    def get_obs_size(self):
        return len(self._obs_keys)

    def get_state(self):
        return self._last_obs_vec.astype(np.float32)

    def get_state_size(self):
        return len(self._obs_keys)

    def get_avail_actions(self):
        return [self.get_avail_agent_actions(0)]

    def get_avail_agent_actions(self, agent_id):
        return [1] * self.get_total_actions()

    def get_total_actions(self):
        # Return the dimensionality for EPyMARL; it will treat as continuous via policy
        return 10

    def reset(self, seed=None, options=None):
        self._last_obs_vec = np.zeros(len(self._obs_keys), dtype=np.float32)
        return [self._last_obs_vec], {}

    def render(self):
        pass

    def close(self):
        pass

    def seed(self, seed=None):
        pass

    def save_replay(self):
        pass

    def get_stats(self):
        return {}

    # --- helpers ---
    def _obs_to_vec(self, obs: Dict[str, Any]) -> np.ndarray:
        vals: List[float] = []
        for k in self._obs_keys:
            v = obs.get(k, 0.0)
            try:
                vals.append(float(v))
            except Exception:
                vals.append(0.0)
        return np.asarray(vals, dtype=np.float32)
