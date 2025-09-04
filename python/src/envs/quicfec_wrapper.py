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
    Supports a 10-D continuous action vector (preferred) and a legacy discrete
    index that selects from a codebook of continuous presets.
    """

    def __init__(
        self,
        rtt_ms: int = 100,
        loss_pct: int = 5,
        bitrate_mbps: int = 10,
        K: int = 40,
        symbol_bytes: int = 1200,
        prefer_local: bool = False,
        action_codebook_size: int = 64,
        common_reward: bool = True,
        reward_scalarisation: str = "sum",
        **kwargs,
    ) -> None:
        self._rtt_ms = int(rtt_ms)
        self._loss_pct = int(loss_pct)
        self._bitrate = int(bitrate_mbps) * 1_000_000

        # Underlying single-episode environment; prefer local smoke script to avoid sudo
        # Use a moderate timeout per episode to prevent hangs
        self._env = QuicFecEnv(prefer_local=prefer_local, timeout_sec=15)
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

        # Continuous action Box (length 10)
        # Tighter safe ranges for shaped runs at 10 Mbps, 100 ms, ~10% loss
        # Action order:
        #   [K, symbol_bytes, R0_pct, R_step, W, ddl_ms, alpha, epsilon, interleaver_span, pacing_gain]
        self._act_low = np.array([16, 400, 0.12, 2, 6, 160, 0.4, 0, 0, 0.85], dtype=np.float32)
        self._act_high = np.array([64, 1200, 0.28, 8, 18, 340, 1.1, 3, 6, 1.15], dtype=np.float32)

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

        # Build a discrete action codebook: each entry is a 10-D vector within bounds.
        # This lets a discrete IPPO policy choose among diverse continuous presets.
        rs = np.random.RandomState(42)
        size = int(max(2, action_codebook_size))
        u = rs.rand(size, 10).astype(np.float32)
        self._codebook = self._act_low + u * (self._act_high - self._act_low)
        # Snap integer-like dims to nearby integers (K, symbol_bytes, R_step, W, ddl_ms, epsilon, interleaver_span)
        int_idx = [0, 1, 3, 4, 5, 7, 8]
        self._codebook[:, int_idx] = np.round(self._codebook[:, int_idx])

    # --- MultiAgentEnv API ---
    def step(self, actions):
        """Returns obss, reward, terminated, truncated, info"""
        # Decode action in dual-mode: continuous vector (preferred) or discrete index -> codebook
        a = self._decode_action(actions)

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
        max_payload = 1200 - safety  # keep margin for headers/qdisc quirks
        symbol_bytes = min(symbol_bytes, max_payload)
        symbol_bytes = symbol_bytes - (symbol_bytes % align)

        R0 = max(2, int(round(K * R0_pct)))
        R_step = max(1, min(R_step, 12))
        W = max(6, min(W, 24))
        ddl_ms = int(min(max(ddl_ms, 150), 340))

        act = Action(
            R0=R0,
            R_step=R_step,
            window_W=W,
            ddl_ms=ddl_ms,
            alpha=alpha,
            epsilon=epsilon,
            interleaver_span=interleaver_span,
            pacing_gain=pacing_gain,
            K=K,
            symbol_bytes=symbol_bytes,
        )

        obs_dict, reward, done, info = self._env.step(
            act,
            rtt_ms=self._rtt_ms,
            loss_pct=self._loss_pct,
            bitrate_mbps=int(self._bitrate / 1_000_000),
        )
        self._last_obs_vec = self._obs_to_vec(obs_dict)
        terminated = bool(done)
        truncated = False
        return [self._last_obs_vec], float(reward), terminated, truncated, {
            "raw_obs": obs_dict,
            **info,
            "applied_action": {
                "K": K,
                "symbol_bytes": symbol_bytes,
                "R0": R0,
                "R_step": R_step,
                "W": W,
                "ddl_ms": ddl_ms,
                "alpha": alpha,
                "epsilon": epsilon,
                "interleaver_span": interleaver_span,
                "pacing_gain": pacing_gain,
            },
        }

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
        # Return the number of discrete actions available (size of the codebook)
        return int(self._codebook.shape[0])

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

    def _decode_action(self, actions: Any) -> np.ndarray:
        """Return a 10-D continuous action within [low, high].
        Accepts either a continuous vector or a discrete index -> codebook.
        Continuous input is interpreted as normalized in [0,1]. If values fall in [-1,1],
        they are linearly mapped to [0,1]. Values outside are clipped.
        """
        # Try to parse as array-like first
        try:
            arr = np.asarray(actions, dtype=np.float32)
            # Common shapes from runners: [1, 10] or [10]
            flat = arr.reshape(-1)
            if flat.size >= 10:
                vec = flat[:10]
                vmin, vmax = float(np.min(vec)), float(np.max(vec))
                # Map from [-1,1] -> [0,1] if needed
                if vmin < -0.05:
                    vec = (vec + 1.0) * 0.5
                # Clip to [0,1]
                vec = np.clip(vec, 0.0, 1.0)
                # Scale to [low, high]
                a = self._act_low + vec * (self._act_high - self._act_low)
                # Quantize integer-like dims
                int_idx = [0, 1, 3, 4, 5, 7, 8]
                a[int_idx] = np.round(a[int_idx])
                return a.astype(np.float32)
        except Exception:
            pass

        # Fallback: treat as discrete index into the codebook
        if isinstance(actions, (list, tuple, np.ndarray)):
            idx = int(np.asarray(actions[0]).reshape(-1)[0])
        else:
            idx = int(actions)
        idx = int(np.clip(idx, 0, len(self._codebook) - 1))
        return self._codebook[idx].astype(np.float32)
