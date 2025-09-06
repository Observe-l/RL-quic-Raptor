from __future__ import annotations

import os
import json
import time
import subprocess
from dataclasses import dataclass
from typing import Dict, Any, Tuple, Optional, List

import numpy as np

try:
    import gymnasium as gym
    from gymnasium import spaces
except Exception:
    import gym  # type: ignore
    from gym import spaces  # type: ignore


@dataclass
class EnvConfig:
    datagrams_enabled: bool = True
    num_connections: int = 1
    cc_mode: str = "bypass"
    target_bitrate_bps: int = 10_000_000
    loss_profile: str = "iid:0"
    K: int = 40
    symbol_bytes: int = 1200


@dataclass
class Action:
    R0: int = 6
    R_step: int = 4
    window_W: int = 8
    ddl_ms: int = 200
    alpha: float = 0.6
    epsilon: int = 1
    interleaver_span: int = 0
    pacing_gain: float = 1.0
    K: int | None = None
    symbol_bytes: int | None = None


class QuicFecRunner:
    def __init__(self, root: str | None = None, ns: str = "qns", timeout_sec: int = 15):
        self.root = root or os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        self.ns = ns
        # Only use the shaped runner script (no local mode)
        self.script = os.path.join(self.root, "scripts", "quicfec_run_once.sh")
        self.obs_jsonl = os.environ.get("QUICFEC_OBS_JSONL", "/tmp/quicfec_rl.jsonl")
        self.last_cfg = None
        self.timeout_sec = int(timeout_sec)

    def reset(self, cfg: EnvConfig) -> Dict[str, Any]:
        self.last_cfg = cfg
        # Ensure sudo is available for shaping runs
        self._sudo_check()
        return {"ok": True}

    def step(self, action: Action, rtt_ms: int, loss_pct: int, bitrate_mbps: Optional[int] = None, loss_mode: Optional[str] = None) -> Tuple[Dict[str, Any], float, bool, Dict[str, Any]]:
        env = os.environ.copy()
        env["REPS"] = "1"
        k_val = action.K if (action.K is not None) else (self.last_cfg.K if self.last_cfg else 40)
        sb_val = action.symbol_bytes if (action.symbol_bytes is not None) else (self.last_cfg.symbol_bytes if self.last_cfg else 1200)
        env["K"] = str(int(k_val))
        env["SYMBOL_BYTES"] = str(int(sb_val))
        env["R0"] = str(int(action.R0))
        env["W"] = str(int(action.window_W))
        env["DDL_MS"] = str(int(action.ddl_ms))
        env["RSTEP"] = str(int(action.R_step))
        env["ALPHA"] = str(float(action.alpha))
        env["EPSILON"] = str(int(action.epsilon))
        env["INTERLEAVER_SPAN"] = str(int(action.interleaver_span))
        env["PACING_GAIN"] = str(float(action.pacing_gain))
        env["ACK_EVERY"] = os.environ.get("ACK_EVERY", "8")
        env["MAX_ATTEMPTS"] = os.environ.get("MAX_ATTEMPTS", "8")
        env["OUT_RAW"] = "/tmp/rl_arq_raw.csv"
        env["OUT_AGG"] = "/tmp/rl_arq_agg.csv"

        lm = (loss_mode or (self.last_cfg.loss_profile if self.last_cfg else None))
        if lm:
            env["LOSS_MODE"] = str(lm)
        env["LOSS_PCT"] = str(int(loss_pct))

        obs_jsonl_path = os.environ.get("QUICFEC_OBS_JSONL", self.obs_jsonl)
        try:
            os.makedirs(os.path.dirname(obs_jsonl_path), exist_ok=True)
        except Exception:
            pass
        env["OBS_JSONL"] = obs_jsonl_path

        if bitrate_mbps is None:
            bitrate_mbps = int((self.last_cfg.target_bitrate_bps if self.last_cfg else 10_000_000) // 1_000_000)
        env["BITRATE_MBPS"] = str(int(bitrate_mbps))

        try:
            env["NS"] = self.ns
            env["RTT_MS"] = str(int(rtt_ms))
            self._sudo_ensure()
            p = subprocess.run(["bash", "-lc", f"bash '{self.script}'"], env=env, capture_output=True, text=True, timeout=self.timeout_sec)
            if p.returncode != 0:
                raise RuntimeError(f"harness failed: code={p.returncode} stderr={p.stderr[-400:]}\nstdout={p.stdout[-400:]}")
            obs = self._read_last_obs(obs_jsonl_path)
            reward = self._compute_reward(obs)
            return obs, reward, True, {}
        except subprocess.TimeoutExpired as te:
            obs = self._default_obs(timeout=True)
            reward = self._compute_reward(obs)
            info = {"error": f"timeout after {self.timeout_sec}s", "stderr_tail": getattr(te, 'stderr', None)}
            return obs, reward, True, info
        except Exception as e:
            obs = self._default_obs(timeout=False)
            reward = self._compute_reward(obs)
            info = {"error": str(e)}
            return obs, reward, True, info

    def _read_last_obs(self, file_path: Optional[str] = None) -> Dict[str, Any]:
        last = None
        path = file_path or self.obs_jsonl
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("[rl-observation] "):
                        try:
                            last = json.loads(line.split(" ", 1)[1])
                        except Exception:
                            continue
        if not last:
            raise RuntimeError("no observation found; check server logs")
        return last

    def _compute_reward(self, obs: Dict[str, Any]) -> float:
        g = float(obs.get("goodput_decode_mbps", 0.0))
        dur_ms = float(obs.get("duration_decode_ms", 1.0))
        residual = int(obs.get("residual_erasures", 0))
        overhead = float(obs.get("fec_overhead_pct_arrival", 0.0))
        attempts = float(obs.get("arq_attempts_mean", 0.0))
        g_norm = min(1.0, g / 10.0)
        reward = g_norm
        if residual:
            reward -= 1.0
        if dur_ms > 1350.0:
            reward -= 0.2
        if overhead > 30.0:
            reward -= (overhead - 30.0) / 100.0
        if attempts > 1.0:
            reward -= min(0.3, 0.05 * (attempts - 1.0))
        return reward

    def _default_obs(self, timeout: bool) -> Dict[str, Any]:
        return {
            "goodput_decode_mbps": 0.0,
            "duration_decode_ms": 2000.0 if timeout else 1500.0,
            "residual_erasures": 1,
            "fec_overhead_pct_arrival": 0.0,
            "arq_attempts_mean": 2.0,
            "arq_attempts_p95": 3.0,
            "rx_unique_at_ddl_mean": 0.0,
            "rx_unique_at_ddl_p95": 0.0,
            "decode_latency_p50_ms": 0.0,
            "decode_latency_p95_ms": 0.0,
            "estimated_available_bw_mbps_p95": 0.0,
            "estimated_available_bw_mbps_peak": 0.0,
        }

    def _sudo_check(self) -> bool:
        try:
            subprocess.run(["sudo", "-n", "true"], check=True, capture_output=True)
            return True
        except subprocess.CalledProcessError:
            return False

    def _sudo_ensure(self) -> None:
        if self._sudo_check():
            return
        askpass = os.environ.get("SUDO_ASKPASS")
        if askpass:
            try:
                subprocess.run(["sudo", "-A", "-v"], check=True)
                return
            except subprocess.CalledProcessError:
                pass
        pw = os.environ.get("SUDO_PASSWORD")
        if pw:
            try:
                p = subprocess.run(["sudo", "-S", "-v"], input=(pw + "\n").encode(), capture_output=True)
                if p.returncode == 0 and self._sudo_check():
                    return
            except Exception:
                pass
        raise RuntimeError("sudo privileges are required. Run 'sudo -v' or set SUDO_ASKPASS/SUDO_PASSWORD.")


class FecEnv(gym.Env):
    metadata = {"render.modes": []}

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        cfg = config or {}
        self.action_space = spaces.Box(low=0.0, high=1.0, shape=(10,), dtype=np.float32)
        self._obs_keys: List[str] = [
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
        self.observation_space = spaces.Box(low=-np.inf, high=np.inf, shape=(len(self._obs_keys),), dtype=np.float32)

        # Episode length control
        self._episode_steps = int(cfg.get("episode_step", 100))
        self._t_in_ep = 0

        # Network defaults
        self._rtt_ms = int(cfg.get("rtt_ms", 100))
        self._loss_pct = int(cfg.get("loss_pct", 5))
        self._loss_mode = str(cfg.get("loss_mode", f"iid:{self._loss_pct}"))
        self._bitrate_mbps = int(cfg.get("bitrate_mbps", 10))
        self._result_dir_hint = cfg.get("result_dir")

        # Action bounds mapping
        self._act_low = np.array([16, 400, 0.12, 2, 6, 160, 0.4, 0, 0, 0.85], dtype=np.float32)
        self._act_high = np.array([64, 1200, 0.28, 8, 18, 340, 1.1, 3, 6, 1.15], dtype=np.float32)

        # Runner
        self._runner = QuicFecRunner(timeout_sec=int(cfg.get("timeout_sec", 30)))
        self._runner.reset(
            EnvConfig(
                datagrams_enabled=True,
                num_connections=1,
                cc_mode="bypass",
                target_bitrate_bps=self._bitrate_mbps * 1_000_000,
                loss_profile=self._loss_mode,
                K=40,
                symbol_bytes=1200,
            )
        )

        self._last_obs_vec = np.zeros((len(self._obs_keys),), dtype=np.float32)
        self._global_step = 0
        self._rng = np.random.RandomState()

    def reset(self, *, seed: Optional[int] = None, options: Optional[Dict[str, Any]] = None):
        self._last_obs_vec[:] = 0.0
        self._t_in_ep = 0
        if seed is not None:
            try:
                self._rng.seed(int(seed))
            except Exception:
                pass
        self._randomize_net_params()
        return self._last_obs_vec.copy(), {}

    def step(self, action: np.ndarray):
        a = np.asarray(action, dtype=np.float32).reshape(-1)
        if a.size < 10:
            raise ValueError("Action must be length-10 array")
        vec01 = np.clip(a[:10], 0.0, 1.0)
        a_scaled = self._act_low + vec01 * (self._act_high - self._act_low)
        int_idx = [0, 1, 3, 4, 5, 7, 8]
        a_scaled[int_idx] = np.round(a_scaled[int_idx])

        K = int(a_scaled[0])
        symbol_bytes = int(a_scaled[1])
        R0_pct = float(a_scaled[2])
        R_step = int(a_scaled[3])
        W = int(a_scaled[4])
        ddl_ms = int(a_scaled[5])
        alpha = float(a_scaled[6])
        epsilon = int(a_scaled[7])
        interleaver_span = int(a_scaled[8])
        pacing_gain = float(a_scaled[9])

        safety = 12
        align = 4
        max_payload = 1200 - safety
        symbol_bytes = min(symbol_bytes, max_payload)
        symbol_bytes = symbol_bytes - (symbol_bytes % align)

        R0 = max(2, int(round(K * R0_pct)))
        R_step = max(1, min(R_step, 12))
        W = max(6, min(W, 24))
        ddl_floor = max(150, int(2.2 * self._rtt_ms))
        ddl_ms = int(min(max(ddl_ms, ddl_floor), 500))

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

        obs_dict, reward, _done_transfer, info = self._runner.step(
            act,
            rtt_ms=self._rtt_ms,
            loss_pct=self._loss_pct,
            bitrate_mbps=self._bitrate_mbps,
            loss_mode=self._loss_mode,
        )
        obs_vec = self._obs_to_vec(obs_dict)
        self._last_obs_vec = obs_vec

        info = {
            **(info or {}),
            "net_params": {
                "rtt_ms": self._rtt_ms,
                "bitrate_mbps": self._bitrate_mbps,
                "loss_mode": self._loss_mode,
            },
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

        # Resolve trial/log dir: prefer Ray trial dir/env override
        dest_dir = (
            os.environ.get("QUICFEC_RESULT_DIR")
            or os.environ.get("RAY_AIR_TRIAL_DIR")
            or os.environ.get("RAY_TUNE_TRIAL_DIR")
            or self._result_dir_hint
            or os.path.join(os.path.dirname(__file__), "results")
        )
        try:
            os.makedirs(dest_dir, exist_ok=True)
            log_path = os.path.join(dest_dir, "step_metrics.jsonl")
            rec = {
                "t": int(self._global_step),
                "ts": time.time(),
                "reward": float(reward),
                "obs_vec": [float(x) for x in obs_vec.tolist()],
                "raw_obs": obs_dict,
                **info,
            }
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec) + "\n")
        except Exception:
            pass

        self._global_step += 1
        self._t_in_ep += 1
        terminated = bool(self._t_in_ep >= self._episode_steps)
        truncated = False
        return obs_vec, float(reward), terminated, truncated, info

    def _obs_to_vec(self, obs: Dict[str, Any]) -> np.ndarray:
        vals: List[float] = []
        for k in self._obs_keys:
            v = obs.get(k, 0.0)
            try:
                vals.append(float(v))
            except Exception:
                vals.append(0.0)
        return np.asarray(vals, dtype=np.float32)

    def _randomize_net_params(self) -> None:
        rng = self._rng
        def pick(xs):
            return xs[int(rng.randint(0, len(xs)))]
        u = rng.rand()
        if u < 0.4:
            p = pick([0, 1, 3, 5, 10, 15])
            rtt = pick([20, 50, 100, 200])
            sigma = pick([2, 5, 10, 20])
            bw = pick([5, 10, 20, 50])
            drift = 0.8 + 0.4 * rng.rand()
            rtt_t = max(1, int(round(rtt + rng.randn() * sigma)))
            self._rtt_ms = rtt_t
            self._bitrate_mbps = max(1, int(round(bw * drift)))
            self._loss_mode = f"iid:{p}"
        elif u < 0.8:
            def ge_from_lengths(pG, pB, LB, LG):
                r = max(0.0, min(100.0, 100.0 * (1.0 - 1.0 / max(1, LG))))
                h = max(0.0, min(100.0, 100.0 * (1.0 - 1.0 / max(1, LB))))
                return pG, r, h, pB
            pG = pick([0.5, 1.0, 2.0])
            pB = pick([10.0, 20.0, 30.0])
            LB = pick([3, 5, 10, 20])
            LG = pick([20, 50, 100])
            p, r, h, k = ge_from_lengths(pG, pB, LB, LG)
            self._rtt_ms = pick([50, 100, 200])
            self._bitrate_mbps = pick([5, 10, 20, 50])
            self._loss_mode = f"gemodel:{p},{r},{h},{k}"
        else:
            p = pick([1, 3, 5])
            base_rtt = pick([50, 100])
            sigma = pick([5, 10])
            bw = pick([10, 20, 50])
            rtt_t = max(1, int(round(base_rtt + rng.randn() * sigma)))
            if rng.rand() < 0.5:
                bw = max(1, int(round(bw * (0.3 + 0.3 * rng.rand()))))
            if rng.rand() < 0.5:
                rtt_t += int(100 + 200 * rng.rand())
            self._rtt_ms = rtt_t
            self._bitrate_mbps = bw
            self._loss_mode = f"iid:{p}"
