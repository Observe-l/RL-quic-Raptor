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
        self.pace_us = 200

    def reset(self, cfg: EnvConfig) -> Dict[str, Any]:
        self.last_cfg = cfg
        # Ensure sudo is available for shaping runs.
        # If we don't fail fast here, training will continue with default observations
        # (and constant negative rewards), which looks like "training runs" but is meaningless.
        self._sudo_ensure()
        return {"ok": True}

    def step(self, action: Action, rtt_ms: int, loss_pct: int, bitrate_mbps: Optional[int] = None, loss_mode: Optional[str] = None) -> Tuple[Dict[str, Any], float, bool, Dict[str, Any]]:
        env = os.environ.copy()
        # Ray worker processes may run with a restricted PATH. The harness
        # requires common tools (e.g., go) to be discoverable.
        path = env.get("PATH", "")
        for p in ("/usr/local/go/bin", "/usr/local/bin", "/usr/bin", "/bin", "/sbin"):
            if p not in path.split(":"):
                path = (path + ":" + p) if path else p
        env["PATH"] = path
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
        env["PACING_US"] = str(np.round(float(action.pacing_gain * self.pace_us)))
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
            # Avoid running as a login shell ("-l"), which can override PATH and
            # break tool discovery in non-interactive Ray workers.
            p = subprocess.run(["bash", "-c", f"bash '{self.script}'"], env=env, capture_output=True, text=True, timeout=self.timeout_sec)
            if p.returncode != 0:
                raise RuntimeError(f"harness failed: code={p.returncode} stderr={p.stderr[-400:]}\nstdout={p.stdout[-400:]}")
            obs = self._read_last_obs(obs_jsonl_path)
        # Reward is computed at the Env level; return 0.0 placeholder here.
            return obs, 0.0, True, {}
        except subprocess.TimeoutExpired as te:
            obs = self._default_obs(timeout=True)
            info = {"error": f"timeout after {self.timeout_sec}s", "stderr_tail": getattr(te, 'stderr', None)}
            return obs, 0.0, True, info
        except Exception as e:
            obs = self._default_obs(timeout=False)
            info = {"error": str(e)}
            return obs, 0.0, True, info

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

    # Reward is computed in FecEnv.step based on the improvement plan.
    def _compute_reward(self, obs: Dict[str, Any]) -> float:  # Deprecated
        g = float(obs.get("goodput_decode_mbps", 0.0))
        return min(1.0, g / 10.0)

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
            "estimated_available_bw_mbps": 0.0,
            # peak removed; only robust estimate is used
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
        # 8-D action in [-1, 1]^8 (tanh-squashed typical); mapped to actual config ranges.
        self.action_space = spaces.Box(low=-1.0, high=1.0, shape=(8,), dtype=np.float32)
        # Base observation keys coming from server
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
            "estimated_available_bw_mbps",
        ]
        # We append normalized network features (4) and previous action (8)
        self._obs_extra_dim = 4 + 8
        self.observation_space = spaces.Box(
            low=-5.0, high=+np.inf, shape=(len(self._obs_keys) + self._obs_extra_dim,), dtype=np.float32
        )

        # Episode length control
        self._episode_steps = int(cfg.get("episode_step", 100))
        self._t_in_ep = 0

        # If the external harness fails (missing deps, netns issues, etc.), it's usually
        # better to fail fast than to keep training on default observations.
        # Timeouts are treated as a valid (bad) outcome by default.
        self._ignore_runner_errors = bool(cfg.get("ignore_runner_errors", False))

        # Curriculum / randomization
        self._randomize_net_params_enabled = bool(cfg.get("randomize_net_params", True))
        self._curriculum_warmup_episodes = int(cfg.get("curriculum_warmup_episodes", 0))

        # Reward shaping (default matches docs/main.pdf Eq. (25) more closely)
        # reward_variant:
        # - "qarc_v1": soft penalties, non-saturating signals for throughput/overhead
        # - "legacy": previous clipped/thresholded reward
        self._reward_variant = str(cfg.get("reward_variant", "qarc_v1"))
        self._reward_w_goodput = float(cfg.get("reward_w_goodput", 1.0))
        self._reward_w_delay = float(cfg.get("reward_w_delay", 0.5))
        self._reward_w_residual = float(cfg.get("reward_w_residual", 1.0))
        self._reward_w_overhead = float(cfg.get("reward_w_overhead", 0.5))
        self._reward_w_arq = float(cfg.get("reward_w_arq", 0.0))
        self._reward_delay_binary = bool(cfg.get("reward_delay_binary", True))
        self._reward_residual_binary = bool(cfg.get("reward_residual_binary", True))

        # Network defaults
        self._rtt_ms = int(cfg.get("rtt_ms", 100))
        self._loss_pct = int(cfg.get("loss_pct", 5))
        self._loss_mode = str(cfg.get("loss_mode", f"iid:{self._loss_pct}"))

        # Remember the non-randomized baseline for curriculum warmup
        self._base_rtt_ms = int(self._rtt_ms)
        self._base_loss_pct = int(self._loss_pct)
        self._base_loss_mode = str(self._loss_mode)
        # Fix physical capacity to 10 Mbps
        self._bitrate_mbps = 10
        self._capacity_mbps = 10.0
        self._result_dir_hint = cfg.get("result_dir")

        # Action mapping ranges from [-1,1] → [low, high]
        # Action order: K, symbol_bytes, R0_pct, R_step, W, ddl_ms, alpha, pacing_gain
        self._low = np.array([10, 768, 0.10, 1, 5, 300, 0.4, 0.85], dtype=np.float32)
        self._high = np.array([64, 1188, 1.00, 20, 20, 600, 1.1, 2], dtype=np.float32)

        # Runner
        self._runner = QuicFecRunner(timeout_sec=int(cfg.get("timeout_sec", 30)))
        self._runner.reset(
            EnvConfig(
                datagrams_enabled=True,
                num_connections=1,
                cc_mode="bypass",
                target_bitrate_bps=int(self._capacity_mbps * 1_000_000),
                loss_profile=self._loss_mode,
                K=40,
                symbol_bytes=1200,
            )
        )

        self._last_obs_vec = np.zeros((len(self._obs_keys) + self._obs_extra_dim,), dtype=np.float32)
        self._prev_action = np.zeros((8,), dtype=np.float32)
        self._cap_hits = 0
        self._last_est_bw_mbps = float(self._capacity_mbps)
        self._norm = _RunningNorm(dim=self.observation_space.shape[0])
        self._global_step = 0
        self.epi = -1
        self._rng = np.random.RandomState()

        # Episode-level diagnostics
        self._ep_return = 0.0
        self._ep_term_sums: Dict[str, float] = {}

    def reset(self, *, seed: Optional[int] = None, options: Optional[Dict[str, Any]] = None):
        self._last_obs_vec[:] = 0.0
        self._t_in_ep = 0
        self.epi += 1
        self._ep_return = 0.0
        self._ep_term_sums = {}
        if seed is not None:
            try:
                self._rng.seed(int(seed))
            except Exception:
                pass

        # Curriculum: keep network fixed for a few warmup episodes, then randomize.
        if self._randomize_net_params_enabled and self.epi >= self._curriculum_warmup_episodes:
            self._randomize_net_params()
        else:
            self._rtt_ms = int(self._base_rtt_ms)
            self._loss_pct = int(self._base_loss_pct)
            self._loss_mode = str(self._base_loss_mode)
        return self._last_obs_vec.copy(), {}

    def step(self, action: np.ndarray):
        a = np.asarray(action, dtype=np.float32).reshape(-1)
        if a.size < 8:
            raise ValueError("Action must be length-8 array")
        a = np.clip(a[:8], -1.0, 1.0)
        # Map from [-1,1] → [low, high]
        a_scaled = self._low + (a + 1.0) * 0.5 * (self._high - self._low)
        # Round discrete fields
        int_idx = [0, 1, 3, 4]
        a_scaled[int_idx] = np.round(a_scaled[int_idx])

        K = int(a_scaled[0])
        symbol_bytes = int(a_scaled[1])
        R0_pct = float(a_scaled[2])
        R_step = int(a_scaled[3])
        W = int(a_scaled[4])
        ddl_ms = int(a_scaled[5])
        alpha = float(a_scaled[6])
        pacing_gain = float(a_scaled[7])

        # Payload alignment and safety margin
        safety = 12
        align = 8
        max_payload = 1200 - safety
        symbol_bytes = min(symbol_bytes, max_payload)
        symbol_bytes = symbol_bytes - (symbol_bytes % align)

        # Dynamic ddl lower bound for satellite
        # ddl_floor = max(300, int(2 * self._rtt_ms))
        # ddl_ms = int(min(max(ddl_ms, ddl_floor), 900))

        # Desired parity and safety clamp by link budget
        R0_desired = max(0, int(round(K * R0_pct)))
        # avail = float(min(self._capacity_mbps, self._last_est_bw_mbps))
        # R0_capped = cap_parity_by_budget(K, symbol_bytes, R0_desired, ddl_ms, avail)
        # cap_hit = int(R0_capped < R0_desired)
        # if cap_hit:
        #     self._cap_hits += 1

        act = Action(
            R0=R0_desired,
            R_step=R_step,
            window_W=W,
            ddl_ms=ddl_ms,
            alpha=float(alpha),
            epsilon=1,  # fixed
            interleaver_span=0,  # fixed
            pacing_gain=float(pacing_gain),
            K=K,
            symbol_bytes=symbol_bytes,
        )

        obs_dict, _reward_unused, _done_transfer, info = self._runner.step(
            act,
            rtt_ms=self._rtt_ms,
            loss_pct=self._loss_pct,
            bitrate_mbps=self._bitrate_mbps,
            loss_mode=self._loss_mode,
        )

        if not self._ignore_runner_errors and info and isinstance(info, dict) and info.get("error"):
            err = str(info.get("error"))
            if not err.lower().startswith("timeout"):
                raise RuntimeError(f"QUIC-FEC harness failed: {err}")
        # Update last estimated bandwidth for next safety clamp
        self._last_est_bw_mbps = float(obs_dict.get("estimated_available_bw_mbps", self._capacity_mbps))
        # Compute reward (variant selectable via env_config)
        reward, r_terms = self._compute_reward_satellite(obs_dict, ddl_ms)
        # Build observation vector: base obs + normalized net features + prev action
        obs_vec_raw = self._obs_to_vec(obs_dict)
        obs_vec = self._augment_obs(obs_vec_raw, ddl_ms)
        obs_vec = self._norm.transform(self._norm.update(obs_vec))
        self._last_obs_vec = obs_vec
        self._prev_action = a.copy()

        info = {
            **(info or {}),
            "net_params": {
                "rtt_ms": self._rtt_ms,
                "bitrate_mbps": self._bitrate_mbps,
                "loss_mode": self._loss_mode,
            },
            "fec_cfg": {
                "K": K,
                "symbol_bytes": symbol_bytes,
                "R0_desired": R0_desired,
                # "R0_capped": R0_capped,
                "R_step": int(act.R_step),
                "W": int(act.window_W),
                "ddl_ms": ddl_ms,
                "alpha": float(alpha),
                "pacing_gain": float(pacing_gain),
            },
            "bw_cap_mbps": float(self._capacity_mbps),
            "est_bw_mbps": float(self._last_est_bw_mbps),
            "goodput_mbps": float(obs_dict.get("goodput_decode_mbps", 0.0)),
            "reward_terms": r_terms,
            # "cap_hit": cap_hit,
            "cap_hits_cum": self._cap_hits,
            "zero_residual_flag": int(obs_dict.get("residual_erasures", 0) == 0),
            "on_time_flag": int(float(obs_dict.get("decode_latency_p95_ms", 0.0)) <= float(ddl_ms)),
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
                "epi": self.epi,
                "reward": float(reward),
                "obs_vec": [float(x) for x in obs_vec.tolist()],
                "raw_obs": obs_dict,
                **info,
            }
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec) + "\n")
        except Exception:
            pass

        # Episode-level aggregates
        self._ep_return += float(reward)
        for k, v in (r_terms or {}).items():
            try:
                self._ep_term_sums[k] = float(self._ep_term_sums.get(k, 0.0) + float(v))
            except Exception:
                continue

        self._global_step += 1
        self._t_in_ep += 1
        terminated = bool(self._t_in_ep >= self._episode_steps)
        truncated = False

        if terminated:
            # Write episode summary to help diagnose learning signal and non-stationarity.
            try:
                epi_path = os.path.join(dest_dir, "episode_metrics.jsonl")
                denom = max(1, int(self._t_in_ep))
                avg_terms = {k: float(v) / float(denom) for k, v in self._ep_term_sums.items()}
                epi_rec = {
                    "epi": int(self.epi),
                    "t_end": int(self._global_step),
                    "episode_steps": int(self._t_in_ep),
                    "episode_return": float(self._ep_return),
                    "avg_reward_terms": avg_terms,
                    "net_params": {
                        "rtt_ms": int(self._rtt_ms),
                        "loss_mode": str(self._loss_mode),
                        "bitrate_mbps": int(self._bitrate_mbps),
                    },
                    "reward_variant": str(self._reward_variant),
                }
                with open(epi_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(epi_rec) + "\n")
            except Exception:
                pass

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

    def _augment_obs(self, base: np.ndarray, ddl_ms: int) -> np.ndarray:
        # Normalized network features
        rtt_feat = float(self._rtt_ms) / 800.0
        cap_feat = 1.0  # 10/10
        estbw_feat = float(self._last_est_bw_mbps) / 10.0
        ddl_feat = float(ddl_ms) / 1200.0
        extras = np.array([
            np.clip(rtt_feat, 0.0, 1.0),
            np.clip(cap_feat, 0.0, 1.0),
            np.clip(estbw_feat, 0.0, 1.0),
            np.clip(ddl_feat, 0.0, 1.0),
        ], dtype=np.float32)
        return np.concatenate([base.astype(np.float32), extras, self._prev_action.astype(np.float32)], axis=0)

    def _randomize_net_params(self) -> None:
        rng = self._rng
        def pick(xs):
            return xs[int(rng.randint(0, len(xs)))]
        # Fixed capacity 10 Mbps
        self._bitrate_mbps = int(self._capacity_mbps)
        # RTT regimes: LEO/MEO/GEO
        rtt_choice = pick([30, 60, 120, 180, 550, 650])
        self._rtt_ms = int(rtt_choice)
        # Loss models: IID and GE burst
        if rng.rand() < 0.5:
            p = pick([1, 3, 5, 10])
            self._loss_mode = f"iid:{p}"
        else:
            # GE params: overall ≈ 3–15%
            pG = pick([0.5, 1.0, 2.0])
            pB = pick([10.0, 20.0, 30.0])
            LB = pick([10, 30, 60, 100])
            LG = pick([20, 50, 80])
            r = max(0.0, min(100.0, 100.0 * (1.0 - 1.0 / max(1, LG))))
            h = max(0.0, min(100.0, 100.0 * (1.0 - 1.0 / max(1, LB))))
            self._loss_mode = f"gemodel:{pG},{r},{h},{pB}"

    def _compute_reward_satellite(self, obs: Dict[str, Any], ddl_ms: int) -> Tuple[float, Dict[str, float]]:
        g = float(obs.get("goodput_decode_mbps", 0.0))
        est = float(obs.get("estimated_available_bw_mbps", self._capacity_mbps))
        e = float(obs.get("residual_erasures", 0.0))
        d95 = float(obs.get("decode_latency_p95_ms", 0.0))
        d = float(max(1, int(ddl_ms)))
        oh = float(obs.get("fec_overhead_pct_arrival", 0.0))
        a95 = float(obs.get("arq_attempts_p95", 0.0))

        if self._reward_variant == "legacy":
            # Previous shaping (kept for reproducibility)
            c = max(1.0, float(min(self._capacity_mbps, est)))
            tp_term = float(np.clip(g / c, 0.0, 1.0))
            lam_e = 0.75
            resid_term = -lam_e * (e / (1.0 + e))
            lam_d = 0.3
            lat_term = -lam_d * max(0.0, (d95 - d) / max(d, 1.0))
            lam_o = 0.3
            oh_term = -lam_o * max(0.0, (oh - 40.0) / 60.0)
            arq_term = -min(0.3, 0.08 * a95)
            r = tp_term + resid_term + lat_term + oh_term + arq_term
            return float(r), {
                "tp_term": float(tp_term),
                "resid_term": float(resid_term),
                "lat_term": float(lat_term),
                "oh_term": float(oh_term),
                "arq_term": float(arq_term),
            }

        # Q-ARC-like shaping (docs/main.pdf Eq. (25))
        # g_tilde: normalize by physical capacity (avoid early saturation from est_bw)
        g_tilde = float(np.clip(g / max(1e-6, float(self._capacity_mbps)), 0.0, 1.0))

        # d_tilde: delay penalty (binary by default, as suggested in the doc)
        if self._reward_delay_binary:
            d_tilde = float(d95 > d)
        else:
            d_tilde = float(np.clip(max(0.0, (d95 - d) / max(d, 1.0)), 0.0, 1.0))

        # l_tilde: residual loss surrogate
        if self._reward_residual_binary:
            l_tilde = float(e > 0.0)
        else:
            l_tilde = float(e / (1.0 + max(0.0, e)))

        # r_tilde: overhead ratio surrogate (pct -> [0,1])
        r_tilde = float(np.clip(oh / 100.0, 0.0, 1.0))

        # Optional ARQ penalty (scaled, non-saturating by default)
        arq_tilde = float(np.clip(a95 / 30.0, 0.0, 1.0))

        tp_term = self._reward_w_goodput * g_tilde
        lat_term = -self._reward_w_delay * d_tilde
        resid_term = -self._reward_w_residual * l_tilde
        oh_term = -self._reward_w_overhead * r_tilde
        arq_term = -self._reward_w_arq * arq_tilde
        r = float(tp_term + lat_term + resid_term + oh_term + arq_term)
        return r, {
            "tp_term": float(tp_term),
            "lat_term": float(lat_term),
            "resid_term": float(resid_term),
            "oh_term": float(oh_term),
            "arq_term": float(arq_term),
            "g_tilde": float(g_tilde),
            "d_tilde": float(d_tilde),
            "l_tilde": float(l_tilde),
            "r_tilde": float(r_tilde),
            "arq_tilde": float(arq_tilde),
            "est_bw_mbps": float(est),
        }


# def cap_parity_by_budget(K: int, sym_bytes: int, desired_R0: int, ddl_ms: int, avail_mbps: float) -> int:
#     bytes_budget = (avail_mbps * 1e6 / 8.0) * (float(ddl_ms) / 1000.0)
#     data_bytes = int(K) * int(sym_bytes)
#     if bytes_budget <= data_bytes:
#         return 0
#     max_parity_symbols = int((bytes_budget - data_bytes) // max(1, int(sym_bytes)))
#     return max(0, min(int(desired_R0), int(max_parity_symbols)))


class _RunningNorm:
    def __init__(self, dim: int, eps: float = 1e-5, clip: float = 5.0):
        self.dim = dim
        self.eps = eps
        self.clip = float(clip)
        self.n = 0
        self.mean = np.zeros((dim,), dtype=np.float64)
        self.M2 = np.zeros((dim,), dtype=np.float64)

    def update(self, x: np.ndarray) -> np.ndarray:
        x = x.astype(np.float64).reshape(-1)
        if x.size != self.dim:
            raise ValueError("Normalizer input dim mismatch")
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        delta2 = x - self.mean
        self.M2 += delta * delta2
        return x.astype(np.float32)

    def transform(self, x: np.ndarray) -> np.ndarray:
        if self.n < 2:
            return np.clip(x.astype(np.float32), -self.clip, self.clip)
        var = self.M2 / max(1, self.n - 1)
        std = np.sqrt(np.maximum(var, self.eps))
        z = (x.astype(np.float64) - self.mean) / std
        return np.clip(z, -self.clip, self.clip).astype(np.float32)
