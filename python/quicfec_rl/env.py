import os
import json
import time
import subprocess
from dataclasses import dataclass
from typing import Dict, Any, Tuple, Optional

@dataclass
class EnvConfig:
    datagrams_enabled: bool = True
    num_connections: int = 1
    cc_mode: str = "bypass"  # "bypass" | "standard"
    target_bitrate_bps: int = 10_000_000
    loss_profile: str = "iid:0"  # e.g., "iid:5" or gemodel
    K: int = 40
    symbol_bytes: int = 1200

@dataclass
class Action:
    R0: int = 6
    R_step: int = 4
    window_W: int = 8
    ddl_ms: int = 50
    alpha: float = 0.6
    epsilon: int = 1
    interleaver_span: int = 0
    pacing_gain: float = 1.0
    # v2 additions (applied at episode boundary):
    K: int | None = None
    symbol_bytes: int | None = None

class QuicFecEnv:
    """
    Minimal single-step env that shells out to the Go harness and parses server-side observation.
    One file transfer == one step. Reset applies loss/bw/RTT via script; Step applies ARQ/FEC params.
    """

    def __init__(self, root: str = None, ns: str = "qns", prefer_local: bool = False, timeout_sec: int = 90):
        self.root = root or os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        self.ns = ns
        self.script = os.path.join(self.root, "scripts", "quicfec_run_once.sh")
        self.local_script = os.path.join(self.root, "scripts", "arq_local_smoke.sh")
        # Default observation sink; can be overridden via QUICFEC_OBS_JSONL
        self.obs_jsonl = os.environ.get("QUICFEC_OBS_JSONL", "/tmp/quicfec_rl.jsonl")
        self.last_cfg = None
        self.prefer_local = prefer_local
        self.timeout_sec = int(timeout_sec)

    def reset(self, cfg: EnvConfig) -> Dict[str, Any]:
        """
        Reset environment shaping via the shell harness. This prepares namespace and build once.
        """
        self.last_cfg = cfg
        # For local mode, no sudo required. For shaped mode, ensure sudo cache is present.
        if not self.prefer_local:
            self._sudo_check()
        return {"ok": True}

    def step(self, action: Action, rtt_ms: int, loss_pct: int, bitrate_mbps: Optional[int] = None, loss_mode: Optional[str] = None) -> Tuple[Dict[str, Any], float, bool, Dict[str, Any]]:
        """
        Run a single episode with given action and shaping, parse the last [rl-observation] JSONL line.
        Returns (obs, reward, done, info).
        """
        # Export knobs via environment for the harness
        env = os.environ.copy()
        env["REPS"] = "1"
        # Allow action to override K/symbol_bytes (v2)
        k_val = action.K if (hasattr(action, "K") and action.K is not None) else self.last_cfg.K
        sb_val = action.symbol_bytes if (hasattr(action, "symbol_bytes") and action.symbol_bytes is not None) else self.last_cfg.symbol_bytes
        env["K"] = str(k_val)
        env["SYMBOL_BYTES"] = str(sb_val)
        env["R0"] = str(action.R0)
        env["W"] = str(action.window_W)
        env["DDL_MS"] = str(action.ddl_ms)
        env["RSTEP"] = str(action.R_step)
        env["ALPHA"] = str(action.alpha)
        # v3 continuous controls (forward to harness)
        env["EPSILON"] = str(getattr(action, "epsilon", 0))
        env["INTERLEAVER_SPAN"] = str(getattr(action, "interleaver_span", 0))
        env["PACING_GAIN"] = str(getattr(action, "pacing_gain", 1.0))
        # Use a conservative default ack pacing under loss to avoid idle timeouts
        env["ACK_EVERY"] = os.environ.get("ACK_EVERY", "8")
        # Allow raising ARQ cap for robustness under higher losses
        env["MAX_ATTEMPTS"] = os.environ.get("MAX_ATTEMPTS", "8")
        env["OUT_RAW"] = "/tmp/rl_arq_raw.csv"
        env["OUT_AGG"] = "/tmp/rl_arq_agg.csv"
        # Loss control: allow explicit LOSS_MODE (iid:10, gemodel:...), else fallback to LOSS_PCT
        lm = loss_mode
        # If not provided explicitly, try from reset cfg
        if not lm and getattr(self, "last_cfg", None) and hasattr(self.last_cfg, "loss_profile"):
            lm = self.last_cfg.loss_profile
        if lm and isinstance(lm, str) and lm.strip():
            env["LOSS_MODE"] = lm.strip()
        env["LOSS_PCT"] = str(int(loss_pct))
        # Allow overriding observation sink per run (and ensure directory exists)
        obs_jsonl_path = os.environ.get("QUICFEC_OBS_JSONL", self.obs_jsonl)
        try:
            os.makedirs(os.path.dirname(obs_jsonl_path), exist_ok=True)
        except Exception:
            pass
        env["OBS_JSONL"] = obs_jsonl_path
        if bitrate_mbps is not None:
            env["BITRATE_MBPS"] = str(int(bitrate_mbps))

        try:
            if self.prefer_local:
                # Localhost path: avoid sudo; rtt/loss shaping not applied here
                p = subprocess.run(["bash", "-lc", f"bash '{self.local_script}'"], env=env, capture_output=True, text=True, timeout=self.timeout_sec)
            else:
                env["NS"] = self.ns
                env["RTT_MS"] = str(rtt_ms)
                env["LOSS_PCT"] = str(loss_pct)
                self._sudo_ensure()
                # Run via bash to ensure env var expansion and PATH usage
                p = subprocess.run(["bash", "-lc", f"bash '{self.script}'"], env=env, capture_output=True, text=True, timeout=self.timeout_sec)
            if p.returncode != 0:
                raise RuntimeError(f"harness failed: code={p.returncode} stderr={p.stderr[-400:]}\nstdout={p.stdout[-400:]}")
            # Parse last observation
            obs = self._read_last_obs(obs_jsonl_path)
            reward = self._compute_reward(obs)
            return obs, reward, True, {}
        except subprocess.TimeoutExpired as te:
            # Timeout: return penalized observation and mark done, include info
            obs = self._default_obs(timeout=True)
            reward = self._compute_reward(obs)
            info = {"error": f"timeout after {self.timeout_sec}s", "stderr_tail": getattr(te, 'stderr', None)}
            return obs, reward, True, info
        except Exception as e:
            # Failure: return penalized observation and mark done, include info
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
        # Goodput-centric with penalties; simple version
        g = float(obs.get("goodput_decode_mbps", 0.0))
        dur_ms = float(obs.get("duration_decode_ms", 1.0))
        residual = int(obs.get("residual_erasures", 0))
        overhead = float(obs.get("fec_overhead_pct_arrival", 0.0))
        attempts = float(obs.get("arq_attempts_mean", 0.0))
        # Normalize by 10 Mbps baseline
        g_norm = min(1.0, g / 10.0)
        reward = g_norm
        # Hard penalties
        if residual:
            reward -= 1.0
        if dur_ms > 1350.0:
            reward -= 0.2
        # Soft penalties
        if overhead > 30.0:
            reward -= (overhead - 30.0) / 100.0
        if attempts > 1.0:
            reward -= min(0.3, 0.05 * (attempts - 1.0))
        return reward

    def _default_obs(self, timeout: bool) -> Dict[str, Any]:
        # Conservative penalized observation when a run fails or times out
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
        # Ensure sudo timestamp is active; try askpass or env password if needed
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
        # Fallback: instruct user to run sudo -v
        raise RuntimeError("sudo privileges are required. Run 'sudo -v' in this shell or set SUDO_ASKPASS or SUDO_PASSWORD.")
