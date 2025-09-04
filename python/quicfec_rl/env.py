import os
import json
import time
import subprocess
from dataclasses import dataclass
from typing import Dict, Any, Tuple

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

    def __init__(self, root: str = None, ns: str = "qns", prefer_local: bool = False):
        self.root = root or os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        self.ns = ns
        self.script = os.path.join(self.root, "scripts", "arq_sweep_bw_rtt_loss.sh")
        self.local_script = os.path.join(self.root, "scripts", "arq_local_smoke.sh")
        self.obs_jsonl = "/tmp/arq_sweep_10mbps_rl.jsonl"
        self.last_cfg: EnvConfig | None = None
        self.prefer_local = prefer_local

    def reset(self, cfg: EnvConfig) -> Dict[str, Any]:
        """
        Reset environment shaping via the shell harness. This prepares namespace and build once.
        """
        self.last_cfg = cfg
        # For local mode, no sudo required. For shaped mode, ensure sudo cache is present.
        if not self.prefer_local:
            self._sudo_check()
        return {"ok": True}

    def step(self, action: Action, rtt_ms: int, loss_pct: int) -> Tuple[Dict[str, Any], float, bool, Dict[str, Any]]:
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
        env["ACK_EVERY"] = "0"
        env["OUT_RAW"] = "/tmp/rl_arq_raw.csv"
        env["OUT_AGG"] = "/tmp/rl_arq_agg.csv"
        env["OBS_JSONL"] = self.obs_jsonl

        if self.prefer_local:
            # Localhost path: avoid sudo; rtt/loss shaping not applied here
            p = subprocess.run([self.local_script], env=env, capture_output=True, text=True)
        else:
            env["NS"] = self.ns
            env["RTTS"] = str(rtt_ms)
            env["LOSSES"] = str(loss_pct)
            self._sudo_ensure()
            p = subprocess.run([self.script], env=env, capture_output=True, text=True)
        if p.returncode != 0:
            raise RuntimeError(f"harness failed: code={p.returncode} stderr={p.stderr[-400:]}\nstdout={p.stdout[-400:]}")
        # Parse last observation
        obs = self._read_last_obs()
        reward = self._compute_reward(obs)
        return obs, reward, True, {}

    def _read_last_obs(self) -> Dict[str, Any]:
        last = None
        if os.path.exists(self.obs_jsonl):
            with open(self.obs_jsonl, "r", encoding="utf-8") as f:
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
