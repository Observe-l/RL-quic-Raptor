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
    # RL runs assume CC enabled with BBRv2. (cc_bypass is lab-only.)
    cc_algo: str = "bbrv2"
    target_bitrate_bps: int = 10_000_000
    loss_profile: str = "iid:0"
    # Coding params.
    # Fix symbol_bytes to 1200 to avoid MTU issues and improve goodput.
    K: int = 30
    symbol_bytes: int = 1200


@dataclass
class Action:
    # Action space for QUIC-FEC control:
    # - K: source symbols per block
    # - R0: initial parity symbols (integer)
    # - RSTEP: incremental repair step size
    K: int = 12
    R0: int = 0
    RSTEP: int = 4


class QuicFecRunner:
    def __init__(
        self,
        root: str | None = None,
        ns: str = "qns",
        timeout_sec: int = 15,
        train_file_bytes: int | None = None,
        post_wait: str = "0ms",
        srv_timeout: str = "30s",
        obs_wait_secs: int | None = None,
    ):
        self.root = root or os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

        # Parallel-safety: multiple training processes (or Ray workers) may run on the same host.
        # The shell harness historically used fixed netns/veth/IP defaults, which causes collisions.
        # Default to a per-process namespace unless the caller explicitly chose a non-default.
        isolate_key = os.environ.get("QUICFEC_ISOLATE_KEY", "")
        if not isolate_key.strip():
            isolate_key = f"pid{os.getpid()}"
        if ns == "qns" and not os.environ.get("QUICFEC_NS"):
            self.ns = f"qns-{isolate_key}"
        else:
            self.ns = os.environ.get("QUICFEC_NS", ns)

        # Keep derived resources stable for the lifetime of this runner.
        self._isolate_key = isolate_key
        # Keep names within the Linux IFNAMSIZ=16 limit.
        self._veth_host = (os.environ.get("QUICFEC_VETH_HOST") or f"vh{isolate_key}")[:15]
        self._veth_ns = (os.environ.get("QUICFEC_VETH_NS") or f"vn{isolate_key}")[:15]

        # Per-run subnet to avoid having multiple host veth interfaces share an IP.
        # Use a stable third octet derived from PID by default.
        if os.environ.get("QUICFEC_HOST_IP") and os.environ.get("QUICFEC_NS_IP"):
            self._host_ip_cidr = str(os.environ.get("QUICFEC_HOST_IP"))
            self._ns_ip_cidr = str(os.environ.get("QUICFEC_NS_IP"))
        else:
            subnet_id = (int(os.getpid()) % 200) + 20
            self._host_ip_cidr = f"10.200.{subnet_id}.1/24"
            self._ns_ip_cidr = f"10.200.{subnet_id}.2/24"

        # Avoid output file collisions on shared basenames.
        self._out_dir = os.environ.get("QUICFEC_OUT_DIR", f"/tmp/quicfec_out_{isolate_key}")
        # Only use the shaped runner script (no local mode)
        self.script = os.path.join(self.root, "scripts", "quicfec_run_once.sh")
        # The shaping harness writes observations as one JSON object per line.
        # We keep the format but use .json suffix (some tools dislike .jsonl).
        self.obs_json = os.environ.get("QUICFEC_OBS_JSON", f"/tmp/quicfec_rl_{isolate_key}.json")
        self.last_cfg = None
        self.timeout_sec = int(timeout_sec)
        self.pace_us = 200
        self.train_file_bytes = int(train_file_bytes) if train_file_bytes is not None else None
        self.post_wait = str(post_wait)
        self.srv_timeout = str(srv_timeout)
        self.obs_wait_secs = int(obs_wait_secs) if obs_wait_secs is not None else None
        self._train_file_path: Optional[str] = None
        # Cache of the last applied network shaping parameters.
        # When stable within an episode, we can skip netns/tc reconfiguration per step.
        self._net_cfg_key: Optional[Tuple[int, str, int]] = None  # (rtt_ms, loss_mode, bitrate_mbps)

    def _ensure_train_file(self) -> Optional[str]:
        if self.train_file_bytes is None:
            return None
        if self._train_file_path and os.path.exists(self._train_file_path):
            return self._train_file_path

        size = int(self.train_file_bytes)
        if size <= 0:
            return None

        # Use a per-process path to avoid clashes between parallel Ray workers.
        path = f"/tmp/quicfec_train_{size}_pid{os.getpid()}.bin"
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
        except Exception:
            pass
        # Create a deterministic, fast-to-generate file (zeros; may be sparse).
        with open(path, "wb") as f:
            f.truncate(size)
        self._train_file_path = path
        return path

    def reset(self, cfg: EnvConfig) -> Dict[str, Any]:
        self.last_cfg = cfg
        # Ensure sudo is available for shaping runs.
        # If we don't fail fast here, training will continue with default observations
        # (and constant negative rewards), which looks like "training runs" but is meaningless.
        self._sudo_ensure()
        self._ensure_train_file()
        # Network config is applied per-episode by FecEnv.reset().
        self._net_cfg_key = None
        return {"ok": True}

    def configure_network(self, *, rtt_ms: int, loss_mode: str, loss_pct: int, bitrate_mbps: int) -> None:
        """Configure netns + tc shaping once (typically at episode start).

        The trial runner script is relatively expensive when it recreates the
        namespace and replaces qdiscs. For RL training, network parameters are
        constant within an episode, so we do this once in reset().
        """

        key = (int(rtt_ms), str(loss_mode), int(bitrate_mbps))
        if self._net_cfg_key == key:
            return

        env = os.environ.copy()
        path = env.get("PATH", "")
        for p in ("/usr/local/go/bin", "/usr/local/bin", "/usr/bin", "/bin", "/sbin"):
            if p not in path.split(":"):
                path = (path + ":" + p) if path else p
        env["PATH"] = path

        cfg = self.last_cfg or EnvConfig()
        env["NS"] = self.ns
        env["VETH_HOST"] = self._veth_host
        env["VETH_NS"] = self._veth_ns
        env["HOST_IP"] = self._host_ip_cidr
        env["NS_IP"] = self._ns_ip_cidr
        env["SRV_IP"] = self._ns_ip_cidr.split("/", 1)[0]
        env["OUT_DIR"] = self._out_dir
        env["RTT_MS"] = str(int(rtt_ms))
        env["LOSS_MODE"] = str(loss_mode)
        env["LOSS_PCT"] = str(int(loss_pct))
        env["BITRATE_MBPS"] = str(int(bitrate_mbps))

        # Keep the file deterministic and per-worker.
        train_file = self._ensure_train_file()
        if train_file:
            env["FILE"] = train_file

        # Ensure the observation file path exists, even though setup-only won't write observations.
        obs_json_path = os.environ.get("QUICFEC_OBS_JSON", self.obs_json)
        try:
            os.makedirs(os.path.dirname(obs_json_path), exist_ok=True)
        except Exception:
            pass
        env["OBS_JSON"] = obs_json_path

        # One-time setup for this episode.
        env["SETUP_ONLY"] = "1"
        env["SKIP_NETNS_RESET"] = "0"
        env["SKIP_TC_CONFIG"] = "0"
        env["SKIP_SYSCTL"] = "0"
        env["SKIP_BUILD"] = "0"

        # Make sure sudo privileges are present.
        self._sudo_ensure()
        p = subprocess.run(
            ["bash", "-c", f"bash '{self.script}'"],
            env=env,
            capture_output=True,
            text=True,
            timeout=self.timeout_sec,
        )
        if p.returncode != 0:
            raise RuntimeError(f"network setup failed: code={p.returncode} stderr={p.stderr[-400:]}\nstdout={p.stdout[-400:]}")

        self._net_cfg_key = key

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
        cfg = self.last_cfg or EnvConfig()
        env["NS"] = self.ns
        env["VETH_HOST"] = self._veth_host
        env["VETH_NS"] = self._veth_ns
        env["HOST_IP"] = self._host_ip_cidr
        env["NS_IP"] = self._ns_ip_cidr
        env["SRV_IP"] = self._ns_ip_cidr.split("/", 1)[0]
        env["OUT_DIR"] = self._out_dir
        # K and RSTEP are controlled by the policy.
        k = int(getattr(action, "K", cfg.K))
        if k < 1:
            k = 1
        env["K"] = str(int(k))
        # Keep SYMBOL_BYTES fixed to avoid MTU-triggered fragmentation.
        env["SYMBOL_BYTES"] = str(int(getattr(cfg, "symbol_bytes", 1200)))

        # Integer parity budget controlled by the policy.
        r0 = int(getattr(action, "R0", 0))
        if r0 < 0:
            r0 = 0
        # Keep semantics consistent with the legacy mapping (R0 never exceeded K).
        if r0 > int(k):
            r0 = int(k)
        env["R0"] = str(int(r0))

        # ARQ policy (RSTEP is controlled by the policy).
        env["W"] = os.environ.get("W", "8")
        env["RSTEP"] = str(int(getattr(action, "RSTEP", int(os.environ.get("RSTEP", "4")))))
        env["MAX_ATTEMPTS"] = os.environ.get("MAX_ATTEMPTS", "5")

        # CC is always enabled with BBRv2.
        env["QUIC_FEC_CC_BYPASS"] = "0"
        env["QUIC_FEC_CC_ALGO"] = str(getattr(cfg, "cc_algo", "bbrv2"))

        # Disable app-level pacing when CC is enabled.
        env["PACE_US"] = "0"

        # Transport selection: datagrams are unreliable; streams are reliable.
        datagrams_enabled = bool(cfg.datagrams_enabled)
        env.setdefault("TRANSPORT", "dgram" if datagrams_enabled else "stream")
        env["ACK_EVERY"] = os.environ.get("ACK_EVERY", "8")
        env["OUT_RAW"] = "/tmp/rl_arq_raw.csv"
        env["OUT_AGG"] = "/tmp/rl_arq_agg.csv"

        # Training speed knobs: keep each trial bounded and avoid linger.
        # The harness defaults POST_WAIT to ~3*RTT to let ARQ settle, but for RL
        # we prefer faster feedback.
        env.setdefault("POST_WAIT", self.post_wait)
        env.setdefault("SRV_TIMEOUT", self.srv_timeout)
        env.setdefault("CLI_TIMEOUT", self.srv_timeout)
        # Avoid long tail waits during training; benchmarks can override.
        env.setdefault("QUIC_FEC_ARQ_DRAIN_CAP_MS", "3000")
        if self.obs_wait_secs is not None:
            env.setdefault("OBS_WAIT_SECS", str(int(self.obs_wait_secs)))

        train_file = self._ensure_train_file()
        if train_file:
            env["FILE"] = train_file

        lm = (loss_mode or (cfg.loss_profile if cfg else None))
        if lm:
            env["LOSS_MODE"] = str(lm)
        env["LOSS_PCT"] = str(int(loss_pct))

        obs_json_path = os.environ.get("QUICFEC_OBS_JSON", self.obs_json)
        try:
            os.makedirs(os.path.dirname(obs_json_path), exist_ok=True)
        except Exception:
            pass
        env["OBS_JSON"] = obs_json_path

        if bitrate_mbps is None:
            bitrate_mbps = int((cfg.target_bitrate_bps if cfg else 10_000_000) // 1_000_000)
        env["BITRATE_MBPS"] = str(int(bitrate_mbps))

        # Network setup optimization:
        # If shaping parameters are constant (typical for RL), configure once and reuse.
        # Only reconfigure when the desired key changes.
        desired_key = (int(rtt_ms), str(lm or f"iid:{int(loss_pct)}"), int(bitrate_mbps))
        if self._net_cfg_key != desired_key:
            try:
                self.configure_network(
                    rtt_ms=int(rtt_ms),
                    loss_mode=desired_key[1],
                    loss_pct=int(loss_pct),
                    bitrate_mbps=int(bitrate_mbps),
                )
            except Exception:
                # Fall back to old behavior (script will reconfigure everything) if setup fails.
                # This keeps the environment robust in interactive/debug sessions.
                self._net_cfg_key = None

        try:
            env["NS"] = self.ns
            env["RTT_MS"] = str(int(rtt_ms))
            self._sudo_ensure()
            # Training optimization: reuse per-episode netns/tc configuration.
            # The episode-level setup is done via configure_network() from reset().
            if self._net_cfg_key is not None:
                env.setdefault("SETUP_ONLY", "0")
                env.setdefault("SKIP_NETNS_RESET", "1")
                env.setdefault("SKIP_TC_CONFIG", "1")
                env.setdefault("SKIP_SYSCTL", "1")
                env.setdefault("SKIP_BUILD", "1")
            # Avoid running as a login shell ("-l"), which can override PATH and
            # break tool discovery in non-interactive Ray workers.
            #
            # Give the harness a small grace window beyond the configured timeout.
            # Otherwise, a Python-side TimeoutExpired can kill the wrapper script
            # while it still has a server running inside the netns, leading to
            # cascading failures on subsequent steps when reusing the netns.
            p = subprocess.run(
                ["bash", "-c", f"bash '{self.script}'"],
                env=env,
                capture_output=True,
                text=True,
                timeout=int(self.timeout_sec) + 10,
            )
            if p.returncode != 0:
                raise RuntimeError(f"harness failed: code={p.returncode} stderr={p.stderr[-400:]}\nstdout={p.stdout[-400:]}")
            obs = self._read_last_obs(obs_json_path)
        # Reward is computed at the Env level; return 0.0 placeholder here.
            return obs, 0.0, True, {}
        except subprocess.TimeoutExpired as te:
            # If the harness times out, assume the netns may have leaked processes.
            # Force a full netns/tc reset on the next step by dropping the cached key.
            self._net_cfg_key = None
            obs = self._default_obs(timeout=True)
            def _to_text(v: Any) -> str | None:
                if v is None:
                    return None
                if isinstance(v, str):
                    return v
                if isinstance(v, (bytes, bytearray, memoryview)):
                    try:
                        return bytes(v).decode("utf-8", errors="replace")
                    except Exception:
                        return repr(v)
                try:
                    return str(v)
                except Exception:
                    return repr(v)

            info = {
                "error": f"timeout after {self.timeout_sec}s",
                "stderr_tail": _to_text(getattr(te, "stderr", None)),
                "stdout_tail": _to_text(getattr(te, "stdout", None)),
            }
            return obs, 0.0, True, info
        except Exception as e:
            obs = self._default_obs(timeout=False)
            info = {"error": str(e)}
            return obs, 0.0, True, info

    def _read_last_obs(self, file_path: Optional[str] = None) -> Dict[str, Any]:
        last = None
        path = file_path or self.obs_json
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
            "goodput_mbps": 0.0,
            "goodput": 0.0,
            "duration_decode_ms": 2000.0 if timeout else 1500.0,
            "duration_transfer_ms": 2000.0 if timeout else 1500.0,
            "residual_erasures": 1,
            "fec_overhead": 0.0,
            "rx_total_symbols": 0,
            "rx_repair_symbols": 0,
            "rx_total_symbol_bytes": 0,
            "ctrl_tx_bytes": 0,
            "ctrl_tx_ack_msgs": 0,
            "ctrl_tx_nack_msgs": 0,
            "ctrl_tx_dropped_msgs": 0,
            "arq_attempts_mean": 2.0,
            "arq_attempts_p95": 3.0,
            "tx_retx_rounds": 0,
            "tx_retx_rounds_mean": 0.0,
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

        # Discrete action space (MultiDiscrete), matching the requirement that
        # controls are chosen from a finite set (not a clipped continuous Box).
        # Order: [K_idx, R0_idx, RSTEP_idx]
        #   K: 20..60 (step=2) -> 21 values
        #   R0: 0..20     -> 21 values
        #   RSTEP: 1..20  -> 20 values
        self.action_space = spaces.MultiDiscrete([21, 21, 20])
        # Policy observation keys.
        # Keep this strictly limited to the learning signal (no debug/leakage).
        # Layout (requested):
        #   goodput,
        #   fec_overhead,
        #   tx_retx_rounds (RSTEP-trigger count on sender),
        #   residual_erasures,
        #   fec_rate (R0/K)
        self._obs_keys: List[str] = [
            "goodput",
            "fec_overhead",
            "tx_retx_rounds",
            "residual_erasures",
            "fec_rate",
        ]
        self.observation_space = spaces.Box(
            low=-5.0, high=+np.inf, shape=(len(self._obs_keys),), dtype=np.float32
        )

        # Whether to apply a running normalization to observations.
        # RL agents often benefit from normalization; contextual bandits may prefer
        # stable, interpretable scales.
        self._normalize_obs = bool(cfg.get("normalize_obs", True))

        # Episode length control
        # By default, treat each transfer as one episode.
        self._episode_steps = int(cfg.get("episode_step", 1))
        self._t_in_ep = 0

        # If the external harness fails (missing deps, netns issues, etc.), it's usually
        # better to fail fast than to keep training on default observations.
        # Timeouts are treated as a valid (bad) outcome by default.
        self._ignore_runner_errors = bool(cfg.get("ignore_runner_errors", False))

        # Invalid-transfer filtering:
        # - timeouts (Python-side) and
        # - md5_ok=0 (harness-side)
        # should not be counted as learning signal nor included in step_metrics.
        # This is critical for the TX-only contextual bandit: failures are often
        # environmental (netns readiness, transient EPERM, etc.) and would poison
        # the contextual update.
        self._ignore_invalid_transfers = bool(cfg.get("ignore_invalid_transfers", True))

        # Curriculum / randomization
        self._randomize_net_params_enabled = bool(cfg.get("randomize_net_params", False))
        self._curriculum_warmup_episodes = int(cfg.get("curriculum_warmup_episodes", 0))

        # Reward shaping (default matches docs/main.pdf Eq. (25) more closely)
        # reward_variant:
        # - "qarc_v1": soft penalties, non-saturating signals for throughput/overhead
        # - "legacy": previous clipped/thresholded reward
        self._reward_variant = str(cfg.get("reward_variant", "qarc_v1"))
        # Default weights for shaping.
        # Latency term removed: bandit controls TX side only.
        self._reward_w_goodput = float(cfg.get("reward_w_goodput", 1.0))
        self._reward_w_residual = float(cfg.get("reward_w_residual", 0.0))
        self._reward_w_overhead = float(cfg.get("reward_w_overhead", 0.3))
        self._reward_w_arq = float(cfg.get("reward_w_arq", 0.0))
        self._reward_residual_binary = bool(cfg.get("reward_residual_binary", True))

        # Network defaults
        self._rtt_ms = int(cfg.get("rtt_ms", 100))
        self._loss_pct = int(cfg.get("loss_pct", 5))
        self._loss_mode = str(cfg.get("loss_mode", f"iid:{self._loss_pct}"))

        # Remember the non-randomized baseline for curriculum warmup
        self._base_rtt_ms = int(self._rtt_ms)
        self._base_loss_pct = int(self._loss_pct)
        self._base_loss_mode = str(self._loss_mode)

        # Link capacity / shaping rate (Mbps)
        self._bitrate_mbps = int(cfg.get("bitrate_mbps", 50))
        self._capacity_mbps = float(self._bitrate_mbps)
        self._result_dir_hint = cfg.get("result_dir")

        # Logging controls
        # - log_obs_vec: large; disable by default to avoid bloating logs.
        # - log_raw_obs_full: deprecated; step_metrics.json always logs policy obs only.
        self._log_obs_vec = bool(cfg.get("log_obs_vec", False))
        self._log_raw_obs_full = bool(cfg.get("log_raw_obs_full", False))
        # NOTE: These JSON-lines logs are useful for debugging, but they tend to
        # clutter results when using bandit runners that already write
        # bandit_metrics.json.
        self._log_step_metrics = bool(cfg.get("log_step_metrics", False))
        self._log_episode_metrics = bool(cfg.get("log_episode_metrics", False))

        # Runner
        # Default training file size: 1 MiB
        default_train_file_bytes = 1 * 1024 * 1024
        timeout_sec = int(cfg.get("timeout_sec", 30))
        self._runner = QuicFecRunner(
            timeout_sec=timeout_sec,
            # Keep the server lifetime bounded to roughly the same budget as the
            # subprocess timeout, so pathological configs (e.g., R0=0) don't hang.
            srv_timeout=f"{max(1, timeout_sec)}s",
            obs_wait_secs=max(1, timeout_sec),
            train_file_bytes=(
                int(cfg.get("train_file_bytes"))
                if cfg.get("train_file_bytes") is not None
                else int(default_train_file_bytes)
            ),
        )
        self._runner.reset(
            EnvConfig(
                datagrams_enabled=True,
                num_connections=1,
                cc_algo="bbrv2",
                target_bitrate_bps=int(self._capacity_mbps * 1_000_000),
                loss_profile=self._loss_mode,
                K=30,
                symbol_bytes=1200,
            )
        )

        self._last_obs_vec = np.zeros((len(self._obs_keys),), dtype=np.float32)
        # True once we've produced at least one valid policy observation via step().
        # With episode_step=1, reset() needs to return a meaningful observation;
        # we use the last step() observation as the next episode's reset obs.
        self._has_last_obs = False
        self._cap_hits = 0
        self._norm = _RunningNorm(dim=self.observation_space.shape[0])
        self._global_step = 0
        self.epi = -1
        self._rng = np.random.RandomState()

        # Episode-level diagnostics
        self._ep_return = 0.0
        self._ep_term_sums: Dict[str, float] = {}

    def reset(self, *, seed: Optional[int] = None, options: Optional[Dict[str, Any]] = None):
        # IMPORTANT for episode_step=1:
        # RLlib will call reset() before every single action selection.
        # Returning all-zeros here makes the policy effectively blind.
        # Instead, return the last valid policy observation from the previous episode.
        # (If no prior step() has run yet, fall back to zeros.)
        if not self._has_last_obs:
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

        # Optional override: allow callers (e.g., bandit runner) to switch network
        # parameters only at reset() boundaries, without enabling randomization.
        if options and isinstance(options, dict):
            if "rtt_ms" in options and options.get("rtt_ms") is not None:
                self._base_rtt_ms = int(options.get("rtt_ms"))
            if "loss_pct" in options and options.get("loss_pct") is not None:
                self._base_loss_pct = int(options.get("loss_pct"))
            if "loss_mode" in options and options.get("loss_mode") is not None:
                self._base_loss_mode = str(options.get("loss_mode"))
            if "bitrate_mbps" in options and options.get("bitrate_mbps") is not None:
                self._bitrate_mbps = int(options.get("bitrate_mbps"))
                # Keep reward normalization consistent with shaping capacity.
                self._capacity_mbps = float(self._bitrate_mbps)

        # Curriculum: keep network fixed for a few warmup episodes, then randomize.
        if self._randomize_net_params_enabled and self.epi >= self._curriculum_warmup_episodes:
            self._randomize_net_params()
        else:
            self._rtt_ms = int(self._base_rtt_ms)
            self._loss_pct = int(self._base_loss_pct)
            self._loss_mode = str(self._base_loss_mode)

        # Training optimization: configure netns/tc once and reuse.
        # Only reconfigure if the network parameters change (e.g., randomization/curriculum).
        desired_key = (int(self._rtt_ms), str(self._loss_mode), int(self._bitrate_mbps))
        if getattr(self._runner, "_net_cfg_key", None) != desired_key:
            try:
                self._runner.configure_network(
                    rtt_ms=int(self._rtt_ms),
                    loss_mode=str(self._loss_mode),
                    loss_pct=int(self._loss_pct),
                    bitrate_mbps=int(self._bitrate_mbps),
                )
            except Exception as e:
                # If shaping setup fails here, step() will fall back to the old behavior.
                if not self._ignore_runner_errors:
                    raise RuntimeError(f"QUIC-FEC network setup failed: {e}")
        return self._last_obs_vec.copy(), {}

    def step(self, action: np.ndarray):
        a = np.asarray(action).reshape(-1)
        if a.size != 3:
            raise ValueError("Action must be length-3 MultiDiscrete array")

        k_idx = int(a[0])
        r0_idx = int(a[1])
        rstep_idx = int(a[2])

        if not (0 <= k_idx <= 20):
            raise ValueError(f"K index out of range: {k_idx}")
        if not (0 <= r0_idx <= 20):
            raise ValueError(f"R0 index out of range: {r0_idx}")
        if not (0 <= rstep_idx <= 19):
            raise ValueError(f"RSTEP index out of range: {rstep_idx}")

        K = 20 + 2 * k_idx
        R0 = int(r0_idx)
        # Keep semantics consistent with legacy behavior (R0 never exceeded K).
        if R0 > int(K):
            R0 = int(K)
        RSTEP = 1 + rstep_idx
        act = Action(K=int(K), R0=int(R0), RSTEP=int(RSTEP))

        obs_dict, _reward_unused, _done_transfer, info = self._runner.step(
            act,
            rtt_ms=self._rtt_ms,
            loss_pct=self._loss_pct,
            bitrate_mbps=self._bitrate_mbps,
            loss_mode=self._loss_mode,
        )

        # Derive policy-safe goodput metric (always present in obs).
        err = None
        if info and isinstance(info, dict):
            err = info.get("error")
        is_timeout = bool(isinstance(err, str) and err.lower().startswith("timeout"))

        # md5_ok is produced by the harness (scripts/quicfec_run_once.sh) and is
        # not part of the policy observation; it is used only to filter invalid runs.
        md5_ok = 1
        try:
            md5_ok = int(obs_dict.get("md5_ok", 1))
        except Exception:
            md5_ok = 1
        is_md5_fail = bool(md5_ok != 1)
        try:
            # Bandit-safe: prefer tx-side goodput estimate (provided by the harness).
            goodput_mbps = float(
                obs_dict.get(
                    "goodput",
                    obs_dict.get(
                        "goodput_mbps",
                        obs_dict.get("goodput_arrival_mbps", obs_dict.get("goodput_decode_mbps", 0.0)),
                    ),
                )
            )
        except Exception:
            goodput_mbps = 0.0
        if is_timeout:
            goodput_mbps = 0.0
        # Keep both keys for compatibility in logs; policy observation uses "goodput".
        obs_dict["goodput_mbps"] = float(goodput_mbps)
        obs_dict["goodput"] = float(goodput_mbps)

        # Append control-derived observation fields.
        # fec_rate is defined as R0/K where R0 is the integer parity used by the sender.
        r0_used = max(0, int(R0))
        obs_dict["fec_rate"] = float(r0_used) / float(max(1, int(K)))

        if not self._ignore_runner_errors and info and isinstance(info, dict) and info.get("error"):
            err = str(info.get("error"))
            if not err.lower().startswith("timeout"):
                raise RuntimeError(f"QUIC-FEC harness failed: {err}")

        # If this transfer is invalid, do not emit learning signal.
        # We intentionally avoid updating last_obs so that reset() returns the
        # last known-good observation.
        if self._ignore_invalid_transfers and (is_timeout or is_md5_fail):
            info = {
                **(info or {}),
                "step_valid": 0,
                "invalid_reason": "timeout" if is_timeout else "md5_fail",
                "md5_ok": int(md5_ok),
            }
            return self._last_obs_vec.copy(), 0.0, False, False, info

        # Compute reward (variant selectable via env_config). If the harness timed out,
        # override with a hard penalty to discourage actions that fail to complete.
        if is_timeout:
            reward = -1.0
            r_terms = {"timeout": 1.0}
        else:
            reward, r_terms = self._compute_reward_satellite(obs_dict)
        # Build policy observation vector.
        obs_vec = self._obs_to_vec(obs_dict)
        if self._normalize_obs:
            obs_vec = self._norm.transform(self._norm.update(obs_vec))
        self._last_obs_vec = obs_vec
        self._has_last_obs = True

        info = {
            **(info or {}),
            "step_valid": 1,
            "net_params": {
                "rtt_ms": self._rtt_ms,
                "bitrate_mbps": self._bitrate_mbps,
                "loss_mode": self._loss_mode,
            },
            "fec_cfg": {
                "K": int(K),
                "symbol_bytes": 1200,
                "R0": int(r0_used),
                "fec_rate": float(r0_used) / float(max(1, int(K))),
                "RSTEP": int(RSTEP),
                "cc_algo": str(getattr(self._runner.last_cfg or EnvConfig(), "cc_algo", "bbrv2")),
            },
            "bw_cap_mbps": float(self._capacity_mbps),
            "goodput_mbps": float(obs_dict.get("goodput", obs_dict.get("goodput_mbps", obs_dict.get("goodput_arrival_mbps", obs_dict.get("goodput_decode_mbps", 0.0))))),
            "reward_terms": r_terms,
            # "cap_hit": cap_hit,
            "cap_hits_cum": self._cap_hits,
            "zero_residual_flag": int(obs_dict.get("residual_erasures", 0) == 0),
            # Latency term removed; keep field for backward-compatible logs.
            "on_time_flag": 0,
        }

        # Resolve trial/log dir: prefer Ray trial dir/env override
        dest_dir = (
            os.environ.get("QUICFEC_RESULT_DIR")
            or os.environ.get("RAY_AIR_TRIAL_DIR")
            or os.environ.get("RAY_TUNE_TRIAL_DIR")
            or self._result_dir_hint
            or os.path.join(os.path.dirname(__file__), "results")
        )

        # Always return raw observations to the caller (useful for smoke tests),
        # even if we disable file logging.
        try:
            info["raw_obs"] = {k: obs_dict.get(k, 0.0) for k in self._obs_keys}
        except Exception:
            pass

        if self._log_step_metrics:
            try:
                os.makedirs(dest_dir, exist_ok=True)
                # Keep JSON format (one JSON object per line) but write to the
                # requested filename.
                log_path = os.path.join(dest_dir, "step_metrics.json")

                rec = {
                    "t": int(self._global_step),
                    "epi": self.epi,
                    "reward": float(reward),
                    "raw_obs": info.get("raw_obs"),
                    **info,
                }

                if self._log_obs_vec:
                    rec["obs_vec"] = [float(x) for x in obs_vec.tolist()]

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

        if terminated and self._log_episode_metrics:
            # Write episode summary to help diagnose learning signal and non-stationarity.
            try:
                epi_path = os.path.join(dest_dir, "episode_metrics.json")
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

    def _randomize_net_params(self) -> None:
        rng = self._rng
        def pick(xs):
            return xs[int(rng.randint(0, len(xs)))]
        # Keep bitrate consistent with configured physical capacity
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

    def _compute_reward_satellite(self, obs: Dict[str, Any]) -> Tuple[float, Dict[str, float]]:
        g = float(obs.get("goodput", obs.get("goodput_mbps", obs.get("goodput_arrival_mbps", obs.get("goodput_decode_mbps", 0.0)))))
        e = float(obs.get("residual_erasures", 0.0))
        oh = float(obs.get("fec_overhead", 0.0))
        # New policy signal: sender-side repair rounds appended in this transfer.
        # Prefer tx_retx_rounds, but fall back to arq_attempts_mean for legacy logs.
        a_mean = float(obs.get("tx_retx_rounds", obs.get("arq_attempts_mean", 0.0)))

        if self._reward_variant == "legacy":
            # Previous shaping (kept for reproducibility)
            c = max(1.0, float(self._capacity_mbps))
            tp_term = float(np.clip(g / c, 0.0, 1.0))
            lam_e = 0.75
            resid_term = -lam_e * (e / (1.0 + e))
            lam_o = 0.3
            # Legacy overhead term: treat fec_overhead as a ratio (repairs/source).
            # Penalize overhead above ~0.5, saturating by ~2.0.
            oh_term = -lam_o * max(0.0, (oh - 0.5) / 1.5)
            arq_term = -min(0.3, 0.02 * a_mean)
            r = tp_term + resid_term + oh_term + arq_term
            return float(r), {
                "tp_term": float(tp_term),
                "resid_term": float(resid_term),
                "oh_term": float(oh_term),
                "arq_term": float(arq_term),
            }

        # Throughput + latency reward shaping.
        # tp_term: normalized by physical capacity.
        c = max(1e-6, float(self._capacity_mbps))
        tp_term = float(self._reward_w_goodput) * float(g / c)

        # Keep residual/overhead/ARQ as penalties (optional knobs).
        if self._reward_residual_binary:
            l_tilde = float(e > 0.0)
        else:
            l_tilde = float(e / (1.0 + max(0.0, e)))
        arq_tilde = float(np.clip(a_mean / 10.0, 0.0, 1.0))

        resid_term = -float(self._reward_w_residual) * float(l_tilde)
        oh_term = float(self._reward_w_overhead) * float(1.0 / (1.0 + (float(oh) / 0.3) ** 2))
        arq_term = -float(self._reward_w_arq) * float(arq_tilde)

        r = float(tp_term + resid_term + oh_term + arq_term)
        return r, {
            "tp_term": float(tp_term),
            "resid_term": float(resid_term),
            "oh_term": float(oh_term),
            "arq_term": float(arq_term),
            "tp_norm": float(np.clip(g / c, 0.0, 1.0)),
            "l_tilde": float(l_tilde),
            "arq_tilde": float(arq_tilde),
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
