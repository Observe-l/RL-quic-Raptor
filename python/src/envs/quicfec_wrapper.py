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
        loss_mode: str | None = None,
        bitrate_mbps: int = 10,
        K: int = 40,
        symbol_bytes: int = 1200,
        prefer_local: bool = False,
        episode_steps: int = 100,
        phase: str = "train",  # one of {train,val,test}
        scenario_family: str | None = None,  # one of {A,B,C} or None for auto
        action_codebook_size: int = 64,
        common_reward: bool = True,
        reward_scalarisation: str = "sum",
        **kwargs,
    ) -> None:
        self._rtt_ms = int(rtt_ms)
        self._loss_pct = int(loss_pct)
        self._loss_mode = loss_mode
        self._bitrate = int(bitrate_mbps) * 1_000_000
        # Persist initial code parameters for env resets
        self._K0 = int(K)
        self._symbol_bytes0 = int(symbol_bytes)

        # Experiment plan (channel schedule) for this episode
        self._episode_steps = int(episode_steps) if int(episode_steps) > 0 else 100
        self._phase = str(phase)
        self._scenario_family = scenario_family  # None => auto sample per design
        self._step_idx = 0
        self._plan: list[dict[str, Any]] = []  # per-step: {rtt_ms, loss_mode, bitrate_mbps}

        # Underlying single-episode environment; prefer local smoke script to avoid sudo
        # Use a moderate timeout per episode to prevent hangs
        self._env = QuicFecEnv(prefer_local=prefer_local, timeout_sec=15)
        self._env.reset(
            EnvConfig(
                datagrams_enabled=True,
                num_connections=1,
                cc_mode="bypass",
                target_bitrate_bps=self._bitrate,
                loss_profile=(self._loss_mode if self._loss_mode else f"iid:{self._loss_pct}"),
                K=self._K0,
                symbol_bytes=self._symbol_bytes0,
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
        self.episode_limit = self._episode_steps
        self._last_obs_vec = np.zeros(len(self._obs_keys), dtype=np.float32)

        # Build initial plan for the first episode
        self._init_episode_plan()

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

        # Choose channel params for this step from the plan
        params = self._plan[self._step_idx] if self._plan and self._step_idx < len(self._plan) else {
            "rtt_ms": self._rtt_ms,
            "loss_mode": (self._loss_mode if self._loss_mode else f"iid:{self._loss_pct}"),
            "bitrate_mbps": int(self._bitrate / 1_000_000),
        }

        # Active network settings for this step (for logging)
        net_rtt_ms = int(params.get("rtt_ms", self._rtt_ms))
        net_bitrate_mbps = int(params.get("bitrate_mbps", int(self._bitrate / 1_000_000)))
        net_loss_mode = (
            str(params.get("loss_mode", self._loss_mode))
            if params.get("loss_mode", None) is not None
            else (self._loss_mode if self._loss_mode else f"iid:{self._loss_pct}")
        )
        # Nominal loss rate if iid:X, else None; for gemodel parse (p,r,h,k)
        net_loss_rate_pct = None
        net_loss_params = None
        try:
            if isinstance(net_loss_mode, str) and net_loss_mode.startswith("iid:"):
                net_loss_rate_pct = float(net_loss_mode.split(":", 1)[1])
            elif isinstance(net_loss_mode, str) and net_loss_mode.startswith("gemodel:"):
                parts = net_loss_mode.split(":", 1)[1].split(",")
                if len(parts) >= 4:
                    p, r, h, k = [float(x) for x in parts[:4]]
                    net_loss_params = {"p": p, "r": r, "h": h, "k": k}
        except Exception:
            net_loss_rate_pct = None

        # Compute bounded action fields
        R0 = max(2, int(round(K * R0_pct)))
        R_step = max(1, min(R_step, 12))
        W = max(6, min(W, 24))
        # Make DDL at least ~2x RTT + slack; allow a bit higher cap for ARQ under loss
        ddl_floor = max(150, int(2.2 * net_rtt_ms))
        ddl_ms = int(min(max(ddl_ms, ddl_floor), 500))

        # Safety floor for redundancy based on loss estimate to avoid trivial decode failures
        # try:
        #     if net_loss_rate_pct is not None and net_loss_rate_pct >= 1.0:
        #         # Ensure at least (loss + 5%) redundancy, capped
        #         min_overhead = min(0.35, (net_loss_rate_pct / 100.0) + 0.05)
        #         R0 = max(R0, int(round(K * min_overhead)))
        # except Exception:
        #     pass

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

        # Under harsher loss, tighten ACK pacing and allow more ARQ attempts
        try:
            if (net_loss_rate_pct is not None and net_loss_rate_pct >= 5.0) or (isinstance(net_loss_mode, str) and net_loss_mode.startswith("gemodel")):
                os.environ["ACK_EVERY"] = os.environ.get("ACK_EVERY", "4")
                os.environ["MAX_ATTEMPTS"] = os.environ.get("MAX_ATTEMPTS", "10")
        except Exception:
            pass

        obs_dict, reward, inner_done, info = self._env.step(
                act,
                rtt_ms=net_rtt_ms,
                loss_pct=self._loss_pct,
                bitrate_mbps=net_bitrate_mbps,
                loss_mode=net_loss_mode,
            )
        self._last_obs_vec = self._obs_to_vec(obs_dict)
        # Manage outer episode termination: only end after planned steps
        self._step_idx += 1
        terminated = bool(self._step_idx >= self.episode_limit)
        truncated = False
        return [self._last_obs_vec], float(reward), terminated, truncated, {
            "raw_obs": obs_dict,
            **info,
            # Flattened network settings for convenience in log aggregation
            "net_rtt_ms": net_rtt_ms,
            "net_bitrate_mbps": net_bitrate_mbps,
            "net_loss_mode": net_loss_mode,
            "net_loss_rate_pct": net_loss_rate_pct,
            "net_loss_params": net_loss_params,
            # Grouped as well
            "net_params": {
                "rtt_ms": net_rtt_ms,
                "bitrate_mbps": net_bitrate_mbps,
                "loss_mode": net_loss_mode,
                "loss_rate_pct": net_loss_rate_pct,
                "loss_params": net_loss_params,
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
        # Reset per-episode state and regenerate the channel plan
        self._last_obs_vec = np.zeros(len(self._obs_keys), dtype=np.float32)
        self._step_idx = 0
        self._init_episode_plan()
        self.episode_limit = self._episode_steps
        # Apply the selected network configuration for this episode to the underlying env
        try:
            params0 = self._plan[0] if (self._plan and len(self._plan) > 0) else {
                "rtt_ms": self._rtt_ms,
                "loss_mode": (self._loss_mode if self._loss_mode else f"iid:{self._loss_pct}"),
                "bitrate_mbps": int(self._bitrate / 1_000_000),
            }
            # Configure the env baseline with episode's initial network settings.
            # Step() will still pass exact values per step, but this keeps env.last_cfg consistent.
            self._env.reset(
                EnvConfig(
                    datagrams_enabled=True,
                    num_connections=1,
                    cc_mode="bypass",
                    target_bitrate_bps=int(params0.get("bitrate_mbps", int(self._bitrate / 1_000_000))) * 1_000_000,
                    loss_profile=str(params0.get("loss_mode", self._loss_mode)) if params0.get("loss_mode", None) else (self._loss_mode if self._loss_mode else f"iid:{self._loss_pct}"),
                    K=self._K0,
                    symbol_bytes=self._symbol_bytes0,
                )
            )
        except Exception:
            # Do not break reset if configuration mapping fails
            pass
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

    # --- scenario planning per experiment design ---
    def _init_episode_plan(self) -> None:
        """Build per-step channel parameters for this episode following the design.
        Scenarios:
          A: iid loss + stable link with jitter and slow BW drift
          B: Gilbert-Elliott bursts
          C: Non-stationary events (BW drop or RTT spike windows)
        Phase controls sampling vs fixed sets (train/val/test).
        """
        rng = np.random.RandomState()

        # Helper picks
        def pick(xs):
            return xs[rng.randint(0, len(xs))]

        def plan_A():
            loss_set = [0, 1, 3, 5, 10, 15]
            rtt_set = [20, 50, 100, 200]
            jitter_set = [2, 5, 10, 20]
            bw_set = [5, 10, 20, 50]
            p = pick(loss_set)
            rtt = pick(rtt_set)
            sigma = pick(jitter_set)
            bw = pick(bw_set)

            # Slow BW drift: change multiplier every 10 steps in [0.8,1.2]
            plan = []
            for t in range(self._episode_steps):
                if t % 10 == 0:
                    drift = 0.8 + 0.4 * rng.rand()
                # approximate RTT jitter by small +/- variation
                rtt_t = max(1, int(round(rtt + rng.randn() * sigma)))
                plan.append({
                    "rtt_ms": rtt_t,
                    "loss_mode": f"iid:{p}",
                    "bitrate_mbps": max(1, int(round(bw * drift)))
                })
            return plan

        def ge_from_lengths(pG, pB, LB, LG):
            # Approximate netem gemodel params (p,r,h,k) in %
            # Use p=pG, k=pB, r≈100*(1-1/LG), h≈100*(1-1/LB)
            r = max(0.0, min(100.0, 100.0 * (1.0 - 1.0 / max(1, LG))))
            h = max(0.0, min(100.0, 100.0 * (1.0 - 1.0 / max(1, LB))))
            return pG, r, h, pB

        def plan_B():
            pG = pick([0.5, 1, 2])
            pB = pick([10, 20, 30])
            LB = pick([3, 5, 10, 20])
            LG = pick([20, 50, 100])
            p, r, h, k = ge_from_lengths(pG, pB, LB, LG)
            rtt = pick([50, 100, 200])
            bw = pick([5, 10, 20, 50])
            plan = [{
                "rtt_ms": rtt,
                "loss_mode": f"gemodel:{p},{r},{h},{k}",
                "bitrate_mbps": bw,
            } for _ in range(self._episode_steps)]
            return plan

        def plan_C():
            # Base params
            base_is_ge = rng.rand() < 0.5
            if base_is_ge:
                p, r, h, k = ge_from_lengths(1.0, 20.0, 5, 50)
                loss_mode_base = f"gemodel:{p},{r},{h},{k}"
            else:
                p = pick([1, 3, 5])
                loss_mode_base = f"iid:{p}"
            rtt = pick([50, 100])
            bw = pick([10, 20, 50])
            sigma = pick([5, 10])
            plan = []
            # Select events windows
            # BW drop between step 30–60, 10–30 steps, to 25–50%
            drop_start = rng.randint(30, 61)
            drop_len = rng.randint(10, 31)
            drop_factor = 0.25 + 0.25 * rng.rand()
            drop_end = min(self._episode_steps, drop_start + drop_len)
            # RTT spike: +100–300 ms for 10 steps, somewhere later
            spike_start = rng.randint(60, 81) if self._episode_steps >= 80 else rng.randint(max(1, self._episode_steps//2), self._episode_steps)
            spike_len = 10
            spike_delta = 100 + int(200 * rng.rand())
            spike_end = min(self._episode_steps, spike_start + spike_len)

            for t in range(self._episode_steps):
                rtt_t = max(1, int(round(rtt + rng.randn() * sigma)))
                bw_t = bw
                if drop_start <= t < drop_end:
                    bw_t = max(1, int(round(bw * drop_factor)))
                if spike_start <= t < spike_end:
                    rtt_t = rtt_t + spike_delta
                plan.append({
                    "rtt_ms": rtt_t,
                    "loss_mode": loss_mode_base,
                    "bitrate_mbps": bw_t,
                })
            return plan

        fam = (self._scenario_family or "auto").upper()
        if fam not in {"A", "B", "C", "AUTO"}:
            fam = "AUTO"

        # Validation/Test fixed sets per design
        if self._phase in {"val", "validation"}:
            if fam in {"A", "AUTO"}:
                # p ∈ {1,5,10}%, μ_RTT ∈ {50,100} ms, BW ∈ {10,20} Mbps, σ_RTT = 5 ms
                loss_choices = [1, 5, 10]
                rtt_choices = [50, 100]
                bw_choices = [10, 20]
                p = pick(loss_choices)
                rtt = pick(rtt_choices)
                bw = pick(bw_choices)
                sigma = 5
                plan = []
                for t in range(self._episode_steps):
                    if t % 10 == 0:
                        drift = 0.8 + 0.4 * rng.rand()
                    rtt_t = max(1, int(round(rtt + rng.randn() * sigma)))
                    plan.append({"rtt_ms": rtt_t, "loss_mode": f"iid:{p}", "bitrate_mbps": max(1, int(round(bw * drift)))})
                self._plan = plan
                return
            if fam in {"B", "AUTO"}:
                # Three fixed GE sets
                candidates = [
                    (1.0, 20.0, 5, 50, 50, 10),
                    (0.5, 30.0, 10, 20, 100, 20),
                    (2.0, 10.0, 20, 100, 200, 5),
                ]
                pG, pB, LB, LG, rtt, bw = pick(candidates)
                p, r, h, k = ge_from_lengths(pG, pB, LB, LG)
                self._plan = [{"rtt_ms": rtt, "loss_mode": f"gemodel:{p},{r},{h},{k}", "bitrate_mbps": bw} for _ in range(self._episode_steps)]
                return
            # C: provide two examples
            candidates = [
                {"bw": 20, "drop_start": 40, "drop_len": 15, "drop_factor": 0.4, "p": 3, "rtt": 50, "sigma": 5, "spike": None},
                {"bw": 10, "ge": (1.0, 20.0, 5, 50), "rtt": 50, "sigma": 5, "spike": {"start": 70, "len": 10, "delta": 200}},
            ]
            cfg = pick(candidates)
            plan = []
            for t in range(self._episode_steps):
                rtt_t = max(1, int(round(cfg["rtt"] + rng.randn() * cfg.get("sigma", 0))))
                bw_t = cfg["bw"]
                loss_mode = f"iid:{cfg['p']}" if "p" in cfg else (lambda x: f"gemodel:{x[0]},{ge_from_lengths(*x)[1]},{ge_from_lengths(*x)[2]},{x[1]}") (cfg["ge"]) if "ge" in cfg else f"iid:1"
                if cfg.get("drop_start") is not None and cfg.get("drop_len") is not None:
                    if cfg["drop_start"] <= t < cfg["drop_start"] + cfg["drop_len"]:
                        bw_t = max(1, int(round(cfg["bw"] * cfg.get("drop_factor", 0.4))))
                if cfg.get("spike") and cfg["spike"]["start"] <= t < cfg["spike"]["start"] + cfg["spike"]["len"]:
                    rtt_t += cfg["spike"]["delta"]
                plan.append({"rtt_ms": rtt_t, "loss_mode": loss_mode, "bitrate_mbps": bw_t})
            self._plan = plan
            return

        if self._phase in {"test", "testing"}:
            if fam in {"A", "AUTO"}:
                # p ∈ {0,3,15}%, μ_RTT ∈ {20,200} ms, BW ∈ {5,50} Mbps, σ_RTT = 10 ms
                p = pick([0, 3, 15])
                rtt = pick([20, 200])
                bw = pick([5, 50])
                sigma = 10
                plan = []
                for t in range(self._episode_steps):
                    if t % 10 == 0:
                        drift = 0.8 + 0.4 * rng.rand()
                    rtt_t = max(1, int(round(rtt + rng.randn() * sigma)))
                    plan.append({"rtt_ms": rtt_t, "loss_mode": f"iid:{p}", "bitrate_mbps": max(1, int(round(bw * drift)))})
                self._plan = plan
                return
            if fam in {"B", "AUTO"}:
                # Three fixed GE test sets
                candidates = [
                    (1.0, 20.0, 10, 50, 100, 50),
                    (0.5, 30.0, 20, 20, 20, 20),
                    (2.0, 10.0, 5, 100, 50, 10),
                ]
                pG, pB, LB, LG, rtt, bw = pick(candidates)
                p, r, h, k = ge_from_lengths(pG, pB, LB, LG)
                self._plan = [{"rtt_ms": rtt, "loss_mode": f"gemodel:{p},{r},{h},{k}", "bitrate_mbps": bw} for _ in range(self._episode_steps)]
                return
            # C: combined event example
            p = 5
            rtt = 100
            bw = 50
            sigma = 10
            plan = []
            for t in range(self._episode_steps):
                rtt_t = max(1, int(round(rtt + rng.randn() * sigma)))
                bw_t = bw
                if 30 <= t < 50:
                    bw_t = max(1, int(round(bw * 0.3)))
                if 60 <= t < 70:
                    rtt_t += 300
                plan.append({"rtt_ms": rtt_t, "loss_mode": f"iid:{p}", "bitrate_mbps": bw_t})
            self._plan = plan
            return

        # Training randomization 40%/40%/20%
        if fam == "A" or (fam == "AUTO" and rng.rand() < 0.4):
            self._plan = plan_A()
        elif fam == "B" or (fam == "AUTO" and rng.rand() < 0.8):
            self._plan = plan_B()
        else:
            self._plan = plan_C()
