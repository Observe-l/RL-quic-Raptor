from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import asdict
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

# Allow running as a script:
#   python3 bandit/run_lints.py ...
# by ensuring the project root (python/) is on sys.path.
_THIS_DIR = os.path.dirname(__file__)
_ROOT_DIR = os.path.abspath(os.path.join(_THIS_DIR, ".."))
if _ROOT_DIR not in sys.path:
    sys.path.insert(0, _ROOT_DIR)

_REPO_ROOT = os.path.abspath(os.path.join(_ROOT_DIR, ".."))

from fecenv_env import FecEnv  # noqa: E402

from bandit.action_set import ActionSet  # noqa: E402
from bandit.context import ContextBuilder, ContextConfig  # noqa: E402
from bandit.features import phi as phi_fn  # noqa: E402
from bandit.lints import LinTS, LinTSConfig  # noqa: E402
from bandit.model_io import load_checkpoint, save_checkpoint  # noqa: E402


def _json_default(o: Any):
    """JSON fallback encoder for long-running experiments."""

    if isinstance(o, (bytes, bytearray, memoryview)):
        try:
            return bytes(o).decode("utf-8", errors="replace")
        except Exception:
            return repr(o)

    try:
        import numpy as _np

        if isinstance(o, _np.generic):
            return o.item()
        if isinstance(o, _np.ndarray):
            return o.tolist()
    except Exception:
        pass

    try:
        return str(o)
    except Exception:
        return repr(o)


def _ensure_dir(p: str) -> None:
    os.makedirs(p, exist_ok=True)


def _fmt_score(x: float) -> str:
    # Filename-safe score string
    s = f"{float(x):.6f}"
    return s.replace("-", "m").replace(".", "p")


def _safe_unlink(prefix: str) -> None:
    for ext in (".npz", ".json"):
        try:
            os.remove(prefix + ext)
        except FileNotFoundError:
            pass


def _load_block_best(block_dir: str) -> List[Tuple[float, int, str]]:
    """Load existing per-block top-k summary if present.

    Returns list of (reward, t, prefix), sorted descending by reward.
    """

    path = os.path.join(block_dir, "best_models.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        topk = data.get("topk")
        if not isinstance(topk, list):
            return []
        out: List[Tuple[float, int, str]] = []
        for item in topk:
            if not isinstance(item, dict):
                continue
            try:
                r = float(item.get("reward"))
                t = int(item.get("t"))
                pfx = str(item.get("prefix"))
            except Exception:
                continue
            if not pfx:
                continue
            out.append((r, t, pfx))
        out.sort(key=lambda x: x[0], reverse=True)
        return out
    except FileNotFoundError:
        return []
    except Exception:
        return []


def _find_latest_saved_prefix(dest_dir: str) -> Optional[str]:
    """Find the latest saved model prefix under a result dir.

    Priority:
      1) <dest_dir>/bandit_model.json (latest checkpoint)
      2) newest per-block checkpoint under <dest_dir>/best_models/**/model_t*_r*.json
    """

    dest_dir = os.path.abspath(dest_dir)
    latest = os.path.join(dest_dir, "bandit_model")
    if os.path.exists(latest + ".json") and os.path.exists(latest + ".npz"):
        return latest

    best_root = os.path.join(dest_dir, "best_models")
    if not os.path.isdir(best_root):
        return None

    best_t = None
    best_prefix = None
    for root, _dirs, files in os.walk(best_root):
        for fn in files:
            if not (fn.startswith("model_t") and fn.endswith(".json")):
                continue
            # Expected: model_t{t}_r{score}.json
            try:
                stem = fn[:-5]
                left, _right = stem.split("_r", 1)
                t_str = left[len("model_t") :]
                t_val = int(t_str)
            except Exception:
                continue
            prefix = os.path.join(root, stem)
            if not os.path.exists(prefix + ".npz"):
                continue
            if best_t is None or int(t_val) > int(best_t):
                best_t = int(t_val)
                best_prefix = str(prefix)
    return best_prefix


def _iid_loss_mode(loss_pct: float) -> str:
    """Build iid loss_mode string from percent input.

    The CLI uses percent, e.g. 0.5 means 0.5%.
    """

    try:
        v = float(loss_pct)
    except Exception:
        v = 0.0
    if not np.isfinite(v):
        v = 0.0
    v = float(np.clip(v, 0.0, 100.0))
    # Preserve decimals (tc netem accepts float percentages).
    return f"iid:{v:g}"


_DEFAULT_IID_LOSS_CYCLE_PCT: List[float] = [
    0.1,
    0.2,
    0.3,
    0.4,
    0.5,
    1.0,
    2.0,
    3.0,
    4.0,
    5.0,
    6.0,
    7.0,
    8.0,
]


def _parse_loss_cycle(s: str) -> List[float]:
    items: List[float] = []
    for part in (s or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            v = float(part)
        except Exception:
            raise ValueError(f"invalid --loss-cycle entry: {part!r}")
        if not np.isfinite(v):
            raise ValueError(f"invalid --loss-cycle entry: {part!r}")
        if v < 0.0 or v > 100.0:
            raise ValueError(f"--loss-cycle entries must be within [0,100], got {v}")
        items.append(float(v))
    if not items:
        raise ValueError("--loss-cycle must contain at least one value")
    return items



def main() -> int:
    ap = argparse.ArgumentParser(
        description="LinTS runner for IID loss (fixed net params) with block-topk checkpointing"
    )

    ap.add_argument("--steps", type=int, default=50000, help="number of bandit steps (transfers)")
    ap.add_argument("--episode-steps", type=int, default=10, help="steps per episode (net params fixed)")
    ap.add_argument("--block-steps", type=int, default=1000, help="checkpointing block size in steps")
    ap.add_argument("--save-topk", type=int, default=3, help="save top-k models within each block")
    ap.add_argument("--warmup", type=int, default=20, help="random warmup steps before LinTS")
    ap.add_argument(
        "--checkpoint-every-episodes",
        type=int,
        default=1,
        help="save latest checkpoint every N episodes (0 disables). Recommended >=1 for resume.",
    )

    ap.add_argument("--rtt-ms", type=int, default=50)
    ap.add_argument("--bitrate-mbps", type=int, default=10)
    ap.add_argument("--timeout-sec", type=int, default=5)
    ap.add_argument("--train-file-bytes", type=int, default=128 * 1024)

    ap.add_argument(
        "--loss-pct",
        type=float,
        default=None,
        help="Fixed IID loss rate in percent (e.g. 0.5 means 0.5%%). If omitted, uses --loss-cycle.",
    )
    ap.add_argument(
        "--loss-cycle",
        type=str,
        default=",".join(f"{x:g}" for x in _DEFAULT_IID_LOSS_CYCLE_PCT),
        help=(
            "Comma-separated IID loss rates (percent) to cycle over per episode, in order, repeating. "
            "Default: 0.1,0.2,0.3,0.4,0.5,1,2,3,4,5,6,7,8"
        ),
    )

    ap.add_argument(
        "--reward-w-goodput",
        type=float,
        default=1.0,
        help="goodput reward weight (tp_term uses goodput/capacity)",
    )
    ap.add_argument("--reward-w-arq", type=float, default=0.1)
    ap.add_argument(
        "--reward-w-overhead",
        type=float,
        default=0.3,
        help="overhead reward weight (uses fec_overhead = tx_repair_symbols/tx_source_symbols)",
    )
    ap.add_argument(
        "--reward-w-done",
        type=float,
        default=0.3,
        help="done_flag penalty weight (done_term = -w_done*(1-done_flag))",
    )
    ap.add_argument("--reward-variant", type=str, default="qarc_v1")
    ap.add_argument("--reward-residual-binary", type=int, default=1)

    # Context builder
    ap.add_argument("--ctx-alpha", type=float, default=0.2)
    ap.add_argument("--ctx-window", type=int, default=50)

    # LinTS
    ap.add_argument("--lints-lam", type=float, default=1.0)
    ap.add_argument("--lints-sigma", type=float, default=0.2)
    ap.add_argument("--lints-rho", type=float, default=0.99)
    ap.add_argument("--lints-recompute", type=int, default=20)
    ap.add_argument("--seed", type=int, default=0)

    ap.add_argument("--result-dir", type=str, default=None, help="directory to write bandit_metrics.json")

    ap.add_argument(
        "--checkpoint-prefix",
        type=str,
        default=None,
        help="prefix path for saving/loading model (writes <prefix>.npz and <prefix>.json)",
    )
    ap.add_argument("--resume", action="store_true", help="resume from --checkpoint-prefix if present")

    args = ap.parse_args()

    total_steps = int(args.steps)
    episode_steps = int(args.episode_steps)
    block_steps = int(args.block_steps)
    save_topk = max(0, int(args.save_topk))
    warmup = int(args.warmup)
    ckpt_every_episodes = int(args.checkpoint_every_episodes)

    if episode_steps <= 0:
        raise ValueError("--episode-steps must be > 0")
    if block_steps <= 0:
        raise ValueError("--block-steps must be > 0")
    if total_steps <= 0:
        raise ValueError("--steps must be > 0")
    if total_steps % episode_steps != 0:
        raise ValueError("--steps must be divisible by --episode-steps to align resets")
    if block_steps % episode_steps != 0:
        raise ValueError("--block-steps must be divisible by --episode-steps to align block saving")
    if ckpt_every_episodes < 0:
        raise ValueError("--checkpoint-every-episodes must be >= 0")

    fixed_loss_pct: Optional[float] = None
    if args.loss_pct is not None:
        fixed_loss_pct = float(args.loss_pct)
    loss_cycle_pct = _parse_loss_cycle(str(args.loss_cycle))

    # Logging
    dest_dir = args.result_dir or os.environ.get("QUICFEC_RESULT_DIR")
    if not dest_dir:
        ts = time.strftime("%Y%m%d-%H%M%S")
        dest_dir = os.path.join(_REPO_ROOT, "python/results", f"bandit-iid-run-{ts}")
    dest_dir = os.path.abspath(dest_dir)
    _ensure_dir(dest_dir)

    log_path = os.path.join(dest_dir, "bandit_metrics.json")

    save_ckpt_prefix = args.checkpoint_prefix
    if not save_ckpt_prefix:
        save_ckpt_prefix = os.path.join(dest_dir, "bandit_model")

    # Create env configured to reset (and apply net params) every episode_steps.
    env_cfg: Dict[str, Any] = {
        "result_dir": str(dest_dir),
        "episode_step": int(episode_steps),
        "rtt_ms": int(args.rtt_ms),
        "loss_pct": 0,
        # Will be applied at reset(options).
        "loss_mode": "iid:0",
        "bitrate_mbps": int(args.bitrate_mbps),
        "timeout_sec": int(args.timeout_sec),
        "train_file_bytes": int(args.train_file_bytes),
        "ddl_ms_values": [25, 40, 55, 70],
        "k_values": list(range(20, 61, 2)),
        "r0_values": list(range(0, 21, 2)),
        "rstep_values": list(range(0, 21, 2)),
        "reward_variant": str(args.reward_variant),
        "reward_w_goodput": float(args.reward_w_goodput),
        "reward_w_arq": float(args.reward_w_arq),
        "reward_w_overhead": float(args.reward_w_overhead),
        "reward_w_done": float(getattr(args, "reward_w_done", 0.3)),
        "reward_residual_binary": bool(int(args.reward_residual_binary)),
        "log_obs_vec": False,
        "log_step_metrics": False,
        "log_episode_metrics": False,
        # Avoid curriculum overriding our externally supplied parameters.
        "randomize_net_params": False,
        "randomize_net_params_enabled": False,
        # Failures are part of the learning signal/statistics.
        "ignore_invalid_transfers": False,
        # Bandit should only consume the environment observation (no debug info).
        "normalize_obs": False,
    }

    env = FecEnv(env_cfg)

    # Initialize or resume model.
    start_t = 0
    loaded_from: Optional[str] = None
    if bool(args.resume):
        load_prefix = None
        if args.checkpoint_prefix and os.path.exists(os.path.abspath(args.checkpoint_prefix) + ".json"):
            load_prefix = os.path.abspath(args.checkpoint_prefix)
        else:
            load_prefix = _find_latest_saved_prefix(dest_dir)

        if load_prefix and os.path.exists(os.path.abspath(load_prefix) + ".json"):
            agent, lints_cfg, ctx, ctx_cfg, action_set, start_t = load_checkpoint(path_prefix=load_prefix)
            loaded_from = str(load_prefix)

    if loaded_from is None:
        ddl_ms_values = [25, 40, 55, 70]
        action_set = ActionSet(ddl_ms_values=ddl_ms_values)
        ctx_cfg = ContextConfig(ewma_alpha=float(args.ctx_alpha), window=int(args.ctx_window))
        ctx = ContextBuilder(ctx_cfg)

        x0 = ctx.get_context()
        m = action_set.onehot_dim
        dim = 1 + int(x0.size) + int(m) + int(x0.size) * int(m)

        lints_cfg = LinTSConfig(
            lam=float(args.lints_lam),
            sigma=float(args.lints_sigma),
            rho=float(args.lints_rho),
            recompute_inv_every=int(args.lints_recompute),
            seed=int(args.seed),
        )
        agent = LinTS(dim=dim, cfg=lints_cfg)

    print(f"[bandit] logging to: {log_path}")
    print(f"[bandit] checkpoint prefix: {os.path.abspath(str(save_ckpt_prefix))}")

    # Action set summary
    try:
        n_actions = int(len(action_set))
        k_n = int(len(action_set.k_values))
        r0_n = int(len(getattr(action_set, "r0_values", [])))
        rs_n = int(len(action_set.rstep_values))
        ddl_n = int(len(action_set.ddl_ms_values))
        print(
            f"[bandit] action_set: n={n_actions} = K({k_n})*R0({r0_n})*RSTEP({rs_n})*DDL({ddl_n}); "
            f"ddl_ms_values={list(action_set.ddl_ms_values)}"
        )
    except Exception:
        pass

    print(
        "note: reward overhead term uses fec_overhead = quic_overhead_ratio = max(0,(quic_sent_bytes-file_bytes)/file_bytes)"
    )

    # Breakpoint semantics: --steps is treated as the target total step index.
    start_t = int(start_t)
    if start_t < 0:
        start_t = 0
    if start_t > 0 and start_t >= total_steps:
        print(f"resume step_t={start_t} >= target --steps={total_steps}; nothing to do")
        print(f"wrote {log_path}")
        return 0

    # Resume alignment
    if start_t % episode_steps != 0:
        start_t_aligned = int(((start_t + episode_steps - 1) // episode_steps) * episode_steps)
        if start_t_aligned != start_t:
            print(
                f"warning: resume step_t={start_t} not aligned to episode boundary; "
                f"skipping forward to {start_t_aligned} (episode_steps={episode_steps})"
            )
            start_t = start_t_aligned

    # Block-based top-k
    best_root = os.path.join(dest_dir, "best_models")
    _ensure_dir(best_root)

    current_block = int(start_t // block_steps)
    block_dir0 = os.path.join(best_root, f"block_{int(current_block):04d}")
    best_in_block: List[Tuple[float, int, str]] = _load_block_best(block_dir0)

    def _write_block_summary(block_idx: int) -> None:
        if save_topk <= 0:
            return
        block_dir = os.path.join(best_root, f"block_{int(block_idx):04d}")
        payload = [
            {
                "rank": int(i + 1),
                "reward": float(r),
                "t": int(t_step),
                "prefix": str(pfx),
                "npz": str(pfx + ".npz"),
                "json": str(pfx + ".json"),
            }
            for i, (r, t_step, pfx) in enumerate(best_in_block)
        ]
        with open(os.path.join(block_dir, "best_models.json"), "w", encoding="utf-8") as f:
            json.dump({"block": int(block_idx), "topk": payload}, f, indent=2, sort_keys=True)

    def maybe_save_topk_in_block(*, reward_val: float, step_t: int, block_idx: int) -> None:
        nonlocal best_in_block
        if save_topk <= 0:
            return

        block_dir = os.path.join(best_root, f"block_{int(block_idx):04d}")
        _ensure_dir(block_dir)

        if len(best_in_block) >= save_topk:
            worst = min(best_in_block, key=lambda x: x[0])[0]
            if float(reward_val) <= float(worst):
                return

        cand_prefix = os.path.join(block_dir, f"model_t{int(step_t)}_r{_fmt_score(float(reward_val))}")
        save_checkpoint(
            path_prefix=cand_prefix,
            agent=agent,
            agent_cfg=lints_cfg,
            ctx=ctx,
            ctx_cfg=ctx_cfg,
            action_set=action_set,
            step_t=int(step_t),
            extra_meta={
                "env_cfg": env_cfg,
                "dest_dir": dest_dir,
                "reward": float(reward_val),
                "block": int(block_idx),
                "loss_mode": str(active_loss_mode),
                "loss_pct": float(active_loss_pct),
            },
        )

        best_in_block.append((float(reward_val), int(step_t), cand_prefix))
        best_in_block.sort(key=lambda x: x[0], reverse=True)

        if len(best_in_block) > save_topk:
            dropped = best_in_block[save_topk:]
            best_in_block = best_in_block[:save_topk]
            for _r, _t, pfx in dropped:
                _safe_unlink(pfx)

        _write_block_summary(int(block_idx))

    def _episode_reset(epi_idx: int) -> Tuple[str, float]:
        if fixed_loss_pct is None:
            pct = float(loss_cycle_pct[int(epi_idx) % int(len(loss_cycle_pct))])
        else:
            pct = float(fixed_loss_pct)
        lm = _iid_loss_mode(float(pct))
        env.reset(
            options={
                "rtt_ms": int(args.rtt_ms),
                "bitrate_mbps": int(args.bitrate_mbps),
                "loss_mode": str(lm),
                "loss_pct": 0,
            }
        )
        return str(lm), float(pct)

    episode_idx = int(start_t // episode_steps)
    active_loss_mode, active_loss_pct = _episode_reset(int(episode_idx))

    max_invalid_skips = int(os.environ.get("BANDIT_INVALID_SKIP_CAP", "500"))
    invalid_skips = 0

    last_t = int(start_t)
    try:
        t = int(start_t)
        while int(t) < int(total_steps):
            last_t = int(t)

            # Block book-keeping
            block_idx = int(int(t) // block_steps)
            if int(block_idx) != int(current_block):
                _write_block_summary(int(current_block))
                current_block = int(block_idx)
                block_dir = os.path.join(best_root, f"block_{int(current_block):04d}")
                best_in_block = _load_block_best(block_dir)

            x = ctx.get_context()

            if int(t) < warmup:
                a_idx = int(np.random.RandomState(int(args.seed) + t).randint(0, len(action_set)))
                theta = None
            else:
                # Build Phi for all candidate actions.
                Phi = np.zeros((len(action_set), agent.dim), dtype=np.float32)
                for i, _a in action_set.iter_actions():
                    Phi[i, :] = phi_fn(x=x, a_onehot=action_set.get_onehot(i))
                a_idx, theta = agent.select(Phi)

            a = action_set.get_action(a_idx)
            env_action = a.to_env_action()

            obs, reward, terminated, truncated, info = env.step(env_action)

            step_valid = True
            try:
                step_valid = bool(int((info or {}).get("step_valid", 1)))
            except Exception:
                step_valid = True
            if not step_valid:
                invalid_skips += 1
                if invalid_skips > max_invalid_skips:
                    raise RuntimeError(
                        f"too many invalid transfers skipped (>{max_invalid_skips}); last info={info}"
                    )
                # Do not advance t.
                continue
            invalid_skips = 0

            # Convert ddl_idx back to ddl_ms for context update
            ddl_ms_values = list(action_set.ddl_ms_values)
            ddl_ms = int(ddl_ms_values[int(a.ddl_idx)])
            ctx.update_from_obs(obs=obs, ddl_ms=int(ddl_ms))

            if int(t) >= warmup:
                ph = phi_fn(x=x, a_onehot=action_set.get_onehot(a_idx))
                agent.update(phi=ph, reward=float(reward))

            rec: Dict[str, Any] = {
                "t": int(t),
                "reward": float(reward),
                "a_idx": int(a_idx),
                "action": {
                    "k_idx": int(a.k_idx),
                    "r0_idx": int(a.r0_idx),
                    "rstep_idx": int(a.rstep_idx),
                    "ddl_idx": int(a.ddl_idx),
                },
                "ddl_ms": int(ddl_ms),
                "context": [float(v) for v in x.tolist()],
                "env_info": info,
                "active_loss_mode": str(active_loss_mode),
                "loss_pct": float(active_loss_pct),
                "block_idx": int(block_idx),
                "ctx_cfg": asdict(ctx_cfg) if t == int(start_t) else None,
                "lints_cfg": asdict(lints_cfg) if t == int(start_t) else None,
                "resume_from": str(loaded_from) if (t == int(start_t) and loaded_from is not None) else None,
            }
            if theta is not None:
                rec["theta_norm"] = float(np.linalg.norm(theta))

            with open(log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False, default=_json_default) + "\n")

            maybe_save_topk_in_block(reward_val=float(reward), step_t=int(t), block_idx=int(block_idx))

            if bool(terminated) or bool(truncated):
                if ckpt_every_episodes > 0:
                    epi_done = int((int(t) + 1) // episode_steps)
                    if epi_done % int(ckpt_every_episodes) == 0:
                        try:
                            save_checkpoint(
                                path_prefix=str(save_ckpt_prefix),
                                agent=agent,
                                agent_cfg=lints_cfg,
                                ctx=ctx,
                                ctx_cfg=ctx_cfg,
                                action_set=action_set,
                                step_t=int(t) + 1,
                                extra_meta={
                                    "env_cfg": env_cfg,
                                    "dest_dir": dest_dir,
                                    "note": "latest",
                                    "checkpoint_every_episodes": int(ckpt_every_episodes),
                                    "loss_mode": str(active_loss_mode),
                                    "loss_pct": float(active_loss_pct),
                                },
                            )
                        except Exception:
                            pass
                episode_idx += 1
                active_loss_mode, active_loss_pct = _episode_reset(int(episode_idx))

            # Count only valid transfers.
            t += 1
    except KeyboardInterrupt:
        # Keep whatever has been saved so far.
        pass
    finally:
        try:
            save_checkpoint(
                path_prefix=str(save_ckpt_prefix),
                agent=agent,
                agent_cfg=lints_cfg,
                ctx=ctx,
                ctx_cfg=ctx_cfg,
                action_set=action_set,
                step_t=int(last_t) + 1,
                extra_meta={"env_cfg": env_cfg, "dest_dir": dest_dir, "note": "latest"},
            )
        except Exception:
            pass

        try:
            _write_block_summary(int(current_block))
        except Exception:
            pass

    print(f"wrote {log_path}")
    if save_topk > 0:
        print(f"saved per-block top-{save_topk} models under {best_root}")
    print(f"saved latest model to {os.path.abspath(str(save_ckpt_prefix))}.npz/.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
