from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import asdict
from typing import Any, Dict, List, Tuple

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
        except Exception:
            pass


def main() -> int:
    ap = argparse.ArgumentParser(description="Contextual bandit (LinTS) runner for QUIC-FEC env")
    ap.add_argument("--steps", "-steps", type=int, default=200, help="number of bandit steps (transfers)")
    ap.add_argument("--warmup", type=int, default=20, help="random warmup steps before LinTS")

    # Env config passthrough (keep aligned with existing env)
    ap.add_argument("--rtt-ms", type=int, default=100)
    ap.add_argument("--loss-pct", type=int, default=5)
    ap.add_argument("--loss-mode", type=str, default=None)
    ap.add_argument("--bitrate-mbps", type=int, default=50)
    ap.add_argument("--timeout-sec", type=int, default=30)
    ap.add_argument("--train-file-bytes", type=int, default=1 * 1024 * 1024)

    ap.add_argument("--reward-w-arq", type=float, default=0.1)
    ap.add_argument("--reward-variant", type=str, default="qarc_v1")
    # Delay shaping: use continuous penalty by default to avoid a hard threshold
    # that can dominate the reward when d95 hovers around ddl.
    ap.add_argument("--reward-delay-binary", type=int, default=0)
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
    # Checkpointing policy: keep only top-k models by observed reward.
    ap.add_argument("--save-topk", type=int, default=3, help="save the top-k models by reward")
    ap.add_argument("--resume", action="store_true", help="resume from --checkpoint-prefix if present")

    args = ap.parse_args()

    loss_mode = args.loss_mode
    if loss_mode is None:
        loss_mode = f"iid:{int(args.loss_pct)}"

    # Create env with episode_step=1 (each step is a transfer)
    env_cfg: Dict[str, Any] = {
        "episode_step": 1,
        "rtt_ms": int(args.rtt_ms),
        "loss_pct": int(args.loss_pct),
        "loss_mode": str(loss_mode),
        "bitrate_mbps": int(args.bitrate_mbps),
        "timeout_sec": int(args.timeout_sec),
        "train_file_bytes": int(args.train_file_bytes),
        "reward_variant": str(args.reward_variant),
        "reward_w_arq": float(args.reward_w_arq),
        "reward_delay_binary": bool(int(args.reward_delay_binary)),
        "reward_residual_binary": bool(int(args.reward_residual_binary)),
        "log_obs_vec": False,
        # Bandit should only consume the environment observation (no debug info).
        "normalize_obs": False,
    }

    env = FecEnv(env_cfg)

    ckpt_prefix = args.checkpoint_prefix

    # Logging
    dest_dir = args.result_dir or os.environ.get("QUICFEC_RESULT_DIR")
    if not dest_dir:
        ts = time.strftime("%Y%m%d-%H%M%S")
        dest_dir = os.path.join(_REPO_ROOT, "python/results", f"bandit-run-{ts}")
    dest_dir = os.path.abspath(dest_dir)
    _ensure_dir(dest_dir)
    # Keep JSON-lines format (one JSON object per line) but use .json suffix.
    log_path = os.path.join(dest_dir, "bandit_metrics.json")
    best_summary_path = os.path.join(dest_dir, "best_models.json")

    if not ckpt_prefix:
        ckpt_prefix = os.path.join(dest_dir, "bandit_model")

    # Initialize or resume model.
    start_t = 0
    if bool(args.resume) and os.path.exists(os.path.abspath(ckpt_prefix) + ".json"):
        agent, lints_cfg, ctx, ctx_cfg, action_set, start_t = load_checkpoint(path_prefix=ckpt_prefix)
    else:
        action_set = ActionSet()
        ctx_cfg = ContextConfig(ewma_alpha=float(args.ctx_alpha), window=int(args.ctx_window))
        ctx = ContextBuilder(ctx_cfg)

        # Feature dim: 1 + d + m + d*m
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

    obs, _ = env.reset()
    # First context is cold-start; keep as zeros.

    total_steps = int(args.steps)
    warmup = int(args.warmup)

    save_topk = max(0, int(args.save_topk))
    best: List[Tuple[float, int, str]] = []
    # Stored under dest_dir to avoid scattering files.
    best_dir = os.path.join(dest_dir, "best_models")
    _ensure_dir(best_dir)

    def maybe_save_topk(*, reward_val: float, step_t: int) -> None:
        nonlocal best
        if save_topk <= 0:
            return
        if len(best) >= save_topk:
            worst = min(best, key=lambda x: x[0])[0]
            if float(reward_val) <= float(worst):
                return

        cand_prefix = os.path.join(best_dir, f"model_t{int(step_t)}_r{_fmt_score(float(reward_val))}")
        save_checkpoint(
            path_prefix=cand_prefix,
            agent=agent,
            agent_cfg=lints_cfg,
            ctx=ctx,
            ctx_cfg=ctx_cfg,
            action_set=action_set,
            step_t=int(step_t),
            extra_meta={"env_cfg": env_cfg, "dest_dir": dest_dir, "reward": float(reward_val)},
        )

        best.append((float(reward_val), int(step_t), cand_prefix))
        best.sort(key=lambda x: x[0], reverse=True)
        # Deduplicate by prefix (paranoia)
        seen = set()
        dedup: List[Tuple[float, int, str]] = []
        for r, t_step, pfx in best:
            if pfx in seen:
                continue
            seen.add(pfx)
            dedup.append((r, t_step, pfx))
        best = dedup

        # Trim and delete dropped checkpoints.
        if len(best) > save_topk:
            dropped = best[save_topk:]
            best = best[:save_topk]
            for _r, _t, pfx in dropped:
                _safe_unlink(pfx)

        # Write summary
        try:
            payload = [
                {
                    "rank": int(i + 1),
                    "reward": float(r),
                    "t": int(t_step),
                    "prefix": str(pfx),
                    "npz": str(pfx + ".npz"),
                    "json": str(pfx + ".json"),
                }
                for i, (r, t_step, pfx) in enumerate(best)
            ]
            with open(best_summary_path, "w", encoding="utf-8") as f:
                json.dump({"topk": payload}, f, indent=2, sort_keys=True)
        except Exception:
            pass

    last_t = int(start_t)
    try:
        for t in range(int(start_t), int(start_t) + total_steps):
            last_t = int(t)
            x = ctx.get_context()

            # Warmup: random action to bootstrap context statistics.
            if (t - int(start_t)) < warmup:
                a_idx = int(np.random.RandomState(int(args.seed) + t).randint(0, len(action_set)))
                theta = None
            else:
                # Build Phi for all candidate actions.
                Phi = np.zeros((len(action_set), dim), dtype=np.float32)
                for i, _a in action_set.iter_actions():
                    Phi[i, :] = phi_fn(x=x, a_onehot=action_set.get_onehot(i))
                a_idx, theta = agent.select(Phi)

            a = action_set.get_action(a_idx)
            env_action = a.to_env_action()

            obs, reward, terminated, truncated, info = env.step(env_action)
            assert terminated or truncated  # env is configured with episode_step=1

            # Convert ddl_idx back to ddl_ms for context update
            ddl_ms_values = [100, 150, 200, 250, 300, 350]
            ddl_ms = int(ddl_ms_values[int(a.ddl_idx)])
            ctx.update_from_obs(obs=obs, ddl_ms=int(ddl_ms))

            # Update LinTS
            if (t - int(start_t)) >= warmup:
                ph = phi_fn(x=x, a_onehot=action_set.get_onehot(a_idx))
                agent.update(phi=ph, reward=float(reward))

            # Episode boundary (one step): reset env to start next transfer.
            env.reset()

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
                "ctx_cfg": asdict(ctx_cfg) if t == 0 else None,
                "lints_cfg": asdict(lints_cfg) if t == 0 else None,
            }
            if theta is not None:
                rec["theta_norm"] = float(np.linalg.norm(theta))

            with open(log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False, default=_json_default) + "\n")

            # Save top-k models by reward.
            maybe_save_topk(reward_val=float(reward), step_t=int(t))
    except KeyboardInterrupt:
        # Keep whatever has been saved so far.
        pass
    finally:
        # Save a "latest" checkpoint for resume.
        try:
            save_checkpoint(
                path_prefix=ckpt_prefix,
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

    print(f"wrote {log_path}")
    if save_topk > 0:
        print(f"saved top-{save_topk} models under {best_dir}")
        print(f"summary: {best_summary_path}")
    print(f"saved latest model to {os.path.abspath(ckpt_prefix)}.npz/.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
