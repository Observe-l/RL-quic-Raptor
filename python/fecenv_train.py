from __future__ import annotations

import argparse
import os
import json
import time
import shutil
import heapq
import subprocess
import sys
from typing import List, Tuple, Optional
import ray
from ray.tune.registry import register_env
from ray.rllib.algorithms.ppo import PPOConfig
from ray.tune.logger import UnifiedLogger

from fecenv_env import FecEnv
from fecenv_config import build_ppo_config


def _ensure_sudo_privileges() -> None:
    """Preflight the sudo requirement used by the QUIC shaping runner.

    Without this, Ray may start and then fail inside a worker when the env is
    constructed, which is harder to diagnose and can look like the training
    process is hung.
    """

    def _sudo_noninteractive_ok() -> bool:
        try:
            subprocess.run(["sudo", "-n", "true"], check=True, capture_output=True)
            return True
        except Exception:
            return False

    if _sudo_noninteractive_ok():
        return

    askpass = os.environ.get("SUDO_ASKPASS")
    if askpass:
        try:
            subprocess.run(["sudo", "-A", "-v"], check=True)
        except Exception:
            pass
        if _sudo_noninteractive_ok():
            return

    pw = os.environ.get("SUDO_PASSWORD")
    if pw:
        try:
            subprocess.run(["sudo", "-S", "-v"], input=(pw + "\n").encode(), check=True, capture_output=True)
        except Exception:
            pass
        if _sudo_noninteractive_ok():
            return

    raise RuntimeError(
        "sudo privileges are required for the QUIC shaping runner. "
        "Run 'sudo -v' once in a terminal, or set SUDO_ASKPASS or SUDO_PASSWORD."
    )


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Train RLlib PPO on QUIC-FEC shaped transfers")
    p.add_argument("--train-episodes", type=int, default=None, help="Number of episodes to train (default via env/config)")
    p.add_argument("--episode-step", type=int, default=None, help="Steps per episode (default 1)")
    p.add_argument("--rtt-ms", type=int, default=None, help="RTT in ms (tc netem)")
    p.add_argument("--loss-mode", type=str, default=None, help="Loss model: none | iid:x | gemodel:p,r,h,k")
    p.add_argument("--loss-pct", type=int, default=None, help="Loss percentage (used when loss_mode not set)")
    p.add_argument("--bitrate-mbps", type=int, default=None, help="Shaping rate in Mbps")
    p.add_argument("--timeout-sec", type=int, default=None, help="Per-step harness timeout in seconds")
    p.add_argument("--train-file-bytes", type=int, default=None, help="Bytes per transfer (default 1 MiB)")

    p.add_argument(
        "--randomize-net-params",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Whether to randomize network params on reset()",
    )
    p.add_argument("--curriculum-warmup-episodes", type=int, default=None, help="Warmup episodes before randomization")

    p.add_argument(
        "--reward-delay-binary",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="If true, delay penalty is a hard threshold; else smooth ratio",
    )
    p.add_argument(
        "--reward-residual-binary",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="If true, residual penalty is binary; else smooth ratio",
    )
    p.add_argument("--reward-w-arq", type=float, default=None, help="ARQ penalty weight (default 0.1)")
    return p.parse_args()


def main():
    args = _parse_args()
    # Fail fast before Ray starts if we don't have shaping privileges.
    try:
        _ensure_sudo_privileges()
    except Exception as e:
        print(f"[FATAL] {e}", file=sys.stderr)
        raise

    # Register env
    register_env("FECEnv-v0", lambda cfg: FecEnv(cfg))

    # Create a per-run results directory under python/results
    base_dir = os.path.dirname(__file__)
    results_root = os.path.join(base_dir, "results")
    os.makedirs(results_root, exist_ok=True)
    run_dir = os.path.join(results_root, time.strftime("run-%Y%m%d-%H%M%S"))
    os.makedirs(run_dir, exist_ok=True)
    # Make env and any subprocesses write step_metrics into this folder
    os.environ["QUICFEC_RESULT_DIR"] = run_dir
    # Also direct Ray/Tune logs to the same run directory
    os.environ["RAY_RESULTS_DIR"] = run_dir

    # Build config; provide only the result_dir. All parameters are centralized in fecenv_config.
    # Args (if set) override env/defaults.
    env_overrides = {
        "result_dir": run_dir,
    }
    if args.train_episodes is not None:
        env_overrides["train_episodes"] = int(args.train_episodes)
    if args.episode_step is not None:
        env_overrides["episode_step"] = int(args.episode_step)
    if args.rtt_ms is not None:
        env_overrides["rtt_ms"] = int(args.rtt_ms)
    if args.loss_pct is not None:
        env_overrides["loss_pct"] = int(args.loss_pct)
    if args.loss_mode is not None:
        env_overrides["loss_mode"] = str(args.loss_mode)
    if args.bitrate_mbps is not None:
        env_overrides["bitrate_mbps"] = int(args.bitrate_mbps)
    if args.timeout_sec is not None:
        env_overrides["timeout_sec"] = int(args.timeout_sec)
    if args.train_file_bytes is not None:
        env_overrides["train_file_bytes"] = int(args.train_file_bytes)
    if args.randomize_net_params is not None:
        env_overrides["randomize_net_params"] = bool(args.randomize_net_params)
    if args.curriculum_warmup_episodes is not None:
        env_overrides["curriculum_warmup_episodes"] = int(args.curriculum_warmup_episodes)
    if args.reward_delay_binary is not None:
        env_overrides["reward_delay_binary"] = bool(args.reward_delay_binary)
    if args.reward_residual_binary is not None:
        env_overrides["reward_residual_binary"] = bool(args.reward_residual_binary)
    if args.reward_w_arq is not None:
        env_overrides["reward_w_arq"] = float(args.reward_w_arq)

    cfg, resolved_env_cfg = build_ppo_config(
        env_name="FECEnv-v0",
        env_config={
            **env_overrides,
        },
    )

    # Ray init and run a small training cycle that covers exactly 1 episode
    ray.init(ignore_reinit_error=True, include_dashboard=False, local_mode=True)
    # Force RLlib to log under run_dir
    def _logger_creator(config):
        return UnifiedLogger(config, logdir=run_dir, loggers=None)

    algo = cfg.build(logger_creator=_logger_creator)

    def _get_reward_mean(result: dict) -> float:
        # RLlib result schema changed across versions. Prefer the env_runners section
        # (ray>=2.3), then fall back to legacy top-level keys.
        try:
            v = (result.get("env_runners") or {}).get("episode_reward_mean")
            if v is None:
                v = result.get("episode_reward_mean")
            if v is None:
                v = result.get("episode_return_mean")
            return float(v or 0.0)
        except Exception:
            return 0.0

    # Training loop: save a checkpoint every episode (assumes 1 episode per iteration)
    # Total episodes controlled via config (train_episodes)
    total_episodes = int(resolved_env_cfg.get("train_episodes", 1))
    best_k: List[Tuple[float, str]] = []  # min-heap of (score, path)
    last_result: Optional[dict] = None
    for ep in range(1, total_episodes + 1):
        result = algo.train()
        # Optional assert: when multiple env runners exist, ensure at least one ep ended.
        # result["episodes_this_iter"] counts completed episodes in this iteration.
        # if int(result.get("episodes_this_iter", 0)) < 1:
        #     # As a fallback, run another iteration until an episode completes.
        #     # This can occur if external settings override batch sizes.
        #     while int(result.get("episodes_this_iter", 0)) < 1:
        #         result = algo.train()
        last_result = result
        # Write/overwrite the latest training summary
        try:
            with open(os.path.join(run_dir, "ray_result.json"), "w", encoding="utf-8") as f:
                json.dump(result, f)
        except Exception:
            pass

        # Save checkpoint for this episode
        ckpt_dir = os.path.join(run_dir, f"checkpoint-ep{ep:04d}")
        try:
            os.makedirs(ckpt_dir, exist_ok=True)
            ckpt = algo.save(checkpoint_dir=ckpt_dir)
            ckpt_path = getattr(ckpt, "checkpoint_path", ckpt)
        except Exception:
            ckpt_path = None

        # Track top-10 by episode reward mean
        score = _get_reward_mean(result)
        if ckpt_path:
            heapq.heappush(best_k, (score, ckpt_dir))
            if len(best_k) > 10:
                worst_score, worst_path = heapq.heappop(best_k)
                if os.path.isdir(worst_path):
                    try:
                        shutil.rmtree(worst_path)
                    except Exception:
                        pass

        print({
            "episode": ep,
            "episode_reward_mean": score,
            "checkpoint": ckpt_path,
        }, flush=True)

    # Final status
    print({
        "results_dir": run_dir,
        "episodes": total_episodes,
        "best_checkpoints": [p for _, p in sorted(best_k, key=lambda x: -x[0])],
    }, flush=True)
    algo.stop()
    ray.shutdown()


if __name__ == "__main__":
    main()
