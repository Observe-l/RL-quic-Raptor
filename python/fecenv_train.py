from __future__ import annotations

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


def main():
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
    cfg, resolved_env_cfg = build_ppo_config(
        env_name="FECEnv-v0",
        env_config={
            "result_dir": run_dir,
        },
    )

    # Ray init and run a small training cycle that covers exactly 1 episode
    ray.init(ignore_reinit_error=True, include_dashboard=False, local_mode=True)
    # Force RLlib to log under run_dir
    def _logger_creator(config):
        return UnifiedLogger(config, logdir=run_dir, loggers=None)

    algo = cfg.build(logger_creator=_logger_creator)

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

        # Track top-10 by episode_reward_mean
        score = float(result.get("episode_reward_mean") or 0.0)
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
