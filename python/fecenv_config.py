from __future__ import annotations

import os
from typing import Dict, Any

from ray.rllib.algorithms.ppo import PPOConfig


def build_ppo_config(env_name: str = "FECEnv-v0", env_config: Dict[str, Any] | None = None) -> tuple[PPOConfig, Dict[str, Any]]:
    # Base results dir
    base_dir = os.path.dirname(__file__)
    default_results_dir = os.path.join(base_dir, "results")
    os.makedirs(default_results_dir, exist_ok=True)

    env_config = dict(env_config or {})
    results_dir = env_config.get("result_dir") or os.environ.get("QUICFEC_RESULT_DIR") or default_results_dir
    os.makedirs(results_dir, exist_ok=True)

    # Read environment parameters (with defaults)
    env_config.setdefault("rtt_ms", int(os.environ.get("RTT_MS", "100")))
    env_config.setdefault("loss_pct", int(os.environ.get("LOSS_PCT", "5")))
    env_config.setdefault("loss_mode", os.environ.get("LOSS_MODE", f"iid:{env_config['loss_pct']}"))
    env_config.setdefault("bitrate_mbps", int(os.environ.get("BITRATE_MBPS", "10")))
    # Not an MDP within an episode (network is constant and each step is an independent transfer).
    # Use episode_step=1 by default and treat each transfer as one episode.
    env_config.setdefault("episode_step", int(os.environ.get("EPISODE_STEP", "1")))
    env_config.setdefault("timeout_sec", int(os.environ.get("TIMEOUT_SEC", "30")))
    env_config.setdefault("train_episodes", int(os.environ.get("TRAIN_EPISODES", "300")))

    # Training speed: per-step payload size (bytes). Default is 1 MiB to reduce wall time
    # while keeping measurements meaningful even at higher RTT.
    env_config.setdefault("train_file_bytes", int(os.environ.get("TRAIN_FILE_BYTES", str(1 * 1024 * 1024))))

    # Curriculum / randomization (helps stabilize PPO on highly non-stationary channels)
    env_config.setdefault("randomize_net_params", os.environ.get("RANDOMIZE_NET_PARAMS", "1") not in ("0", "false", "False"))
    env_config.setdefault("curriculum_warmup_episodes", int(os.environ.get("CURRICULUM_WARMUP_EPISODES", "50")))

    # Reward shaping (defaults closer to docs/main.pdf Eq. (25))
    env_config.setdefault("reward_variant", os.environ.get("REWARD_VARIANT", "qarc_v1"))
    env_config.setdefault("reward_w_goodput", float(os.environ.get("REWARD_W_GOODPUT", "1.0")))
    env_config.setdefault("reward_w_delay", float(os.environ.get("REWARD_W_DELAY", "0.5")))
    env_config.setdefault("reward_w_residual", float(os.environ.get("REWARD_W_RESIDUAL", "1.0")))
    env_config.setdefault("reward_w_overhead", float(os.environ.get("REWARD_W_OVERHEAD", "0.5")))
    env_config.setdefault("reward_w_arq", float(os.environ.get("REWARD_W_ARQ", "0.1")))
    # Continuous reward by default (no hard thresholds).
    env_config.setdefault("reward_delay_binary", os.environ.get("REWARD_DELAY_BINARY", "0") not in ("0", "false", "False"))
    env_config.setdefault("reward_residual_binary", os.environ.get("REWARD_RESIDUAL_BINARY", "0") not in ("0", "false", "False"))

    env_config["result_dir"] = results_dir

    # PPO hyperparameters
    lr = float(os.environ.get("LR", str(env_config.get("lr", 5e-4))))
    train_batch_size = int(
        os.environ.get("TRAIN_BATCH_SIZE", str(env_config.get("train_batch_size", env_config["episode_step"])))
    )
    # RLlib PPO (ray>=2.x) expects sgd_minibatch_size + num_sgd_iter.
    # Keep env var names stable for your scripts, but map them to RLlib's API.
    sgd_minibatch_size = int(
        os.environ.get("MINIBATCH_SIZE", str(env_config.get("sgd_minibatch_size", env_config["episode_step"])))
    )
    num_sgd_iter = int(os.environ.get("NUM_EPOCHS", str(env_config.get("num_sgd_iter", 1))))
    num_env_runners = int(os.environ.get("NUM_ENV_RUNNERS", str(env_config.get("num_env_runners", 1))))
    rollout_fragment_length = int(os.environ.get("ROLLOUT_FRAGMENT_LENGTH", str(env_config.get("rollout_fragment_length", env_config["episode_step"]))))

    # Make Ray/Tune honor our results directory (root)
    os.environ.setdefault("RAY_RESULTS_DIR", results_dir)

    cfg = (
        PPOConfig()
        .environment(env=env_name, env_config=env_config)
        .framework("torch")
        .env_runners(num_env_runners=num_env_runners, rollout_fragment_length=rollout_fragment_length, batch_mode="complete_episodes")
        .training(train_batch_size=train_batch_size, sgd_minibatch_size=sgd_minibatch_size, num_sgd_iter=num_sgd_iter, lr=lr)
        .resources(num_gpus=1)
        .reporting(min_sample_timesteps_per_iteration=0, min_time_s_per_iteration=0)
    )
    return cfg, env_config
