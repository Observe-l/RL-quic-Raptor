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
    env_config.setdefault("episode_step", int(os.environ.get("EPISODE_STEP", "100")))
    env_config.setdefault("timeout_sec", int(os.environ.get("TIMEOUT_SEC", "15")))
    env_config.setdefault("train_episodes", int(os.environ.get("TRAIN_EPISODES", "300")))
    env_config["result_dir"] = results_dir

    # PPO hyperparameters
    lr = float(os.environ.get("LR", str(env_config.get("lr", 5e-4))))
    train_batch_size = int(os.environ.get("TRAIN_BATCH_SIZE", str(env_config.get("train_batch_size", env_config["episode_step"]))))
    minibatch_size = int(os.environ.get("MINIBATCH_SIZE", str(env_config.get("minibatch_size", env_config["episode_step"]))))
    num_epochs = int(os.environ.get("NUM_EPOCHS", str(env_config.get("num_epochs", 1))))
    num_env_runners = int(os.environ.get("NUM_ENV_RUNNERS", str(env_config.get("num_env_runners", 0))))
    rollout_fragment_length = int(os.environ.get("ROLLOUT_FRAGMENT_LENGTH", str(env_config.get("rollout_fragment_length", 1))))

    # Make Ray/Tune honor our results directory (root)
    os.environ.setdefault("RAY_RESULTS_DIR", results_dir)

    cfg = (
        PPOConfig()
        .environment(env=env_name, env_config=env_config)
        .framework("torch")
        .env_runners(num_env_runners=num_env_runners, rollout_fragment_length=rollout_fragment_length, batch_mode="truncate_episodes")
        .training(train_batch_size=train_batch_size, minibatch_size=minibatch_size, num_epochs=num_epochs, lr=lr)
        .resources(num_gpus=0)
        .evaluation(evaluation_interval=1, evaluation_duration=10, evaluation_duration_unit="episodes")
    )
    return cfg, env_config
