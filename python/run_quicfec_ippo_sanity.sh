#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")" && pwd)

# Use CUDA if available; otherwise CPU
export CUDA_VISIBLE_DEVICES=${CUDA_VISIBLE_DEVICES:-}

# Run EPyMARL main with IPPO and our quicfec env
python -u "$ROOT/src/main.py" \
  --env-config=quicfec \
  --config=ippo \
  seed=42 \
  use_cuda=False \
  use_tensorboard=False \
  use_wandb=False \
  t_max=50 \
  test_interval=25 \
  runner_log_interval=10 \
  learner_log_interval=10
