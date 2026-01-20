"""Contextual bandit (LinTS) wrapper for the QUIC-FEC environment.

This package intentionally does NOT modify the existing RL (RLlib/PPO) env.
Instead, it imports and uses `FecEnv` as a black-box simulator.
"""

from .action_set import ActionSet, ActionSpec
from .context import ContextBuilder, ContextConfig
from .lints import LinTS, LinTSConfig
