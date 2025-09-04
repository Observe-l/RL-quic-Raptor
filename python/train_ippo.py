import os
import time
import random
from dataclasses import asdict

from quicfec_rl.env import QuicFecEnv, EnvConfig, Action

# Minimal single-episode runner to validate the environment.
# EPyMARL wiring: this env can be wrapped into EPyMARL's interface (not included here).

def main():
    env = QuicFecEnv()
    cfg = EnvConfig(
        datagrams_enabled=True,
        num_connections=1,
        cc_mode="bypass",
        target_bitrate_bps=10_000_000,
        loss_profile="iid:5",
        K=40,
        symbol_bytes=1200,
    )
    env.reset(cfg)

    # Sample an action (these would come from the policy in IPPO)
    act = Action(R0=6, R_step=4, window_W=8, ddl_ms=50, alpha=0.6, epsilon=1, interleaver_span=0, pacing_gain=1.0)
    obs, reward, done, info = env.step(act, rtt_ms=100, loss_pct=5)
    print("obs:", obs)
    print("reward:", reward)

if __name__ == "__main__":
    main()
