import os
import sys

# Ensure the package root is importable
PY_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PY_ROOT not in sys.path:
    sys.path.insert(0, PY_ROOT)

from quicfec_rl.env import EnvConfig, Action, QuicFecEnv
from quicfec_wrapper import QuicFecWrapper


def main():
    # Direct QuicFecEnv test (local, sudo-free)
    e = QuicFecEnv(prefer_local=True)
    e.reset(EnvConfig())
    obs, rew, done, info = e.step(Action(), rtt_ms=100, loss_pct=5)
    print("[QuicFecEnv] obs:", obs)
    print("[QuicFecEnv] reward:", rew)

    # EPyMARL wrapper test
    w = QuicFecWrapper(prefer_local=True)
    w.reset()
    obss, rew2, done2, trunc2, info2 = w.step([0])
    print("[QuicFecWrapper] obs vec:", obss[0])
    print("[QuicFecWrapper] reward:", rew2)
    print("done:", done2, "truncated:", trunc2)


if __name__ == "__main__":
    main()
