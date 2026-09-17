import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path

from ir_model import simulate_session as _simulate_session

# Updated GE parameters
alpha = 0.03
beta = 0.3

# System parameters
K = 100
R0 = 0
RTT = 0.050
tau = 0.04
bw = 10e6
L = 1000

Delta = (L * 8) / bw

# Monte Carlo trials per (T, ΔR) point. Keep this modest since we sweep 5×51 points.
TRIALS = 2000

def simulate_session(B, T_deadline_s, deltaR, mode, trials=TRIALS, seed=9):
    """
    Session: B blocks share a single global deadline T.
    Blocks are independent (independent GE chains), but share bandwidth => total time is sum of per-block times.
    We transmit blocks sequentially (equivalent for shared-bandwidth resource accounting).
    Success if all B blocks finish within global T.
    """
    rng_seed = seed + B * 100 + int(T_deadline_s * 1000) * 3 + deltaR * 7 + (0 if mode == "IR" else 1)
    return _simulate_session(
        B=B,
        T_deadline_s=T_deadline_s,
        deltaR=deltaR,
        mode=mode,
        trials=trials,
        seed=rng_seed,
        K=K,
        R0=R0,
        alpha=alpha,
        beta=beta,
        delta=Delta,
        cooldown=tau + RTT,
    )


deltaR_vals = list(range(0, 51))

# Session has a fixed number of blocks; we vary the global deadline T.
B = 1
T_vals_ms = [200, 300, 400]

curves = {}
rows = []
arq_points = {}
for T_ms in T_vals_ms:
    T_deadline_s = float(T_ms) / 1000.0
    P_arq, E_arq = simulate_session(B, T_deadline_s, 0, "ARQ", trials=TRIALS, seed=11)
    arq_points[int(T_ms)] = float(P_arq)
    rows.append(
        {
            "T_ms": int(T_ms),
            "B": int(B),
            "DeltaR": 0,
            "Mode": "ARQ",
            "P": float(P_arq),
            "overhead": float((E_arq - B * K) / (B * K)),
        }
    )
    pts = []
    for dR in deltaR_vals:
        # ΔR=0 remains incremental redundancy with no extra margin; it is
        # intentionally different from the explicit ARQ baseline above.
        P_i, E_i = simulate_session(B, T_deadline_s, dR, "IR", trials=TRIALS, seed=11)
        overhead = (E_i - B * K) / (B * K)
        pts.append((int(dR), float(P_i), float(overhead)))
        rows.append(
            {
                "T_ms": int(T_ms),
                "B": int(B),
                "DeltaR": int(dR),
                "Mode": "IR",
                "P": float(P_i),
                "overhead": float(overhead),
            }
        )
    curves[int(T_ms)] = pts

# Plot: One figure, curves for different deadlines T.
plt.figure()
for i, T_ms in enumerate(T_vals_ms):
    pts = curves[int(T_ms)]
    xs = [p[0] for p in pts]
    ys = [p[1] for p in pts]
    (ln,) = plt.plot(xs, ys, label=f"T={int(T_ms)}ms")

    if xs and xs[0] == 0:
        plt.scatter([xs[0]], [arq_points[int(T_ms)]], marker="s", s=28,
                    color=ln.get_color(), label="_nolegend_", zorder=3)

plt.scatter([], [], marker="s", s=28, color="k", label="ARQ")
plt.xlabel(r"$\Delta R$")
plt.ylabel("Success probability P")
# plt.title("Corrected: Shared deadline T, shared bw; GE(α=0.03, β=0.3)")
plt.grid(True)
plt.legend(loc="best")
OUTPUT_DIR = Path(__file__).resolve().parent / "results"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
plt.savefig(OUTPUT_DIR / "vary_ddl.png", dpi=200, bbox_inches="tight")
plt.show()

def _head_rows_for(T_ms: int, n: int = 8):
    out = []
    for r in rows:
        if int(r.get("T_ms", -1)) != int(T_ms):
            continue
        out.append(r)
    out.sort(key=lambda r: int(r.get("DeltaR", 0)))
    return out[:n]

_head_rows_for(100, 8), _head_rows_for(200, 8)
