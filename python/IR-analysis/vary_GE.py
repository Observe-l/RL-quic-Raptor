import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path

from ir_model import simulate_one_block as _simulate_one_block
from ir_model import simulate_session as _simulate_session

# Fixed system parameters
K = 100
R0 = 0
T = 0.30
RTT = 0.050
tau = 0.04
bw = 10e6
L = 1000
Delta = (L * 8) / bw

B = 1  # number of blocks

# Define GE parameter sets with same pi ≈ 0.1 but different burst lengths
# pi = alpha / (alpha + beta) ≈ 0.1
ge_params = [
    (0.01, 0.09),   # longer burst (small beta)
    (0.02, 0.18),   # medium
    (0.05, 0.45)    # short burst (large beta)
]

def simulate_one_block(alpha, beta, deltaR, rng, mode="IR"):
    return _simulate_one_block(
        K=K,
        R0=R0,
        deltaR=deltaR,
        mode=mode,
        alpha=alpha,
        beta=beta,
        delta=Delta,
        cooldown=tau + RTT,
        rng=rng,
    )

def simulate_session(alpha, beta, deltaR, mode="IR", trials=5000, seed=1):
    rng_seed = seed + int(alpha * 1000) + (0 if mode == "IR" else 1)
    P, E_N = _simulate_session(
        B=B,
        T_deadline_s=T,
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
    overhead = (E_N - B * K) / (B * K)
    return P, overhead

deltaR_vals = list(range(0, 50))

plt.figure()

for (alpha, beta) in ge_params:
    Ps = []
    P_arq, _arq_overhead = simulate_session(alpha, beta, 0, mode="ARQ")
    for dR in deltaR_vals:
        # ΔR=0 remains incremental redundancy with no extra margin; it is
        # intentionally different from the explicit ARQ baseline.
        P, _oh = simulate_session(alpha, beta, dR, mode="IR")
        Ps.append(P)
    (ln,) = plt.plot(deltaR_vals, Ps, label=f"$\\alpha$={alpha:g}, $\\beta$={beta:g}")
    if deltaR_vals:
        plt.scatter([deltaR_vals[0]], [P_arq], marker="s", s=28, color=ln.get_color(),
                    label="_nolegend_", zorder=3)

plt.scatter([], [], marker="s", s=28, color="k", label="ARQ")
plt.xlabel(r"$\Delta R$")
plt.ylabel("Success probability P")
# plt.title("Impact of Burst Length under same π≈0.1 (B=4)")
plt.grid(True)
plt.legend(loc="best")
OUTPUT_DIR = Path(__file__).resolve().parent / "results"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
plt.savefig(OUTPUT_DIR / "vary_GE.png", dpi=200, bbox_inches="tight")
plt.show()
