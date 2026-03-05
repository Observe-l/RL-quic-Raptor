import numpy as np
import matplotlib.pyplot as plt

# Fixed system parameters
K = 100
R0 = 0
T = 0.30
RTT = 0.100
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

def simulate_one_block(alpha, beta, deltaR, rng):
    piB = alpha / (alpha + beta)
    state = 1 if rng.random() < piB else 0  # 0=G, 1=B

    def step(s):
        if s == 0:
            return 1 if rng.random() < alpha else 0
        else:
            return 0 if rng.random() < beta else 1

    time = 0.0
    sent = 0

    # Initial transmission
    n0 = K + R0
    losses0 = 0
    for _ in range(n0):
        if state == 1:
            losses0 += 1
        state = step(state)
        time += Delta
        sent += 1

    d = max(0, losses0 - (R0 - 1))
    if d == 0:
        return True, sent, time

    cooldown = tau + RTT

    while d > 0:
        n = d + deltaR
        losses = 0
        for _ in range(n):
            if state == 1:
                losses += 1
            state = step(state)
            time += Delta
            sent += 1

        d = max(0, losses - deltaR)
        if d == 0:
            return True, sent, time

        time += cooldown

    return True, sent, time

def simulate_session(alpha, beta, deltaR, trials=5000, seed=1):
    rng = np.random.default_rng(seed + int(alpha*1000))
    succ = 0
    total_sent = 0

    for _ in range(trials):
        t_used = 0.0
        n_sent = 0
        ok_all = True
        for _b in range(B):
            ok, s, t = simulate_one_block(alpha, beta, deltaR, rng)
            t_used += t
            n_sent += s
            if t_used > T or not ok:
                ok_all = False
                break
        succ += int(ok_all)
        total_sent += n_sent

    P = succ / trials
    E_N = total_sent / trials
    overhead = (E_N - B*K) / (B*K)
    return P, overhead

deltaR_vals = list(range(0, 50))

plt.figure()

for (alpha, beta) in ge_params:
    Ps = []
    for dR in deltaR_vals:
        P, _oh = simulate_session(alpha, beta, dR)
        Ps.append(P)
    (ln,) = plt.plot(deltaR_vals, Ps, label=f"$\\alpha$={alpha:g}, $\\beta$={beta:g}")
    # Mark ΔR=0 (ARQ) as the curve start point.
    if deltaR_vals:
        plt.scatter([deltaR_vals[0]], [Ps[0]], marker="s", s=28, color=ln.get_color(), label="_nolegend_", zorder=3)

# Legend handle for ARQ marker.
plt.scatter([], [], marker="s", s=28, color="k", label=r"ARQ ($\Delta R=0$)")

plt.xlabel(r"$\Delta R$")
plt.ylabel("Success probability P")
# plt.title("Impact of Burst Length under same π≈0.1 (B=4)")
plt.grid(True)
plt.legend(loc="best")
plt.show()
