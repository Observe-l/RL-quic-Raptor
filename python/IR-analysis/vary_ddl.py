import numpy as np
import matplotlib.pyplot as plt

# Updated GE parameters
alpha = 0.03
beta = 0.3

# System parameters
K = 100
R0 = 0
RTT = 0.100
tau = 0.04
bw = 10e6
L = 1000

Delta = (L * 8) / bw

# Monte Carlo trials per (T, ΔR) point. Keep this modest since we sweep 5×51 points.
TRIALS = 2000

def simulate_one_block_with_chain(deltaR, mode, rng):
    """Return (success, sent_packets, time_spent)."""
    piB = alpha / (alpha + beta)
    state = 1 if rng.random() < piB else 0  # 0=G, 1=B

    def step(s):
        if s == 0:
            return 1 if rng.random() < alpha else 0
        else:
            return 0 if rng.random() < beta else 1

    time = 0.0
    sent = 0

    # Initial send
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
        n = (d + deltaR) if mode == 'IR' else d

        losses = 0
        for _ in range(n):
            if state == 1:
                losses += 1
            state = step(state)
            time += Delta
            sent += 1

        if mode == 'IR':
            d = max(0, losses - deltaR)
        else:
            d = losses

        if d == 0:
            return True, sent, time

        time += cooldown

    return True, sent, time


def simulate_session(B, T_deadline_s, deltaR, mode, trials=TRIALS, seed=9):
    """
    Session: B blocks share a single global deadline T.
    Blocks are independent (independent GE chains), but share bandwidth => total time is sum of per-block times.
    We transmit blocks sequentially (equivalent for shared-bandwidth resource accounting).
    Success if all B blocks finish within global T.
    """
    rng = np.random.default_rng(seed + B * 100 + int(T_deadline_s * 1000) * 3 + deltaR * 7 + (0 if mode == "IR" else 1))
    succ = 0
    total_sent = 0
    total_time = 0.0  # only for mean; per trial we enforce deadline
    for _ in range(trials):
        t_used = 0.0
        n_sent = 0
        ok_all = True
        for _b in range(B):
            ok, s, t = simulate_one_block_with_chain(deltaR, mode, rng)
            t_used += t
            n_sent += s
            if t_used > T_deadline_s or (not ok):
                ok_all = False
                break
        succ += int(ok_all)
        total_sent += n_sent
        total_time += min(t_used, T_deadline_s)  # just for reference
    P = succ / trials
    E_N = total_sent / trials
    return P, E_N


deltaR_vals = list(range(0, 51))

# Session has a fixed number of blocks; we vary the global deadline T.
B = 1
T_vals_ms = [100, 125, 150]

curves = {}
rows = []
for T_ms in T_vals_ms:
    T_deadline_s = float(T_ms) / 1000.0
    pts = []
    for dR in deltaR_vals:
        # Note: ARQ is equivalent to IR with ΔR=0 under this model.
        P_i, E_i = simulate_session(B, T_deadline_s, dR, "IR", trials=TRIALS, seed=11)
        overhead = (E_i - B * K) / (B * K)
        pts.append((int(dR), float(P_i), float(overhead)))
        rows.append(
            {
                "T_ms": int(T_ms),
                "B": int(B),
                "DeltaR": int(dR),
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

    # Mark the curve start (ΔR=0), which corresponds to ARQ under this model.
    if xs and xs[0] == 0:
        plt.scatter([xs[0]], [ys[0]], marker="s", s=28, color=ln.get_color(), label="_nolegend_", zorder=3)


plt.scatter([], [], marker="s", s=28, color="k", label=r"ARQ ($\Delta R=0$)")
plt.xlabel(r"$\Delta R$")
plt.ylabel("Success probability P")
# plt.title("Corrected: Shared deadline T, shared bw; GE(α=0.03, β=0.3)")
plt.grid(True)
plt.legend(loc="best")
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

