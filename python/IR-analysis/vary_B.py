import numpy as np
import matplotlib.pyplot as plt

# Updated GE parameters
alpha = 0.03
beta = 0.3

# System parameters
K = 60
R0 = 2
T = 0.500
RTT = 0.120
tau = 0.055
bw = 10e6
L = 1200

Delta = (L * 8) / bw

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


def simulate_session(B, deltaR, mode, trials=6000, seed=9):
    """
    Session: B blocks share a single global deadline T.
    Blocks are independent (independent GE chains), but share bandwidth => total time is sum of per-block times.
    We transmit blocks sequentially (equivalent for shared-bandwidth resource accounting).
    Success if all B blocks finish within global T.
    """
    rng = np.random.default_rng(seed + B*100 + deltaR*7 + (0 if mode=='IR' else 1))
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
            if t_used > T or (not ok):
                ok_all = False
                break
        succ += int(ok_all)
        total_sent += n_sent
        total_time += min(t_used, T)  # just for reference
    P = succ / trials
    E_N = total_sent / trials
    return P, E_N


deltaR_vals = list(range(0, 21))
Bs = [1, 2, 4, 6]

curves = {}
arq_baseline = {}
rows = []
for B in Bs:
    # ARQ baseline once per B (deltaR irrelevant)
    P_a, E_a = simulate_session(B, 0, "ARQ", trials=6000, seed=11)
    oa = (E_a - B * K) / (B * K)
    arq_baseline[B] = (oa, P_a)

    pts = []
    for dR in deltaR_vals:
        P_i, E_i = simulate_session(B, dR, "IR", trials=6000, seed=11)
        overhead = (E_i - B * K) / (B * K)
        pts.append((float(overhead), float(P_i), int(dR)))
        rows.append({"B": int(B), "DeltaR": int(dR), "overhead": float(overhead), "P_IR": float(P_i), "overhead_ARQ": float(oa), "P_ARQ": float(P_a)})
    pts.sort(key=lambda t: t[0])
    curves[B] = pts

# Plot: One figure, curves for B=1,2,4 (IR sweep), and ARQ baseline points
plt.figure()
for B in Bs:
    pts = curves[int(B)]
    xs = [p[0] for p in pts]
    ys = [p[1] for p in pts]
    plt.plot(xs, ys, label=f"B={B}")
    # ARQ baseline point
    oa, pa = arq_baseline[int(B)]
    plt.scatter([oa], [pa], label="_nolegend_")

plt.xlabel("Overhead")
plt.ylabel("Success probability P")
# plt.title("Corrected: Shared deadline T, shared bw; GE(α=0.03, β=0.3)")
plt.grid(True)
plt.legend(title="B", loc="best")
plt.show()

def _head_rows_for(B: int, n: int = 8):
    out = []
    for r in rows:
        if int(r.get("B", -1)) != int(B):
            continue
        out.append(r)
    out.sort(key=lambda r: float(r.get("overhead", 0.0)))
    return out[:n]

_head_rows_for(1, 8), _head_rows_for(2, 8)

