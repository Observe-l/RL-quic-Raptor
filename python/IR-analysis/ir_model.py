"""Small GE Monte-Carlo model used by the IR-analysis scripts.

The model distinguishes source symbols from repair symbols.  This matters for
the systematic fast path: receiving all K source symbols is sufficient, while
the simplified incremental-redundancy model otherwise uses K+1 innovative
symbols as its conservative decoding target.
"""

import numpy as np


def simulate_one_block(
    *,
    K,
    R0,
    deltaR,
    mode,
    alpha,
    beta,
    delta,
    cooldown,
    rng,
):
    """Return ``(success, sent_packets, elapsed_seconds)`` for one block.

    ``ARQ`` sends K source packets and retransmits only source packets lost in
    the previous round.  It therefore succeeds as soon as all K source
    packets have arrived.

    ``IR`` sends K source plus R0 fresh repair packets initially.  Subsequent
    rounds send fresh repair packets.  It succeeds when either all K source
    packets have arrived or at least K+1 distinct source/repair symbols have
    arrived.  The latter is the conservative target used by the DIR model.
    """
    mode = str(mode).upper()
    if mode == "DIR":
        mode = "IR"
    if mode not in {"ARQ", "IR"}:
        raise ValueError(f"unknown mode: {mode}")
    K = int(K)
    R0 = max(0, int(R0))
    deltaR = max(0, int(deltaR))

    pi_bad = alpha / (alpha + beta)
    state = 1 if rng.random() < pi_bad else 0  # 0=G, 1=B

    def next_state(s):
        if s == 0:
            return 1 if rng.random() < alpha else 0
        return 0 if rng.random() < beta else 1

    received_sources = set()
    received_repairs = set()
    sent = 0
    elapsed = 0.0

    def transmit(kind, symbol_id):
        nonlocal state, sent, elapsed
        lost = state == 1
        state = next_state(state)
        elapsed += delta
        sent += 1
        if not lost:
            if kind == "source":
                received_sources.add(symbol_id)
            else:
                received_repairs.add(symbol_id)
        return not lost

    def recovered():
        # Systematic fast path: K source symbols are enough.
        if len(received_sources) >= K:
            return True
        # Conservative DIR target for a non-systematic source/repair mix.
        return len(received_sources) + len(received_repairs) >= K + 1

    if mode == "ARQ":
        # Pure ARQ has no initial repair symbols. R0 belongs to the IR path.
        pending = list(range(K))
        while pending:
            next_pending = []
            for source_id in pending:
                if not transmit("source", source_id):
                    next_pending.append(source_id)
            if not next_pending:
                return True, sent, elapsed
            pending = next_pending
            elapsed += cooldown
        return True, sent, elapsed

    # Initial systematic source symbols followed by R0 fresh repairs.
    for source_id in range(K):
        transmit("source", source_id)
    for repair_id in range(R0):
        transmit("repair", repair_id)
    if recovered():
        return True, sent, elapsed

    # The first incremental-repair batch is feedback-driven too: the receiver
    # must detect the deficit, wait for its soft deadline, and let the NACK
    # traverse the RTT before the sender can transmit fresh repairs.  Keeping
    # this delay here makes IR comparable with ARQ under a finite deadline.
    elapsed += cooldown
    next_repair_id = R0
    while True:
        deficit = max(0, K + 1 - (len(received_sources) + len(received_repairs)))
        if deficit <= 0 or recovered():
            return True, sent, elapsed

        # deltaR is fresh incremental redundancy, not source retransmission.
        round_count = deficit + deltaR
        for _ in range(round_count):
            transmit("repair", next_repair_id)
            next_repair_id += 1
        if recovered():
            return True, sent, elapsed
        elapsed += cooldown


def simulate_session(
    *,
    B,
    T_deadline_s,
    deltaR,
    mode,
    trials,
    seed,
    K,
    R0,
    alpha,
    beta,
    delta,
    cooldown,
):
    """Simulate B sequential blocks sharing one global deadline."""
    rng = np.random.default_rng(seed)
    successes = 0
    total_sent = 0
    for _ in range(int(trials)):
        elapsed = 0.0
        sent = 0
        ok_all = True
        for _ in range(int(B)):
            ok, block_sent, block_time = simulate_one_block(
                K=K,
                R0=R0,
                deltaR=deltaR,
                mode=mode,
                alpha=alpha,
                beta=beta,
                delta=delta,
                cooldown=cooldown,
                rng=rng,
            )
            elapsed += block_time
            sent += block_sent
            if not ok or elapsed > T_deadline_s:
                ok_all = False
                break
        successes += int(ok_all)
        total_sent += sent
    return successes / float(trials), total_sent / float(trials)
