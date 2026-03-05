#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Convert Veins RSU rx trace (time,sender,seq,rxOk) into QUIC-FEC offline traces & params.

Input CSV expected columns:
  - time: float seconds (OMNeT++ simTime)
  - sender: sender id (int or string)
  - seq: int sequence number
  - rxOk: 1 if received, 0 if lost

Outputs (in outdir):
  - packet_trace.csv
  - summary_by_sender.csv
  - ge_params_by_sender.csv
  - window_stats.csv
  - quic_fec_params.json
"""

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
import zlib

import numpy as np
import pandas as pd


# --------------------------
# Data structures
# --------------------------
@dataclass
class GEParams:
    # Markov transitions
    p_g2b: float      # P(B|G)
    r_b2g: float      # P(G|B)
    pi_bad: float     # stationary P(B)
    mean_bad_run: float
    mean_good_run: float

    # Emissions
    eps_good: float   # P(loss|G)
    eps_bad: float    # P(loss|B)


# --------------------------
# Utilities
# --------------------------
def safe_float(x, default=np.nan):
    try:
        return float(x)
    except Exception:
        return default


def burst_lengths(loss_seq: np.ndarray) -> np.ndarray:
    """Lengths of consecutive losses (loss_seq==1)."""
    if loss_seq.size == 0:
        return np.array([], dtype=int)
    is_loss = loss_seq.astype(bool)
    out = []
    cur = 0
    for v in is_loss:
        if v:
            cur += 1
        else:
            if cur > 0:
                out.append(cur)
                cur = 0
    if cur > 0:
        out.append(cur)
    return np.array(out, dtype=int)


def estimate_nominal_interval(g: pd.DataFrame) -> float:
    """
    Estimate nominal send interval using received packets where seq increments by 1.
    Falls back to median dt of received packets.
    """
    gg = g.sort_values(["seq", "time"])
    recv = gg[gg["rxOk"] == 1].copy()
    if len(recv) < 2:
        return np.nan

    recv["dseq"] = recv["seq"].diff()
    recv["dt"] = recv["time"].diff()

    dt1 = recv.loc[(recv["dseq"] == 1) & (recv["dt"] > 0), "dt"].to_numpy()
    if dt1.size >= 5:
        return float(np.median(dt1))

    dt_any = recv.loc[(recv["dt"] > 0), "dt"].to_numpy()
    if dt_any.size >= 5:
        return float(np.median(dt_any))

    return np.nan


def steady_state_firstlast_success(gg: pd.DataFrame) -> pd.DataFrame:
    """Steady interval = [first success seq, last success seq]."""
    ok_seqs = gg.loc[gg["rxOk"] == 1, "seq"].to_numpy()
    if ok_seqs.size >= 2:
        s0, s1 = int(ok_seqs[0]), int(ok_seqs[-1])
        return gg[(gg["seq"] >= s0) & (gg["seq"] <= s1)].copy()
    return gg.copy()


def steady_state_by_recvpps(
    gg: pd.DataFrame,
    window_s: float,
    min_recv_pps: float,
    min_good_windows: int = 1,
    fallback: str = "first_last_success",
) -> pd.DataFrame:
    """
    Recommended steady: keep only windows where recv_pps >= min_recv_pps.
    """
    g = gg.sort_values("time").copy()
    g = g[g["time"].notna()].copy()
    if g.empty or window_s <= 0:
        return gg.iloc[0:0].copy()

    t0 = float(g["time"].min())
    g["tbin"] = np.floor((g["time"] - t0) / window_s).astype(int)

    win = g.groupby("tbin")["rxOk"].sum().reset_index(name="rx_cnt")
    win["recv_pps"] = win["rx_cnt"] / window_s

    good_bins = win.loc[win["recv_pps"] >= min_recv_pps, "tbin"].to_numpy()
    if good_bins.size >= min_good_windows:
        steady = g[g["tbin"].isin(set(good_bins))].copy()
        return steady.sort_values(["seq", "time"]).copy()

    if fallback == "first_last_success":
        return steady_state_firstlast_success(gg)
    if fallback == "full":
        return gg.copy()
    return gg.iloc[0:0].copy()


# --------------------------
# HMM-GE fitting (Baum–Welch)
# --------------------------
def _fb_scaled(y, p, r, eps_g, eps_b, pi):
    """
    Forward-backward with scaling for 2-state Bernoulli HMM.
    y: 0=success, 1=loss
    """
    y = np.asarray(y, dtype=int)
    T = len(y)
    A = np.array([[1 - p, p],
                  [r, 1 - r]], dtype=float)
    eps = np.array([eps_g, eps_b], dtype=float)

    # emission likelihood P(y_t | state)
    emit = np.where(y[:, None] == 1, eps[None, :], (1 - eps)[None, :])  # (T,2)

    alpha = np.zeros((T, 2), dtype=float)
    c = np.zeros(T, dtype=float)

    alpha[0] = pi * emit[0]
    c[0] = alpha[0].sum()
    if c[0] <= 0:
        c[0] = 1e-300
    alpha[0] /= c[0]

    for t in range(1, T):
        alpha[t] = (alpha[t - 1] @ A) * emit[t]
        c[t] = alpha[t].sum()
        if c[t] <= 0:
            c[t] = 1e-300
        alpha[t] /= c[t]

    beta = np.zeros((T, 2), dtype=float)
    beta[-1] = 1.0
    for t in range(T - 2, -1, -1):
        beta[t] = A @ (emit[t + 1] * beta[t + 1])
        beta[t] /= c[t + 1]

    gamma = alpha * beta
    gamma /= gamma.sum(axis=1, keepdims=True)

    xi = np.zeros((T - 1, 2, 2), dtype=float)
    for t in range(T - 1):
        numer = alpha[t][:, None] * A * (emit[t + 1][None, :] * beta[t + 1][None, :])
        denom = numer.sum()
        if denom <= 0:
            denom = 1e-300
        xi[t] = numer / denom

    ll = float(np.sum(np.log(c)))
    return ll, gamma, xi


def fit_gilbert_elliott_hmm(loss_seq: np.ndarray,
                            max_iter: int = 200,
                            tol: float = 1e-6) -> GEParams:
    """
    Realistic GE as a 2-state HMM:
      states: Good/Bad
      transitions: p=P(B|G), r=P(G|B)
      emissions: eps_good=P(loss|G), eps_bad=P(loss|B)

    EM (Baum–Welch) with light Beta priors (MAP) to keep eps_good small and eps_bad large.
    """
    if loss_seq.size < 2:
        return GEParams(np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan)

    y = loss_seq.astype(int)  # 1=loss, 0=success
    overall = float(np.mean(y))

    # Init (robust)
    eps_g = float(np.clip(overall * 0.2, 1e-5, 0.2))
    eps_b = float(np.clip(overall * 2.0 + 0.05, 0.05, 0.99999))
    p = float(np.clip(0.01 + overall * 0.1, 1e-6, 0.5))
    r = float(np.clip(0.10, 1e-6, 0.9))

    # stationary init pi
    pi_b = p / (p + r) if (p + r) > 0 else 0.1
    pi = np.array([1 - pi_b, pi_b], dtype=float)

    # Beta priors (MAP)
    # eps_good prior ~ small
    a_g, b_g = 1.2, 80.0
    # eps_bad prior ~ large
    a_b, b_b = 80.0, 1.2

    prev_ll = -1e18
    for _ in range(max_iter):
        ll, gamma, xi = _fb_scaled(y, p, r, eps_g, eps_b, pi)

        # M-step transitions
        sum_xi = xi.sum(axis=0)
        from_g = gamma[:-1, 0].sum()
        from_b = gamma[:-1, 1].sum()

        p_new = float(sum_xi[0, 1] / from_g) if from_g > 0 else p
        r_new = float(sum_xi[1, 0] / from_b) if from_b > 0 else r
        p_new = float(np.clip(p_new, 1e-7, 1 - 1e-7))
        r_new = float(np.clip(r_new, 1e-7, 1 - 1e-7))

        # M-step emissions (MAP)
        w_g = gamma[:, 0].sum()
        w_b = gamma[:, 1].sum()
        loss_g = (gamma[:, 0] * y).sum()
        loss_b = (gamma[:, 1] * y).sum()

        eps_g_new = float((loss_g + a_g - 1) / (w_g + a_g + b_g - 2)) if w_g > 0 else eps_g
        eps_b_new = float((loss_b + a_b - 1) / (w_b + a_b + b_b - 2)) if w_b > 0 else eps_b
        eps_g_new = float(np.clip(eps_g_new, 1e-7, 1 - 1e-7))
        eps_b_new = float(np.clip(eps_b_new, 1e-7, 1 - 1e-7))

        # enforce eps_good < eps_bad (swap labels if needed)
        if eps_g_new > eps_b_new:
            eps_g_new, eps_b_new = eps_b_new, eps_g_new
            p_new, r_new = r_new, p_new

        # update pi to stationary of new transitions
        pi_b = p_new / (p_new + r_new)
        pi = np.array([1 - pi_b, pi_b], dtype=float)

        p, r, eps_g, eps_b = p_new, r_new, eps_g_new, eps_b_new

        if abs(ll - prev_ll) < tol:
            break
        prev_ll = ll

    pi_bad = p / (p + r) if (p + r) > 0 else np.nan
    mean_bad = 1.0 / r if r > 0 else np.inf
    mean_good = 1.0 / p if p > 0 else np.inf

    return GEParams(
        p_g2b=p,
        r_b2g=r,
        pi_bad=pi_bad,
        mean_bad_run=mean_bad,
        mean_good_run=mean_good,
        eps_good=eps_g,
        eps_bad=eps_b,
    )


# --------------------------
# Stats per block
# --------------------------
def compute_block_stats(block: pd.DataFrame, nominal_interval: float) -> dict:
    delivered = block["rxOk"].to_numpy().astype(int)
    loss_seq = 1 - delivered  # 1=loss, 0=success

    loss_rate = float(np.mean(loss_seq)) if loss_seq.size else np.nan

    bl = burst_lengths(loss_seq)
    mean_burst = float(np.mean(bl)) if bl.size else 0.0
    max_burst = int(np.max(bl)) if bl.size else 0
    p95_burst = float(np.percentile(bl, 95)) if bl.size else 0.0

    mean_burst_s = float(mean_burst * nominal_interval) if np.isfinite(nominal_interval) else np.nan
    max_burst_s = float(max_burst * nominal_interval) if np.isfinite(nominal_interval) else np.nan

    tmin, tmax = float(np.nanmin(block["time"])), float(np.nanmax(block["time"]))
    dur = max(1e-9, tmax - tmin)
    recv_pps = float(np.sum(delivered) / dur)
    send_pps = float(len(block) / dur)

    ge = fit_gilbert_elliott_hmm(loss_seq)

    # Optional sanity check: reconstructed overall loss from GE params
    if np.isfinite(ge.pi_bad) and np.isfinite(ge.eps_good) and np.isfinite(ge.eps_bad):
        loss_recon = ge.pi_bad * ge.eps_bad + (1 - ge.pi_bad) * ge.eps_good
    else:
        loss_recon = np.nan

    return {
        "n_packets": int(len(block)),
        "loss_rate": loss_rate,
        "success_rate": 1.0 - loss_rate if np.isfinite(loss_rate) else np.nan,

        "mean_burst_len_pkts": mean_burst,
        "p95_burst_len_pkts": p95_burst,
        "max_burst_len_pkts": max_burst,
        "mean_burst_len_s": mean_burst_s,
        "max_burst_len_s": max_burst_s,

        "recv_rate_pps": recv_pps,
        "send_rate_pps_est": send_pps,
        "t_start": tmin,
        "t_end": tmax,

        # GE(HMM)
        "ge_p_g2b": ge.p_g2b,
        "ge_r_b2g": ge.r_b2g,
        "ge_pi_bad": ge.pi_bad,
        "ge_mean_bad_run_pkts": ge.mean_bad_run,
        "ge_mean_good_run_pkts": ge.mean_good_run,
        "ge_eps_good": ge.eps_good,
        "ge_eps_bad": ge.eps_bad,
        "ge_loss_recon": loss_recon,
    }


# --------------------------
# Main
# --------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="rsu_rx_trace.csv", help="Input RSU trace CSV")
    ap.add_argument("--outdir", default="out_quic_fec", help="Output directory")

    # window stats output
    ap.add_argument("--window", type=float, default=0.1, help="Window size (s) for window_stats.csv")

    # steady-by-recvpps parameters (recommended)
    ap.add_argument("--steady_window", type=float, default=1.0, help="Window size (s) for steady_rp filtering")
    ap.add_argument("--min_recv_pps", type=float, default=5.0, help="Threshold recv_pps for steady_rp windows")
    ap.add_argument("--min_good_windows", type=int, default=3, help="Minimum number of good windows to accept steady_rp")
    ap.add_argument("--steady_fallback", default="first_last_success",
                    choices=["first_last_success", "full", "empty"],
                    help="Fallback policy if steady_rp has too few good windows")

    # JSON filtering by success_rate_steady_rp
    ap.add_argument("--min_success_steady_rp", type=float, default=0.6,
                    help="Filter quic_fec_params.json to keep only senders with success_rate_steady_rp >= this value")
    ap.add_argument("--filter_json_by_success_steady_rp", action=argparse.BooleanOptionalAction, default=True,
                    help="Enable/disable filtering senders in quic_fec_params.json by success_rate_steady_rp")

    args = ap.parse_args()

    in_path = Path(args.input)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(in_path)

    required = {"time", "sender", "seq", "rxOk"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Missing columns {missing}. Found columns: {list(df.columns)}")

    df["time"] = df["time"].apply(safe_float)
    df["seq"] = pd.to_numeric(df["seq"], errors="coerce").astype("Int64")
    df["rxOk"] = pd.to_numeric(df["rxOk"], errors="coerce").fillna(0).astype(int)
    df = df[df["seq"].notna()].copy()
    df["seq"] = df["seq"].astype(int)

    # keep sender as string (stable)
    df["sender"] = df["sender"].astype(str)

    # sort
    df = df.sort_values(["sender", "seq", "time"]).reset_index(drop=True)

    # Per-packet replay trace
    packet_trace = df.rename(columns={"rxOk": "delivered"})[["time", "sender", "seq", "delivered"]].copy()
    packet_trace.to_csv(outdir / "packet_trace.csv", index=False)

    # Global interval fallback
    global_interval = np.nan
    tmp = df[df["rxOk"] == 1].sort_values(["sender", "seq", "time"]).copy()
    if len(tmp) >= 2:
        tmp["dseq"] = tmp.groupby("sender")["seq"].diff()
        tmp["dt"] = tmp.groupby("sender")["time"].diff()
        dt1 = tmp.loc[(tmp["dseq"] == 1) & (tmp["dt"] > 0), "dt"].to_numpy()
        if dt1.size >= 10:
            global_interval = float(np.median(dt1))

    summaries = []
    ge_rows = []

    sender_json_payload = {}
    sender_success_steady_rp = {}

    for sender, g in df.groupby("sender", sort=False):
        gg = g.sort_values(["seq", "time"]).copy()

        # Assign per-sender RTT (ms) in [50,150], deterministic by sender
        rtt_ms = 50 + (zlib.crc32(sender.encode("utf-8")) % 101)

        nominal = estimate_nominal_interval(gg)
        if not np.isfinite(nominal):
            nominal = global_interval

        # If some loss rows have NaN time, reconstruct approx times if possible
        if gg["time"].isna().any() and np.isfinite(nominal):
            anchor = gg[gg["time"].notna()].iloc[0]
            t0 = float(anchor["time"])
            s0 = int(anchor["seq"])
            idx_nan = gg["time"].isna()
            gg.loc[idx_nan, "time"] = t0 + (gg.loc[idx_nan, "seq"].astype(int) - s0) * nominal

        # FULL
        full_stats = compute_block_stats(gg, nominal)

        # steady-firstlast
        steady_fl = steady_state_firstlast_success(gg)
        steady_fl_stats = compute_block_stats(steady_fl, nominal)

        # steady-recvpps
        steady_rp = steady_state_by_recvpps(
            gg,
            window_s=float(args.steady_window),
            min_recv_pps=float(args.min_recv_pps),
            min_good_windows=int(args.min_good_windows),
            fallback=str(args.steady_fallback),
        )
        if len(steady_rp):
            steady_rp_stats = compute_block_stats(steady_rp, nominal)
        else:
            steady_rp_stats = {
                "n_packets": 0, "loss_rate": np.nan, "success_rate": np.nan,
                "mean_burst_len_pkts": np.nan, "p95_burst_len_pkts": np.nan, "max_burst_len_pkts": np.nan,
                "mean_burst_len_s": np.nan, "max_burst_len_s": np.nan,
                "recv_rate_pps": np.nan, "send_rate_pps_est": np.nan,
                "t_start": np.nan, "t_end": np.nan,
                "ge_p_g2b": np.nan, "ge_r_b2g": np.nan, "ge_pi_bad": np.nan,
                "ge_mean_bad_run_pkts": np.nan, "ge_mean_good_run_pkts": np.nan,
                "ge_eps_good": np.nan, "ge_eps_bad": np.nan, "ge_loss_recon": np.nan,
            }

        # Summary row
        summaries.append({
            "sender": sender,
            "nominal_interval_s": nominal,

            # FULL
            "n_packets_full": full_stats["n_packets"],
            "loss_rate_full": full_stats["loss_rate"],
            "success_rate_full": full_stats["success_rate"],
            "mean_burst_len_pkts_full": full_stats["mean_burst_len_pkts"],
            "p95_burst_len_pkts_full": full_stats["p95_burst_len_pkts"],
            "max_burst_len_pkts_full": full_stats["max_burst_len_pkts"],
            "mean_burst_len_s_full": full_stats["mean_burst_len_s"],
            "max_burst_len_s_full": full_stats["max_burst_len_s"],
            "recv_rate_pps_full": full_stats["recv_rate_pps"],
            "send_rate_pps_est_full": full_stats["send_rate_pps_est"],
            "t_start_full": full_stats["t_start"],
            "t_end_full": full_stats["t_end"],

            "ge_p_g2b_full": full_stats["ge_p_g2b"],
            "ge_r_b2g_full": full_stats["ge_r_b2g"],
            "ge_pi_bad_full": full_stats["ge_pi_bad"],
            "ge_eps_good_full": full_stats["ge_eps_good"],
            "ge_eps_bad_full": full_stats["ge_eps_bad"],
            "ge_loss_recon_full": full_stats["ge_loss_recon"],

            # steady_fl
            "n_packets_steady_fl": steady_fl_stats["n_packets"],
            "loss_rate_steady_fl": steady_fl_stats["loss_rate"],
            "success_rate_steady_fl": steady_fl_stats["success_rate"],
            "mean_burst_len_pkts_steady_fl": steady_fl_stats["mean_burst_len_pkts"],
            "p95_burst_len_pkts_steady_fl": steady_fl_stats["p95_burst_len_pkts"],
            "max_burst_len_pkts_steady_fl": steady_fl_stats["max_burst_len_pkts"],
            "mean_burst_len_s_steady_fl": steady_fl_stats["mean_burst_len_s"],
            "max_burst_len_s_steady_fl": steady_fl_stats["max_burst_len_s"],
            "recv_rate_pps_steady_fl": steady_fl_stats["recv_rate_pps"],
            "send_rate_pps_est_steady_fl": steady_fl_stats["send_rate_pps_est"],
            "t_start_steady_fl": steady_fl_stats["t_start"],
            "t_end_steady_fl": steady_fl_stats["t_end"],

            "ge_p_g2b_steady_fl": steady_fl_stats["ge_p_g2b"],
            "ge_r_b2g_steady_fl": steady_fl_stats["ge_r_b2g"],
            "ge_pi_bad_steady_fl": steady_fl_stats["ge_pi_bad"],
            "ge_eps_good_steady_fl": steady_fl_stats["ge_eps_good"],
            "ge_eps_bad_steady_fl": steady_fl_stats["ge_eps_bad"],
            "ge_loss_recon_steady_fl": steady_fl_stats["ge_loss_recon"],

            # steady_rp
            "n_packets_steady_rp": steady_rp_stats["n_packets"],
            "loss_rate_steady_rp": steady_rp_stats["loss_rate"],
            "success_rate_steady_rp": steady_rp_stats["success_rate"],
            "mean_burst_len_pkts_steady_rp": steady_rp_stats["mean_burst_len_pkts"],
            "p95_burst_len_pkts_steady_rp": steady_rp_stats["p95_burst_len_pkts"],
            "max_burst_len_pkts_steady_rp": steady_rp_stats["max_burst_len_pkts"],
            "mean_burst_len_s_steady_rp": steady_rp_stats["mean_burst_len_s"],
            "max_burst_len_s_steady_rp": steady_rp_stats["max_burst_len_s"],
            "recv_rate_pps_steady_rp": steady_rp_stats["recv_rate_pps"],
            "send_rate_pps_est_steady_rp": steady_rp_stats["send_rate_pps_est"],
            "t_start_steady_rp": steady_rp_stats["t_start"],
            "t_end_steady_rp": steady_rp_stats["t_end"],

            "ge_p_g2b_steady_rp": steady_rp_stats["ge_p_g2b"],
            "ge_r_b2g_steady_rp": steady_rp_stats["ge_r_b2g"],
            "ge_pi_bad_steady_rp": steady_rp_stats["ge_pi_bad"],
            "ge_eps_good_steady_rp": steady_rp_stats["ge_eps_good"],
            "ge_eps_bad_steady_rp": steady_rp_stats["ge_eps_bad"],
            "ge_loss_recon_steady_rp": steady_rp_stats["ge_loss_recon"],
        })

        # GE params table row (compact)
        ge_rows.append({
            "sender": sender,
            "nominal_interval_s": nominal,

            "p_g2b_full": full_stats["ge_p_g2b"],
            "r_b2g_full": full_stats["ge_r_b2g"],
            "pi_bad_full": full_stats["ge_pi_bad"],
            "eps_good_full": full_stats["ge_eps_good"],
            "eps_bad_full": full_stats["ge_eps_bad"],
            "mean_bad_run_pkts_full": full_stats["ge_mean_bad_run_pkts"],
            "mean_good_run_pkts_full": full_stats["ge_mean_good_run_pkts"],

            "p_g2b_steady_fl": steady_fl_stats["ge_p_g2b"],
            "r_b2g_steady_fl": steady_fl_stats["ge_r_b2g"],
            "pi_bad_steady_fl": steady_fl_stats["ge_pi_bad"],
            "eps_good_steady_fl": steady_fl_stats["ge_eps_good"],
            "eps_bad_steady_fl": steady_fl_stats["ge_eps_bad"],
            "mean_bad_run_pkts_steady_fl": steady_fl_stats["ge_mean_bad_run_pkts"],
            "mean_good_run_pkts_steady_fl": steady_fl_stats["ge_mean_good_run_pkts"],

            "p_g2b_steady_rp": steady_rp_stats["ge_p_g2b"],
            "r_b2g_steady_rp": steady_rp_stats["ge_r_b2g"],
            "pi_bad_steady_rp": steady_rp_stats["ge_pi_bad"],
            "eps_good_steady_rp": steady_rp_stats["ge_eps_good"],
            "eps_bad_steady_rp": steady_rp_stats["ge_eps_bad"],
            "mean_bad_run_pkts_steady_rp": steady_rp_stats["ge_mean_bad_run_pkts"],
            "mean_good_run_pkts_steady_rp": steady_rp_stats["ge_mean_good_run_pkts"],
        })

        sender_success_steady_rp[sender] = steady_rp_stats["success_rate"]

        sender_json_payload[sender] = {
            "nominal_interval_s": nominal,
            "rtt_ms": int(rtt_ms),

            "GE_full": {
                "p_g2b": full_stats["ge_p_g2b"],
                "r_b2g": full_stats["ge_r_b2g"],
                "pi_bad": full_stats["ge_pi_bad"],
                "eps_good": full_stats["ge_eps_good"],
                "eps_bad": full_stats["ge_eps_bad"],
                "mean_bad_run_pkts": full_stats["ge_mean_bad_run_pkts"],
                "mean_good_run_pkts": full_stats["ge_mean_good_run_pkts"],
                "loss_recon": full_stats["ge_loss_recon"],
            },
            "GE_steady_fl": {
                "p_g2b": steady_fl_stats["ge_p_g2b"],
                "r_b2g": steady_fl_stats["ge_r_b2g"],
                "pi_bad": steady_fl_stats["ge_pi_bad"],
                "eps_good": steady_fl_stats["ge_eps_good"],
                "eps_bad": steady_fl_stats["ge_eps_bad"],
                "mean_bad_run_pkts": steady_fl_stats["ge_mean_bad_run_pkts"],
                "mean_good_run_pkts": steady_fl_stats["ge_mean_good_run_pkts"],
                "loss_recon": steady_fl_stats["ge_loss_recon"],
            },
            "GE_steady_rp": {
                "p_g2b": steady_rp_stats["ge_p_g2b"],
                "r_b2g": steady_rp_stats["ge_r_b2g"],
                "pi_bad": steady_rp_stats["ge_pi_bad"],
                "eps_good": steady_rp_stats["ge_eps_good"],
                "eps_bad": steady_rp_stats["ge_eps_bad"],
                "mean_bad_run_pkts": steady_rp_stats["ge_mean_bad_run_pkts"],
                "mean_good_run_pkts": steady_rp_stats["ge_mean_good_run_pkts"],
                "loss_recon": steady_rp_stats["ge_loss_recon"],
            },

            "success_rate_steady_rp": steady_rp_stats["success_rate"],
            "loss_rate_steady_rp": steady_rp_stats["loss_rate"],
        }

    # Write CSVs
    summary_df = pd.DataFrame(summaries).sort_values("sender")
    summary_df.to_csv(outdir / "summary_by_sender.csv", index=False)

    ge_df = pd.DataFrame(ge_rows).sort_values("sender")
    ge_df.to_csv(outdir / "ge_params_by_sender.csv", index=False)

    # Per-window stats (full windowing)
    win = float(args.window)
    if win <= 0:
        raise ValueError("--window must be > 0")

    df2 = df[df["time"].notna()].copy()
    df2["tbin"] = np.floor(df2["time"] / win).astype(int)

    wrows = []
    for (sender, tbin), g in df2.groupby(["sender", "tbin"], sort=False):
        delivered = g["rxOk"].to_numpy().astype(int)
        loss_seq = 1 - delivered
        bl = burst_lengths(loss_seq)
        wrows.append({
            "sender": sender,
            "tbin": int(tbin),
            "t_start": float(tbin * win),
            "t_end": float((tbin + 1) * win),
            "n_packets": int(len(g)),
            "loss_rate": float(np.mean(loss_seq)) if loss_seq.size else np.nan,
            "recv_rate_pps": float(np.sum(delivered) / win),
            "mean_burst_len_pkts": float(np.mean(bl)) if bl.size else 0.0,
            "max_burst_len_pkts": int(np.max(bl)) if bl.size else 0,
        })

    window_df = pd.DataFrame(wrows)
    window_df.to_csv(outdir / "window_stats.csv", index=False)

    # Build JSON (filtered only here)
    compact = {
        "window_stats_s": win,
        "rtt_ms": {
            "min": 50,
            "max": 150,
            "method": "rtt_ms = 50 + (crc32(sender) % 101)",
        },
        "steady_rp": {
            "window_s": float(args.steady_window),
            "min_recv_pps": float(args.min_recv_pps),
            "min_good_windows": int(args.min_good_windows),
            "fallback": str(args.steady_fallback),
        },
        "json_filter": {
            "enabled": bool(args.filter_json_by_success_steady_rp),
            "min_success_rate_steady_rp": float(args.min_success_steady_rp),
            "rule": "keep sender iff success_rate_steady_rp is finite AND >= threshold",
        },
        "senders": {}
    }

    kept, dropped = 0, 0
    thr = float(args.min_success_steady_rp)

    for sender, payload in sender_json_payload.items():
        if not args.filter_json_by_success_steady_rp:
            compact["senders"][sender] = payload
            kept += 1
            continue

        sr = sender_success_steady_rp.get(sender, np.nan)
        if np.isfinite(sr) and (sr >= thr):
            compact["senders"][sender] = payload
            kept += 1
        else:
            dropped += 1

    with open(outdir / "quic_fec_params.json", "w", encoding="utf-8") as f:
        json.dump(compact, f, indent=2, ensure_ascii=False)

    print(f"[OK] Wrote outputs to: {outdir.resolve()}")
    print(" - packet_trace.csv (unfiltered)")
    print(" - summary_by_sender.csv (unfiltered)")
    print(" - ge_params_by_sender.csv (unfiltered)")
    print(" - window_stats.csv (unfiltered)")
    print(" - quic_fec_params.json (FILTERED by success_rate_steady_rp)"
          if args.filter_json_by_success_steady_rp else
          " - quic_fec_params.json (unfiltered)")
    if args.filter_json_by_success_steady_rp:
        print(f"   JSON filter: kept={kept}, dropped={dropped}, threshold={thr}")


if __name__ == "__main__":
    main()