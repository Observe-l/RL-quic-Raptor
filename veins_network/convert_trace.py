#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Convert Veins RSU rx trace (time,sender,seq,rxOk) into QUIC-FEC offline traces & params.

Input CSV expected columns:
  - time: float seconds (OMNeT++ simTime)
  - sender: sender id (int or string)
  - seq: int sequence number (monotonic per sender if you fixed per-sender expectedSeq)
  - rxOk: 1 if received, 0 if lost
    (If you expanded missing seq to rxOk=0 rows, even better.)

Outputs (in outdir):
  - packet_trace.csv              : time,sender,seq,delivered
  - summary_by_sender.csv         : loss/burst/rates for FULL + steady_fl + steady_rp
  - ge_params_by_sender.csv       : GE params for FULL + steady_fl + steady_rp
  - window_stats.csv              : per-sender per-window loss stats (full windowing)
  - quic_fec_params.json          : compact JSON with nominal interval + GE params (full/fl/rp)
    NOTE: senders in this JSON can be filtered by success_rate_steady_rp >= threshold (default 0.8)
"""

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
import zlib

import numpy as np
import pandas as pd


@dataclass
class GEParams:
    p_g2b: float
    r_b2g: float
    pi_bad: float
    mean_bad_run: float
    mean_good_run: float


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


def fit_gilbert_elliott(loss_seq: np.ndarray) -> GEParams:
    """
    2-state Markov on {Good=delivered, Bad=loss}.
      p = P(B|G), r = P(G|B)
      pi_B = p/(p+r)
      mean bad run (pkts) ~ 1/r
      mean good run (pkts) ~ 1/p
    """
    if loss_seq.size < 2:
        return GEParams(np.nan, np.nan, np.nan, np.nan, np.nan)

    s = loss_seq.astype(int)  # 0=G, 1=B
    g_to_b = np.sum((s[:-1] == 0) & (s[1:] == 1))
    b_to_g = np.sum((s[:-1] == 1) & (s[1:] == 0))
    from_g = np.sum(s[:-1] == 0)
    from_b = np.sum(s[:-1] == 1)

    p = g_to_b / from_g if from_g > 0 else np.nan
    r = b_to_g / from_b if from_b > 0 else np.nan

    if np.isfinite(p) and np.isfinite(r) and (p + r) > 0:
        pi_b = p / (p + r)
        mean_bad = 1.0 / r if r > 0 else np.inf
        mean_good = 1.0 / p if p > 0 else np.inf
    else:
        pi_b = np.nan
        mean_bad = np.nan
        mean_good = np.nan

    return GEParams(p, r, pi_b, mean_bad, mean_good)


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


def compute_block_stats(block: pd.DataFrame, nominal_interval: float) -> dict:
    """Loss/burst/rates + GE params for a block."""
    delivered = block["rxOk"].to_numpy().astype(int)
    loss_seq = 1 - delivered

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

    ge = fit_gilbert_elliott(loss_seq)

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
        "ge_p_g2b": ge.p_g2b,
        "ge_r_b2g": ge.r_b2g,
        "ge_pi_bad": ge.pi_bad,
        "ge_mean_bad_run_pkts": ge.mean_bad_run,
        "ge_mean_good_run_pkts": ge.mean_good_run,
    }


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
    ap.add_argument("--min_success_steady_rp", type=float, default=0.8,
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

    # Keep this dict so we can filter JSON without changing CSV outputs
    sender_json_payload = {}
    sender_success_steady_rp = {}  # sender -> success_rate_steady_rp

    for sender, g in df.groupby("sender", sort=False):
        gg = g.sort_values(["seq", "time"]).copy()

        # Assign a per-sender RTT (ms) in [50,150].
        # Use a deterministic pseudo-random mapping from sender id so results are reproducible.
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

        # steady-recvpps (recommended)
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
        })

        # GE rows
        ge_rows.append({
            "sender": sender,
            "nominal_interval_s": nominal,

            "p_g2b_full": full_stats["ge_p_g2b"],
            "r_b2g_full": full_stats["ge_r_b2g"],
            "pi_bad_full": full_stats["ge_pi_bad"],
            "mean_bad_run_pkts_full": full_stats["ge_mean_bad_run_pkts"],
            "mean_good_run_pkts_full": full_stats["ge_mean_good_run_pkts"],

            "p_g2b_steady_fl": steady_fl_stats["ge_p_g2b"],
            "r_b2g_steady_fl": steady_fl_stats["ge_r_b2g"],
            "pi_bad_steady_fl": steady_fl_stats["ge_pi_bad"],
            "mean_bad_run_pkts_steady_fl": steady_fl_stats["ge_mean_bad_run_pkts"],
            "mean_good_run_pkts_steady_fl": steady_fl_stats["ge_mean_good_run_pkts"],

            "p_g2b_steady_rp": steady_rp_stats["ge_p_g2b"],
            "r_b2g_steady_rp": steady_rp_stats["ge_r_b2g"],
            "pi_bad_steady_rp": steady_rp_stats["ge_pi_bad"],
            "mean_bad_run_pkts_steady_rp": steady_rp_stats["ge_mean_bad_run_pkts"],
            "mean_good_run_pkts_steady_rp": steady_rp_stats["ge_mean_good_run_pkts"],
        })

        # Cache success_rate_steady_rp for JSON filtering
        sender_success_steady_rp[sender] = steady_rp_stats["success_rate"]

        # Prepare sender payload for JSON (we'll filter later)
        sender_json_payload[sender] = {
            "nominal_interval_s": nominal,
            "rtt_ms": int(rtt_ms),
            "GE_full": {
                "p_g2b": full_stats["ge_p_g2b"],
                "r_b2g": full_stats["ge_r_b2g"],
                "pi_bad": full_stats["ge_pi_bad"],
                "mean_bad_run_pkts": full_stats["ge_mean_bad_run_pkts"],
                "mean_good_run_pkts": full_stats["ge_mean_good_run_pkts"],
            },
            "GE_steady_fl": {
                "p_g2b": steady_fl_stats["ge_p_g2b"],
                "r_b2g": steady_fl_stats["ge_r_b2g"],
                "pi_bad": steady_fl_stats["ge_pi_bad"],
                "mean_bad_run_pkts": steady_fl_stats["ge_mean_bad_run_pkts"],
                "mean_good_run_pkts": steady_fl_stats["ge_mean_good_run_pkts"],
            },
            "GE_steady_rp": {
                "p_g2b": steady_rp_stats["ge_p_g2b"],
                "r_b2g": steady_rp_stats["ge_r_b2g"],
                "pi_bad": steady_rp_stats["ge_pi_bad"],
                "mean_bad_run_pkts": steady_rp_stats["ge_mean_bad_run_pkts"],
                "mean_good_run_pkts": steady_rp_stats["ge_mean_good_run_pkts"],
            },
            "success_rate_steady_rp": steady_rp_stats["success_rate"],
            "loss_rate_steady_rp": steady_rp_stats["loss_rate"],
        }

    # Write CSVs (unfiltered)
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

    # Build JSON (filtered only here, per your request)
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
