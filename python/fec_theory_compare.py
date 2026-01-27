#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import math
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class RunResult:
    loss_pct: float
    cc_bypass: int  # 0 or 1
    rep: int
    k: int
    symbol_bytes: int
    r0: int
    r0_theory: int
    r0_target: float
    goodput_mbps: Optional[float]
    goodput_decode_mbps: Optional[float]
    goodput_arrival_mbps: Optional[float]
    md5_ok: Optional[int]
    dur_ms: Optional[int]
    duration_transfer_ms: Optional[int]
    duration_arrival_ms: Optional[int]
    residual_erasures: Optional[int]
    fec_overhead: Optional[float]
    ctrl_tx_nack_msgs: Optional[int]
    arq_attempts_p95: Optional[float]


def _compute_r0_theory(k: int, loss_pct: float) -> int:
    """Theoretical minimum initial repairs R0 for iid loss.

    Requirement: E[received] = (K + R0) * (1-p) >= K => R0 >= K*p/(1-p)
    """
    if loss_pct <= 0.0:
        return 0
    if loss_pct >= 100.0:
        return k  # degenerate; cap
    p = float(loss_pct) / 100.0
    return int(math.ceil((float(k) * p) / (1.0 - p)))


def _decode_success_prob(k: int, r0: int, loss_pct: float) -> float:
    """Probability a block decodes from initial (K+R0) transmissions under i.i.d loss.

    Success means: receive at least K packets out of N = K+R0.
    Equivalently: number of losses X <= R0, where X ~ Binomial(N, p).
    """
    if loss_pct <= 0.0:
        return 1.0
    if loss_pct >= 100.0:
        return 0.0
    p = float(loss_pct) / 100.0
    n = int(k + r0)
    # Sum_{i=0..r0} C(n,i) p^i (1-p)^(n-i)
    q = 1.0 - p
    total = 0.0
    for i in range(0, int(r0) + 1):
        total += math.comb(n, i) * (p**i) * (q ** (n - i))
    # Clamp for numeric drift
    if total < 0.0:
        return 0.0
    if total > 1.0:
        return 1.0
    return total


def _pick_r0_for_target(k: int, loss_pct: float, target_success_prob: float, r0_cap: int = 200) -> int:
    """Pick smallest R0 such that P(success) >= target.

    This avoids the common pathology where the *expected* received packets are enough,
    but the tail probability still triggers ARQ frequently (causing W-shaped goodput).
    """
    if target_success_prob <= 0.0:
        return 0
    if target_success_prob >= 1.0:
        target_success_prob = 0.999999
    for r0 in range(0, r0_cap + 1):
        if _decode_success_prob(k, r0, loss_pct) >= target_success_prob:
            return r0
    return r0_cap


def _parse_last_rl_observation(output: str) -> Optional[Dict[str, Any]]:
    last = None
    for line in output.splitlines():
        if line.startswith("[rl-observation] "):
            try:
                last = json.loads(line.split(" ", 1)[1])
            except Exception:
                continue
    return last


def _parse_run_line(output: str) -> Tuple[Optional[float], Optional[int], Optional[int]]:
    # Example:
    # [run] bitrate=10Mbps rtt=20ms loss=iid dur_ms=6620 md5_ok=1 s_mbps=3.93
    goodput = None
    md5_ok = None
    dur_ms = None
    for line in output.splitlines():
        if not line.startswith("[run] "):
            continue
        parts = line.split()
        for p in parts:
            if p.startswith("dur_ms="):
                try:
                    dur_ms = int(p.split("=", 1)[1])
                except Exception:
                    pass
            elif p.startswith("md5_ok="):
                try:
                    md5_ok = int(p.split("=", 1)[1])
                except Exception:
                    pass
            elif p.startswith("s_mbps="):
                try:
                    goodput = float(p.split("=", 1)[1])
                except Exception:
                    pass
    return goodput, md5_ok, dur_ms


def _run_once(
    *,
    repo_root: Path,
    loss_pct: float,
    cc_bypass: int,
    transport: str,
    bitrate_mbps: int,
    rtt_ms: int,
    k: int,
    symbol_bytes: int,
    r0: int,
    force_build: bool,
    timeout_s: int,
    pace_mode: str,
    rep: int,
    r0_target: float,
    goodput_key: str,
    ddl_ms: int,
    cc_algo: str,
) -> RunResult:
    env = os.environ.copy()
    env["LOSS_MODE"] = "iid"
    # scripts/quicfec_run_once.sh passes LOSS_PCT directly to `tc netem loss ${LOSS_PCT}%`,
    # which supports decimal percentages (e.g., 0.1%).
    env["LOSS_PCT"] = str(float(loss_pct))
    env["QUIC_FEC_CC_BYPASS"] = "1" if int(cc_bypass) == 1 else "0"
    if int(cc_bypass) == 0:
        env["QUIC_FEC_CC_ALGO"] = str(cc_algo)
    env["TRANSPORT"] = str(transport)
    env["BITRATE_MBPS"] = str(int(bitrate_mbps))
    env["RTT_MS"] = str(int(rtt_ms))
    env["K"] = str(int(k))
    env["SYMBOL_BYTES"] = str(int(symbol_bytes))
    env["R0"] = str(int(r0))
    env["R0_TARGET"] = str(float(r0_target))
    # Receiver-side decode deadline (also drives ARQ scheduling / backoff). A large DDL (e.g. 900ms)
    # makes any rare ARQ event add a big tail, which is the main reason for W-shaped goodput.
    env["DDL_MS"] = str(int(ddl_ms))

    if force_build:
        env["FORCE_BUILD"] = "1"

    if pace_mode == "auto":
        env.pop("PACE_US", None)
        env.pop("PACING_US", None)
    elif pace_mode == "disabled":
        env["PACE_US"] = "0"
    else:
        raise ValueError(f"unknown pace_mode: {pace_mode}")

    script = repo_root / "scripts" / "quicfec_run_once.sh"
    # Don't do `sudo -v` here (it can prompt and inject non-determinism).
    # The called script already requires cached sudo and exits with a clear error otherwise.
    p = subprocess.run(
        ["bash", "-lc", f"'{script}'"],
        cwd=str(repo_root),
        env=env,
        text=True,
        capture_output=True,
        timeout=timeout_s,
    )
    output = (p.stdout or "") + "\n" + (p.stderr or "")

    if p.returncode != 0:
        tail = "\n".join(output.splitlines()[-80:])
        raise RuntimeError(
            "quicfec_run_once.sh failed "
            f"(rc={p.returncode}, loss={loss_pct}, cc_bypass={cc_bypass}, rep={rep}).\n"
            f"--- output tail ---\n{tail}"
        )

    obs = _parse_last_rl_observation(output)
    goodput_run, md5_ok, dur_ms = _parse_run_line(output)

    if obs is None and goodput_run is None and md5_ok is None:
        # Script may have exited early without server-stats / rl-observation.
        tail = "\n".join(output.splitlines()[-80:])
        raise RuntimeError(
            "No observation found (missing [rl-observation] / [run] lines). "
            f"loss={loss_pct} cc_bypass={cc_bypass} rep={rep}.\n"
            f"--- output tail ---\n{tail}"
        )

    goodput = None
    goodput_decode = None
    goodput_arrival = None
    duration_arrival_ms = None
    duration_transfer_ms = None
    residual_erasures = None
    fec_overhead = None
    ctrl_tx_nack = None
    arq_attempts_p95 = None
    if obs is not None:
        try:
            goodput_decode = float(obs.get("goodput_decode_mbps"))
        except Exception:
            goodput_decode = None
        try:
            goodput_arrival = float(obs.get("goodput_arrival_mbps"))
        except Exception:
            goodput_arrival = None
        try:
            duration_arrival_ms = int(obs.get("duration_arrival_ms"))
        except Exception:
            duration_arrival_ms = None
        try:
            duration_transfer_ms = int(obs.get("duration_transfer_ms"))
        except Exception:
            duration_transfer_ms = None
        try:
            residual_erasures = int(obs.get("residual_erasures"))
        except Exception:
            residual_erasures = None
        try:
            fec_overhead = float(obs.get("fec_overhead", obs.get("fec_overhead_pct_arrival")))
        except Exception:
            fec_overhead = None
        try:
            ctrl_tx_nack = int(obs.get("ctrl_tx_nack_msgs"))
        except Exception:
            ctrl_tx_nack = None
        try:
            arq_attempts_p95 = float(obs.get("arq_attempts_p95"))
        except Exception:
            arq_attempts_p95 = None

    if goodput_key == "decode":
        goodput = goodput_decode
    elif goodput_key == "arrival":
        goodput = goodput_arrival
    else:
        raise ValueError(f"unknown goodput_key: {goodput_key}")

    if goodput is None:
        goodput = goodput_run

    r0_theory = _compute_r0_theory(k, loss_pct)

    return RunResult(
        loss_pct=float(loss_pct),
        cc_bypass=int(cc_bypass),
        rep=int(rep),
        k=int(k),
        symbol_bytes=int(symbol_bytes),
        r0=int(r0),
        r0_theory=int(r0_theory),
        r0_target=float(r0_target),
        goodput_mbps=goodput,
        goodput_decode_mbps=goodput_decode,
        goodput_arrival_mbps=goodput_arrival,
        md5_ok=md5_ok,
        dur_ms=dur_ms,
        duration_transfer_ms=duration_transfer_ms,
        duration_arrival_ms=duration_arrival_ms,
        residual_erasures=residual_erasures,
        fec_overhead=fec_overhead,
        ctrl_tx_nack_msgs=ctrl_tx_nack,
        arq_attempts_p95=arq_attempts_p95,
    )


def _run_once_with_retries(
    *,
    retries: int,
    **kwargs: Any,
) -> RunResult:
    """Run a trial, retrying a few times on transient failures.

    Under randomized netem loss, QUIC handshake can occasionally fail (e.g. repeated
    loss of initial packets), which would otherwise introduce high variance / missing
    observations. Retrying keeps the *measurement* stable without changing protocol code.
    """
    last_err: Optional[BaseException] = None
    for attempt in range(int(retries) + 1):
        try:
            return _run_once(**kwargs)
        except Exception as e:
            last_err = e
            if attempt >= int(retries):
                raise
            # Brief backoff to avoid reusing an unlucky immediate start pattern.
            time.sleep(0.2)
    assert last_err is not None
    raise last_err


def _write_csv(path: Path, rows: List[RunResult]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "loss_pct",
                "cc_bypass",
                "rep",
                "k",
                "symbol_bytes",
                "r0",
                "r0_theory",
                "r0_target",
                "goodput_mbps",
                "goodput_decode_mbps",
                "goodput_arrival_mbps",
                "md5_ok",
                "dur_ms",
                "duration_transfer_ms",
                "duration_arrival_ms",
                "residual_erasures",
                "fec_overhead",
                "ctrl_tx_nack_msgs",
                "arq_attempts_p95",
            ],
        )
        w.writeheader()
        for r in rows:
            w.writerow(
                {
                    "loss_pct": r.loss_pct,
                    "cc_bypass": r.cc_bypass,
                    "rep": r.rep,
                    "k": r.k,
                    "symbol_bytes": r.symbol_bytes,
                    "r0": r.r0,
                    "r0_theory": r.r0_theory,
                    "r0_target": r.r0_target,
                    "goodput_mbps": r.goodput_mbps,
                    "goodput_decode_mbps": r.goodput_decode_mbps,
                    "goodput_arrival_mbps": r.goodput_arrival_mbps,
                    "md5_ok": r.md5_ok,
                    "dur_ms": r.dur_ms,
                    "duration_transfer_ms": r.duration_transfer_ms,
                    "duration_arrival_ms": r.duration_arrival_ms,
                    "residual_erasures": r.residual_erasures,
                    "fec_overhead": r.fec_overhead,
                    "ctrl_tx_nack_msgs": r.ctrl_tx_nack_msgs,
                    "arq_attempts_p95": r.arq_attempts_p95,
                }
            )


def _plot(
    path_png: Path,
    path_pdf: Optional[Path],
    rows: List[RunResult],
    title: str,
    goodput_key: str,
) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    def _median(vals: List[float]) -> float:
        if not vals:
            return 0.0
        vals = sorted(vals)
        mid = len(vals) // 2
        if len(vals) % 2 == 1:
            return float(vals[mid])
        return float((vals[mid - 1] + vals[mid]) / 2.0)

    def series(cc_bypass: int) -> Tuple[List[float], List[float], List[int]]:
        xs: List[float] = []
        ys: List[float] = []
        fails: List[int] = []
        losses = sorted({float(r.loss_pct) for r in rows})
        for loss_pct in losses:
            group = [r for r in rows if r.cc_bypass == cc_bypass and r.loss_pct == loss_pct]
            ok = [r for r in group if (r.md5_ok == 1 and (r.residual_erasures or 0) == 0 and r.goodput_mbps is not None)]
            xs.append(loss_pct)
            ys.append(_median([float(r.goodput_mbps) for r in ok]))
            fails.append(len(group) - len(ok))
        return xs, ys, fails

    present = sorted({int(r.cc_bypass) for r in rows})
    data: Dict[int, Tuple[List[int], List[float], List[int]]] = {v: series(v) for v in present}

    path_png.parent.mkdir(parents=True, exist_ok=True)
    plt.figure(figsize=(6.2, 4.2), dpi=160)

    # Map cc_bypass to a stable label + color.
    labels = {0: "QUIC (CC)", 1: "QUIC+FEC+ARQ (cc_bypass)"}
    markers = {0: "o", 1: "s"}
    colors = {0: "C0", 1: "C1"}

    for v in present:
        xs, ys, fails = data[v]
        plt.plot(xs, ys, marker=markers.get(v, "o"), linewidth=2.0, label=labels.get(v, f"cc_bypass={v}"), color=colors.get(v, None))
        # Mark failures with an 'x' at y=0 for visibility
        for x, fc in zip(xs, fails):
            if fc > 0:
                plt.scatter([x], [0.0], marker="x", s=55, linewidths=2.0, color=colors.get(v, None))
    plt.xlabel("i.i.d. loss rate (%)")
    if goodput_key == "arrival":
        plt.ylabel("Arrival Goodput (Mbps)")
    else:
        plt.ylabel("Decode Goodput (Mbps)")
    plt.title(title)
    plt.grid(True, which="both", linestyle="--", alpha=0.35)
    plt.legend(frameon=False)
    plt.tight_layout()
    plt.savefig(path_png)
    if path_pdf is not None:
        plt.savefig(path_pdf)


def main() -> int:
    ap = argparse.ArgumentParser(description="Pick theory R0 per loss and compare cc_bypass vs CC.")
    ap.add_argument("--loss", default="0,5,10,15,20", help="Comma-separated loss percents")
    ap.add_argument("--bitrate-mbps", type=int, default=100)
    ap.add_argument("--rtt-ms", type=int, default=20)
    ap.add_argument("--transport", choices=["dgram", "stream"], default="dgram")
    ap.add_argument("--k", type=int, default=30)
    ap.add_argument("--symbol-bytes", type=int, default=1032)
    ap.add_argument("--pace-mode", choices=["auto", "disabled"], default="auto")
    ap.add_argument(
        "--goodput-key",
        choices=["decode", "arrival"],
        default="decode",
        help="Which metric to plot / report when available in [rl-observation]",
    )
    ap.add_argument("--timeout-s", type=int, default=90)
    ap.add_argument(
        "--cc-algo",
        choices=["cubic", "reno", "bbr", "bbrv2"],
        default="cubic",
        help="Congestion control algorithm when CC is enabled (cc_bypass=0).",
    )
    ap.add_argument(
        "--ddl-ms",
        type=int,
        default=150,
        help="Server rx DDL in ms (drives ARQ/NACK timing). Smaller reduces tail latency under loss.",
    )
    ap.add_argument("--reps", type=int, default=5, help="Repetitions per point (median is plotted)")
    ap.add_argument(
        "--cc-mode",
        choices=["bypass", "cc", "both"],
        default="both",
        help="Which mode(s) to run: bypass=only QUIC_FEC_CC_BYPASS=1, cc=only CC enabled, both=runs both.",
    )
    ap.add_argument("--run-retries", type=int, default=2, help="Retries per trial on transient failures")
    ap.add_argument(
        "--r0-target",
        type=float,
        default=0.99,
        help="Target initial-decode success probability for picking R0 (binomial tail)",
    )
    ap.add_argument("--out-csv", default="python/results/fec_theory_compare.csv")
    ap.add_argument("--out-png", default="python/results/fec_theory_compare.png")
    ap.add_argument("--out-pdf", default="", help="Optional PDF output path (empty to skip)")
    ap.add_argument("--title", default="Goodput vs i.i.d. loss (theory R0 per loss)")
    args = ap.parse_args()

    repo_root = Path(__file__).resolve().parents[1]

    losses = [float(x.strip()) for x in str(args.loss).split(",") if x.strip() != ""]

    results: List[RunResult] = []
    force_build_first = True
    for loss_pct in losses:
        r0_theory = _compute_r0_theory(args.k, loss_pct)
        r0 = _pick_r0_for_target(args.k, loss_pct, float(args.r0_target))
        for rep in range(int(args.reps)):
            if str(args.cc_mode) == "bypass":
                cc_bypass_values = (1,)
            elif str(args.cc_mode) == "cc":
                cc_bypass_values = (0,)
            else:
                cc_bypass_values = (1, 0)
            for cc_bypass in cc_bypass_values:
                r = _run_once_with_retries(
                    retries=int(args.run_retries),
                    repo_root=repo_root,
                    loss_pct=loss_pct,
                    cc_bypass=cc_bypass,
                    transport=args.transport,
                    bitrate_mbps=args.bitrate_mbps,
                    rtt_ms=args.rtt_ms,
                    k=args.k,
                    symbol_bytes=args.symbol_bytes,
                    r0=r0,
                    force_build=force_build_first,
                    timeout_s=args.timeout_s,
                    pace_mode=args.pace_mode,
                    rep=rep,
                    r0_target=float(args.r0_target),
                    goodput_key=str(args.goodput_key),
                    ddl_ms=int(args.ddl_ms),
                    cc_algo=str(args.cc_algo),
                )
                force_build_first = False
                results.append(r)
                print(
                    f"loss={loss_pct}% rep={rep} cc_bypass={cc_bypass} R0={r0} (theory={r0_theory}) goodput={r.goodput_mbps} (decode={r.goodput_decode_mbps} arrival={r.goodput_arrival_mbps}) md5_ok={r.md5_ok} residual={r.residual_erasures}",
                    file=sys.stderr,
                )

    out_csv = Path(args.out_csv)
    out_png = Path(args.out_png)
    out_pdf = Path(args.out_pdf) if str(args.out_pdf).strip() else None
    _write_csv(out_csv, results)
    _plot(out_png, out_pdf, results, args.title, str(args.goodput_key))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
