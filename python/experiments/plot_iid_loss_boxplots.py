#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import numpy as np

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402


_METHOD_ORDER_DEFAULT = [
    # ours first
    "bandit",
    "fec_k60_r0_2_rstep_2",
    "fec_k40_r0_10_rstep_8",
    # baselines
    "quic_bbrv2",
    "flec",
]

_METHOD_LABELS = {
    "bandit": "BCIR",
    "quic_bbrv2": "QUIC",
    "fec_k60_r0_2_rstep_2": "IR-FEC1",
    "fec_k40_r0_10_rstep_8": "IR-FEC2",
    "flec": "FLEC",
}

_METHOD_COLORS = {
    "bandit": "#1f77b4",
    "quic_bbrv2": "#ff7f0e",
    "fec_k60_r0_2_rstep_2": "#2ca02c",
    "fec_k40_r0_10_rstep_8": "#d62728",
    "flec": "#9467bd",
}


_METHOD_MARKERS = {
    # Use thin/small marker glyphs so they don't occlude the CI error bars.
    "bandit": "+",
    "fec_k60_r0_2_rstep_2": "x",
    # Keep consistent with plot_overhead_and_delay_from_bandit_evallog.py
    "fec_k40_r0_10_rstep_8": "1",
    "quic_bbrv2": "2",
    "flec": ".",
}

_METHOD_HATCHES = {
    # Requested: fill with dot/pipe/dash-like patterns.
    "bandit": "..",
    "fec_k60_r0_2_rstep_2": "||",
    "fec_k40_r0_10_rstep_8": "--",
    "quic_bbrv2": "xx",
    "flec": "++",
}


def _configure_matplotlib() -> None:
    # Avoid inheriting any global style (e.g., seaborn defaults from user matplotlibrc).
    plt.style.use("default")
    plt.rcParams.update(
        {
            "figure.figsize": (7.0, 2.6),
            "font.size": 8,
            "axes.labelsize": 8,
            "axes.titlesize": 8,
            "legend.fontsize": 7,
            "xtick.labelsize": 7,
            "ytick.labelsize": 7,
            # White background + thin gray grid.
            "figure.facecolor": "white",
            "axes.facecolor": "white",
            "savefig.facecolor": "white",
            "axes.axisbelow": True,
            "axes.edgecolor": "black",
            "axes.spines.top": True,
            "axes.spines.right": True,
            "axes.grid": True,
            # IEEE-ish: light dashed grid.
            "grid.color": "#c7c7c7",
            "grid.alpha": 0.3,
            "grid.linewidth": 0.5,
            "grid.linestyle": "--",
            "lines.linewidth": 0.9,
            # Ticks point inward (paper style).
            "xtick.direction": "in",
            "ytick.direction": "in",
            "xtick.major.size": 3.0,
            "ytick.major.size": 3.0,
            "savefig.dpi": 400,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
            "font.family": "serif",
            "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
        }
    )


def _legend_outside(ax: plt.Axes, *, methods_order: Optional[List[str]] = None) -> None:
    # Put legend outside the axes on the right.
    # If methods_order is provided, enforce that legend order (even if we draw BCIR last for visibility).
    handles, labels = ax.get_legend_handles_labels()
    if methods_order:
        desired_labels = [_METHOD_LABELS.get(m, m) for m in methods_order]
        by_label = {lab: h for h, lab in zip(handles, labels)}
        new_handles: List[object] = []
        new_labels: List[str] = []
        for lab in desired_labels:
            if lab in by_label:
                new_handles.append(by_label[lab])
                new_labels.append(lab)
        # Append any remaining labels (shouldn't usually happen, but keep it robust).
        for h, lab in zip(handles, labels):
            if lab not in set(new_labels):
                new_handles.append(h)
                new_labels.append(lab)
        handles, labels = new_handles, new_labels

    ax.legend(
        handles,
        labels,
        loc="upper left",
        bbox_to_anchor=(1.02, 1.0),
        borderaxespad=0.0,
        frameon=True,
    )


def _parse_lim(s: str) -> Optional[Tuple[float, float]]:
    """Parse a limit string 'min,max' into a tuple."""
    s = str(s or "").strip()
    if not s:
        return None
    parts = [p.strip() for p in s.split(",")]
    if len(parts) != 2:
        return None
    try:
        lo = float(parts[0])
        hi = float(parts[1])
    except Exception:
        return None
    if not (math.isfinite(lo) and math.isfinite(hi)):
        return None
    if lo == hi:
        return None
    return (lo, hi) if lo < hi else (hi, lo)


def _to_int(row: Dict[str, str], k: str, default: int = 0) -> int:
    try:
        return int(float(row.get(k, str(default)) or str(default)))
    except Exception:
        return default


def _to_float(row: Dict[str, str], k: str, default: float = 0.0) -> float:
    try:
        return float(row.get(k, str(default)) or str(default))
    except Exception:
        return default


def _parse_iid_loss_pct(loss_mode: str) -> Optional[float]:
    s = str(loss_mode or "").strip()
    if not s.startswith("iid:"):
        return None
    try:
        return float(s.split(":", 1)[1])
    except Exception:
        return None


def _mean_ci95(values: Sequence[float]) -> Tuple[float, float]:
    xs = [float(v) for v in values if isinstance(v, (int, float)) and math.isfinite(float(v))]
    if not xs:
        return float("nan"), float("nan")
    mu = float(np.mean(xs))
    if len(xs) < 2:
        return mu, 0.0
    sd = float(np.std(xs, ddof=1))
    se = sd / math.sqrt(float(len(xs)))
    return mu, 1.96 * se


@dataclass
class Point:
    method: str
    loss_pct: float
    overhead: float
    e2e_delay_ms: float


def _desired_task(file_bytes: int) -> str:
    return "delay_128kb" if int(file_bytes) == 128 * 1024 else f"file_{int(file_bytes)}B"


def _load_baseline_points(*, results_csv: Path, file_bytes: int, methods: set[str], sender_ids: Optional[set[int]]) -> List[Point]:
    pts: List[Point] = []
    task_wanted = _desired_task(int(file_bytes))

    with results_csv.open("r", encoding="utf-8", newline="") as f:
        r = csv.DictReader(f)
        for row in r:
            method = (row.get("method") or "").strip()
            if method not in methods:
                continue

            task = (row.get("task") or "").strip() or task_wanted
            if task != task_wanted:
                continue

            if _to_int(row, "success", 0) != 1:
                continue

            sid = _to_int(row, "sender_id", 0)
            if sender_ids is not None and sid not in sender_ids:
                continue

            loss_pct = _parse_iid_loss_pct(row.get("loss_mode") or "")
            if loss_pct is None:
                continue

            overhead = _to_float(row, "overhead_ratio", 0.0)
            delay_ms = _to_float(row, "e2e_delay_ms", 0.0)

            if not math.isfinite(overhead) or overhead < 0:
                continue
            if not math.isfinite(delay_ms) or delay_ms <= 0:
                continue

            pts.append(Point(method=method, loss_pct=float(loss_pct), overhead=float(overhead), e2e_delay_ms=float(delay_ms)))

    return pts


def _load_bandit_eval_points(*, eval_jsonl: Path, methods: set[str], sender_ids: Optional[set[int]]) -> List[Point]:
    pts: List[Point] = []
    if "bandit" not in methods:
        return pts

    with eval_jsonl.open("r", encoding="utf-8") as f:
        for line in f:
            line = (line or "").strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue
            if not isinstance(d, dict):
                continue

            loss_pct = _parse_iid_loss_pct(d.get("loss_mode") or "")
            if loss_pct is None:
                continue

            try:
                sid = int(d.get("sender_id", 0) or 0)
            except Exception:
                sid = 0
            if sender_ids is not None and sid not in sender_ids:
                continue

            env_info = d.get("env_info")
            if not isinstance(env_info, dict):
                continue
            step_valid = int(env_info.get("step_valid", 0) or 0)
            if step_valid != 1:
                continue

            # Fairness requirement: QUIC-layer overhead ratio.
            qov = env_info.get("quic_overhead_ratio", None)
            try:
                overhead = float(qov) if qov is not None else float("nan")
            except Exception:
                overhead = float("nan")
            if not math.isfinite(overhead) or overhead < 0:
                continue

            try:
                delay_ms = float(env_info.get("e2e_delay_ms", 0.0) or 0.0)
            except Exception:
                delay_ms = 0.0
            if not math.isfinite(delay_ms) or delay_ms <= 0:
                continue

            pts.append(Point(method="bandit", loss_pct=float(loss_pct), overhead=float(overhead), e2e_delay_ms=float(delay_ms)))

    return pts


def _load_flec_points(*, flec_jsonl: Path, methods: set[str], sender_ids: Optional[set[int]]) -> List[Point]:
    pts: List[Point] = []
    if "flec" not in methods:
        return pts
    if not flec_jsonl.exists():
        return pts

    with flec_jsonl.open("r", encoding="utf-8") as f:
        for line in f:
            line = (line or "").strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue
            if not isinstance(d, dict):
                continue

            # Some FLEC logs don't include sender_id.
            try:
                sid = int(d.get("sender", 0) or 0)
            except Exception:
                sid = 0
            if sender_ids is not None and sid not in sender_ids:
                continue

            ok = int(d.get("ok", 0) or 0)
            if ok != 1:
                continue

            # FLEC IID logs use loss_pct (percent units). Older logs may use p_pct.
            try:
                loss_pct = float(d.get("loss_pct", d.get("p_pct", float("nan"))))
            except Exception:
                loss_pct = float("nan")
            if not math.isfinite(loss_pct):
                continue

            try:
                overhead = float(d.get("overhead", 0.0) or 0.0)
            except Exception:
                overhead = 0.0
            if not math.isfinite(overhead) or overhead < 0:
                continue

            try:
                delay_ms = float(d.get("e2e_s", 0.0) or 0.0) * 1000.0
            except Exception:
                delay_ms = 0.0
            if not math.isfinite(delay_ms) or delay_ms <= 0:
                continue

            pts.append(Point(method="flec", loss_pct=float(loss_pct), overhead=float(overhead), e2e_delay_ms=float(delay_ms)))

    return pts


def _infer_flec_jsonl_iid(*, flec_dir: Path, file_bytes: int) -> Path:
    size_tag = "1m" if int(file_bytes) >= 1024 * 1024 else "128k"
    return flec_dir / f"flec_iid_{size_tag}.jsonl"


def _is_ours(method: str) -> bool:
    m = str(method or "")
    return m == "bandit" or m.startswith("fec_")


def _lineplot_with_ci(
    *,
    out_path: Path,
    ylabel: str,
    loss_pcts: List[float],
    methods: List[str],
    values_by: Dict[Tuple[str, float], List[float]],
    y_scale: float = 1.0,
    xlim: Optional[Tuple[float, float]] = None,
    ylim: Optional[Tuple[float, float]] = None,
) -> None:
    _configure_matplotlib()
    fig, ax = plt.subplots(figsize=(5.0, 2.6))

    xs_all = [float(lp) for lp in loss_pcts]
    # Draw BCIR last so it stays visible when it overlaps another method.
    draw_methods = [m for m in methods if m != "bandit"] + (["bandit"] if "bandit" in methods else [])
    for method in draw_methods:
        color = _METHOD_COLORS.get(method, None)
        label = _METHOD_LABELS.get(method, method)
        linestyle = "-" if _is_ours(method) else "--"
        marker = _METHOD_MARKERS.get(method, ".")

        xs: List[float] = []
        ys: List[float] = []
        yerr: List[float] = []
        for lp in loss_pcts:
            vals = values_by.get((method, float(lp)), [])
            mu, ci = _mean_ci95(vals)
            if not math.isfinite(float(mu)):
                continue
            xs.append(float(lp))
            ys.append(float(mu) * float(y_scale))
            yerr.append((float(ci) * float(y_scale)) if math.isfinite(float(ci)) else 0.0)

        if not xs:
            continue

        # If two methods overlap, make IR-FEC1 thicker so it is still visible underneath BCIR.
        is_ir_fec1 = method == "fec_k60_r0_2_rstep_2"
        is_bcir = method == "bandit"
        markersize = 3.2 if is_ir_fec1 else 2.0
        markeredgewidth = 1.0 if is_ir_fec1 else 0.6
        linewidth = 1.6 if is_ir_fec1 else (0.9 if is_bcir else 1.0)
        elinewidth = 1.1 if is_ir_fec1 else 0.9
        capthick = 1.1 if is_ir_fec1 else 0.9

        ax.errorbar(
            xs,
            ys,
            yerr=yerr,
            fmt=marker,
            markersize=markersize,
            markeredgewidth=markeredgewidth,
            color=color,
            ecolor=color,
            elinewidth=elinewidth,
            capsize=2.0,
            capthick=capthick,
            linestyle=linestyle,
            linewidth=linewidth,
            alpha=0.95,
            label=label,
            barsabove=True,
            zorder=5 if method == "bandit" else (3 if _is_ours(method) else 2),
        )

    ax.set_xticks(xs_all)
    ax.set_xticklabels([f"{lp:g}%" for lp in loss_pcts])
    ax.set_xlabel("IID loss rate")
    ax.set_ylabel(ylabel)

    if xlim is not None:
        ax.set_xlim(float(xlim[0]), float(xlim[1]))
    if ylim is not None:
        ax.set_ylim(float(ylim[0]), float(ylim[1]))

    # Spec: dashed grid with alpha=0.3.
    ax.grid(True, linestyle="--", alpha=0.3)

    _legend_outside(ax, methods_order=methods)
    fig.tight_layout()

    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, bbox_inches="tight")
    if out_path.suffix.lower() != ".png":
        fig.savefig(out_path.with_suffix(".png"), bbox_inches="tight")
    plt.close(fig)


def _tradeoff_scatter(
    *,
    out_path: Path,
    pts: List[Point],
    methods: List[str],
    loss_pcts: List[float],
    overhead_scale: float = 100.0,
    xlim: Optional[Tuple[float, float]] = None,
    ylim: Optional[Tuple[float, float]] = None,
) -> None:
    # Tradeoff plot: one point per loss rate (per method).
    _configure_matplotlib()
    fig, ax = plt.subplots(figsize=(5.0, 2.6))

    loss_set = {float(lp) for lp in loss_pcts}

    # Defaults preserve the current behavior unless overridden by CLI.
    xlim_eff = xlim if xlim is not None else (0.0, 33.0)
    ylim_eff = ylim if ylim is not None else (850.0, 1150.0)

    # Draw BCIR last so it stays visible when it overlaps another method.
    draw_methods = [m for m in methods if m != "bandit"] + (["bandit"] if "bandit" in methods else [])
    for method in draw_methods:
        color = _METHOD_COLORS.get(method, None)
        label = _METHOD_LABELS.get(method, method)
        marker = _METHOD_MARKERS.get(method, ".")

        xs: List[float] = []
        ys: List[float] = []
        for lp in loss_pcts:
            lp_f = float(lp)
            if lp_f not in loss_set:
                continue
            ovs = [float(p.overhead) for p in pts if p.method == method and float(p.loss_pct) == lp_f and math.isfinite(float(p.overhead))]
            ds = [float(p.e2e_delay_ms) for p in pts if p.method == method and float(p.loss_pct) == lp_f and math.isfinite(float(p.e2e_delay_ms))]
            if not ovs or not ds:
                continue
            x = float(np.mean(ovs)) * float(overhead_scale)
            y = float(np.mean(ds))

            # Spec: do not show outliers. Hard filter to visible axis range.
            if x < float(xlim_eff[0]) or x > float(xlim_eff[1]):
                continue
            if y < float(ylim_eff[0]) or y > float(ylim_eff[1]):
                continue
            xs.append(float(x))
            ys.append(float(y))

        if not xs:
            continue

        is_ir_fec1 = method == "fec_k60_r0_2_rstep_2"
        ax.scatter(
            xs,
            ys,
            marker=marker,
            s=22 if is_ir_fec1 else 14,
            linewidths=1.0 if is_ir_fec1 else 0.6,
            alpha=0.85,
            color=color,
            label=label,
            zorder=5 if method == "bandit" else 3,
            rasterized=True,
        )

    ax.set_xlabel("Overhead Ratio (%)")
    ax.set_ylabel("E2E delay (ms)")
    ax.set_xlim(float(xlim_eff[0]), float(xlim_eff[1]))
    ax.set_ylim(float(ylim_eff[0]), float(ylim_eff[1]))
    ax.grid(True, linestyle="--", alpha=0.3)
    _legend_outside(ax, methods_order=methods)
    fig.tight_layout()

    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, bbox_inches="tight")
    if out_path.suffix.lower() != ".png":
        fig.savefig(out_path.with_suffix(".png"), bbox_inches="tight")
    plt.close(fig)


def main() -> int:
    ap = argparse.ArgumentParser(description="IID loss-rate line plots (mean with 95% CI) for overhead and E2E delay.")
    ap.add_argument("--baseline-in-dir", type=str, required=True, help="Directory with results.csv from run_raw_fec1_fec2_baselines.py")
    ap.add_argument("--bandit-eval-log", type=str, default="", help="Bandit eval JSONL (bandit_eval_metrics.jsonl)")
    ap.add_argument("--out-dir", type=str, required=True)

    ap.add_argument("--file-bytes", type=int, default=128 * 1024)
    ap.add_argument("--sender-ids", type=str, default="", help="Optional sender_id list, e.g. '28' or '28,30'")

    ap.add_argument(
        "--loss-pcts",
        type=str,
        default="0.1,0.2,0.3,0.4,0.5",
        help="Comma list of IID loss rates (in percent units), e.g. '0.1,0.2,0.5'",
    )

    ap.add_argument(
        "--methods",
        type=str,
        default=",".join(_METHOD_ORDER_DEFAULT),
        help="Comma list of methods to include (supports: bandit, quic_bbrv2, fec_*, flec)",
    )

    ap.add_argument("--flec-jsonl", type=str, default="", help="Optional FLEC jsonl to include as method 'flec'")
    ap.add_argument("--flec-dir", type=str, default="", help="Optional directory containing flec_iid_{128k,1m}.jsonl")

    # Manual axis ranges for the 3 figures. Format: 'min,max'.
    ap.add_argument("--overhead-xlim", type=str, default="", help="xlim for overhead line plot, e.g. '0.08,0.52'")
    ap.add_argument("--overhead-ylim", type=str, default="", help="ylim for overhead line plot, e.g. '0,10' (percent units)")
    ap.add_argument("--delay-xlim", type=str, default="", help="xlim for delay line plot, e.g. '0.08,0.52'")
    ap.add_argument("--delay-ylim", type=str, default="", help="ylim for delay line plot, e.g. '0,600'")
    ap.add_argument("--tradeoff-xlim", type=str, default="", help="xlim for tradeoff plot, e.g. '0,33' (percent units)")
    ap.add_argument("--tradeoff-ylim", type=str, default="", help="ylim for tradeoff plot, e.g. '0,1200'")

    args = ap.parse_args()

    overhead_xlim = _parse_lim(str(args.overhead_xlim))
    overhead_ylim = _parse_lim(str(args.overhead_ylim))
    delay_xlim = _parse_lim(str(args.delay_xlim))
    delay_ylim = _parse_lim(str(args.delay_ylim))
    tradeoff_xlim = _parse_lim(str(args.tradeoff_xlim))
    tradeoff_ylim = _parse_lim(str(args.tradeoff_ylim))

    baseline_in_dir = Path(str(args.baseline_in_dir))
    results_csv = baseline_in_dir / "results.csv"
    if not results_csv.exists():
        raise SystemExit(f"missing baseline results.csv: {results_csv}")

    out_dir = Path(str(args.out_dir))
    out_dir.mkdir(parents=True, exist_ok=True)

    sender_ids: Optional[set[int]] = None
    if str(args.sender_ids or "").strip():
        sender_ids = {int(x.strip()) for x in str(args.sender_ids).split(",") if x.strip()}

    methods = [m.strip() for m in str(args.methods).split(",") if m.strip()]
    methods_set = set(methods)

    loss_pcts = []
    for part in str(args.loss_pcts).split(","):
        part = (part or "").strip()
        if not part:
            continue
        if part.endswith("%"):
            part = part[:-1]
        try:
            loss_pcts.append(float(part))
        except Exception:
            continue
    loss_pcts = [float(x) for x in loss_pcts]

    pts: List[Point] = []
    pts.extend(_load_baseline_points(results_csv=results_csv, file_bytes=int(args.file_bytes), methods=methods_set, sender_ids=sender_ids))

    if str(args.bandit_eval_log or "").strip() and "bandit" in methods_set:
        pts.extend(
            _load_bandit_eval_points(
                eval_jsonl=Path(str(args.bandit_eval_log)),
                methods=methods_set,
                sender_ids=sender_ids,
            )
        )

    if str(args.flec_jsonl or "").strip() and "flec" in methods_set:
        pts.extend(
            _load_flec_points(
                flec_jsonl=Path(str(args.flec_jsonl)),
                methods=methods_set,
                sender_ids=sender_ids,
            )
        )
    else:
        flec_dir_s = str(args.flec_dir or "").strip()
        if flec_dir_s:
            flec_path = _infer_flec_jsonl_iid(flec_dir=Path(flec_dir_s), file_bytes=int(args.file_bytes))
            if flec_path.exists():
                # Auto-add method if not already requested.
                if "flec" not in methods_set:
                    methods.append("flec")
                    methods_set.add("flec")
                pts.extend(_load_flec_points(flec_jsonl=flec_path, methods=methods_set, sender_ids=sender_ids))
            else:
                print(f"WARN: flec jsonl not found: {flec_path}")

    if not pts:
        raise SystemExit("no points loaded")

    # Build value maps
    overhead_by: Dict[Tuple[str, float], List[float]] = {}
    delay_by: Dict[Tuple[str, float], List[float]] = {}
    for p in pts:
        if float(p.loss_pct) not in set(float(x) for x in loss_pcts):
            continue
        overhead_by.setdefault((p.method, float(p.loss_pct)), []).append(float(p.overhead))
        delay_by.setdefault((p.method, float(p.loss_pct)), []).append(float(p.e2e_delay_ms))

    # Keep method order but only those requested.
    methods_ordered = [m for m in _METHOD_ORDER_DEFAULT if m in methods]
    methods_ordered.extend([m for m in methods if m not in methods_ordered])

    # Plot overhead
    _lineplot_with_ci(
        out_path=out_dir / "iid_loss_line_overhead.pdf",
        ylabel="Overhead Ratio (%)",
        loss_pcts=loss_pcts,
        methods=methods_ordered,
        values_by=overhead_by,
        y_scale=100.0,
        xlim=overhead_xlim,
        ylim=overhead_ylim,
    )

    # Plot delay
    _lineplot_with_ci(
        out_path=out_dir / "iid_loss_line_e2e_delay_ms.pdf",
        ylabel="E2E delay (ms)",
        loss_pcts=loss_pcts,
        methods=methods_ordered,
        values_by=delay_by,
        xlim=delay_xlim,
        ylim=delay_ylim,
    )

    # Tradeoff: one point per loss rate.
    _tradeoff_scatter(
        out_path=out_dir / "iid_loss_tradeoff_overhead_vs_delay.pdf",
        pts=pts,
        methods=methods_ordered,
        loss_pcts=loss_pcts,
        xlim=tradeoff_xlim,
        ylim=tradeoff_ylim,
    )

    # Print quick coverage summary
    for m in methods_ordered:
        counts = [len(overhead_by.get((m, float(lp)), [])) for lp in loss_pcts]
        print(f"{m}: counts per loss%: {counts}")

    print(f"OUT: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
