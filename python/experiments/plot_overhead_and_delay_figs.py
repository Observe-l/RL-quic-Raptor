#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import math
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import numpy as np

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402


_METHOD_ORDER = [
    "bandit",
    "quic_bbrv2",
    "fec_k30_r0_2_rstep_6",
    "fec_k30_r0_10_rstep_6",
    "flec",
]

_METHOD_LABELS = {
    "bandit": "QUIC-FEC-Bandit",
    "quic_bbrv2": "QUIC",
    "fec_k30_r0_2_rstep_6": "IR-FEC1",
    "fec_k30_r0_10_rstep_6": "IR-FEC2",
    "flec": "FLEC",
}

_METHOD_COLORS = {
    "bandit": "#1f77b4",
    "quic_bbrv2": "#ff7f0e",
    "fec_k30_r0_2_rstep_6": "#2ca02c",
    "fec_k30_r0_10_rstep_6": "#d62728",
    "flec": "#9467bd",
}

_METHOD_MARKERS = {
    "bandit": "o",
    "quic_bbrv2": "^",
    "flec": "x",
    "fec_k30_r0_2_rstep_6": "s",
    "fec_k30_r0_10_rstep_6": "D",
}


def _method_label(method: str) -> str:
    # Keep this consistent with overhead_vs_completion_scatter.py / goodput_vs_overhead_from_runs.py.
    if method == "bandit":
        return "QUIC-FEC-Bandit"
    if method == "quic_bbrv2":
        return "QUIC"
    if method == "flec":
        return "FLEC"
    # Known fixed baselines.
    if method in _METHOD_LABELS:
        return str(_METHOD_LABELS[method])
    return str(method)


def _style_maps_for_methods(methods: List[str]) -> Tuple[Dict[str, str], Dict[str, str], Dict[str, str]]:
    """Return (labels, colors, markers) for the given methods.

    Uses the same defaults/palette/markers as overhead_vs_completion_scatter.py.
    """

    labels: Dict[str, str] = dict(_METHOD_LABELS)
    colors: Dict[str, str] = dict(_METHOD_COLORS)
    markers: Dict[str, str] = dict(_METHOD_MARKERS)

    fec_methods = sorted({m for m in methods if str(m).startswith("fec_")})
    fec_palette = ["#2ca02c", "#d62728", "#17becf", "#bcbd22", "#8c564b", "#e377c2"]
    fec_markers = ["s", "D", "P", "X", "v", "<"]
    for i, m in enumerate(fec_methods):
        labels.setdefault(m, _method_label(str(m)))
        colors.setdefault(m, fec_palette[i % len(fec_palette)])
        markers.setdefault(m, fec_markers[i % len(fec_markers)])

    # Ensure core methods exist.
    for m in methods:
        labels.setdefault(m, _method_label(str(m)))
        colors.setdefault(m, None)
        markers.setdefault(m, "o")

    return labels, colors, markers


def _configure_matplotlib() -> None:
    plt.rcParams.update(
        {
            "figure.figsize": (8.6, 3.4),
            "font.size": 10,
            "axes.labelsize": 10,
            "axes.titlesize": 10,
            "legend.fontsize": 8,
            "xtick.labelsize": 9,
            "ytick.labelsize": 9,
            "axes.grid": True,
            "grid.alpha": 0.25,
            "lines.linewidth": 1.1,
            "savefig.dpi": 400,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
        }
    )


def _ecdf(values: Sequence[float]) -> Tuple[np.ndarray, np.ndarray]:
    x = np.asarray([v for v in values if np.isfinite(v)], dtype=np.float64)
    if x.size == 0:
        return np.asarray([], dtype=np.float64), np.asarray([], dtype=np.float64)
    x = np.sort(x)
    y = np.arange(1, x.size + 1, dtype=np.float64) / float(x.size)
    return x, y


@dataclass
class Trial:
    task: str
    method: str
    sender_id: int
    is_warmup: int
    success: int
    dur_ms: int
    goodput_mbps: float
    overhead_ratio: float


def _load_flec_trials(*, flec_jsonl: Path) -> List[Trial]:
    """Load FLEC per-trial jsonl and map into the same Trial schema.

    Expected keys per line (best-effort):
      sender, ok, e2e_s, tx_total_bytes, tx_data_bytes, overhead
    """

    import json
    from flec_metrics import flec_corrected_e2e_delay_s, flec_corrected_goodput_mbps, flec_corrected_overhead_ratio

    out: List[Trial] = []
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

            try:
                sender_id = int(d.get("sender", 0) or 0)
                ok = int(d.get("ok", 0) or 0)
                delay_s = flec_corrected_e2e_delay_s(d)
                dur_ms = int(float(delay_s) * 1000.0) if delay_s is not None else 0
                overhead_ratio = flec_corrected_overhead_ratio(d)
                if overhead_ratio is None:
                    overhead_ratio = 0.0
                gp = flec_corrected_goodput_mbps(d)
                goodput_mbps = float(gp) if gp is not None else 0.0
            except Exception:
                continue

            out.append(
                Trial(
                    task="delay_128kb",
                    method="flec",
                    sender_id=int(sender_id),
                    is_warmup=0,
                    success=int(ok),
                    dur_ms=int(dur_ms),
                    goodput_mbps=float(goodput_mbps),
                    overhead_ratio=float(overhead_ratio),
                )
            )
    return out


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


def _load_trials(results_csv: Path) -> List[Trial]:
    out: List[Trial] = []
    with results_csv.open("r", encoding="utf-8", newline="") as f:
        r = csv.DictReader(f)
        for row in r:
            method = (row.get("method") or "").strip()
            if not method:
                continue
            out.append(
                Trial(
                    task=(row.get("task") or "").strip(),
                    method=method,
                    sender_id=_to_int(row, "sender_id", 0),
                    is_warmup=_to_int(row, "is_warmup", 0),
                    success=_to_int(row, "success", 0),
                    dur_ms=_to_int(row, "dur_ms", 0),
                    goodput_mbps=_to_float(row, "goodput_mbps", 0.0),
                    overhead_ratio=_to_float(row, "overhead_ratio", 0.0),
                )
            )
    return out


def _method_list_in_data(trials: Iterable[Trial]) -> List[str]:
    seen = set()
    out: List[str] = []
    for t in trials:
        if t.method in seen:
            continue
        seen.add(t.method)
        out.append(t.method)
    # Prefer our known order, then anything else.
    ordered = [m for m in _METHOD_ORDER if m in seen]
    ordered.extend([m for m in out if m not in ordered])
    return ordered


def _filter_trials(
    trials: Iterable[Trial],
    *,
    task: str,
    include_failures: bool,
    include_warmup: bool,
) -> List[Trial]:
    out: List[Trial] = []
    for t in trials:
        if t.task != task:
            continue
        if not include_warmup and int(t.is_warmup) != 0:
            continue
        if not include_failures and int(t.success) != 1:
            continue
        if t.dur_ms <= 0:
            continue
        if not math.isfinite(float(t.overhead_ratio)):
            continue
        out.append(t)
    return out


def _compute_completion_ratio_points(
    trials: List[Trial],
    *,
    ddl_ms: int,
) -> List[Tuple[str, float, float]]:
    """Compute points (method, overhead_mean, complete_ratio) per (sender,method).

    Matches overhead_vs_completion_scatter.py:
      complete := success==1 && dur_ms>0 && dur_ms<=ddl_ms
      complete_ratio := complete_n / n
      overhead_mean := mean(overhead_ratio over successful runs)
    """

    by: Dict[Tuple[int, str], List[Trial]] = {}
    for t in trials:
        by.setdefault((int(t.sender_id), str(t.method)), []).append(t)

    pts: List[Tuple[str, float, float]] = []
    for (_sid, method), rs in sorted(by.items(), key=lambda kv: (kv[0][1], kv[0][0])):
        if not rs:
            continue

        overheads_ok = [float(r.overhead_ratio) for r in rs if int(r.success) == 1 and math.isfinite(float(r.overhead_ratio))]
        overhead_mean = float(np.mean(overheads_ok)) if overheads_ok else 0.0

        complete_n = 0
        for r in rs:
            if int(r.success) == 1 and int(r.dur_ms) > 0 and int(r.dur_ms) <= int(ddl_ms):
                complete_n += 1
        complete_ratio = float(complete_n) / float(len(rs)) if rs else 0.0

        pts.append((str(method), float(overhead_mean), float(complete_ratio)))

    return pts


def _aggregate_sender_method_mean(points: List[Trial], *, y: str) -> List[Tuple[str, float, float]]:
    """Return points as (method, overhead_mean, y_mean) aggregated by (sender,method)."""

    by: Dict[Tuple[int, str], List[Trial]] = {}
    for t in points:
        by.setdefault((int(t.sender_id), str(t.method)), []).append(t)

    out: List[Tuple[str, float, float]] = []
    for (_sid, method), rows in sorted(by.items(), key=lambda kv: (kv[0][1], kv[0][0])):
        ovs = [float(r.overhead_ratio) for r in rows if math.isfinite(float(r.overhead_ratio))]
        if y == "goodput":
            ys = [float(r.goodput_mbps) for r in rows if math.isfinite(float(r.goodput_mbps)) and float(r.goodput_mbps) > 0]
        else:
            ys = [float(r.dur_ms) for r in rows if r.dur_ms > 0]
        if not ovs or not ys:
            continue
        out.append((str(method), float(np.mean(ovs)), float(np.mean(ys))))
    return out


def _scatter_plot(
    *,
    out_path: Path,
    title: str,
    xlabel: str,
    ylabel: str,
    pts: List[Tuple[str, float, float]],
    xlim: Optional[Tuple[float, float]] = None,
    ylim: Optional[Tuple[float, float]] = None,
) -> None:
    _configure_matplotlib()
    fig, ax = plt.subplots()

    methods = []
    for method, _x, _y in pts:
        if method not in methods:
            methods.append(method)

    labels, colors, markers = _style_maps_for_methods(methods)

    for method in methods:
        xs = [x for m, x, _y in pts if m == method]
        ys = [y for m, _x, y in pts if m == method]
        if not xs:
            continue
        marker = markers.get(method, "o")
        # Matplotlib ignores edgecolors for unfilled markers like 'x'.
        edgecolors = "none" if marker not in {"x", "+"} else None
        ax.scatter(
            xs,
            ys,
            s=26,
            alpha=0.85,
            marker=marker,
            label=labels.get(method, method),
            color=colors.get(method, None),
            edgecolors=edgecolors,
        )

    if title:
        ax.set_title(title)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    if xlim is not None:
        ax.set_xlim(float(xlim[0]), float(xlim[1]))
    if ylim is not None:
        ax.set_ylim(float(ylim[0]), float(ylim[1]))
    ax.legend(loc="best", frameon=True)
    fig.tight_layout()

    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path)
    if out_path.suffix.lower() != ".png":
        fig.savefig(out_path.with_suffix(".png"))
    plt.close(fig)


def _plot_delay_cdf(*, out_path: Path, title: str, series: List[Tuple[str, Sequence[float]]], xmax_ms: float) -> None:
    _configure_matplotlib()
    fig, ax = plt.subplots()

    labels, colors, _markers = _style_maps_for_methods([m for m, _ in series])
    for method, vals in series:
        x, y = _ecdf(vals)
        if x.size == 0:
            continue
        ax.plot(x, y, label=labels.get(method, method), color=colors.get(method, None))

    if title:
        ax.set_title(title)
    ax.set_xlabel("E2E delay per message (ms)")
    ax.set_ylabel("CDF")
    ax.set_ylim(0.0, 1.0)
    if xmax_ms is not None and float(xmax_ms) > 0:
        ax.set_xlim(0.0, float(xmax_ms))

    ax.legend(loc="lower right", frameon=True)
    fig.tight_layout()

    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path)
    if out_path.suffix.lower() != ".png":
        fig.savefig(out_path.with_suffix(".png"))
    plt.close(fig)


def _plot_completion_ratio_2x2(
    *,
    out_path: Path,
    ddl_ms_list: Sequence[int],
    trials: List[Trial],
    ylim: Tuple[float, float],
) -> None:
    """2x2 grid: completion-ratio vs overhead, one subplot per DDL.

    Matches overhead_vs_completion_scatter.py's 2x2 layout.
    """

    ddl_ms_list = [int(x) for x in ddl_ms_list if int(x) > 0]
    ddl_ms_list = list(ddl_ms_list)[:4]
    if not ddl_ms_list:
        return

    methods = _method_list_in_data(trials)
    labels, colors, markers = _style_maps_for_methods(methods)

    _configure_matplotlib()
    fig, axes = plt.subplots(2, 2, figsize=(7.2, 6.0), sharex=False, sharey=True)
    axes_flat = list(axes.flatten())

    for i, ddl_ms in enumerate(ddl_ms_list):
        ax = axes_flat[i]
        pts = _compute_completion_ratio_points(trials, ddl_ms=int(ddl_ms))

        for method in methods:
            xs = [x for m, x, _y in pts if m == method]
            ys = [y for m, _x, y in pts if m == method]
            if not xs:
                continue
            ax.scatter(
                xs,
                ys,
                s=26,
                alpha=0.85,
                marker=markers.get(method, "o"),
                color=colors.get(method, None),
                label=labels.get(method, method),
            )

        ax.set_title(f"DDL={int(ddl_ms)}ms")
        ax.set_xlabel("overhead")
        ax.set_ylim(float(ylim[0]), float(ylim[1]))
        if i % 2 == 0:
            ax.set_ylabel("Completion ratio")
        ax.legend(loc="lower right", frameon=True)

    for j in range(len(ddl_ms_list), 4):
        axes_flat[j].axis("off")

    fig.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path)
    if out_path.suffix.lower() != ".png":
        fig.savefig(out_path.with_suffix(".png"))
    plt.close(fig)


def main() -> int:
    ap = argparse.ArgumentParser(
        description=(
            "One-shot plotting from compare_ge_steady_rp_paper_figs.py results.csv: "
            "goodput-vs-overhead, completion-vs-overhead, and delay CDF"
        )
    )
    ap.add_argument(
        "--in-dir",
        type=str,
        required=True,
        help="Directory containing results.csv (output of compare_ge_steady_rp_paper_figs.py)",
    )
    ap.add_argument(
        "--flec-jsonl",
        type=str,
        default="python/results/paper-delay-rtt50/flec_GE_GE_steady_rp_10mbps_rtt50_128k_20260128-173352.jsonl",
        help="Optional FLEC jsonl to overlay as a baseline (default: paper-delay-rtt50 flec jsonl)",
    )
    ap.add_argument(
        "--flec-e2e-offset-ms",
        type=float,
        default=0.0,
        help="FLEC-only: add this offset (ms) to e2e delay (default 0).",
    )
    ap.add_argument(
        "--out-dir",
        type=str,
        default="",
        help="Output directory (default: --in-dir)",
    )
    ap.add_argument(
        "--aggregate",
        type=str,
        default="sender_method_mean",
        choices=["none", "sender_method_mean"],
        help="Build scatter points per-run or mean over (sender,method)",
    )
    ap.add_argument(
        "--include-failures",
        action="store_true",
        help="Include success==0 rows (default: exclude)",
    )
    ap.add_argument(
        "--include-warmup",
        action="store_true",
        help="Include warmup rows (default: exclude)",
    )
    ap.add_argument(
        "--xmax-delay-ms",
        type=float,
        default=800.0,
        help="Upper x-axis limit for delay CDF plot (ms)",
    )
    ap.add_argument(
        "--goodput-task",
        type=str,
        default="auto",
        choices=["auto", "delay_128kb", "goodput_3mb"],
        help="Which task to use for goodput-vs-overhead (auto picks goodput_3mb if present else delay_128kb)",
    )

    args = ap.parse_args()

    os.environ["FLEC_E2E_OFFSET_MS"] = str(float(getattr(args, "flec_e2e_offset_ms", 0.0) or 0.0))

    in_dir = Path(args.in_dir)
    results_csv = in_dir / "results.csv"
    if not results_csv.exists():
        raise SystemExit(f"results.csv not found: {results_csv}")

    out_dir = Path(args.out_dir) if str(args.out_dir).strip() else in_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    trials = _load_trials(results_csv)

    # Optional FLEC baseline overlay.
    flec_path_s = str(getattr(args, "flec_jsonl", "") or "").strip()
    if flec_path_s:
        flec_path = Path(flec_path_s).expanduser()
        if flec_path.exists():
            trials.extend(_load_flec_trials(flec_jsonl=flec_path))
        else:
            print("[warn] flec_jsonl not found, skipping:", flec_path)

    methods = _method_list_in_data(trials)

    include_failures = bool(args.include_failures)
    include_warmup = bool(args.include_warmup)

    # Completion vs overhead (delay task)
    delay_trials = _filter_trials(
        trials,
        task="delay_128kb",
        include_failures=include_failures,
        include_warmup=include_warmup,
    )
    if str(args.aggregate) == "none":
        pts_delay = [(t.method, float(t.overhead_ratio), float(t.dur_ms)) for t in delay_trials]
    else:
        pts_delay = _aggregate_sender_method_mean(delay_trials, y="dur")

    _scatter_plot(
        out_path=out_dir / "fig_completion_vs_overhead.pdf",
        title="",
        xlabel="Overhead ",
        ylabel="Completion time (ms)",
        pts=pts_delay,
        xlim=None,
    )

    # Completion ratio vs overhead at fixed DDL thresholds (paper-style).
    ddl_list = [150, 250, 350, 450]
    for ddl_ms in ddl_list:
        pts_cr = _compute_completion_ratio_points(delay_trials, ddl_ms=int(ddl_ms))
        _scatter_plot(
            out_path=out_dir / f"fig_completion_ratio_vs_overhead_ddl{int(ddl_ms)}.pdf",
            title="",
            xlabel="Overhead ",
            ylabel=f"Completion ratio (dur_ms <= {int(ddl_ms)} ms)",
            pts=pts_cr,
            xlim=None,
            ylim=(-0.05, 1.05),
        )

    # Completion ratio vs overhead (2x2)
    _plot_completion_ratio_2x2(
        out_path=out_dir / "fig_completion_ratio_vs_overhead_2x2.pdf",
        ddl_ms_list=ddl_list,
        trials=delay_trials,
        ylim=(-0.05, 1.05),
    )

    # Goodput vs overhead.
    gp_task = str(args.goodput_task)
    if gp_task == "auto":
        has_gp = any(t.task == "goodput_3mb" and int(t.is_warmup) == 0 for t in trials)
        gp_task = "goodput_3mb" if has_gp else "delay_128kb"

    gp_trials = _filter_trials(
        trials,
        task=str(gp_task),
        include_failures=include_failures,
        include_warmup=include_warmup,
    )
    if str(args.aggregate) == "none":
        pts_gp = [(t.method, float(t.overhead_ratio), float(t.goodput_mbps)) for t in gp_trials if t.goodput_mbps > 0]
    else:
        pts_gp = _aggregate_sender_method_mean(gp_trials, y="goodput")

    _scatter_plot(
        out_path=out_dir / "fig_goodput_vs_overhead.pdf",
        title="",
        xlabel="Overhead ",
        ylabel="Goodput (Mbps)",
        pts=pts_gp,
        xlim=None,
    )

    # Delay CDF (delay task)
    delay_series: List[Tuple[str, Sequence[float]]] = []
    for m in methods:
        vals = [float(t.dur_ms) for t in delay_trials if t.method == m and int(t.success) == 1 and t.dur_ms > 0]
        delay_series.append((m, vals))

    _plot_delay_cdf(
        out_path=out_dir / "fig_delay_cdf.pdf",
        title="",
        series=delay_series,
        xmax_ms=float(args.xmax_delay_ms),
    )

    print("OUT:", out_dir)
    print("- completion vs overhead:", out_dir / "fig_completion_vs_overhead.pdf")
    print("- goodput vs overhead:   ", out_dir / "fig_goodput_vs_overhead.pdf")
    print("- delay cdf:             ", out_dir / "fig_delay_cdf.pdf")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
