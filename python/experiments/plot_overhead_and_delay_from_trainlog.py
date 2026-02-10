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


_METHOD_ORDER = [
    "bandit",
    "quic_bbrv2",
    "fec_k30_r0_2_rstep_6",
    "fec_k30_r0_10_rstep_6",
]

_METHOD_LABELS = {
    "bandit": "BCIR",
    "quic_bbrv2": "QUIC",
    "fec_k30_r0_2_rstep_6": "IR-FEC1",
    "fec_k30_r0_10_rstep_6": "IR-FEC2",
}

_METHOD_COLORS = {
    "bandit": "#1f77b4",
    "quic_bbrv2": "#ff7f0e",
    "fec_k30_r0_2_rstep_6": "#2ca02c",
    "fec_k30_r0_10_rstep_6": "#d62728",
}

_METHOD_MARKERS = {
    "bandit": "o",
    "quic_bbrv2": "^",
    "fec_k30_r0_2_rstep_6": "s",
    "fec_k30_r0_10_rstep_6": "D",
}


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


def _goodput_mbps(*, file_bytes: int, dur_ms: float) -> float:
    if file_bytes <= 0:
        return 0.0
    if not np.isfinite(float(dur_ms)) or float(dur_ms) <= 0:
        return 0.0
    sec = float(dur_ms) / 1000.0
    return float(file_bytes) * 8.0 / 1e6 / sec


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


def _method_list_in_data(trials: Iterable[Trial], *, methods_preferred: Sequence[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for t in trials:
        if t.method in seen:
            continue
        seen.add(t.method)
        out.append(t.method)
    ordered = [m for m in methods_preferred if m in seen]
    ordered.extend([m for m in out if m not in ordered])
    return ordered


def _filter_trials(
    trials: Iterable[Trial],
    *,
    task: str,
    include_failures: bool,
) -> List[Trial]:
    out: List[Trial] = []
    for t in trials:
        if t.task != task:
            continue
        if not include_failures and int(t.success) != 1:
            continue
        if int(t.dur_ms) <= 0:
            continue
        if not math.isfinite(float(t.overhead_ratio)):
            continue
        out.append(t)
    return out


def _style_maps_for_methods(methods: List[str]) -> Tuple[Dict[str, str], Dict[str, str], Dict[str, str]]:
    labels: Dict[str, str] = dict(_METHOD_LABELS)
    colors: Dict[str, str] = dict(_METHOD_COLORS)
    markers: Dict[str, str] = dict(_METHOD_MARKERS)

    for m in methods:
        labels.setdefault(m, m)
        colors.setdefault(m, None)
        markers.setdefault(m, "o")

    return labels, colors, markers


def _aggregate_sender_method_mean(points: List[Trial], *, y: str) -> List[Tuple[str, float, float]]:
    by: Dict[Tuple[int, str], List[Trial]] = {}
    for t in points:
        by.setdefault((int(t.sender_id), str(t.method)), []).append(t)

    out: List[Tuple[str, float, float]] = []
    for (_sid, method), rows in sorted(by.items(), key=lambda kv: (kv[0][1], kv[0][0])):
        ovs = [float(r.overhead_ratio) for r in rows if math.isfinite(float(r.overhead_ratio))]
        if y == "goodput":
            ys = [float(r.goodput_mbps) for r in rows if math.isfinite(float(r.goodput_mbps)) and float(r.goodput_mbps) > 0]
        else:
            ys = [float(r.dur_ms) for r in rows if int(r.dur_ms) > 0]
        if not ovs or not ys:
            continue
        out.append((str(method), float(np.mean(ovs)), float(np.mean(ys))))
    return out


def _compute_completion_ratio_points(
    trials: List[Trial],
    *,
    ddl_ms: int,
) -> List[Tuple[str, float, float]]:
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


def _scatter_plot(
    *,
    out_path: Path,
    title: str,
    xlabel: str,
    ylabel: str,
    pts: List[Tuple[str, float, float]],
) -> None:
    _configure_matplotlib()
    fig, ax = plt.subplots()

    methods: List[str] = []
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
    ax.legend(loc="best", frameon=True)
    fig.tight_layout()

    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path)
    if out_path.suffix.lower() != ".png":
        fig.savefig(out_path.with_suffix(".png"))
    plt.close(fig)


def _plot_delay_cdf(*, out_path: Path, title: str, series: List[Tuple[str, Sequence[float]]], xin_ms: float, xmax_ms: float) -> None:
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
    # if xmax_ms is not None and float(xmax_ms) > 0:
    ax.set_xlim(float(xin_ms), float(xmax_ms))

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
    ddl_ms_list = [int(x) for x in ddl_ms_list if int(x) > 0]
    ddl_ms_list = list(ddl_ms_list)[:4]
    if not ddl_ms_list:
        return

    methods = _method_list_in_data(trials, methods_preferred=_METHOD_ORDER)
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


def _load_baseline_trials(*, results_csv: Path, file_bytes: int, duration_field: str) -> List[Trial]:
    out: List[Trial] = []
    with results_csv.open("r", encoding="utf-8", newline="") as f:
        r = csv.DictReader(f)
        for row in r:
            method = (row.get("method") or "").strip()
            if not method:
                continue

            task = (row.get("task") or "").strip()
            if not task:
                task = "delay_128kb" if int(file_bytes) == 128 * 1024 else f"file_{int(file_bytes)}B"

            sender_id = _to_int(row, "sender_id", 0)
            success = _to_int(row, "success", 0)
            dur_ms_server = _to_float(row, "dur_ms", 0.0)
            e2e_delay_ms = _to_float(row, "e2e_delay_ms", 0.0)
            overhead_ratio = _to_float(row, "overhead_ratio", 0.0)

            # Requirement: goodput := file_size / dur_ms (server dur_ms).
            goodput_mbps = _goodput_mbps(file_bytes=int(file_bytes), dur_ms=float(dur_ms_server))

            if duration_field == "e2e_delay_ms":
                dur_ms_plot = int(round(float(e2e_delay_ms)))
            else:
                dur_ms_plot = int(round(float(dur_ms_server)))

            out.append(
                Trial(
                    task=str(task),
                    method=str(method),
                    sender_id=int(sender_id),
                    is_warmup=0,
                    success=int(success),
                    dur_ms=int(dur_ms_plot),
                    goodput_mbps=float(goodput_mbps),
                    overhead_ratio=float(overhead_ratio),
                )
            )
    return out


def _load_bandit_trials_from_trainlog(
    *,
    train_log: Path,
    file_bytes: int,
    duration_field: str,
    t_min: Optional[int],
    t_max: Optional[int],
    sender_ids: Optional[Sequence[int]],
) -> List[Trial]:
    out: List[Trial] = []
    with train_log.open("r", encoding="utf-8") as f:
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

            t = d.get("t", None)
            if t is None:
                continue
            try:
                t_i = int(t)
            except Exception:
                continue
            if t_min is not None and t_i < int(t_min):
                continue
            if t_max is not None and t_i > int(t_max):
                continue

            sid = d.get("sender_id", None)
            try:
                sid_i = int(sid) if sid is not None else 0
            except Exception:
                sid_i = 0
            if sender_ids is not None and len(sender_ids) > 0 and sid_i not in set(int(x) for x in sender_ids):
                continue

            env_info = d.get("env_info")
            if not isinstance(env_info, dict):
                continue

            step_valid = int(env_info.get("step_valid", 0) or 0)
            dur_ms_server = float(env_info.get("dur_ms", 0.0) or 0.0)
            e2e_delay_ms = float(env_info.get("e2e_delay_ms", 0.0) or 0.0)
            raw_obs = env_info.get("raw_obs") if isinstance(env_info.get("raw_obs"), dict) else {}
            overhead_ratio = float(raw_obs.get("fec_overhead", 0.0) or 0.0)

            # Requirement: goodput := file_size / dur_ms (server dur_ms).
            goodput_mbps = _goodput_mbps(file_bytes=int(file_bytes), dur_ms=float(dur_ms_server))

            if duration_field == "e2e_delay_ms":
                dur_ms_plot = int(round(float(e2e_delay_ms)))
            else:
                dur_ms_plot = int(round(float(dur_ms_server)))

            task = "delay_128kb" if int(file_bytes) == 128 * 1024 else f"file_{int(file_bytes)}B"
            out.append(
                Trial(
                    task=str(task),
                    method="bandit",
                    sender_id=int(sid_i),
                    is_warmup=0,
                    success=int(step_valid),
                    dur_ms=int(dur_ms_plot),
                    goodput_mbps=float(goodput_mbps),
                    overhead_ratio=float(overhead_ratio),
                )
            )

    return out


def main() -> int:
    ap = argparse.ArgumentParser(
        description=(
            "Plot overhead+delay figures using baseline CSV (quic/raw + FEC1/2) and bandit QUIC-FEC from training log."
        )
    )
    ap.add_argument("--baseline-in-dir", type=str, required=True, help="Directory containing results.csv from run_raw_fec1_fec2_baselines.py")
    ap.add_argument("--bandit-train-log", type=str, required=True, help="Bandit training log JSONL file")
    ap.add_argument("--out-dir", type=str, default="", help="Output directory (default: baseline-in-dir)")

    ap.add_argument("--file-bytes", type=int, default=128 * 1024, help="Payload size in bytes (default 128KB)")
    ap.add_argument(
        "--duration-field",
        type=str,
        default="e2e_delay_ms",
        choices=["dur_ms", "e2e_delay_ms"],
        help="Which duration to plot as delay: dur_ms (server) or e2e_delay_ms.",
    )

    ap.add_argument("--t-min", type=int, default=None, help="Minimum t (inclusive) for training log")
    ap.add_argument("--t-max", type=int, default=None, help="Maximum t (inclusive) for training log")
    ap.add_argument("--sender-ids", type=str, default="", help="Optional sender_id list, e.g. '28' or '28,30'")

    ap.add_argument(
        "--methods",
        type=str,
        default="bandit,quic_bbrv2,fec_k30_r0_2_rstep_6,fec_k30_r0_10_rstep_6",
        help="Comma list of methods to include",
    )

    ap.add_argument("--aggregate", type=str, default="none", choices=["none", "sender_method_mean"])
    ap.add_argument("--include-failures", action="store_true")
    ap.add_argument("--xmin-delay-ms", type=float, default=0.0)
    ap.add_argument("--xmax-delay-ms", type=float, default=800.0)

    args = ap.parse_args()

    baseline_in_dir = Path(str(args.baseline_in_dir))
    baseline_csv = baseline_in_dir / "results.csv"
    if not baseline_csv.exists():
        raise SystemExit(f"missing baseline results.csv: {baseline_csv}")

    out_dir = Path(str(args.out_dir)) if str(args.out_dir or "").strip() else baseline_in_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    sender_ids: Optional[List[int]] = None
    if str(args.sender_ids or "").strip():
        sender_ids = [int(x.strip()) for x in str(args.sender_ids).split(",") if x.strip()]

    methods_wanted = [m.strip() for m in str(args.methods).split(",") if m.strip()]

    trials: List[Trial] = []
    if "bandit" in methods_wanted:
        trials.extend(
            _load_bandit_trials_from_trainlog(
                train_log=Path(str(args.bandit_train_log)),
                file_bytes=int(args.file_bytes),
                duration_field=str(args.duration_field),
                t_min=args.t_min,
                t_max=args.t_max,
                sender_ids=sender_ids,
            )
        )

    baseline_trials = _load_baseline_trials(
        results_csv=baseline_csv,
        file_bytes=int(args.file_bytes),
        duration_field=str(args.duration_field),
    )
    trials.extend([t for t in baseline_trials if t.method in methods_wanted])

    task = "delay_128kb" if int(args.file_bytes) == 128 * 1024 else f"file_{int(args.file_bytes)}B"

    trials_f = _filter_trials(trials, task=task, include_failures=bool(args.include_failures))
    if not trials_f:
        raise SystemExit("no trials after filtering")

    methods_in_data = _method_list_in_data(trials_f, methods_preferred=_METHOD_ORDER)

    # Scatter: goodput vs overhead
    if str(args.aggregate) == "sender_method_mean":
        pts_goodput = _aggregate_sender_method_mean(trials_f, y="goodput")
        pts_delay = _aggregate_sender_method_mean(trials_f, y="delay")
    else:
        pts_goodput = [(t.method, float(t.overhead_ratio), float(t.goodput_mbps)) for t in trials_f]
        pts_delay = [(t.method, float(t.overhead_ratio), float(t.dur_ms)) for t in trials_f]

    title_suffix = f"file={int(args.file_bytes)}B"
    if args.t_min is not None or args.t_max is not None:
        title_suffix += f" t=[{args.t_min},{args.t_max}]"

    _scatter_plot(
        out_path=out_dir / "goodput_vs_overhead.pdf",
        title=f"Goodput vs overhead ({title_suffix})",
        xlabel="overhead",
        ylabel="goodput (Mbps)",
        pts=pts_goodput,
    )

    _scatter_plot(
        out_path=out_dir / "delay_vs_overhead.pdf",
        title=f"Delay vs overhead ({title_suffix})",
        xlabel="overhead",
        ylabel=f"delay ({str(args.duration_field)})",
        pts=pts_delay,
    )

    # Delay CDF
    series: List[Tuple[str, Sequence[float]]] = []
    for m in methods_in_data:
        xs = [float(t.dur_ms) for t in trials_f if t.method == m and int(t.success) == 1 and int(t.dur_ms) > 0]
        series.append((m, xs))

    _plot_delay_cdf(
        out_path=out_dir / "delay_cdf.pdf",
        title=f"Delay CDF ({title_suffix})",
        series=series,
        xin_ms=float(args.xmin_delay_ms),
        xmax_ms=float(args.xmax_delay_ms),
    )

    # Completion ratio: use the same DDL grid as the paper plots.
    _plot_completion_ratio_2x2(
        out_path=out_dir / "completion_vs_overhead_2x2.pdf",
        ddl_ms_list=[200, 300, 400, 500],
        trials=trials_f,
        ylim=(-0.02, 1.02),
    )

    print(f"OUT: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
