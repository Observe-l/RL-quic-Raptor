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
    # Ours first (legend order requirement)
    "bandit",
    "fec_k60_r0_2_rstep_2",
    "fec_k40_r0_10_rstep_8",
    # Baselines
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
    # Prefer small, line-constructed markers for dense IEEE plots.
    "bandit": "+",
    "fec_k60_r0_2_rstep_2": "x",
    "fec_k40_r0_10_rstep_8": "1",
    "quic_bbrv2": "2",
    "flec": ".",
}


def _configure_matplotlib() -> None:
    # Avoid inheriting any global style (e.g., seaborn defaults from user matplotlibrc).
    plt.style.use("default")
    plt.rcParams.update(
        {
            # IEEE-friendly defaults (single-column-ish). Individual plots may override size.
            "figure.figsize": (3.8, 2.40),
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
            "grid.color": "#d0d0d0",
            "grid.alpha": 0.55,
            "grid.linewidth": 0.4,
            "grid.linestyle": "-",
            "lines.linewidth": 0.9,
            # Ticks point inward (paper style).
            "xtick.direction": "in",
            "ytick.direction": "in",
            "xtick.major.size": 3.0,
            "ytick.major.size": 3.0,
            "savefig.dpi": 400,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
            # Try a Times-like serif for IEEE; fall back gracefully.
            "font.family": "serif",
            "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
        }
    )


def _is_ours_method(method: str) -> bool:
    m = str(method or "")
    if m == "bandit":
        return True
    if m.startswith("fec_"):
        return True
    return False


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


def _goodput_mbps_from_flec(*, data_bytes: int, e2e_s: float, rtt_ms: float) -> float:
    # Requirement (FLEC): goodput := data_size / (e2e_delay - RTT/2)
    # with e2e_delay from file and RTT matching the baseline RTT.
    if int(data_bytes) <= 0:
        return 0.0
    if not np.isfinite(float(e2e_s)) or float(e2e_s) <= 0:
        return 0.0
    if not np.isfinite(float(rtt_ms)) or float(rtt_ms) < 0:
        rtt_ms = 0.0
    denom_s = float(e2e_s) - float(rtt_ms) / 2000.0
    if not np.isfinite(denom_s) or denom_s <= 0:
        return 0.0
    return float(data_bytes) * 8.0 / 1e6 / float(denom_s)


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


def _filter_trials_for_completion(trials: Iterable[Trial], *, task: str) -> List[Trial]:
    """Filter only by task and basic numeric sanity.

    IMPORTANT: Do NOT drop failures here.
    Completion ratio should have denominator = all trials (including failures/timeouts),
    otherwise it becomes a conditional ratio over successes only.
    """

    out: List[Trial] = []
    for t in trials:
        if t.task != task:
            continue
        if not math.isfinite(float(t.overhead_ratio)):
            continue
        # Allow dur_ms==0 for failures; they count as not completed.
        if int(t.dur_ms) < 0:
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
    fig, ax = plt.subplots(figsize=(3.8, 2.40))

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
        # Smaller points + transparency for dense scatter.
        ax.scatter(
            xs,
            ys,
            s=14,
            alpha=0.55,
            marker=marker,
            label=labels.get(method, method),
            color=colors.get(method, None),
            linewidths=0.45,
            rasterized=True,
        )

    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)

    # Keep legend placement as before (do not move to top).
    ax.legend(loc="best", frameon=True)

    fig.tight_layout()

    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path)
    if out_path.suffix.lower() != ".png":
        fig.savefig(out_path.with_suffix(".png"))
    plt.close(fig)


def _plot_delay_cdf(*, out_path: Path, title: str, series: List[Tuple[str, Sequence[float]]], xin_ms: float, xmax_ms: float) -> None:
    _configure_matplotlib()
    fig, ax = plt.subplots(figsize=(3.8, 2.40))

    labels, colors, _markers = _style_maps_for_methods([m for m, _ in series])
    for method, vals in series:
        x, y = _ecdf(vals)
        if x.size == 0:
            continue
        ax.plot(
            x,
            y,
            label=labels.get(method, method),
            color=colors.get(method, None),
            linestyle=("-" if _is_ours_method(method) else "--"),
            linewidth=0.85,
        )
    ax.set_xlabel("E2E delay per message (ms)")
    ax.set_ylabel("CDF")
    ax.set_ylim(0.0, 1.0)
    # if xmax_ms is not None and float(xmax_ms) > 0:
    ax.set_xlim(float(xin_ms), float(xmax_ms))

    # Keep legend placement as before.
    ax.legend(loc="upper left", frameon=True)
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
    # Two-column-ish figure.
    fig, axes = plt.subplots(2, 2, figsize=(7.00, 3.60), sharex=False, sharey=True)
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
                s=12,
                alpha=0.55,
                marker=markers.get(method, "o"),
                color=colors.get(method, None),
                label=labels.get(method, method),
                linewidths=0.45,
                rasterized=True,
            )

        # No subplot titles (paper-style). Use a small in-axes annotation instead.
        ax.text(
            0.02,
            0.96,
            f"DDL={int(ddl_ms)}ms",
            transform=ax.transAxes,
            va="top",
            ha="left",
            fontsize=7,
        )
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

            # Fair comparison requirement:
            # Use QUIC-layer byte overhead ratio for both raw QUIC and QUIC-FEC.
            # Prefer env_info.quic_overhead_ratio when present; fall back to old fec_overhead
            # (repair/source) only for backwards compatibility with older logs.
            overhead_ratio: float
            qov = env_info.get("quic_overhead_ratio", None)
            try:
                qov_f = float(qov) if qov is not None else float("nan")
            except Exception:
                qov_f = float("nan")
            if np.isfinite(qov_f) and qov_f >= 0:
                overhead_ratio = float(qov_f)
            else:
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


def _load_flec_trials(
    *,
    flec_jsonl: Path,
    file_bytes: int,
    duration_field: str,
    sender_ids: Optional[Sequence[int]],
    fallback_rtt_ms: Optional[int],
) -> List[Trial]:
    out: List[Trial] = []
    if not flec_jsonl.exists():
        return out

    sender_allow: Optional[set[int]] = None
    if sender_ids is not None and len(sender_ids) > 0:
        sender_allow = set(int(x) for x in sender_ids)

    task = "delay_128kb" if int(file_bytes) == 128 * 1024 else f"file_{int(file_bytes)}B"

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
                sid = int(d.get("sender", 0) or 0)
            except Exception:
                sid = 0
            if sender_allow is not None and sid not in sender_allow:
                continue

            ok = int(d.get("ok", 0) or 0)
            # e2e delay and overhead are used directly from file.
            e2e_s = float(d.get("e2e_s", 0.0) or 0.0)
            overhead = float(d.get("overhead", 0.0) or 0.0)

            # Prefer RTT from file; fall back to baseline RTT if missing.
            rtt_ms = d.get("rtt_ms", None)
            try:
                rtt_ms_f = float(rtt_ms) if rtt_ms is not None else float(fallback_rtt_ms or 0)
            except Exception:
                rtt_ms_f = float(fallback_rtt_ms or 0)

            # Determine payload size for goodput.
            data_bytes = d.get("payload_bytes", None)
            if data_bytes is None:
                data_bytes = d.get("resp_bytes", None)
            if data_bytes is None:
                data_bytes = d.get("received_bytes", None)
            try:
                data_i = int(data_bytes) if data_bytes is not None else int(file_bytes)
            except Exception:
                data_i = int(file_bytes)

            goodput = _goodput_mbps_from_flec(data_bytes=int(data_i), e2e_s=float(e2e_s), rtt_ms=float(rtt_ms_f))

            delay_ms = int(round(float(e2e_s) * 1000.0)) if float(e2e_s) > 0 else 0
            if duration_field not in {"dur_ms", "e2e_delay_ms"}:
                duration_field = "e2e_delay_ms"
            # FLEC only provides E2E; we use it for both plotting modes.
            dur_ms_plot = int(delay_ms)

            out.append(
                Trial(
                    task=str(task),
                    method="flec",
                    sender_id=int(sid),
                    is_warmup=0,
                    success=int(ok),
                    dur_ms=int(dur_ms_plot),
                    goodput_mbps=float(goodput),
                    overhead_ratio=float(overhead),
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
    ap.add_argument("--flec-jsonl", type=str, default="", help="Optional FLEC results jsonl (adds method 'flec')")
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
        default="bandit,quic_bbrv2,fec_k60_r0_2_rstep_2,fec_k40_r0_10_rstep_8",
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

    # Optional: load FLEC jsonl if requested and included in methods.
    flec_path_s = str(args.flec_jsonl or "").strip()
    if "flec" in methods_wanted and flec_path_s:
        # Fallback RTT: try baseline meta.json args.rtt_ms (IID default), else 0.
        fallback_rtt_ms: Optional[int] = None
        meta_path = baseline_in_dir / "meta.json"
        if meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
                if isinstance(meta, dict):
                    a = meta.get("args")
                    if isinstance(a, dict):
                        fallback_rtt_ms = int(a.get("rtt_ms", 0) or 0)
            except Exception:
                fallback_rtt_ms = None

        trials.extend(
            _load_flec_trials(
                flec_jsonl=Path(flec_path_s),
                file_bytes=int(args.file_bytes),
                duration_field=str(args.duration_field),
                sender_ids=sender_ids,
                fallback_rtt_ms=fallback_rtt_ms,
            )
        )

    task = "delay_128kb" if int(args.file_bytes) == 128 * 1024 else f"file_{int(args.file_bytes)}B"

    trials_scatter = _filter_trials(trials, task=task, include_failures=bool(args.include_failures))
    if not trials_scatter:
        raise SystemExit("no trials after filtering")

    trials_completion = _filter_trials_for_completion(trials, task=task)

    methods_in_data = _method_list_in_data(trials_scatter, methods_preferred=_METHOD_ORDER)

    # Scatter: goodput vs overhead
    if str(args.aggregate) == "sender_method_mean":
        pts_goodput = _aggregate_sender_method_mean(trials_scatter, y="goodput")
        pts_delay = _aggregate_sender_method_mean(trials_scatter, y="delay")
    else:
        pts_goodput = [(t.method, float(t.overhead_ratio), float(t.goodput_mbps)) for t in trials_scatter]
        pts_delay = [(t.method, float(t.overhead_ratio), float(t.dur_ms)) for t in trials_scatter]

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
        xs = [float(t.dur_ms) for t in trials_scatter if t.method == m and int(t.success) == 1 and int(t.dur_ms) > 0]
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
        trials=trials_completion,
        ylim=(-0.02, 1.02),
    )

    print(f"OUT: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
