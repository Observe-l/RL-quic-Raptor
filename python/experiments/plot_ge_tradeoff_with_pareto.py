#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import Ellipse  # noqa: E402


_METHOD_ORDER_DEFAULT = [
    "bandit",
    "fec_k60_r0_2_rstep_2",
    "fec_k40_r0_10_rstep_8",
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
    "bandit": "#1f77b4",  # deep-ish blue
    "quic_bbrv2": "#ff7f0e",  # orange
    "fec_k60_r0_2_rstep_2": "#2ca02c",  # green
    "fec_k40_r0_10_rstep_8": "#d62728",  # red
    "flec": "#9467bd",  # purple
}

_METHOD_MARKERS = {
    "bandit": "+",
    "fec_k60_r0_2_rstep_2": "x",
    "fec_k40_r0_10_rstep_8": "1",
    "quic_bbrv2": "2",
    "flec": ".",
}


def _configure_matplotlib() -> None:
    plt.style.use("default")
    plt.rcParams.update(
        {
            "figure.figsize": (5.0, 2.8),
            "font.size": 8,
            "axes.labelsize": 8,
            "axes.titlesize": 8,
            "legend.fontsize": 7,
            "xtick.labelsize": 7,
            "ytick.labelsize": 7,
            "figure.facecolor": "white",
            "axes.facecolor": "white",
            "savefig.facecolor": "white",
            "axes.axisbelow": True,
            "axes.grid": True,
            "grid.color": "#c7c7c7",
            "grid.alpha": 0.3,
            "grid.linewidth": 0.5,
            "grid.linestyle": "--",
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


def _desired_task(file_bytes: int) -> str:
    return "delay_128kb" if int(file_bytes) == 128 * 1024 else f"file_{int(file_bytes)}B"


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


def _mean_ci95(xs: Sequence[float]) -> Tuple[float, float]:
    vals = [float(x) for x in xs if isinstance(x, (int, float)) and math.isfinite(float(x))]
    if not vals:
        return float("nan"), float("nan")
    mu = float(np.mean(vals))
    if len(vals) < 2:
        return mu, 0.0
    sd = float(np.std(vals, ddof=1))
    se = sd / math.sqrt(float(len(vals)))
    return mu, 1.96 * se


def _chi2_cdf_df2(x: float) -> float:
    # Chi-square CDF for k=2: 1 - exp(-x/2) * (1 + x/2)
    if x <= 0:
        return 0.0
    return 1.0 - math.exp(-x / 2.0) * (1.0 + x / 2.0)


def _chi2_ppf_df2(p: float, *, iters: int = 80) -> float:
    # Numerically invert CDF for k=2 without scipy.
    p = float(p)
    if not (0.0 < p < 1.0):
        raise ValueError("p must be in (0,1)")
    lo, hi = 0.0, 1000.0
    for _ in range(iters):
        mid = (lo + hi) / 2.0
        if _chi2_cdf_df2(mid) < p:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2.0


@dataclass(frozen=True)
class SenderPoint:
    method: str
    sender_id: int
    x_overhead: float
    xerr: float
    y_delay_ms: float
    yerr: float


def _load_baseline_samples(
    *,
    results_csv: Path,
    file_bytes: int,
    methods: set[str],
    sender_ids: Optional[set[int]],
) -> Dict[Tuple[str, int], Tuple[List[float], List[float]]]:
    task_wanted = _desired_task(int(file_bytes))
    out: Dict[Tuple[str, int], Tuple[List[float], List[float]]] = {}

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

            sender = _to_int(row, "sender_id", 0)
            if sender_ids is not None and sender not in sender_ids:
                continue

            loss_mode = (row.get("loss_mode") or "").strip()
            if not loss_mode.startswith("gemodel:"):
                continue

            overhead = _to_float(row, "overhead_ratio", float("nan"))
            delay_ms = _to_float(row, "e2e_delay_ms", float("nan"))
            if not (math.isfinite(overhead) and overhead >= 0):
                continue
            if not (math.isfinite(delay_ms) and delay_ms > 0):
                continue

            ovs, ds = out.setdefault((method, int(sender)), ([], []))
            ovs.append(float(overhead))
            ds.append(float(delay_ms))

    return out


def _load_bandit_eval_samples(
    *,
    eval_jsonl: Path,
    sender_ids: Optional[set[int]],
) -> Dict[Tuple[str, int], Tuple[List[float], List[float]]]:
    out: Dict[Tuple[str, int], Tuple[List[float], List[float]]] = {}

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

            sender = int(d.get("sender_id", 0) or 0)
            if sender_ids is not None and sender not in sender_ids:
                continue

            loss_mode = (d.get("loss_mode") or "").strip()
            if not loss_mode.startswith("gemodel:"):
                continue

            env_info = d.get("env_info")
            if not isinstance(env_info, dict):
                continue
            if int(env_info.get("step_valid", 0) or 0) != 1:
                continue

            try:
                overhead = float(env_info.get("quic_overhead_ratio", float("nan")))
            except Exception:
                overhead = float("nan")
            try:
                delay_ms = float(env_info.get("e2e_delay_ms", float("nan")))
            except Exception:
                delay_ms = float("nan")

            if not (math.isfinite(overhead) and overhead >= 0):
                continue
            if not (math.isfinite(delay_ms) and delay_ms > 0):
                continue

            ovs, ds = out.setdefault(("bandit", int(sender)), ([], []))
            ovs.append(float(overhead))
            ds.append(float(delay_ms))

    return out


def _load_flec_ge_samples(
    *,
    flec_jsonl: Path,
    sender_ids: Optional[set[int]],
) -> Dict[Tuple[str, int], Tuple[List[float], List[float]]]:
    out: Dict[Tuple[str, int], Tuple[List[float], List[float]]] = {}
    if not flec_jsonl.exists():
        return out

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

            sender = int(d.get("sender", 0) or 0)
            if sender_ids is not None and sender not in sender_ids:
                continue

            if int(d.get("ok", 0) or 0) != 1:
                continue

            try:
                overhead = float(d.get("overhead", float("nan")))
            except Exception:
                overhead = float("nan")
            try:
                delay_ms = float(d.get("e2e_s", float("nan"))) * 1000.0
            except Exception:
                delay_ms = float("nan")

            if not (math.isfinite(overhead) and overhead >= 0):
                continue
            if not (math.isfinite(delay_ms) and delay_ms > 0):
                continue

            ovs, ds = out.setdefault(("flec", int(sender)), ([], []))
            ovs.append(float(overhead))
            ds.append(float(delay_ms))

    return out


def _sender_points_from_samples(
    *,
    samples: Dict[Tuple[str, int], Tuple[List[float], List[float]]],
    overhead_scale: float,
) -> List[SenderPoint]:
    pts: List[SenderPoint] = []
    for (method, sender), (ovs, ds) in samples.items():
        mu_o, ci_o = _mean_ci95(ovs)
        mu_d, ci_d = _mean_ci95(ds)
        if not (math.isfinite(mu_o) and math.isfinite(mu_d)):
            continue
        pts.append(
            SenderPoint(
                method=str(method),
                sender_id=int(sender),
                x_overhead=float(mu_o) * float(overhead_scale),
                xerr=float(ci_o) * float(overhead_scale) if math.isfinite(ci_o) else 0.0,
                y_delay_ms=float(mu_d),
                yerr=float(ci_d) if math.isfinite(ci_d) else 0.0,
            )
        )
    return pts


def _pareto_frontier(points: Sequence[SenderPoint]) -> List[SenderPoint]:
    """Pareto frontier minimizing (overhead, delay)."""
    pts = [p for p in points if math.isfinite(p.x_overhead) and math.isfinite(p.y_delay_ms)]
    pts.sort(key=lambda p: (p.x_overhead, p.y_delay_ms))

    frontier: List[SenderPoint] = []
    best_delay = float("inf")
    for p in pts:
        if p.y_delay_ms < best_delay - 1e-12:
            frontier.append(p)
            best_delay = p.y_delay_ms
    return frontier


def _add_cov_ellipse(
    ax: plt.Axes,
    xs: Sequence[float],
    ys: Sequence[float],
    *,
    level: float,
    color: str,
    alpha: float,
    linewidth: float,
    zorder: float,
) -> None:
    # Covariance ellipse for point cloud (not CI of the mean).
    x = np.asarray(xs, dtype=float)
    y = np.asarray(ys, dtype=float)
    ok = np.isfinite(x) & np.isfinite(y)
    x = x[ok]
    y = y[ok]
    if x.size < 3:
        return

    cov = np.cov(np.vstack([x, y]), ddof=1)
    if not np.all(np.isfinite(cov)):
        return

    mean_x = float(np.mean(x))
    mean_y = float(np.mean(y))

    # Eigen-decomposition.
    vals, vecs = np.linalg.eigh(cov)
    order = np.argsort(vals)[::-1]
    vals = vals[order]
    vecs = vecs[:, order]
    vals = np.maximum(vals, 0.0)

    # Scale by chi-square quantile for 2D.
    q = _chi2_ppf_df2(float(level))
    width = 2.0 * math.sqrt(float(vals[0]) * q)
    height = 2.0 * math.sqrt(float(vals[1]) * q)
    angle = math.degrees(math.atan2(float(vecs[1, 0]), float(vecs[0, 0])))

    e = Ellipse(
        (mean_x, mean_y),
        width=width,
        height=height,
        angle=angle,
        facecolor=color,
        edgecolor=color,
        alpha=alpha,
        linewidth=linewidth,
        fill=True,
        zorder=zorder,
    )
    ax.add_patch(e)


def _plot_tradeoff(
    *,
    out_path: Path,
    points: List[SenderPoint],
    methods_order: List[str],
    overhead_is_percent: bool,
    title: str,
    ellipse_level: float,
    scatter_alpha: float,
) -> None:
    _configure_matplotlib()
    fig, ax = plt.subplots(figsize=(5.0, 2.8))

    # Draw per-method sender points as semi-transparent scatter,
    # plus one center point + covariance ellipse.
    for method in methods_order:
        pts_m = [p for p in points if p.method == method]
        if not pts_m:
            continue
        color = _METHOD_COLORS.get(method, None)
        marker = _METHOD_MARKERS.get(method, ".")
        label = _METHOD_LABELS.get(method, method)

        xs = [p.x_overhead for p in pts_m]
        ys = [p.y_delay_ms for p in pts_m]

        ax.scatter(
            xs,
            ys,
            s=7,
            c=color,
            marker=marker,
            linewidths=0.8,
            alpha=float(scatter_alpha),
            label=None,
            zorder=2,
        )

        # Center point: mean of per-sender means.
        cx = float(np.mean(np.asarray(xs, dtype=float)))
        cy = float(np.mean(np.asarray(ys, dtype=float)))
        ax.scatter(
            [cx],
            [cy],
            s=28,
            c=color,
            marker="o",
            linewidths=0.9,
            edgecolors="black",
            alpha=0.95,
            label=label,
            zorder=4,
        )

        # 2D covariance ellipse (e.g., 68% level).
        _add_cov_ellipse(
            ax,
            xs,
            ys,
            level=float(ellipse_level),
            color=color,
            alpha=0.16,
            linewidth=0.8,
            zorder=1,
        )

    ax.set_xlabel("Overhead Ratio (%)" if overhead_is_percent else "Overhead Ratio")
    ax.set_ylabel("E2E delay (ms)")
    # Intentionally no title (paper-style).

    ax.grid(True, linestyle="--", alpha=0.3)
    ax.legend(loc="upper left", bbox_to_anchor=(1.02, 1.0), borderaxespad=0.0, frameon=True)

    fig.subplots_adjust(right=0.78)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, bbox_inches="tight")
    if out_path.suffix.lower() != ".png":
        fig.savefig(out_path.with_suffix(".png"), bbox_inches="tight")
    plt.close(fig)


def main() -> int:
    ap = argparse.ArgumentParser(
        description=(
            "GE tradeoff (mean overhead vs mean delay) per sender with 95% CI error bars, "
            "and Pareto frontier. Each point is one sender's averaged samples across GE params."
        )
    )
    ap.add_argument("--baseline-in-dir", type=str, required=True, help="Directory containing results.csv")
    ap.add_argument("--bandit-eval-log", type=str, default="", help="bandit_eval_metrics.jsonl for BCIR")
    ap.add_argument("--flec-jsonl", type=str, default="", help="Optional explicit FLEC GE jsonl")
    ap.add_argument("--flec-dir", type=str, default="", help="Directory containing flec_GE_128k.jsonl / flec_GE_1m.jsonl")
    ap.add_argument("--out", type=str, required=True, help="Output PDF path")
    ap.add_argument("--file-bytes", type=int, default=128 * 1024)
    ap.add_argument("--sender-ids", type=str, default="", help="Comma-separated sender ids to include")
    ap.add_argument("--methods", type=str, default=",".join(_METHOD_ORDER_DEFAULT))
    ap.add_argument("--no-percent", action="store_true", help="Do not multiply overhead by 100")
    ap.add_argument("--title", type=str, default="")
    ap.add_argument(
        "--ellipse-level",
        type=float,
        default=0.68,
        help="Covariance ellipse level (default: 0.68 for ~1-sigma in 2D)",
    )
    ap.add_argument(
        "--scatter-alpha",
        type=float,
        default=0.32,
        help="Alpha for per-sender scatter points (default: 0.32)",
    )

    args = ap.parse_args()

    baseline_in_dir = Path(str(args.baseline_in_dir))
    results_csv = baseline_in_dir / "results.csv"
    if not results_csv.exists():
        raise SystemExit(f"missing baseline results.csv: {results_csv}")

    out_path = Path(str(args.out))

    sender_ids: Optional[set[int]] = None
    if str(args.sender_ids or "").strip():
        sender_ids = {int(x.strip()) for x in str(args.sender_ids).split(",") if x.strip()}

    methods = [m.strip() for m in str(args.methods).split(",") if m.strip()]
    methods_set = set(methods)

    overhead_scale = 1.0 if bool(args.no_percent) else 100.0

    samples: Dict[Tuple[str, int], Tuple[List[float], List[float]]] = {}

    baseline_samples = _load_baseline_samples(
        results_csv=results_csv,
        file_bytes=int(args.file_bytes),
        methods=methods_set,
        sender_ids=sender_ids,
    )
    samples.update(baseline_samples)

    if str(args.bandit_eval_log or "").strip() and "bandit" in methods_set:
        bandit_samples = _load_bandit_eval_samples(eval_jsonl=Path(str(args.bandit_eval_log)), sender_ids=sender_ids)
        for k, v in bandit_samples.items():
            ovs, ds = samples.setdefault(k, ([], []))
            ovs.extend(v[0])
            ds.extend(v[1])

    if "flec" in methods_set:
        flec_path = Path(str(args.flec_jsonl)) if str(args.flec_jsonl or "").strip() else None
        if flec_path is None:
            flec_dir = str(args.flec_dir or "").strip()
            if flec_dir:
                flec_path = Path(flec_dir) / ("flec_GE_1m.jsonl" if int(args.file_bytes) >= 1024 * 1024 else "flec_GE_128k.jsonl")

        if flec_path is not None and flec_path.exists():
            flec_samples = _load_flec_ge_samples(flec_jsonl=flec_path, sender_ids=sender_ids)
            for k, v in flec_samples.items():
                ovs, ds = samples.setdefault(k, ([], []))
                ovs.extend(v[0])
                ds.extend(v[1])

    points = _sender_points_from_samples(samples=samples, overhead_scale=overhead_scale)
    if not points:
        raise SystemExit("no sender points")

    methods_ordered = [m for m in _METHOD_ORDER_DEFAULT if m in methods]
    methods_ordered.extend([m for m in methods if m not in methods_ordered])

    _plot_tradeoff(
        out_path=out_path,
        points=points,
        methods_order=methods_ordered,
        overhead_is_percent=not bool(args.no_percent),
        title=str(args.title or ""),
        ellipse_level=float(args.ellipse_level),
        scatter_alpha=float(args.scatter_alpha),
    )

    # Sanity print counts per method.
    for m in methods_ordered:
        n = sum(1 for p in points if p.method == m)
        if n:
            print(f"{m}: senders={n}")
    print(f"OUT: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
