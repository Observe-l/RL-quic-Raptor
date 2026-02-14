#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import math
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402


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


_UNIFORM_BLUE = "#1f77b4"


def _configure_matplotlib() -> None:
    plt.style.use("default")
    plt.rcParams.update(
        {
            "figure.figsize": (4.8, 2.6),
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


def _mean_finite(xs: Sequence[float]) -> Optional[float]:
    vals = [float(x) for x in xs if isinstance(x, (int, float)) and math.isfinite(float(x))]
    if not vals:
        return None
    return float(np.mean(vals))


def _load_baseline_overhead(
    *,
    results_csv: Path,
    file_bytes: int,
    methods: set[str],
    sender_ids: Optional[set[int]],
    loss_modes: Optional[set[str]],
) -> Dict[Tuple[str, int, str], List[float]]:
    """Return overhead samples keyed by (method, sender_id, ge_param_str)."""

    task_wanted = _desired_task(int(file_bytes))
    out: Dict[Tuple[str, int, str], List[float]] = {}

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
            if loss_modes is not None and loss_mode not in loss_modes:
                continue

            overhead = _to_float(row, "overhead_ratio", float("nan"))
            if not math.isfinite(float(overhead)) or overhead < 0:
                continue

            out.setdefault((method, int(sender), loss_mode), []).append(float(overhead))

    return out


def _load_bandit_eval_overhead(
    *,
    eval_jsonl: Path,
    sender_ids: Optional[set[int]],
    loss_modes: Optional[set[str]],
) -> Dict[Tuple[str, int, str], List[float]]:
    """Bandit eval overhead keyed by (bandit, sender_id, ge_param_str)."""

    out: Dict[Tuple[str, int, str], List[float]] = {}
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
            if loss_modes is not None and loss_mode not in loss_modes:
                continue

            env_info = d.get("env_info")
            if not isinstance(env_info, dict):
                continue
            if int(env_info.get("step_valid", 0) or 0) != 1:
                continue

            qov = env_info.get("quic_overhead_ratio", None)
            try:
                overhead = float(qov) if qov is not None else float("nan")
            except Exception:
                overhead = float("nan")
            if not math.isfinite(float(overhead)) or overhead < 0:
                continue

            out.setdefault(("bandit", int(sender), loss_mode), []).append(float(overhead))

    return out


def _format_ge_loss_mode(*, p_pct: float, r_pct: float, rtt_ms: float) -> str:
    # Match baseline formatting: gemodel:1.905626,10.377358,0.000000,99.000000
    return f"gemodel:{p_pct:.6f},{r_pct:.6f},0.000000,{float(rtt_ms):.6f}"


def _load_flec_ge_overhead(
    *,
    flec_jsonl: Path,
    sender_ids: Optional[set[int]],
    loss_modes: Optional[set[str]],
) -> Dict[Tuple[str, int, str], List[float]]:
    out: Dict[Tuple[str, int, str], List[float]] = {}
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
                p_pct = float(d.get("p_pct", float("nan")))
                r_pct = float(d.get("r_pct", float("nan")))
                rtt_ms = float(d.get("rtt_ms", float("nan")))
            except Exception:
                continue
            if not (math.isfinite(p_pct) and math.isfinite(r_pct) and math.isfinite(rtt_ms)):
                continue

            loss_mode = _format_ge_loss_mode(p_pct=p_pct, r_pct=r_pct, rtt_ms=rtt_ms)
            if loss_modes is not None and loss_mode not in loss_modes:
                continue

            try:
                overhead = float(d.get("overhead", float("nan")))
            except Exception:
                overhead = float("nan")
            if not math.isfinite(float(overhead)) or overhead < 0:
                continue

            out.setdefault(("flec", int(sender), loss_mode), []).append(float(overhead))

    return out


def _collapse_to_vehicle_means(
    samples_by_vehicle: Dict[Tuple[str, int, str], List[float]]
) -> Dict[str, List[float]]:
    """Collapse 30 reps into mean per (sender, ge_param), then group by method."""

    by_method: Dict[str, List[float]] = {}
    for (method, _sender, _ge), xs in samples_by_vehicle.items():
        mu = _mean_finite(xs)
        if mu is None:
            continue
        by_method.setdefault(method, []).append(float(mu))
    return by_method


def _boxplot(
    *,
    out_path: Path,
    by_method: Dict[str, List[float]],
    methods_order: List[str],
    y_percent: bool,
    title: str,
) -> None:
    _configure_matplotlib()
    fig, ax = plt.subplots(figsize=(4.8, 2.6))

    data: List[List[float]] = []
    labels: List[str] = []
    colors: List[str] = []
    for m in methods_order:
        xs = by_method.get(m, [])
        if not xs:
            continue
        ys = [float(x) * 100.0 for x in xs] if y_percent else [float(x) for x in xs]
        data.append(ys)
        labels.append(_METHOD_LABELS.get(m, m))
        colors.append(_UNIFORM_BLUE)

    bp = ax.boxplot(
        data,
        patch_artist=True,
        widths=0.55,
        showfliers=False,
        whis=1.5,
        medianprops={"color": "black", "linewidth": 1.0},
        boxprops={"linewidth": 0.9},
        whiskerprops={"linewidth": 0.9},
        capprops={"linewidth": 0.9},
        flierprops={"marker": ".", "markersize": 2.0, "markerfacecolor": "0.25", "markeredgecolor": "0.25", "alpha": 0.6},
    )

    for patch, c in zip(bp["boxes"], colors):
        patch.set_facecolor(c)
        patch.set_alpha(1.0)
        patch.set_edgecolor(c)

    ax.set_xticklabels(labels)
    ax.set_ylabel("Overhead Ratio (%)" if y_percent else "Overhead Ratio")
    # Intentionally no title (paper-style).
    ax.grid(True, axis="y", linestyle="--", alpha=0.3)

    fig.subplots_adjust(bottom=0.22)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, bbox_inches="tight")
    if out_path.suffix.lower() != ".png":
        fig.savefig(out_path.with_suffix(".png"), bbox_inches="tight")
    plt.close(fig)


def main() -> int:
    ap = argparse.ArgumentParser(
        description=(
            "GE overhead boxplot. Each (sender_id, GE parameter) is treated as one vehicle; "
            "overhead is averaged across reps, then boxplotted per method."
        )
    )
    ap.add_argument("--baseline-in-dir", type=str, required=True, help="Directory containing results.csv")
    ap.add_argument("--bandit-eval-log", type=str, default="", help="bandit_eval_metrics.jsonl for BCIR")
    ap.add_argument("--flec-jsonl", type=str, default="", help="Optional explicit FLEC GE jsonl")
    ap.add_argument("--flec-dir", type=str, default="", help="Directory containing flec_GE_128k.jsonl / flec_GE_1m.jsonl")
    ap.add_argument("--out", type=str, required=True, help="Output PDF path")
    ap.add_argument("--file-bytes", type=int, default=128 * 1024)
    ap.add_argument("--sender-ids", type=str, default="", help="Comma-separated sender ids to include")
    ap.add_argument(
        "--loss-modes",
        type=str,
        default="",
        help="Semicolon-separated GE loss_mode strings to include (exact match).",
    )
    ap.add_argument(
        "--loss-mode",
        action="append",
        default=[],
        help="Repeatable: GE loss_mode string to include (exact match).",
    )
    ap.add_argument("--methods", type=str, default=",".join(_METHOD_ORDER_DEFAULT))
    ap.add_argument("--no-percent", action="store_true", help="Do not multiply overhead by 100")
    ap.add_argument("--title", type=str, default="")

    args = ap.parse_args()

    baseline_in_dir = Path(str(args.baseline_in_dir))
    results_csv = baseline_in_dir / "results.csv"
    if not results_csv.exists():
        raise SystemExit(f"missing baseline results.csv: {results_csv}")

    out_path = Path(str(args.out))

    sender_ids: Optional[set[int]] = None
    if str(args.sender_ids or "").strip():
        sender_ids = {int(x.strip()) for x in str(args.sender_ids).split(",") if x.strip()}

    loss_modes: Optional[set[str]] = None
    loss_modes_list: List[str] = []
    loss_modes_list.extend([str(x).strip() for x in (args.loss_mode or []) if str(x).strip()])
    if str(args.loss_modes or "").strip():
        loss_modes_list.extend([x.strip() for x in str(args.loss_modes).split(";") if x.strip()])
    if loss_modes_list:
        loss_modes = set(loss_modes_list)

    methods = [m.strip() for m in str(args.methods).split(",") if m.strip()]
    methods_set = set(methods)

    samples: Dict[Tuple[str, int, str], List[float]] = {}

    samples.update(
        _load_baseline_overhead(
            results_csv=results_csv,
            file_bytes=int(args.file_bytes),
            methods=methods_set,
            sender_ids=sender_ids,
            loss_modes=loss_modes,
        )
    )

    if str(args.bandit_eval_log or "").strip() and "bandit" in methods_set:
        bandit_samples = _load_bandit_eval_overhead(
            eval_jsonl=Path(str(args.bandit_eval_log)),
            sender_ids=sender_ids,
            loss_modes=loss_modes,
        )
        for k, v in bandit_samples.items():
            samples.setdefault(k, []).extend(v)

    if "flec" in methods_set:
        flec_path = Path(str(args.flec_jsonl)) if str(args.flec_jsonl or "").strip() else None
        if flec_path is None:
            flec_dir = str(args.flec_dir or "").strip()
            if flec_dir:
                flec_path = Path(flec_dir) / ("flec_GE_1m.jsonl" if int(args.file_bytes) >= 1024 * 1024 else "flec_GE_128k.jsonl")

        if flec_path is not None and flec_path.exists():
            flec_samples = _load_flec_ge_overhead(
                flec_jsonl=flec_path,
                sender_ids=sender_ids,
                loss_modes=loss_modes,
            )
            for k, v in flec_samples.items():
                samples.setdefault(k, []).extend(v)

    by_method = _collapse_to_vehicle_means(samples)

    methods_ordered = [m for m in _METHOD_ORDER_DEFAULT if m in methods]
    methods_ordered.extend([m for m in methods if m not in methods_ordered])

    _boxplot(
        out_path=out_path,
        by_method=by_method,
        methods_order=methods_ordered,
        y_percent=not bool(args.no_percent),
        title=str(args.title or ""),
    )

    # Quick sanity print.
    for m in methods_ordered:
        xs = by_method.get(m, [])
        if not xs:
            continue
        print(f"{m}: vehicles={len(xs)} mean_overhead={float(np.mean(xs)):.6f}")

    print(f"OUT: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
