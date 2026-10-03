#!/usr/bin/env python3
"""Recreate the two IID overhead figures and include FLEC-RQ.

The existing ``iid-100k-overhead.png`` figure is backed by 128 KiB runs;
this script deliberately keeps those source series and adds the matching
128 KiB FLEC-RQ data rather than changing the figure's existing comparison.
"""
from __future__ import annotations

import csv
import json
import math
from collections import defaultdict
from pathlib import Path
from statistics import fmean
from typing import DefaultDict, Dict, Iterable, List, Tuple

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402


ROOT = Path(__file__).resolve().parents[2]
FIGURES = ROOT / "figures" / "vary_density"
LOSS_LEVELS = (0.1, 0.2, 0.3, 0.4, 0.5)

SERIES = (
    ("BC-DIR", "#E7B05D", "^"),
    ("FLEC", "#86AFC1", "X"),
    ("FLEC-RQ", "#A6C97A", "P"),
    ("QUIC", "#D1B98C", "D"),
)


def _loss_value(value: object) -> float | None:
    try:
        loss = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(loss):
        return None
    return loss


def _iid_loss_mode(value: object) -> float | None:
    text = str(value or "").strip().lower()
    if not text.startswith("iid:"):
        return None
    return _loss_value(text.split(":", 1)[1])


def _mean_by_loss(rows: Iterable[Tuple[float, float]]) -> Dict[float, List[float]]:
    grouped: DefaultDict[float, List[float]] = defaultdict(list)
    for loss, overhead in rows:
        if loss in LOSS_LEVELS and math.isfinite(overhead) and overhead >= 0:
            grouped[loss].append(overhead)
    return dict(grouped)


def _read_bandit(path: Path, file_bytes: int) -> Dict[float, List[float]]:
    rows: List[Tuple[float, float]] = []
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            record = json.loads(line)
            env = record.get("env_info")
            if not isinstance(env, dict) or int(env.get("step_valid", 0) or 0) != 1:
                continue
            try:
                actual_size = int(record.get("file_bytes", 0) or 0)
            except (TypeError, ValueError):
                continue
            if actual_size != file_bytes:
                continue
            loss = _iid_loss_mode(record.get("loss_mode"))
            if loss is None:
                net_params = env.get("net_params")
                loss = _iid_loss_mode(net_params.get("loss_mode")) if isinstance(net_params, dict) else None
            try:
                overhead = float(env["quic_overhead_ratio"])
            except (KeyError, TypeError, ValueError):
                continue
            if loss is not None:
                rows.append((loss, overhead))
    return _mean_by_loss(rows)


def _read_quic(path: Path, task: str) -> Dict[float, List[float]]:
    rows: List[Tuple[float, float]] = []
    with path.open(encoding="utf-8", newline="") as stream:
        for record in csv.DictReader(stream):
            if record.get("task") != task or record.get("method") != "quic_bbrv2":
                continue
            if record.get("success") != "1":
                continue
            loss = _iid_loss_mode(record.get("loss_mode"))
            try:
                overhead = float(record["overhead_ratio"])
            except (KeyError, TypeError, ValueError):
                continue
            if loss is not None:
                rows.append((loss, overhead))
    return _mean_by_loss(rows)


def _read_flec(path: Path, file_bytes: int) -> Dict[float, List[float]]:
    """Use the same plugin-payload-excluded overhead measure for both FLECs."""
    rows: List[Tuple[float, float]] = []
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            record = json.loads(line)
            try:
                size = int(record.get("tx_data_bytes", record.get("file_bytes", 0)) or 0)
                ok = int(record.get("ok", 0) or 0)
                loss = _loss_value(record.get("loss_pct", record.get("p_pct")))
                overhead = float(record["overhead_attempted_minus_plugin_payload"])
            except (KeyError, TypeError, ValueError):
                continue
            if size != file_bytes or ok != 1 or loss is None:
                continue
            rows.append((loss, overhead))
    return _mean_by_loss(rows)


def _validate(name: str, grouped: Dict[float, List[float]]) -> None:
    missing = [loss for loss in LOSS_LEVELS if not grouped.get(loss)]
    if missing:
        raise RuntimeError(f"{name}: no valid observations for IID loss {missing}")


def _configure_style() -> None:
    plt.style.use("default")
    plt.rcParams.update(
        {
            "font.family": "serif",
            "font.serif": ["Times New Roman", "Nimbus Roman", "DejaVu Serif"],
            "figure.figsize": (3.8, 2.4),
            "figure.facecolor": "white",
            "axes.facecolor": "white",
            "savefig.facecolor": "white",
            "axes.edgecolor": "black",
            "axes.linewidth": 0.55,
            "axes.grid": True,
            "axes.axisbelow": True,
            "grid.color": "#999999",
            "grid.linestyle": (0, (1.2, 2.2)),
            "grid.linewidth": 0.65,
            "grid.alpha": 0.9,
            "lines.linewidth": 1.8,
            "font.size": 8,
            "axes.labelsize": 9,
            "xtick.labelsize": 7.5,
            "ytick.labelsize": 7.5,
            "legend.fontsize": 8.2,
            "xtick.direction": "in",
            "ytick.direction": "in",
            "xtick.major.size": 2.0,
            "ytick.major.size": 2.0,
        }
    )


def _plot(output: Path, series: Dict[str, Dict[float, List[float]]]) -> None:
    _configure_style()
    fig, ax = plt.subplots(figsize=(3.8, 2.4))

    for label, color, marker in SERIES:
        grouped = series[label]
        means = [fmean(grouped[loss]) for loss in LOSS_LEVELS]
        ax.plot(
            LOSS_LEVELS,
            means,
            label=label,
            color=color,
            marker=marker,
            linewidth=1.8,
            markersize=5.5,
            markeredgewidth=0.5,
        )

    ax.set_xticks(LOSS_LEVELS, [f"{loss:.1f}" for loss in LOSS_LEVELS])
    ax.set_xlabel("IID loss rate (%)")
    ax.set_ylabel("Mean overhead ratio")
    ax.legend(
        loc="center right",
        bbox_to_anchor=(1.0, 0.64),
        frameon=True,
        fancybox=False,
        framealpha=1.0,
        facecolor="white",
        edgecolor="#aaaaaa",
        borderaxespad=0.6,
        borderpad=0.45,
        labelspacing=0.45,
        handlelength=2.0,
    )
    ax.get_legend().get_frame().set_linewidth(0.5)

    # Keep the canvas and axes placement consistent with the existing PNGs.
    fig.subplots_adjust(left=0.13, right=0.97, top=0.95, bottom=0.18)
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=400)
    plt.close(fig)


def _load_figure_data(size_tag: str, file_bytes: int, task: str) -> Dict[str, Dict[float, List[float]]]:
    results = ROOT / "python" / "results"
    if size_tag == "128k":
        bandit = results / "iid-128k-bandit-data-48827" / "bandit_eval_metrics.jsonl"
        quic = results / "iid-128k-baseline-data" / "results.csv"
    else:
        bandit = results / "iid-1m-bandit-data-49365" / "bandit_eval_metrics.jsonl"
        quic = results / "iid-1m-baseline-data" / "results.csv"

    flec_dir = results / "flec_data"
    series = {
        "BC-DIR": _read_bandit(bandit, file_bytes),
        "FLEC": _read_flec(flec_dir / f"flec_iid_{size_tag}.jsonl", file_bytes),
        "FLEC-RQ": _read_flec(flec_dir / f"flec_raptorq_iid_{size_tag}.jsonl", file_bytes),
        "QUIC": _read_quic(quic, task),
    }
    for name, grouped in series.items():
        _validate(f"{size_tag} {name}", grouped)
    return series


def main() -> None:
    specs = (
        ("128k", 128 * 1024, "delay_128kb", "iid-100k-overhead.png"),
        ("1m", 1024 * 1024, "file_1048576B", "iid-1m-overhead.png"),
    )
    for size_tag, file_bytes, task, filename in specs:
        series = _load_figure_data(size_tag, file_bytes, task)
        print(f"{filename}:")
        for label, _, _ in SERIES:
            grouped = series[label]
            stats = [
                f"{loss:.1f}: {fmean(grouped[loss]):.6f} (n={len(grouped[loss])})"
                for loss in LOSS_LEVELS
            ]
            print(f"  {label}: " + ", ".join(stats))
        _plot(FIGURES / filename, series)
        print(f"  saved: {FIGURES / filename}")


if __name__ == "__main__":
    main()
