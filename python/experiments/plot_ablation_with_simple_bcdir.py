#!/usr/bin/env python3
"""Rebuild ablation figures with the latest simple-BBRv2 fixed BC-DIR run.

Completion is pooled over all trials (failures remain in the denominator).
Overhead is averaged over successful trials per sender, then shown as a
distribution across senders, matching the existing ablation figures' grain.
"""

from __future__ import annotations

import argparse
import csv
import math
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Sequence

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DIR = ROOT / "python/results/vary_density"
DEFAULT_FIGURES = ROOT / "figures/vary_density"
DEADLINES_MS = (200, 300, 400, 500)
METHODS = (
    ("BC-DIR", "#E7B05D"),
    ("Fixed BC-DIR", "#C8893C"),
    ("DIR-only", "#A6C97A"),
    ("FEC-only", "#B8A3C7"),
    ("QUIC", "#D1B98C"),
)


def read_method(path: Path, method: str) -> List[Dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8") as source:
        rows = [row for row in csv.DictReader(source) if row.get("method") == method]
    if not rows:
        raise ValueError(f"no rows for method {method!r} in {path}")

    keys = [(row["sender_id"], row["rep"]) for row in rows]
    if len(keys) != len(set(keys)):
        raise ValueError(f"{path}: duplicate sender/rep keys for {method}")
    per_sender = Counter(row["sender_id"] for row in rows)
    if len(per_sender) != 61 or set(per_sender.values()) != {30}:
        raise ValueError(
            f"{path}: expected 61 senders x 30 trials for {method}, "
            f"found {len(per_sender)} senders and repetition counts "
            f"{sorted(set(per_sender.values()))}"
        )
    return rows


def _completion(rows: Sequence[Dict[str, str]], deadline_ms: int) -> tuple[int, int, float]:
    completed = 0
    for row in rows:
        try:
            delay = float(row.get("e2e_delay_ms", "nan"))
            success = int(float(row.get("success", "0") or 0)) == 1
        except (TypeError, ValueError):
            continue
        if success and math.isfinite(delay) and 0 < delay <= deadline_ms:
            completed += 1
    return completed, len(rows), completed / len(rows)


def draw_completion(
    series: Dict[str, List[Dict[str, str]]], out_path: Path
) -> Dict[str, Dict[int, tuple[int, int, float]]]:
    fig, ax = plt.subplots(figsize=(14, 12), dpi=100)
    centers = np.arange(len(DEADLINES_MS), dtype=float)
    width = 0.115
    offsets = np.linspace(-0.32, 0.32, len(METHODS))
    results: Dict[str, Dict[int, tuple[int, int, float]]] = {}

    for index, (label, color) in enumerate(METHODS):
        rows = series[label]
        results[label] = {}
        heights = []
        for deadline in DEADLINES_MS:
            result = _completion(rows, deadline)
            results[label][deadline] = result
            heights.append(result[2])
        ax.bar(
            centers + offsets[index],
            heights,
            width=width,
            color=color,
            edgecolor="black",
            linewidth=1.7,
            label=label,
            zorder=3,
        )

    ax.set_xlim(-0.5, len(DEADLINES_MS) - 0.5)
    ax.set_ylim(0.0, 1.02)
    ax.set_xticks(centers, [str(deadline) for deadline in DEADLINES_MS])
    ax.set_yticks(np.linspace(0, 1, 6))
    ax.set_xlabel("Transmission Deadline (ms)", fontsize=36, labelpad=18)
    ax.set_ylabel("Completion ratio", fontsize=36, labelpad=20)
    ax.tick_params(
        axis="both", labelsize=31, width=2.2, length=7, pad=8, direction="in"
    )
    ax.set_axisbelow(True)
    ax.grid(
        True,
        which="major",
        axis="both",
        color="#9B9B9B",
        linestyle=(0, (1.2, 2.2)),
        linewidth=1.6,
    )
    for spine in ax.spines.values():
        spine.set_linewidth(2.4)
        spine.set_color("black")
    legend = ax.legend(
        loc="upper left",
        bbox_to_anchor=(0.02, 0.98),
        fontsize=30,
        frameon=True,
        fancybox=False,
        borderpad=0.45,
        labelspacing=0.45,
        handlelength=1.7,
        handletextpad=0.55,
    )
    legend.get_frame().set_facecolor("white")
    legend.get_frame().set_edgecolor("#BDBDBD")
    legend.get_frame().set_linewidth(1.5)
    legend.get_frame().set_alpha(0.96)
    fig.subplots_adjust(left=0.155, right=0.967, bottom=0.17, top=0.955)
    fig.savefig(out_path, dpi=100, facecolor="white")
    plt.close(fig)
    return results


def sender_mean_success_overhead(rows: Iterable[Dict[str, str]]) -> List[float]:
    grouped: Dict[str, List[float]] = defaultdict(list)
    for row in rows:
        try:
            if int(float(row.get("success", "0") or 0)) != 1:
                continue
            value = float(row.get("overhead_ratio", "nan"))
        except (TypeError, ValueError):
            continue
        if math.isfinite(value) and value >= 0:
            grouped[row["sender_id"]].append(value)
    return [float(np.mean(values)) for _, values in sorted(grouped.items()) if values]


def _quantile(values: Sequence[float], p: float) -> float:
    return float(np.quantile(values, p)) if values else math.nan


def draw_overhead(
    series: Dict[str, List[Dict[str, str]]], out_path: Path
) -> Dict[str, Dict[str, float]]:
    fig, ax = plt.subplots(figsize=(15.2, 9.6), dpi=100)
    values = [sender_mean_success_overhead(series[label]) for label, _ in METHODS]
    colors = [color for _, color in METHODS]
    boxplot = ax.boxplot(
        values,
        patch_artist=True,
        widths=0.55,
        whis=1.5,
        showfliers=False,
        medianprops={"color": "black", "linewidth": 2.8},
        whiskerprops={"color": "black", "linewidth": 2.8},
        capprops={"color": "black", "linewidth": 2.8},
        boxprops={"edgecolor": "black", "linewidth": 2.8},
    )
    for patch, color in zip(boxplot["boxes"], colors):
        patch.set_facecolor(color)
        patch.set_alpha(1.0)

    labels = ["BC-DIR", "Fixed\nBC-DIR", "DIR-only", "FEC-only", "QUIC"]
    ax.set_xticks(np.arange(1, len(labels) + 1), labels)
    upper_whiskers = []
    for samples in values:
        q1, q3 = np.quantile(samples, [0.25, 0.75])
        upper_fence = q3 + 1.5 * (q3 - q1)
        upper_whiskers.append(max(value for value in samples if value <= upper_fence))
    y_max = max(1.77, math.ceil((max(upper_whiskers) + 0.2) / 0.25) * 0.25)
    ax.set_ylim(0.0, y_max)
    ax.set_yticks(np.arange(0.0, y_max + 0.001, 0.25))
    ax.set_xlabel("Method", fontsize=36, labelpad=19)
    ax.set_ylabel("Overhead ratio", fontsize=36, labelpad=19)
    ax.tick_params(
        axis="both", labelsize=31, width=2.2, length=7, pad=8, direction="in"
    )
    ax.set_axisbelow(True)
    ax.grid(
        True,
        which="major",
        axis="y",
        color="#9B9B9B",
        linestyle=(0, (1.2, 2.2)),
        linewidth=1.6,
    )
    for spine in ax.spines.values():
        spine.set_linewidth(2.4)
        spine.set_color("black")
    fig.subplots_adjust(left=0.142, right=0.968, bottom=0.278, top=0.95)
    fig.savefig(out_path, dpi=100, facecolor="white")
    plt.close(fig)

    summary: Dict[str, Dict[str, float]] = {}
    for (label, _), sender_values in zip(METHODS, values):
        summary[label] = {
            "sender_count": len(sender_values),
            "q1": _quantile(sender_values, 0.25),
            "median": _quantile(sender_values, 0.5),
            "q3": _quantile(sender_values, 0.75),
        }
    return summary


def write_summary(
    path: Path,
    completion: Dict[str, Dict[int, tuple[int, int, float]]],
    overhead: Dict[str, Dict[str, float]],
    source_by_method: Dict[str, Path],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    columns = (
        "metric",
        "method",
        "threshold_ms",
        "count",
        "denominator",
        "value",
        "successful_senders",
        "q1",
        "median",
        "q3",
        "source_csv",
    )
    with path.open("w", newline="", encoding="utf-8") as target:
        writer = csv.writer(target)
        writer.writerow(columns)
        for label, _ in METHODS:
            for deadline, (count, denominator, ratio) in completion[label].items():
                writer.writerow(
                    (
                        "completion",
                        label,
                        deadline,
                        count,
                        denominator,
                        ratio,
                        "",
                        "",
                        "",
                        "",
                        source_by_method[label],
                    )
                )
            stats = overhead[label]
            writer.writerow(
                (
                    "overhead_sender_mean_success_only",
                    label,
                    "",
                    "",
                    "",
                    "",
                    stats["sender_count"],
                    stats["q1"],
                    stats["median"],
                    stats["q3"],
                    source_by_method[label],
                )
            )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--bandit-csv",
        type=Path,
        default=DEFAULT_DIR / "ge-128k-bandit-data-48328/bandit_eval_results.csv",
    )
    parser.add_argument(
        "--simple-fixed-csv",
        type=Path,
        default=DEFAULT_DIR
        / "ge-128k-simple-bbrv2-k40-r10-dr10-61x30-21par-20261001/bandit_eval_results.csv",
    )
    parser.add_argument(
        "--baseline-csv",
        type=Path,
        default=DEFAULT_DIR / "40&10-ge-128k-baseline/results.pre-fixed-bc-dir-20260930.csv",
    )
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_FIGURES)
    parser.add_argument(
        "--summary-csv",
        type=Path,
        default=DEFAULT_DIR / "ablation_fixed_bcdir_summary.csv",
    )
    args = parser.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    series = {
        "BC-DIR": read_method(args.bandit_csv, "bandit"),
        "Fixed BC-DIR": read_method(args.simple_fixed_csv, "fixed_bc_dir_k40_r10_dr10"),
        "DIR-only": read_method(args.baseline_csv, "fec_k40_r0_0_rstep_10"),
        "FEC-only": read_method(args.baseline_csv, "fec_k40_r0_10_rstep_0"),
        "QUIC": read_method(args.baseline_csv, "quic_bbrv2"),
    }

    fixed_rows = series["Fixed BC-DIR"]
    for row in fixed_rows:
        if (int(row["K"]), int(row["R0"]), int(row["RSTEP"])) != (40, 10, 10):
            raise ValueError("latest Fixed BC-DIR input includes an unexpected FEC action")

    plt.rcParams.update(
        {
            "font.family": "serif",
            "font.serif": ["DejaVu Serif"],
            "axes.unicode_minus": False,
            "savefig.facecolor": "white",
        }
    )
    completion = draw_completion(series, args.out_dir / "ablation-completion.png")
    overhead = draw_overhead(series, args.out_dir / "ablation-overhead.png")
    source_by_method = {
        "BC-DIR": args.bandit_csv,
        "Fixed BC-DIR": args.simple_fixed_csv,
        "DIR-only": args.baseline_csv,
        "FEC-only": args.baseline_csv,
        "QUIC": args.baseline_csv,
    }
    write_summary(args.summary_csv, completion, overhead, source_by_method)

    print(f"wrote {args.out_dir / 'ablation-completion.png'}")
    print(f"wrote {args.out_dir / 'ablation-overhead.png'}")
    print(f"wrote {args.summary_csv}")
    for deadline, (_, denominator, ratio) in completion["Fixed BC-DIR"].items():
        print(f"Fixed BC-DIR completion <= {deadline} ms: {ratio:.6f} ({denominator} trials)")
    print(f"Fixed BC-DIR overhead summary: {overhead['Fixed BC-DIR']}")


if __name__ == "__main__":
    main()
