#!/usr/bin/env python3
from __future__ import annotations

import argparse
import math
import sys
from pathlib import Path
from typing import List

import numpy as np

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402


EXPERIMENTS_DIR = Path(__file__).resolve().parent
if str(EXPERIMENTS_DIR) not in sys.path:
    sys.path.insert(0, str(EXPERIMENTS_DIR))

from paper10_plot_common import (  # noqa: E402
    auto_methods_in_trials,
    configure_matplotlib_like_paper,
    desired_task_from_file_bytes,
    filter_trials,
    is_finite_nonneg,
    is_finite_pos,
    load_all_trials,
    method_color,
    method_marker,
    method_label,
    parse_methods_csv,
    save_current_figure,
    set_flec_offset_env,
)


def main() -> None:
    ap = argparse.ArgumentParser(description="(Paper10 #4) Overhead vs E2E delay (one point per method)")

    ap.add_argument("--scenario", choices=["ge", "iid"], default="ge")
    ap.add_argument("--file-bytes", type=int, default=128 * 1024)
    ap.add_argument("--methods", type=str, default="bandit,fec_k60_r0_2_rstep_2,fec_k40_r0_10_rstep_8,quic_bbrv2,flec")

    ap.add_argument("--flec-jsonl", type=str, default="python/results/flec_data/*.jsonl")
    ap.add_argument("--baseline-glob", type=str, default="python/results/*-baseline-data/results.csv")
    ap.add_argument("--bandit-glob", type=str, default="python/results/*-bandit-*/bandit_eval_results.csv")

    ap.add_argument("--baseline-in-dir", action="append", default=[], help="Explicit baseline input dir (expects results.csv). Repeatable.")
    ap.add_argument("--baseline-results-csv", action="append", default=[], help="Explicit baseline results.csv path. Repeatable.")
    ap.add_argument("--bandit-eval-results-csv", action="append", default=[], help="Explicit bandit_eval_results.csv path. Repeatable.")
    ap.add_argument("--bandit-eval-log", action="append", default=[], help="Explicit bandit_eval_metrics.jsonl path. Repeatable.")
    ap.add_argument(
        "--only-inputs-specified",
        action="store_true",
        help="If set, ignore --baseline-glob/--bandit-glob and only load explicit inputs.",
    )

    ap.add_argument("--flec-e2e-offset-ms", type=float, default=0.0)

    ap.add_argument("--xmin", type=float, default=None, help="Optional x-axis min")
    ap.add_argument("--xmax", type=float, default=None, help="Optional x-axis max")
    ap.add_argument("--ymin", type=float, default=None, help="Optional y-axis min")
    ap.add_argument("--ymax", type=float, default=None, help="Optional y-axis max")

    ap.add_argument("--out", type=str, default="python/results/paper10_figs/04_overhead_vs_delay_scatter.pdf")

    args = ap.parse_args()

    configure_matplotlib_like_paper()

    set_flec_offset_env(args.flec_e2e_offset_ms)

    trials_all = load_all_trials(
        baseline_glob=args.baseline_glob,
        bandit_glob=args.bandit_glob,
        flec_jsonl=args.flec_jsonl,
        baseline_in_dirs=args.baseline_in_dir,
        baseline_csvs=args.baseline_results_csv,
        bandit_eval_results_csvs=args.bandit_eval_results_csv,
        bandit_eval_logs=args.bandit_eval_log,
        only_inputs_specified=bool(args.only_inputs_specified),
    )

    task = desired_task_from_file_bytes(args.file_bytes)
    trials = [
        t
        for t in filter_trials(trials_all, scenario=args.scenario, task=task)
        if t.success == 1
        and is_finite_pos(float(t.e2e_delay_ms))
        and is_finite_nonneg(float(t.overhead_ratio))
    ]

    methods = parse_methods_csv(args.methods)
    if not methods:
        methods = auto_methods_in_trials(trials)

    fig, ax = plt.subplots()

    for m in methods:
        xs = [float(t.overhead_ratio) for t in trials if t.method == m]
        ys = [float(t.e2e_delay_ms) for t in trials if t.method == m]
        if not xs:
            continue
        xm = float(np.mean(xs))
        ym = float(np.mean(ys))
        c = method_color(m) or "C0"
        ax.scatter(
            [xm],
            [ym],
            s=110,
            marker=method_marker(m),
            label=method_label(m),
            facecolors=c,
            edgecolors=c,
            linewidths=0.8,
        )

    ax.set_xlabel("Overhead ratio")
    ax.set_ylabel("E2E delay (ms)")
    ax.set_title(f"Overhead vs E2E delay ({args.scenario})")
    ax.legend()

    xmin0, xmax0 = ax.get_xlim()
    ymin0, ymax0 = ax.get_ylim()

    # Default to showing the origin for the arrow, unless user overrides.
    if args.xmin is None:
        ax.set_xlim(left=min(0.0, xmin0), right=xmax0)
    if args.ymin is None:
        ax.set_ylim(bottom=min(0.0, ymin0), top=ymax0)

    if args.xmin is not None or args.xmax is not None:
        ax.set_xlim(
            left=(args.xmin if args.xmin is not None else ax.get_xlim()[0]),
            right=(args.xmax if args.xmax is not None else ax.get_xlim()[1]),
        )
    if args.ymin is not None or args.ymax is not None:
        ax.set_ylim(
            bottom=(args.ymin if args.ymin is not None else ax.get_ylim()[0]),
            top=(args.ymax if args.ymax is not None else ax.get_ylim()[1]),
        )

    # Add "better" callout box in lower-left, with transparent fill.
    box_axes_xy = (0.06, 0.06)
    better_text = ax.text(
        box_axes_xy[0],
        box_axes_xy[1],
        "better",
        transform=ax.transAxes,
        ha="left",
        va="bottom",
        bbox=dict(boxstyle="round,pad=0.18", facecolor="none", edgecolor="black", linewidth=0.8),
        zorder=6,
    )

    plt.tight_layout()
    fig.canvas.draw()

    # Solid black arrow from origin to the textbox bottom-left corner.
    bbox = better_text.get_window_extent(renderer=fig.canvas.get_renderer())
    box_corner_data = ax.transData.inverted().transform((float(bbox.x0), float(bbox.y0)))
    ax.annotate(
        "",
        xy=(float(box_corner_data[0]), float(box_corner_data[1])),
        xytext=(0.0, 0.0),
        arrowprops=dict(arrowstyle="->", color="black", linewidth=1.0),
        zorder=5,
    )

    save_current_figure(Path(args.out))


if __name__ == "__main__":
    main()
