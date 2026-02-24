#!/usr/bin/env python3
from __future__ import annotations

import argparse
import math
import sys
from pathlib import Path
from typing import Dict, List, Tuple

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
    load_all_trials,
    method_color,
    method_label,
    parse_iid_loss_pct,
    parse_methods_csv,
    save_current_figure,
    set_flec_offset_env,
)


def _sorted_unique(xs: List[float]) -> List[float]:
    return sorted({float(x) for x in xs if math.isfinite(float(x))})


def main() -> None:
    ap = argparse.ArgumentParser(description="(Paper10 #9) IID: mean overhead vs loss rate (line chart)")

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

    ap.add_argument("--out", type=str, default="python/results/paper10_figs/09_iid_overhead_vs_loss_mean_bar.pdf")

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
    trials_raw = [t for t in filter_trials(trials_all, scenario="iid", task=task) if t.success == 1]

    trials: List[Tuple[float, object]] = []
    for t in trials_raw:
        lp = parse_iid_loss_pct(t.loss_mode)
        if lp is None:
            continue
        if not is_finite_nonneg(float(t.overhead_ratio)):
            continue
        trials.append((float(lp), t))

    methods = parse_methods_csv(args.methods)
    if not methods:
        methods = auto_methods_in_trials([t for (_lp, t) in trials])

    losses = _sorted_unique([lp for (lp, _t) in trials])
    if not losses or not methods:
        raise SystemExit("no IID data found for requested task/methods")

    plt.figure()

    for i, m in enumerate(methods):
        ys: List[float] = []
        for loss in losses:
            xs = [float(t.overhead_ratio) for (lp, t) in trials if lp == loss and t.method == m]
            ys.append(float(np.mean(xs)) if xs else float("nan"))
        plt.plot(
            losses,
            ys,
            marker="o",
            linewidth=1.8,
            markersize=4,
            label=method_label(m),
            color=(method_color(m) or f"C{i}"),
        )

    plt.xticks(losses, [str(x) for x in losses])
    plt.legend(loc="best")

    plt.xlabel("IID loss rate (%)")
    plt.ylabel("Mean overhead ratio")
    # plt.title("IID: mean overhead vs loss rate")
    plt.grid(True, axis="y")

    ax = plt.gca()
    xmin0, xmax0 = ax.get_xlim()
    ymin0, ymax0 = ax.get_ylim()
    if args.xmin is not None or args.xmax is not None:
        ax.set_xlim(left=(args.xmin if args.xmin is not None else xmin0), right=(args.xmax if args.xmax is not None else xmax0))
    if args.ymin is not None or args.ymax is not None:
        ax.set_ylim(bottom=(args.ymin if args.ymin is not None else ymin0), top=(args.ymax if args.ymax is not None else ymax0))

    plt.tight_layout()

    save_current_figure(Path(args.out))


if __name__ == "__main__":
    main()
