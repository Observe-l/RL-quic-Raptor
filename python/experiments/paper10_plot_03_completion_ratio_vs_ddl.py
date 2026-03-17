#!/usr/bin/env python3
from __future__ import annotations

import argparse
import math
import sys
from pathlib import Path
from typing import List

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

import numpy as np


EXPERIMENTS_DIR = Path(__file__).resolve().parent
if str(EXPERIMENTS_DIR) not in sys.path:
    sys.path.insert(0, str(EXPERIMENTS_DIR))

from paper10_plot_common import (  # noqa: E402
    auto_methods_in_trials,
    configure_matplotlib_like_paper,
    desired_task_from_file_bytes,
    filter_trials,
    in_ge_pibad_range,
    is_finite_pos,
    load_all_trials,
    method_color,
    method_label,
    parse_methods_csv,
    save_current_figure,
    set_flec_offset_env,
)


def _completion_ratio(trials, ddl_ms: float) -> float:
    trials = list(trials)
    if not trials:
        return float("nan")

    ddl = float(ddl_ms)

    def _complete(t) -> bool:
        if t.success != 1:
            return False
        if not math.isfinite(float(t.e2e_delay_ms)):
            return False
        d = float(t.e2e_delay_ms)
        return d > 0 and d <= ddl

    complete_n = sum(1 for t in trials if _complete(t))
    return float(complete_n) / float(len(trials))


def main() -> None:
    ap = argparse.ArgumentParser(description="(Paper10 #3) Completion ratio vs DDL")

    ap.add_argument("--scenario", choices=["ge", "iid"], default="ge")
    ap.add_argument("--file-bytes", type=int, default=128 * 1024)
    ap.add_argument("--methods", type=str, default="bandit,fec_k40_r0_0_rstep_4,fec_k40_r0_4_rstep_0,quic_bbrv2,flec")

    ap.add_argument("--ddl-ms-list", type=str, default="200,300,400,500")

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
    ap.add_argument("--pibad-min", type=float, default=0, help="Optional GE pi_bad lower bound in percent")
    ap.add_argument("--pibad-max", type=float, default=100, help="Optional GE pi_bad upper bound in percent")

    ap.add_argument("--xmin", type=float, default=None, help="Optional x-axis min")
    ap.add_argument("--xmax", type=float, default=None, help="Optional x-axis max")
    ap.add_argument("--ymin", type=float, default=None, help="Optional y-axis min")
    ap.add_argument("--ymax", type=float, default=None, help="Optional y-axis max")

    ap.add_argument("--out", type=str, default="python/results/paper10_figs/03_completion_ratio_vs_ddl.pdf")

    args = ap.parse_args()

    configure_matplotlib_like_paper()
    label_fontsize = 10
    legend_fontsize = 10
    title_fontsize = 10
    tick_fontsize = 10

    ddl_ms_list: List[float] = []
    for part in str(args.ddl_ms_list or "").split(","):
        p = str(part).strip()
        if not p:
            continue
        ddl_ms_list.append(float(p))

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
    trials = filter_trials(trials_all, scenario=args.scenario, task=task)
    if args.scenario == "ge" and (args.pibad_min is not None or args.pibad_max is not None):
        trials = [
            t
            for t in trials
            if in_ge_pibad_range(
                t.loss_mode,
                pibad_min_pct=args.pibad_min,
                pibad_max_pct=args.pibad_max,
            )
        ]

    methods = parse_methods_csv(args.methods)
    if not methods:
        methods = auto_methods_in_trials(trials)

    plt.figure(figsize=(3.5, 3.0))

    x = np.arange(len(ddl_ms_list), dtype=float) * 0.72
    group_span = 0.56
    slot_w = group_span / max(1, len(methods))
    w = slot_w * 0.72

    for i, m in enumerate(methods):
        dm = [t for t in trials if t.method == m]
        if not dm:
            continue
        ys = [_completion_ratio(dm, ddl) for ddl in ddl_ms_list]
        offsets = (i - (len(methods) - 1) / 2.0) * slot_w
        plt.bar(x + offsets, ys, width=w, label=method_label(m), color=(method_color(m) or "C0"))

    plt.ylim(0.0, 1.02)
    plt.xticks(x, [str(int(d)) if float(d).is_integer() else str(d) for d in ddl_ms_list])
    plt.xticks(fontsize=tick_fontsize)
    plt.yticks(fontsize=tick_fontsize)
    plt.xlabel("Transmission Deadline (ms)", fontsize=label_fontsize)
    plt.ylabel("Completion ratio", fontsize=label_fontsize)
    # plt.title(f"Completion ratio vs DDL ({args.scenario}, task={task})", fontsize=title_fontsize)
    plt.legend(loc="upper left", fontsize=legend_fontsize)

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
