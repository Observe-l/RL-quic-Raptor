#!/usr/bin/env python3
from __future__ import annotations

import argparse
import math
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402


EXPERIMENTS_DIR = Path(__file__).resolve().parent
if str(EXPERIMENTS_DIR) not in sys.path:
    sys.path.insert(0, str(EXPERIMENTS_DIR))

from paper10_plot_common import (  # noqa: E402
    auto_methods_in_trials,
    configure_matplotlib_like_paper,
    filter_trials,
    is_finite_nonneg,
    is_finite_pos,
    load_all_trials,
    method_color,
    method_label,
    parse_methods_csv,
    save_current_figure,
    set_flec_offset_env,
)


_FILE_TASK_RE = re.compile(r"^file_(?P<bytes>\d+)B$")


def _pick_goodput_task(tasks: List[str], preferred: str) -> str:
    if preferred in tasks:
        return preferred

    file_tasks: List[Tuple[int, str]] = []
    for t in tasks:
        m = _FILE_TASK_RE.match(str(t))
        if not m:
            continue
        try:
            b = int(m.group("bytes"))
        except Exception:
            continue
        file_tasks.append((b, str(t)))

    if file_tasks:
        file_tasks.sort()
        return file_tasks[-1][1]

    return "delay_128kb"


def _group_sender_loss_method_mean(trials) -> List[Tuple[str, float, float]]:
    acc: Dict[Tuple[int, str, str], List[Tuple[float, float]]] = defaultdict(list)
    for t in trials:
        key = (int(t.sender_id), str(t.loss_mode), str(t.method))
        acc[key].append((float(t.overhead_ratio), float(t.goodput_mbps)))

    out: List[Tuple[str, float, float]] = []
    for (_sender_id, _loss_mode, method), pairs in acc.items():
        ovs = [p[0] for p in pairs]
        gps = [p[1] for p in pairs]
        out.append((method, float(sum(ovs)) / len(ovs), float(sum(gps)) / len(gps)))
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="(Paper10 #10) Goodput vs overhead scatter")

    ap.add_argument("--scenario", choices=["ge", "iid"], default="ge")
    ap.add_argument("--task", type=str, default="")
    ap.add_argument("--task-preferred", type=str, default="file_1048576B")

    ap.add_argument("--methods", type=str, default="bandit,fec_k60_r0_2_rstep_2,fec_k40_r0_10_rstep_8,quic_bbrv2,flec")

    ap.add_argument("--agg", choices=["per_trial", "sender_loss_method_mean"], default="sender_loss_method_mean")

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

    ap.add_argument("--out", type=str, default="python/results/paper10_figs/10_goodput_vs_overhead_scatter.pdf")

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

    scenario_trials = [t for t in trials_all if t.loss_mode and t.task and (t.loss_mode.startswith("gemodel:") if args.scenario == "ge" else t.loss_mode.startswith("iid:"))]

    task = str(args.task or "").strip()
    if not task:
        task = _pick_goodput_task(sorted({t.task for t in scenario_trials}), preferred=str(args.task_preferred))

    trials = [
        t
        for t in filter_trials(trials_all, scenario=args.scenario, task=task)
        if t.success == 1
        and is_finite_pos(float(t.goodput_mbps))
        and is_finite_nonneg(float(t.overhead_ratio))
    ]

    methods = parse_methods_csv(args.methods)
    if not methods:
        methods = auto_methods_in_trials(trials)

    plt.figure()

    if args.agg == "sender_loss_method_mean":
        pts = _group_sender_loss_method_mean(trials)
        for m in methods:
            xs = [ov for (mm, ov, gp) in pts if mm == m]
            ys = [gp for (mm, ov, gp) in pts if mm == m]
            if not xs:
                continue
            plt.scatter(xs, ys, s=18, alpha=0.8, label=method_label(m), color=method_color(m))
    else:
        for m in methods:
            xs = [float(t.overhead_ratio) for t in trials if t.method == m]
            ys = [float(t.goodput_mbps) for t in trials if t.method == m]
            if not xs:
                continue
            plt.scatter(xs, ys, s=10, alpha=0.6, label=method_label(m), color=method_color(m))

    plt.xlabel("Overhead ratio")
    plt.ylabel("Goodput (Mbps)")
    plt.title(f"Goodput vs overhead ({args.scenario}, task={task}, {args.agg})")
    plt.legend()

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
