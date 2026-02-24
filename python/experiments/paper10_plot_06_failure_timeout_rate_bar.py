#!/usr/bin/env python3
from __future__ import annotations

import argparse
import math
import sys
from pathlib import Path
from typing import List, Tuple

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
    load_all_trials,
    method_color,
    method_label,
    parse_methods_csv,
    save_current_figure,
    set_flec_offset_env,
)


def _failed_or_timed_out(t, timeout_ms: float) -> bool:
    if t.success != 1:
        return True
    if not math.isfinite(float(t.e2e_delay_ms)):
        return True
    return float(t.e2e_delay_ms) > float(timeout_ms)


def main() -> None:
    ap = argparse.ArgumentParser(description="(Paper10 #6) Failure/timeout rate bar chart")

    ap.add_argument("--scenario", choices=["ge", "iid"], default="ge")
    ap.add_argument("--file-bytes", type=int, default=128 * 1024)
    ap.add_argument("--methods", type=str, default="bandit,fec_k60_r0_2_rstep_2,fec_k40_r0_10_rstep_8,quic_bbrv2,flec")

    ap.add_argument("--timeout-s", type=float, default=1.0)

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

    ap.add_argument("--out", type=str, default="python/results/paper10_figs/06_failure_timeout_rate_bar.pdf")

    args = ap.parse_args()

    configure_matplotlib_like_paper()

    timeout_ms = float(args.timeout_s) * 1000.0

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

    methods = parse_methods_csv(args.methods)
    if not methods:
        methods = auto_methods_in_trials(trials)

    rows: List[Tuple[str, float]] = []
    for m in methods:
        dm = [t for t in trials if t.method == m]
        if not dm:
            continue
        rate = sum(1 for t in dm if _failed_or_timed_out(t, timeout_ms=timeout_ms)) / float(len(dm))
        rows.append((m, float(rate)))

    labels = [method_label(m) for (m, _r) in rows]
    ys = [r for (_m, r) in rows]
    cols = [(method_color(m) or "C0") for (m, _r) in rows]

    plt.figure()
    plt.bar(labels, ys, color=cols)
    plt.ylim(0.0, 1.0)
    plt.ylabel("Failure/timeout rate")
    # plt.title(f"Failure/timeout rate (timeout={args.timeout_s}s, {args.scenario}, task={task})")
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
