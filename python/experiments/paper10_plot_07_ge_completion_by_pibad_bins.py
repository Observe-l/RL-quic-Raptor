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
    load_all_trials,
    method_color,
    method_label,
    parse_ge_pibad_pct,
    parse_methods_csv,
    save_current_figure,
    set_flec_offset_env,
)


def _bin_index(x: float, bins: List[float]) -> int:
    # bins: edges, right-open intervals [bins[i], bins[i+1])
    for i in range(len(bins) - 1):
        if float(bins[i]) <= x < float(bins[i + 1]):
            return i
    return len(bins) - 2


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
    ap = argparse.ArgumentParser(description="(Paper10 #7) GE completion ratio by pi_bad bins")

    ap.add_argument("--file-bytes", type=int, default=128 * 1024)
    ap.add_argument("--methods", type=str, default="bandit,fec_k60_r0_2_rstep_2,fec_k40_r0_10_rstep_8,quic_bbrv2,flec")

    ap.add_argument("--ge-ddl-ms", type=float, default=500.0)

    ap.add_argument("--bins", type=str, default="0,1,3,6,100")
    ap.add_argument("--bin-labels", type=str, default="<1%,1-3%,3-6%,>6%")

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

    ap.add_argument("--out", type=str, default="python/results/paper10_figs/07_ge_completion_by_pibad_bins.pdf")

    args = ap.parse_args()

    configure_matplotlib_like_paper()

    bins: List[float] = [float(x.strip()) for x in str(args.bins).split(",") if str(x).strip()]
    if len(bins) < 2:
        raise SystemExit("bins must have at least 2 edges")

    labels = [x.strip() for x in str(args.bin_labels).split(",") if str(x).strip()]
    if len(labels) != (len(bins) - 1):
        # fallback to auto labels
        labels = [f"[{bins[i]}, {bins[i+1]})" for i in range(len(bins) - 1)]

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
    trials = filter_trials(trials_all, scenario="ge", task=task)

    # Attach pi_bad.
    trials_w: List[Tuple[int, float, object]] = []
    for t in trials:
        p = parse_ge_pibad_pct(t.loss_mode)
        if p is None or not math.isfinite(float(p)):
            continue
        bi = _bin_index(float(p), bins)
        trials_w.append((bi, float(p), t))

    methods = parse_methods_csv(args.methods)
    if not methods:
        methods = auto_methods_in_trials(trials)

    # For each bin and method, compute completion ratio.
    ratios: Dict[Tuple[int, str], float] = {}
    for bi in range(len(bins) - 1):
        for m in methods:
            dm = [t for (_bi, _p, t) in trials_w if _bi == bi and t.method == m]
            ratios[(bi, m)] = _completion_ratio(dm, ddl_ms=float(args.ge_ddl_ms))

    x = np.arange(len(labels), dtype=float)
    w = 0.8 / max(1, len(methods))

    plt.figure()
    for i, m in enumerate(methods):
        ys = [ratios.get((bi, m), float("nan")) for bi in range(len(labels))]
        offsets = (i - (len(methods) - 1) / 2.0) * w
        plt.bar(x + offsets, ys, width=w, label=method_label(m), color=(method_color(m) or "C0"))

    plt.ylim(0.0, 1.02)
    plt.xticks(x, labels)
    plt.xlabel("Average loss rate")
    plt.ylabel(f"Completion ratio (DDL={float(args.ge_ddl_ms):g}ms)")
    # plt.title("GE completion ratio by pi_bad bins")
    plt.grid(True, axis="y")
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
