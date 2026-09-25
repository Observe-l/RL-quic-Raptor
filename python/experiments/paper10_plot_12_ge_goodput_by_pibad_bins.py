#!/usr/bin/env python3
from __future__ import annotations

import argparse
import math
import sys
from pathlib import Path
from typing import Dict, List, Tuple

import matplotlib
import numpy as np

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


def _parse_bin_ranges(spec: str) -> List[Tuple[float, float]]:
    out: List[Tuple[float, float]] = []
    for part in str(spec or "").split(","):
        p = str(part).strip()
        if not p:
            continue
        if "-" not in p:
            raise SystemExit(f"invalid bin range: {p}")
        lo_s, hi_s = p.split("-", 1)
        lo = float(lo_s.strip())
        hi = float(hi_s.strip())
        if hi < lo:
            lo, hi = hi, lo
        out.append((float(lo), float(hi)))
    if not out:
        raise SystemExit("bin-ranges must contain at least one range")
    return out


def _in_bin(value: float, lo: float, hi: float) -> bool:
    if value < lo:
        return False
    if math.isclose(value, hi):
        return True
    return value < hi


def main() -> None:
    ap = argparse.ArgumentParser(description="Mean goodput by GE pi_bad bins")
    ap.add_argument("--file-bytes", type=int, default=128 * 1024)
    ap.add_argument("--methods", type=str, default="bandit,flec,flec_raptorq,quic_bbrv2")
    ap.add_argument("--bin-ranges", type=str, default="0-10,1-30,2-50,3-100")
    ap.add_argument("--bin-labels", type=str, default="300,600,900,1200")
    ap.add_argument("--xlabel", type=str, default="Traffic Intensity")

    ap.add_argument("--flec-jsonl", type=str, default="python/results/flec_data/*.jsonl")
    ap.add_argument("--flec-raptorq-jsonl", type=str, default="")
    ap.add_argument("--baseline-glob", type=str, default="python/results/*-baseline-data/results.csv")
    ap.add_argument("--bandit-glob", type=str, default="python/results/*-bandit-*/bandit_eval_results.csv")
    ap.add_argument("--baseline-in-dir", action="append", default=[])
    ap.add_argument("--baseline-results-csv", action="append", default=[])
    ap.add_argument("--bandit-eval-results-csv", action="append", default=[])
    ap.add_argument("--bandit-eval-log", action="append", default=[])
    ap.add_argument("--only-inputs-specified", action="store_true")
    ap.add_argument("--flec-e2e-offset-ms", type=float, default=0.0)

    ap.add_argument("--ymin", type=float, default=0.0)
    ap.add_argument("--ymax", type=float, default=None)
    ap.add_argument("--out", type=str, default="figures/vary_density/v2x-goodput.png")
    args = ap.parse_args()

    configure_matplotlib_like_paper()
    bin_ranges = _parse_bin_ranges(args.bin_ranges)
    labels = [x.strip() for x in str(args.bin_labels).split(",") if str(x).strip()]
    if len(labels) != len(bin_ranges):
        labels = [f"{lo:g}-{hi:g}" for lo, hi in bin_ranges]

    set_flec_offset_env(args.flec_e2e_offset_ms)
    trials_all = load_all_trials(
        baseline_glob=args.baseline_glob,
        bandit_glob=args.bandit_glob,
        flec_jsonl=args.flec_jsonl,
        flec_raptorq_jsonl=args.flec_raptorq_jsonl,
        baseline_in_dirs=args.baseline_in_dir,
        baseline_csvs=args.baseline_results_csv,
        bandit_eval_results_csvs=args.bandit_eval_results_csv,
        bandit_eval_logs=args.bandit_eval_log,
        only_inputs_specified=bool(args.only_inputs_specified),
    )

    task = desired_task_from_file_bytes(args.file_bytes)
    trials = [t for t in filter_trials(trials_all, scenario="ge", task=task) if t.success == 1]
    trials_ge = []
    for t in trials:
        p = parse_ge_pibad_pct(t.loss_mode)
        if p is not None and math.isfinite(float(p)):
            trials_ge.append((float(p), t))

    methods = parse_methods_csv(args.methods) or auto_methods_in_trials(trials)
    means: Dict[Tuple[int, str], float] = {}
    counts: Dict[Tuple[int, str], int] = {}
    for bi, (lo, hi) in enumerate(bin_ranges):
        for method in methods:
            xs = [
                float(t.goodput_mbps)
                for p, t in trials_ge
                if _in_bin(p, lo, hi)
                and t.method == method
                and math.isfinite(float(t.goodput_mbps))
                and float(t.goodput_mbps) > 0.0
            ]
            counts[(bi, method)] = len(xs)
            means[(bi, method)] = float(np.mean(xs)) if xs else float("nan")

    if not any(n for n in counts.values()):
        raise SystemExit("No successful GE goodput samples found for the selected inputs")

    fig, ax = plt.subplots()
    x = np.arange(len(labels), dtype=float)
    group_span = 0.72
    slot_w = group_span / max(1, len(methods))
    bar_w = slot_w * 0.82
    for i, method in enumerate(methods):
        ys = [means.get((bi, method), float("nan")) for bi in range(len(labels))]
        offsets = (i - (len(methods) - 1) / 2.0) * slot_w
        ax.bar(
            x + offsets,
            ys,
            width=bar_w,
            label=method_label(method),
            color=method_color(method) or f"C{i}",
        )

    ax.set_xticks(x, labels)
    ax.set_xlabel(str(args.xlabel))
    ax.set_ylabel("Mean Goodput (Mbps)")
    ax.set_ylim(bottom=float(args.ymin), top=args.ymax)
    ax.grid(True, axis="y")

    # Keep the legend outside the axes so it cannot cover the first, highest bars.
    ncol = min(max(1, len(methods)), 4)
    fig.legend(
        loc="upper center",
        bbox_to_anchor=(0.5, 0.99),
        ncol=ncol,
        columnspacing=0.9,
        handlelength=1.3,
        handletextpad=0.35,
    )
    fig.tight_layout(rect=(0.0, 0.0, 1.0, 0.88))
    save_current_figure(Path(args.out))

    for bi, label in enumerate(labels):
        summary = ", ".join(
            f"{method_label(method)}={means[(bi, method)]:.3f} Mbps (n={counts[(bi, method)]})"
            if counts[(bi, method)]
            else f"{method_label(method)}=n/a (n=0)"
            for method in methods
        )
        print(f"traffic={label}: {summary}")


if __name__ == "__main__":
    main()
