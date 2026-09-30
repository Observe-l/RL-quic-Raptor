#!/usr/bin/env python3
"""Plot only the effective feature dimension using the vary_density regret style."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

import numpy as np


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATA = ROOT / "figures" / "bandit" / "ge-lints-effective-dimension-learning.csv"
DEFAULT_OUTPUT = ROOT / "figures" / "vary_density" / "effective-feature-dimension.png"
EXPERIMENTS_DIR = Path(__file__).resolve().parent

import sys

if str(EXPERIMENTS_DIR) not in sys.path:
    sys.path.insert(0, str(EXPERIMENTS_DIR))

from paper10_plot_common import configure_matplotlib_like_paper, save_current_figure


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--max-step", type=int, default=11000)
    args = parser.parse_args()
    if args.max_step <= 0:
        raise SystemExit("--max-step must be positive")

    with args.data.open("r", newline="", encoding="utf-8") as handle:
        rows = [
            row for row in csv.DictReader(handle)
            if int(row["checkpoint_step"]) <= args.max_step
        ]
    rows.sort(key=lambda row: int(row["checkpoint_step"]))
    if not rows:
        raise SystemExit(f"no effective-dimension data through step {args.max_step} in {args.data}")

    steps = np.asarray([int(row["checkpoint_step"]) for row in rows], dtype=np.int64)
    dimension = np.asarray(
        [float(row["effective_feature_dimension"]) for row in rows], dtype=np.float64
    )
    if len(np.unique(steps)) != len(steps) or np.any(np.diff(steps) <= 0):
        raise SystemExit("checkpoint steps must be unique and increasing")
    if not np.isfinite(dimension).all() or np.any(dimension < 0):
        raise SystemExit("effective feature dimensions must be finite and nonnegative")
    if int(steps[-1]) != args.max_step:
        raise SystemExit(
            f"requested endpoint {args.max_step} is unavailable; latest included step is {steps[-1]}"
        )

    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.ticker import MultipleLocator

    configure_matplotlib_like_paper()
    fig, ax = plt.subplots(figsize=(3.8, 2.4))
    ax.plot(steps, dimension, color="#155b88", linewidth=1.6, zorder=2)
    ax.axvline(2000, color="#667781", linewidth=0.8, linestyle=":", zorder=1)
    ax.set_xlim(0, args.max_step)
    ax.set_ylim(0, max(100, int(np.ceil(float(dimension.max()) / 100) * 100)))
    tick_step = max(500, int(round((args.max_step / 5) / 500) * 500))
    ax.set_xticks(np.arange(0, args.max_step, tick_step))
    ax.yaxis.set_major_locator(MultipleLocator(100))
    ax.set_xlabel("Step")
    ax.set_ylabel("Effective feature dimension")
    ax.grid(True)
    fig.tight_layout()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    save_current_figure(args.output)
    print(args.output)
    print(f"plotted {len(steps)} checkpoints, {steps[0]}–{steps[-1]}; max={dimension.max():.3f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
