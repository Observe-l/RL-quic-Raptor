#!/usr/bin/env python3
"""Plot median Bandit regret across training checkpoints."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

import numpy as np


DEFAULT_SUMMARY = Path(
    "python/results/ge-100kb-bandit-checkpoint-eval-20x-2s-regret-20260917/"
    "regret_summary.csv"
)
DEFAULT_OUTPUT = Path("python/figure/bandit_median_regret_vs_training_step.png")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    with args.summary.open("r", newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        raise SystemExit(f"no rows found in {args.summary}")

    rows.sort(key=lambda row: int(row["checkpoint_step"]))
    steps = np.asarray([int(row["checkpoint_step"]) for row in rows])
    median_regret = np.asarray([float(row["median_regret"]) for row in rows])
    p10 = np.asarray([float(row["p10_regret"]) for row in rows])
    p90 = np.asarray([float(row["p90_regret"]) for row in rows])

    fig, ax = plt.subplots(figsize=(8.5, 5.5), dpi=160)
    ax.plot(
        steps,
        median_regret,
        color="#1f77b4",
        linewidth=2.0,
        label="Median regret",
    )
    ax.fill_between(
        steps,
        p10,
        p90,
        color="#1f77b4",
        alpha=0.18,
        label="Across-scene 10–90th percentile",
    )
    ax.axhline(
        0.0,
        color="#333333",
        linewidth=1.0,
        linestyle="--",
        label="Zero regret",
    )
    ax.set_xlabel("Training checkpoint (step)")
    ax.set_ylabel("Reward regret (oracle − bandit)")
    ax.set_title("Median Bandit policy regret on GE_steady_rp")
    ax.grid(True, color="#d0d0d0", linewidth=0.7, alpha=0.8)
    ax.legend(loc="best", frameon=True)
    fig.tight_layout()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(args.output, bbox_inches="tight")
    plt.close(fig)
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
