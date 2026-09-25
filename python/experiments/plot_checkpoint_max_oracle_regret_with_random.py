#!/usr/bin/env python3
"""Overlay random-policy regret on the per-scene best-checkpoint plot."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from statistics import mean, median

import numpy as np


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_EVAL_ROOT = ROOT / "python" / "results" / "ge-100kb-bandit-checkpoint-eval-20x-2s-regret-20260917"
DEFAULT_RANDOM_ROOT = ROOT / "python" / "results" / "ge-100kb-random-baseline-20x-2s-par21-20260918"
DEFAULT_OUTPUT = ROOT / "python" / "figure" / "bandit_checkpoint_max_oracle_regret_vs_training_step_with_random.png"


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--eval-root", type=Path, default=DEFAULT_EVAL_ROOT)
    parser.add_argument("--random-root", type=Path, default=DEFAULT_RANDOM_ROOT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    checkpoint_summary = read_csv(args.eval_root / "checkpoint_max_oracle_regret_summary.csv")
    checkpoint_oracle = read_csv(args.eval_root / "checkpoint_max_oracle_per_scene.csv")
    random_scene = read_csv(args.random_root / "random_scene_summary.csv")
    if not checkpoint_summary or not checkpoint_oracle or not random_scene:
        raise SystemExit("one or more required summary files are empty")

    oracle_by_scene = {int(row["sender_id"]): float(row["oracle_reward"]) for row in checkpoint_oracle}
    random_by_scene = {int(row["sender_id"]): float(row["random_reward"]) for row in random_scene}
    if set(oracle_by_scene) != set(random_by_scene):
        raise SystemExit("checkpoint oracle and random summaries do not cover the same GE scenes")

    random_regrets = [oracle_by_scene[sid] - random_by_scene[sid] for sid in sorted(oracle_by_scene)]
    random_mean_regret = mean(random_regrets)
    random_median_regret = median(random_regrets)

    comparison_path = args.eval_root / "checkpoint_max_oracle_random_comparison.json"
    comparison = {
        "random_policy": "random_per_transfer",
        "scene_count": len(random_regrets),
        "mean_regret_vs_checkpoint_max_oracle": random_mean_regret,
        "median_regret_vs_checkpoint_max_oracle": random_median_regret,
        "positive_regret_fraction": mean(1.0 if value > 0 else 0.0 for value in random_regrets),
        "checkpoint_oracle_source": str(args.eval_root / "checkpoint_max_oracle_per_scene.csv"),
        "random_source": str(args.random_root / "random_scene_summary.csv"),
    }
    comparison_path.write_text(json.dumps(comparison, indent=2) + "\n", encoding="utf-8")

    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    checkpoint_summary.sort(key=lambda row: int(row["checkpoint_step"]))
    steps = np.asarray([int(row["checkpoint_step"]) for row in checkpoint_summary])
    mean_regret = np.asarray([float(row["mean_regret"]) for row in checkpoint_summary])
    p10 = np.asarray([float(row["p10_regret"]) for row in checkpoint_summary])
    p90 = np.asarray([float(row["p90_regret"]) for row in checkpoint_summary])

    fig, ax = plt.subplots(figsize=(8.5, 5.5), dpi=160)
    ax.plot(steps, mean_regret, color="#1f77b4", linewidth=2.0, label="Bandit mean regret")
    ax.fill_between(
        steps,
        p10,
        p90,
        color="#1f77b4",
        alpha=0.18,
        label="Bandit across-scene 10–90th percentile",
    )
    ax.axhline(
        random_mean_regret,
        color="#ff7f0e",
        linewidth=2.0,
        linestyle="-.",
        label=f"Random policy mean regret ({random_mean_regret:.3f})",
    )
    ax.axhline(0.0, color="#333333", linewidth=1.0, linestyle="--", label="Zero regret")
    ax.set_xlabel("Training checkpoint (step)")
    ax.set_ylabel("Reward regret (checkpoint oracle − policy)")
    ax.set_title("Bandit and random-policy regret against best checkpoint")
    ax.grid(True, color="#d0d0d0", linewidth=0.7, alpha=0.8)
    ax.legend(loc="best", frameon=True)
    fig.tight_layout()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(args.output, bbox_inches="tight")
    plt.close(fig)
    print(f"output={args.output}")
    print(f"random_mean_regret_vs_checkpoint_oracle={random_mean_regret:.12f}")
    print(f"random_median_regret_vs_checkpoint_oracle={random_median_regret:.12f}")
    print(f"comparison={comparison_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
