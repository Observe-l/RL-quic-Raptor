#!/usr/bin/env python3
"""Overlay the random-policy regret baseline on the checkpoint regret curve."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from statistics import mean

import numpy as np


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BANDIT_SUMMARY = ROOT / "python" / "results" / "ge-100kb-bandit-checkpoint-eval-20x-2s-regret-20260917" / "regret_summary.csv"
DEFAULT_ORACLE = ROOT / "python" / "results" / "ge-100kb-oracle-all-actions-20x-2s-par121-20260918" / "oracle.json"
DEFAULT_RANDOM_SCENES = ROOT / "python" / "results" / "ge-100kb-random-baseline-20x-2s-par21-20260918" / "random_scene_summary.csv"
DEFAULT_OUTPUT = ROOT / "python" / "figure" / "bandit_regret_vs_training_step_with_random.png"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bandit-summary", type=Path, default=DEFAULT_BANDIT_SUMMARY)
    parser.add_argument("--oracle-json", type=Path, default=DEFAULT_ORACLE)
    parser.add_argument("--random-scenes", type=Path, default=DEFAULT_RANDOM_SCENES)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    with args.bandit_summary.open("r", newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        raise SystemExit(f"no Bandit summary rows found in {args.bandit_summary}")
    oracle = json.loads(args.oracle_json.read_text(encoding="utf-8"))
    oracle_scenes = oracle.get("scenes", {})
    oracle_by_scene = {
        int(sender_id): float(scene["oracle"]["mean_reward"])
        for sender_id, scene in oracle_scenes.items()
        if scene.get("complete") and isinstance(scene.get("oracle"), dict)
    }
    with args.random_scenes.open("r", newline="", encoding="utf-8") as handle:
        random_rows = list(csv.DictReader(handle))
    random_by_scene = {int(row["sender_id"]): float(row["random_reward"]) for row in random_rows}
    if not oracle_by_scene or set(oracle_by_scene) != set(random_by_scene):
        raise SystemExit(
            "oracle and random summaries must contain the same complete GE scenes: "
            f"oracle={len(oracle_by_scene)} random={len(random_by_scene)}"
        )
    random_regrets = [oracle_by_scene[sid] - random_by_scene[sid] for sid in sorted(oracle_by_scene)]
    random_regret = mean(random_regrets)

    rows.sort(key=lambda row: int(row["checkpoint_step"]))
    steps = np.asarray([int(row["checkpoint_step"]) for row in rows])
    mean_regret = np.asarray([float(row["mean_regret"]) for row in rows])
    p10 = np.asarray([float(row["p10_regret"]) for row in rows])
    p90 = np.asarray([float(row["p90_regret"]) for row in rows])
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(10.5, 5.5), dpi=160)
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
        random_regret,
        color="#ff7f0e",
        linewidth=2.0,
        linestyle="-.",
        label=f"Random policy mean regret ({random_regret:.3f})",
    )
    ax.axhline(0.0, color="#333333", linewidth=1.0, linestyle="--", label="Zero regret")
    ax.set_xlabel("Training checkpoint (step)")
    ax.set_ylabel("Reward regret (oracle − policy)")
    ax.set_title("Bandit and random-policy regret on GE_steady_rp")
    ax.grid(True, color="#d0d0d0", linewidth=0.7, alpha=0.8)
    ax.legend(loc="center left", bbox_to_anchor=(1.015, 0.5), frameon=True)
    fig.subplots_adjust(left=0.10, right=0.72, bottom=0.13, top=0.91)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(args.output, bbox_inches="tight")
    plt.close(fig)
    print(args.output)
    print(f"random_mean_regret={random_regret:.12f}")
    print(f"oracle={args.oracle_json} scenes={len(oracle_by_scene)}")
    print(f"random_scenes={args.random_scenes}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
