#!/usr/bin/env python3
"""Build a hindsight checkpoint oracle and plot regret against it.

For each GE scene, the oracle is the highest mean validation reward observed
among all evaluated checkpoints.  This is an empirical upper envelope on the
same validation data, not an independent test-set oracle.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from statistics import mean, median
from typing import Dict, List

import numpy as np


DEFAULT_EVAL_ROOT = Path(
    "python/results/ge-100kb-bandit-checkpoint-eval-20x-2s-regret-20260917"
)
DEFAULT_FIGURE_DIR = Path("python/figure")


def percentile(values: List[float], q: float) -> float:
    return float(np.percentile(np.asarray(values, dtype=np.float64), q))


def read_checkpoint_rows(eval_root: Path) -> Dict[int, List[dict]]:
    rows_by_step: Dict[int, List[dict]] = {}
    for path in sorted(eval_root.glob("checkpoint_t*/checkpoint_scene_regret.csv")):
        step = int(path.parent.name.removeprefix("checkpoint_t"))
        with path.open("r", newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        if not rows:
            raise SystemExit(f"empty checkpoint summary: {path}")
        for row in rows:
            row["checkpoint_step"] = step
            row["sender_id"] = int(row["sender_id"])
            row["bandit_reward"] = float(row["bandit_reward"])
        rows_by_step[step] = rows
    if not rows_by_step:
        raise SystemExit(f"no checkpoint_scene_regret.csv files found under {eval_root}")
    return rows_by_step


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--eval-root", type=Path, default=DEFAULT_EVAL_ROOT)
    parser.add_argument("--figure-dir", type=Path, default=DEFAULT_FIGURE_DIR)
    args = parser.parse_args()

    rows_by_step = read_checkpoint_rows(args.eval_root)
    steps = sorted(rows_by_step)
    expected_scenes = {row["sender_id"] for row in rows_by_step[steps[0]]}
    for step, rows in rows_by_step.items():
        scene_ids = {row["sender_id"] for row in rows}
        if scene_ids != expected_scenes or len(rows) != len(expected_scenes):
            raise SystemExit(
                f"incomplete or inconsistent scene coverage at checkpoint {step}: "
                f"rows={len(rows)} scenes={len(scene_ids)} expected={len(expected_scenes)}"
            )

    # Select the best observed checkpoint independently for each GE scene.
    by_scene: Dict[int, List[dict]] = defaultdict(list)
    for rows in rows_by_step.values():
        for row in rows:
            by_scene[row["sender_id"]].append(row)

    oracle_rows: List[dict] = []
    oracle_by_scene: Dict[int, dict] = {}
    for sender_id in sorted(by_scene):
        # Deterministic tie break: use the earliest checkpoint.
        best = max(
            by_scene[sender_id],
            key=lambda row: (row["bandit_reward"], -row["checkpoint_step"]),
        )
        oracle = {
            "sender_id": sender_id,
            "oracle_checkpoint_step": best["checkpoint_step"],
            "oracle_reward": best["bandit_reward"],
            "oracle_reward_std": float(best["bandit_reward_std"]),
            "oracle_success_rate": float(best["bandit_success_rate"]),
            "oracle_mean_duration_ms": float(best["mean_duration_ms"]),
            "oracle_mean_goodput_mbps": float(best["mean_goodput_mbps"]),
            "oracle_mean_overhead": float(best["mean_overhead"]),
        }
        oracle_rows.append(oracle)
        oracle_by_scene[sender_id] = oracle

    oracle_path = args.eval_root / "checkpoint_max_oracle_per_scene.csv"
    oracle_fields = list(oracle_rows[0])
    with oracle_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=oracle_fields)
        writer.writeheader()
        writer.writerows(oracle_rows)

    summary_rows: List[dict] = []
    scene_regret_rows: List[dict] = []
    for step in steps:
        regrets: List[float] = []
        for row in sorted(rows_by_step[step], key=lambda item: item["sender_id"]):
            oracle = oracle_by_scene[row["sender_id"]]
            regret = oracle["oracle_reward"] - row["bandit_reward"]
            regrets.append(regret)
            scene_regret_rows.append(
                {
                    "checkpoint_step": step,
                    "sender_id": row["sender_id"],
                    "oracle_checkpoint_step": oracle["oracle_checkpoint_step"],
                    "oracle_reward": oracle["oracle_reward"],
                    "bandit_reward": row["bandit_reward"],
                    "regret": regret,
                }
            )
        summary_rows.append(
            {
                "checkpoint_step": step,
                "scenes": len(regrets),
                "mean_regret": mean(regrets),
                "median_regret": median(regrets),
                "p10_regret": percentile(regrets, 10),
                "p90_regret": percentile(regrets, 90),
                "positive_regret_fraction": mean(1.0 if value > 0 else 0.0 for value in regrets),
                "zero_regret_fraction": mean(1.0 if abs(value) <= 1e-12 else 0.0 for value in regrets),
            }
        )

    summary_path = args.eval_root / "checkpoint_max_oracle_regret_summary.csv"
    scene_path = args.eval_root / "checkpoint_max_oracle_per_scene_regret.csv"
    with summary_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(summary_rows[0]))
        writer.writeheader()
        writer.writerows(summary_rows)
    with scene_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(scene_regret_rows[0]))
        writer.writeheader()
        writer.writerows(scene_regret_rows)

    metadata = {
        "definition": "For each GE scene, choose the checkpoint with the highest mean validation reward.",
        "interpretation": "hindsight empirical upper envelope on the same validation data; not an independent oracle",
        "checkpoint_count": len(steps),
        "checkpoint_range": [min(steps), max(steps)],
        "scene_count": len(expected_scenes),
        "repeats_per_checkpoint_scene": 20,
        "winner_checkpoint_counts": dict(sorted(Counter(row["oracle_checkpoint_step"] for row in oracle_rows).items())),
        "source": str(args.eval_root),
    }
    metadata_path = args.eval_root / "checkpoint_max_oracle_manifest.json"
    metadata_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")

    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    args.figure_dir.mkdir(parents=True, exist_ok=True)
    x = np.asarray([int(row["checkpoint_step"]) for row in summary_rows])
    mean_regret = np.asarray([float(row["mean_regret"]) for row in summary_rows])
    median_regret = np.asarray([float(row["median_regret"]) for row in summary_rows])
    p10 = np.asarray([float(row["p10_regret"]) for row in summary_rows])
    p90 = np.asarray([float(row["p90_regret"]) for row in summary_rows])

    def save_plot(values: np.ndarray, ylabel: str, title: str, filename: str) -> Path:
        fig, ax = plt.subplots(figsize=(8.5, 5.5), dpi=160)
        ax.plot(x, values, color="#1f77b4", linewidth=2.0, label=ylabel.split(" (")[0])
        ax.fill_between(
            x,
            p10,
            p90,
            color="#1f77b4",
            alpha=0.18,
            label="Across-scene 10–90th percentile",
        )
        ax.axhline(0.0, color="#333333", linewidth=1.0, linestyle="--", label="Zero regret")
        ax.set_xlabel("Training checkpoint (step)")
        ax.set_ylabel(ylabel)
        ax.set_title(title)
        ax.grid(True, color="#d0d0d0", linewidth=0.7, alpha=0.8)
        ax.legend(loc="lower right", frameon=True)
        fig.tight_layout()
        output = args.figure_dir / filename
        fig.savefig(output, bbox_inches="tight")
        plt.close(fig)
        return output

    mean_plot = save_plot(
        mean_regret,
        "Reward regret (checkpoint oracle − bandit)",
        "Regret against per-scene best checkpoint",
        "bandit_checkpoint_max_oracle_regret_vs_training_step.png",
    )
    median_plot = save_plot(
        median_regret,
        "Median reward regret (checkpoint oracle − bandit)",
        "Median regret against per-scene best checkpoint",
        "bandit_checkpoint_max_oracle_median_regret_vs_training_step.png",
    )

    print(f"validated checkpoints={len(steps)} scenes={len(expected_scenes)}")
    print(f"oracle={oracle_path}")
    print(f"summary={summary_path}")
    print(f"scene_regret={scene_path}")
    print(f"mean_plot={mean_plot}")
    print(f"median_plot={median_plot}")
    print(f"manifest={metadata_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
