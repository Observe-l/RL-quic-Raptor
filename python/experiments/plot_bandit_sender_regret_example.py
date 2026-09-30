#!/usr/bin/env python3
"""Plot one explicitly illustrative sender's Oracle regret against its random baseline."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import sys

import numpy as np


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RESULT_DIR = (
    ROOT
    / "python"
    / "results"
    / "ge-lints-under40-5000-2s-rho9999-exactinv-eval12-oracle-20260929"
)
DEFAULT_RANDOM_SCENES = (
    ROOT
    / "python"
    / "results"
    / "ge-100kb-random-baseline-20x-2s-qdisc-continuous-par24-20260924"
    / "random_scene_summary.csv"
)
EXPERIMENTS_DIR = Path(__file__).resolve().parent
if str(EXPERIMENTS_DIR) not in sys.path:
    sys.path.insert(0, str(EXPERIMENTS_DIR))

from paper10_plot_common import configure_matplotlib_like_paper, save_current_figure


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result-dir", type=Path, default=DEFAULT_RESULT_DIR)
    parser.add_argument("--random-scenes", type=Path, default=DEFAULT_RANDOM_SCENES)
    parser.add_argument("--sender-id", type=int, default=58)
    parser.add_argument("--smooth-window", type=int, default=5)
    parser.add_argument("--max-step", type=int, default=3800,
                        help="show only observations through this checkpoint")
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()
    if args.smooth_window < 1 or args.smooth_window % 2 == 0:
        raise SystemExit("--smooth-window must be a positive odd number")
    if args.max_step <= 0:
        raise SystemExit("--max-step must be positive")

    per_sender_path = args.result_dir / "oracle_regret_per_sender.csv"
    rows = [row for row in read_csv(per_sender_path) if int(row["sender_id"]) == args.sender_id]
    rows.sort(key=lambda row: int(row["checkpoint_step"]))
    if not rows:
        raise SystemExit(f"sender {args.sender_id} not present in {per_sender_path}")
    available_max_step = max(int(row["checkpoint_step"]) for row in rows)
    if args.max_step > available_max_step:
        raise SystemExit(f"--max-step {args.max_step} exceeds available data through {available_max_step}")
    # Truncate before smoothing so the endpoint does not use observations beyond the displayed window.
    rows = [row for row in rows if int(row["checkpoint_step"]) <= args.max_step]
    steps = np.asarray([int(row["checkpoint_step"]) for row in rows], dtype=np.int64)
    regret = np.asarray([float(row["regret"]) for row in rows], dtype=np.float64)
    repeats = np.asarray([int(row["repeat_count"]) for row in rows], dtype=np.int64)
    if len(set(steps.tolist())) != len(steps) or np.any(np.diff(steps) <= 0):
        raise SystemExit("sender data must contain unique, increasing checkpoint steps")
    if not np.all(repeats == 20):
        raise SystemExit(f"expected exactly 20 evaluation repeats/checkpoint, found {sorted(set(repeats))}")

    random_rows = [
        row for row in read_csv(args.random_scenes)
        if int(row["sender_id"]) == args.sender_id
    ]
    if len(random_rows) != 1:
        raise SystemExit(f"expected one random-baseline row for sender {args.sender_id}")
    random_regret = float(random_rows[0]["random_regret"])

    half_window = args.smooth_window // 2
    smoothed = np.asarray(
        [
            np.mean(regret[max(0, i - half_window): min(len(regret), i + half_window + 1)])
            for i in range(len(regret))
        ],
        dtype=np.float64,
    )
    initial_mask = steps <= 500
    descent_mask = (steps >= 1500) & (steps <= 1900)
    post_mask = steps > 2000
    if not (np.any(initial_mask) and np.any(descent_mask) and np.any(post_mask)):
        raise SystemExit("sender data does not cover the requested early, descent, and post-2000 windows")

    initial_mean = float(np.mean(regret[initial_mask]))
    descent_mean = float(np.mean(regret[descent_mask]))
    post_smoothed = smoothed[post_mask]
    metrics = {
        "sender_id": args.sender_id,
        "displayed_step_range": [0, args.max_step],
        "repeat_count_per_checkpoint": 20,
        "random_regret_same_sender": random_regret,
        "first_checkpoint_regret": float(regret[0]),
        "first_5_checkpoints_mean_regret": initial_mean,
        "regret_mean_steps_1500_1900": descent_mean,
        "post_2000_centered_sma_mean_regret": float(np.mean(post_smoothed)),
        "post_2000_centered_sma_std_regret_sample": float(np.std(post_smoothed, ddof=1)),
        "post_2000_centered_sma_min_regret": float(np.min(post_smoothed)),
        "post_2000_centered_sma_max_regret": float(np.max(post_smoothed)),
        "smoothing": f"centered {args.smooth_window}-checkpoint simple moving average; edge windows shrink",
        "selection_note": "Illustrative sender selected for the requested trajectory; not a population estimate.",
        "source_per_sender_csv": str(per_sender_path.resolve()),
        "source_random_scenes_csv": str(args.random_scenes.resolve()),
    }

    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    output = args.output or (ROOT / "figures" / "vary_density" / "regret.png")
    configure_matplotlib_like_paper()
    fig, ax = plt.subplots(figsize=(3.8, 2.4))
    ax.plot(
        steps,
        smoothed,
        color="#155b88",
        linewidth=1.6,
        label="BC-DIR",
        zorder=2,
    )
    ax.axhline(
        random_regret,
        color="#ff7f0e",
        linewidth=1.4,
        linestyle="--",
        label="Random",
        zorder=1,
    )
    ax.axvline(2000, color="#667781", linewidth=0.8, linestyle=":", zorder=1)
    ax.set_xlim(0, args.max_step)
    if args.max_step == 3800:
        ax.set_xticks([0, 500, 1000, 1500, 2000, 2500, 3000, 3500])
    ax.set_ylim(bottom=0)
    ax.set_xlabel("Step")
    ax.set_ylabel("Regret")
    ax.grid(True)
    ax.legend(loc="upper right")
    fig.tight_layout()

    output.parent.mkdir(parents=True, exist_ok=True)
    save_current_figure(output)

    csv_output = args.result_dir / f"oracle_regret_sender_{args.sender_id}_illustrative.csv"
    with csv_output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["checkpoint_step", "sender_id", "regret", "centered_sma_regret", "random_regret_same_sender", "repeat_count"])
        for step, value, smooth, repeat_count in zip(steps, regret, smoothed, repeats):
            writer.writerow([int(step), args.sender_id, float(value), float(smooth), random_regret, int(repeat_count)])
    metrics_output = args.result_dir / f"oracle_regret_sender_{args.sender_id}_illustrative_metrics.json"
    metrics_output.write_text(json.dumps(metrics, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(output)
    print(csv_output)
    print(metrics_output)
    print(json.dumps(metrics, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
