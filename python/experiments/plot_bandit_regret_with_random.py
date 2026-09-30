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
    parser.add_argument(
        "--bandit-per-sender",
        type=Path,
        default=None,
        help="optional per-checkpoint sender CSV; when supplied, random/oracle are restricted to this cohort",
    )
    parser.add_argument("--oracle-json", type=Path, default=DEFAULT_ORACLE)
    parser.add_argument("--random-scenes", type=Path, default=DEFAULT_RANDOM_SCENES)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--smooth-window", type=int, default=1, help="odd centered moving-average window in checkpoints")
    args = parser.parse_args()
    if args.smooth_window < 1 or args.smooth_window % 2 == 0:
        raise SystemExit("--smooth-window must be a positive odd number")

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
    if not oracle_by_scene:
        raise SystemExit("oracle summary contains no complete scenes")

    if args.bandit_per_sender is not None:
        with args.bandit_per_sender.open("r", newline="", encoding="utf-8") as handle:
            per_sender_rows = list(csv.DictReader(handle))
        senders_by_step: dict[int, set[int]] = {}
        for row in per_sender_rows:
            senders_by_step.setdefault(int(row["checkpoint_step"]), set()).add(int(row["sender_id"]))
        if not senders_by_step:
            raise SystemExit(f"no sender rows found in {args.bandit_per_sender}")
        selected_senders = set.union(*senders_by_step.values())
        if any(senders != selected_senders for senders in senders_by_step.values()):
            raise SystemExit("bandit per-sender CSV has inconsistent sender cohorts across checkpoints")
    else:
        selected_senders = set(oracle_by_scene) & set(random_by_scene)

    missing_oracle = selected_senders - set(oracle_by_scene)
    missing_random = selected_senders - set(random_by_scene)
    if missing_oracle or missing_random:
        raise SystemExit(
            "selected bandit cohort must be present in both oracle and random summaries: "
            f"selected={len(selected_senders)} missing_oracle={sorted(missing_oracle)} "
            f"missing_random={sorted(missing_random)}"
        )
    if not selected_senders:
        raise SystemExit("oracle, random, and bandit summaries have no common senders")

    random_regrets = [oracle_by_scene[sid] - random_by_scene[sid] for sid in sorted(selected_senders)]
    random_regret = mean(random_regrets)

    rows.sort(key=lambda row: int(row["checkpoint_step"]))
    steps = np.asarray([int(row["checkpoint_step"]) for row in rows])
    mean_regret = np.asarray([float(row["mean_regret"]) for row in rows])
    p10 = np.asarray([float(row["p10_regret"]) for row in rows])
    p90 = np.asarray([float(row["p90_regret"]) for row in rows])
    if args.bandit_per_sender is not None and any(int(row["scenes"]) != len(selected_senders) for row in rows):
        raise SystemExit("bandit summary scene counts do not match the selected sender cohort")

    half_window = args.smooth_window // 2
    moving_average = np.asarray(
        [
            np.mean(mean_regret[max(0, idx - half_window) : min(len(mean_regret), idx + half_window + 1)])
            for idx in range(len(mean_regret))
        ],
        dtype=np.float64,
    )

    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(10.5, 5.8), dpi=160)
    if args.smooth_window > 1:
        ax.plot(steps, moving_average, color="#155b88", linewidth=2.8,
                label=f"Bandit {args.smooth_window}-checkpoint moving average")
    else:
        ax.plot(steps, mean_regret, color="#155b88", linewidth=2.2, marker="o", markersize=3,
                label="Bandit mean regret")
    ax.axhline(
        random_regret,
        color="#ff7f0e",
        linewidth=2.2,
        linestyle="--",
        label=f"Random policy, same {len(selected_senders)} senders ({random_regret:.3f})",
    )
    ax.axhline(0.0, color="#333333", linewidth=1.0, linestyle="--", label="Zero regret")
    ax.set_xlabel("Training checkpoint (step)")
    ax.set_ylabel("Mean reward regret (per-sender oracle − policy)")
    ax.set_title("Bandit regret vs. per-sender Oracle on GE_steady_rp")
    ax.grid(True, color="#d0d0d0", linewidth=0.7, alpha=0.8)
    ax.legend(loc="center left", bbox_to_anchor=(1.015, 0.5), frameon=True)
    note = (
        f"Centered moving average ({args.smooth_window} checkpoints); random baseline: "
        f"20 transfers/sender, restricted to the same {len(selected_senders)}-sender cohort."
    )
    fig.text(0.10, 0.025, note, ha="left", va="bottom", fontsize=8.5, color="#444444")
    fig.subplots_adjust(left=0.10, right=0.72, bottom=0.18, top=0.91)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(args.output, bbox_inches="tight")
    plt.close(fig)

    csv_output = args.output.with_suffix(".csv")
    with csv_output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["checkpoint_step", "mean_regret_raw", "mean_regret_moving_average", "p10_regret",
                        "p90_regret", "random_mean_regret", "sender_count", "smoothing_window"],
        )
        writer.writeheader()
        for idx, row in enumerate(rows):
            writer.writerow({
                "checkpoint_step": int(row["checkpoint_step"]),
                "mean_regret_raw": float(mean_regret[idx]),
                "mean_regret_moving_average": float(moving_average[idx]),
                "p10_regret": float(p10[idx]),
                "p90_regret": float(p90[idx]),
                "random_mean_regret": float(random_regret),
                "sender_count": len(selected_senders),
                "smoothing_window": int(args.smooth_window),
            })
    comparison = {
        "metric": "per-sender Oracle mean reward minus policy mean reward",
        "aggregation": "unweighted mean over the same bandit sender cohort",
        "random_source": str(args.random_scenes.resolve()),
        "oracle_source": str(args.oracle_json.resolve()),
        "bandit_summary_source": str(args.bandit_summary.resolve()),
        "bandit_per_sender_source": str(args.bandit_per_sender.resolve()) if args.bandit_per_sender else None,
        "sender_count": len(selected_senders),
        "sender_ids": sorted(selected_senders),
        "random_mean_regret": float(random_regret),
        "random_per_sender_regret": {str(sid): float(oracle_by_scene[sid] - random_by_scene[sid]) for sid in sorted(selected_senders)},
        "smoothing": f"centered simple moving average over {args.smooth_window} checkpoints; edge windows shrink",
    }
    comparison_path = args.output.with_name(args.output.stem + "_comparison.json")
    comparison_path.write_text(json.dumps(comparison, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(args.output)
    print(f"random_mean_regret={random_regret:.12f}")
    print(f"shared_senders={len(selected_senders)} smoothing_window={args.smooth_window}")
    print(f"random_scenes={args.random_scenes}")
    print(f"data={csv_output}")
    print(f"comparison={comparison_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
