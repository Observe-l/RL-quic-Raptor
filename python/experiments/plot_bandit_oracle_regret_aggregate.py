#!/usr/bin/env python3
"""Plot aggregate checkpoint Oracle regret in the sender-58 illustrative style."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

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


def centered_sma(values: np.ndarray, window: int) -> np.ndarray:
    left = window // 2
    right = window - left
    return np.asarray(
        [np.mean(values[max(0, i - left): min(len(values), i + right)])
         for i in range(len(values))],
        dtype=np.float64,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result-dir", type=Path, default=DEFAULT_RESULT_DIR)
    parser.add_argument("--random-scenes", type=Path, default=DEFAULT_RANDOM_SCENES)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--smooth-window", type=int, default=10)
    parser.add_argument("--max-step", type=int, default=11000,
                        help="last checkpoint shown on the x-axis (default: 11000)")
    args = parser.parse_args()
    if args.smooth_window < 1:
        raise SystemExit("--smooth-window must be a positive integer")
    if args.max_step < 1:
        raise SystemExit("--max-step must be a positive integer")

    sender_path = args.result_dir / "oracle_regret_per_sender.csv"
    summary_path = args.result_dir / "oracle_regret_summary.csv"
    sender_rows = read_csv(sender_path)
    summary_rows = read_csv(summary_path)
    by_step: dict[int, list[dict[str, str]]] = defaultdict(list)
    for row in sender_rows:
        by_step[int(row["checkpoint_step"])].append(row)
    summaries = {int(row["checkpoint_step"]): row for row in summary_rows}
    if len(summaries) != len(summary_rows):
        raise SystemExit("duplicate checkpoint in oracle_regret_summary.csv")

    # During asynchronous training, the two CSVs can be refreshed moments apart.
    # Use only checkpoints fully present in both files and with a complete cohort.
    complete_steps: list[int] = []
    cohort: set[int] | None = None
    means: list[float] = []
    for step in sorted(set(by_step) & set(summaries)):
        rows = by_step[step]
        sender_ids = {int(row["sender_id"]) for row in rows}
        summary = summaries[step]
        expected_senders = int(summary["scenes"])
        if (len(rows) != expected_senders or len(sender_ids) != expected_senders
                or int(summary["excluded_all_minus_one_senders"]) != 0):
            continue
        if any(int(row["repeat_count"]) != 20 for row in rows):
            continue
        if cohort is None:
            cohort = sender_ids
        if sender_ids != cohort:
            raise SystemExit(f"eligible sender cohort changed at checkpoint {step}")
        regrets = np.asarray([float(row["regret"]) for row in rows], dtype=np.float64)
        if not np.isfinite(regrets).all():
            raise SystemExit(f"non-finite sender regret at checkpoint {step}")
        mean_regret = float(np.mean(regrets))
        if not np.isclose(mean_regret, float(summary["mean_regret"]), atol=1e-10):
            raise SystemExit(f"per-sender regrets do not reconcile to summary at checkpoint {step}")
        complete_steps.append(step)
        means.append(mean_regret)

    if not complete_steps or cohort is None:
        raise SystemExit("no complete, reconciled Oracle evaluations found")
    if any(b - a != 100 for a, b in zip(complete_steps, complete_steps[1:])):
        raise SystemExit("complete Oracle evaluation checkpoints are not contiguous by 100 steps")

    random_rows = read_csv(args.random_scenes)
    random_by_sender = {int(row["sender_id"]): float(row["random_regret"]) for row in random_rows}
    if not cohort.issubset(random_by_sender):
        raise SystemExit("random baseline is missing sender(s) in the Oracle evaluation cohort")
    random_regret = float(np.mean([random_by_sender[sid] for sid in sorted(cohort)]))

    latest_complete_step = int(complete_steps[-1])
    if args.max_step > latest_complete_step:
        raise SystemExit(
            f"requested --max-step {args.max_step} exceeds the latest complete "
            f"checkpoint {latest_complete_step}"
        )
    if args.max_step not in complete_steps:
        raise SystemExit(
            f"requested --max-step {args.max_step} is not a complete evaluation checkpoint"
        )
    visible = np.asarray(complete_steps, dtype=np.int64) <= args.max_step
    steps = np.asarray(complete_steps, dtype=np.int64)[visible]
    regret = np.asarray(means, dtype=np.float64)[visible]
    max_step = args.max_step
    first_checkpoint_rows = by_step[int(steps[0])]
    first_checkpoint_sender_regrets = np.asarray(
        [float(row["regret"]) for row in first_checkpoint_rows], dtype=np.float64
    )
    zero_anchor_regret = float(np.percentile(first_checkpoint_sender_regrets, 90))
    plot_steps = np.concatenate((np.asarray([0], dtype=np.int64), steps))
    smoothing_input = np.concatenate((np.asarray([zero_anchor_regret]), regret))
    plot_regret = centered_sma(smoothing_input, args.smooth_window)

    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    output = args.output or (args.result_dir / "oracle_regret_all_senders_illustrative.png")
    configure_matplotlib_like_paper()
    fig, ax = plt.subplots(figsize=(3.8, 2.4))
    ax.plot(plot_steps, plot_regret, color="#155b88", linewidth=1.6, label="BC-DIR", zorder=2)
    ax.axhline(random_regret, color="#ff7f0e", linewidth=1.4, linestyle="--",
               label="Random", zorder=1)
    ax.axvline(2000, color="#667781", linewidth=0.8, linestyle=":", zorder=1)
    ax.set_xlim(0, max_step)
    tick_step = max(500, int(round((max_step / 5) / 500) * 500))
    # Keep the endpoint as the axis limit, not as a labeled tick.
    ax.set_xticks(np.arange(0, max_step, tick_step))
    ax.set_ylim(0, 0.32)
    ax.set_xlabel("Step")
    ax.set_ylabel("Regret")
    ax.grid(True)
    ax.legend(loc="upper right")
    fig.tight_layout()
    output.parent.mkdir(parents=True, exist_ok=True)
    save_current_figure(output)

    data_path = output.with_suffix(".csv")
    with data_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow([
            "checkpoint_step", "plotted_regret", "raw_mean_oracle_regret",
            "zero_step_anchor_input", "centered_sma_regret", "point_type",
            "random_mean_oracle_regret", "sender_count", "repeats_per_sender",
            "smoothing_window",
        ])
        writer.writerow([
            0, float(plot_regret[0]), "", zero_anchor_regret, float(plot_regret[0]),
            "first_checkpoint_p90_sender_anchor_in_smoothing",
            random_regret, len(cohort), 20, args.smooth_window,
        ])
        for index, (step, value) in enumerate(zip(steps, regret), start=1):
            writer.writerow([
                int(step), float(plot_regret[index]), float(value), "",
                float(plot_regret[index]), "sender_mean_centered_sma",
                random_regret, len(cohort), 20,
                args.smooth_window,
            ])
    metrics = {
        "plot": str(output.resolve()),
        "source_per_sender_csv": str(sender_path.resolve()),
        "source_summary_csv": str(summary_path.resolve()),
        "source_random_scenes_csv": str(args.random_scenes.resolve()),
        "regret_definition": "unweighted mean across eligible senders of per-sender oracle reward minus policy reward",
        "sender_count": len(cohort),
        "repeats_per_sender_per_checkpoint": 20,
        "displayed_step_range": [0, max_step],
        "displayed_regret_range": [0, 0.32],
        "plotted_through_step": max_step,
        "latest_complete_evaluation_step": latest_complete_step,
        "zero_step_anchor": {
            "value": zero_anchor_regret,
            "percentile": 90,
            "percentile_method": "linear",
            "source_checkpoint_step": int(steps[0]),
            "definition": "90th percentile of per-sender regrets at the first complete checkpoint; included as the step-0 input to the plotted moving average",
        },
        "random_mean_oracle_regret_same_cohort": random_regret,
        "smoothing": (
            f"centered {args.smooth_window}-checkpoint simple moving average; "
            "even windows are centered between checkpoints and assigned to the later checkpoint; "
            "edge windows shrink; the step-0 anchor is included in the smoothing input"
        ),
    }
    metrics_path = output.with_name(output.stem + "_metrics.json")
    metrics_path.write_text(json.dumps(metrics, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(output)
    print(data_path)
    print(metrics_path)
    print(json.dumps(metrics, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
