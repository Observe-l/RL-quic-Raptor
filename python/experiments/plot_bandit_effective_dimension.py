#!/usr/bin/env python3
"""Plot LinTS effective feature dimension alongside Oracle regret over training."""

from __future__ import annotations

import argparse
import csv
import json
import re
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
DEFAULT_OUTPUT = ROOT / "figures" / "bandit" / "ge-lints-effective-dimension-learning.png"


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def read_jsonl(path: Path, *, allow_incomplete_tail: bool = False) -> list[dict]:
    rows = []
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as exc:
            is_unterminated_tail = line_number == len(lines) and not line.endswith(("\n", "\r"))
            if allow_incomplete_tail and is_unterminated_tail:
                break
            raise ValueError(f"invalid JSON at {path}:{line_number}: {exc}") from exc
    return rows


def centered_mean(values: np.ndarray, window: int) -> np.ndarray:
    half = window // 2
    return np.asarray(
        [np.mean(values[max(0, i - half): min(len(values), i + half + 1)])
         for i in range(len(values))],
        dtype=np.float64,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result-dir", type=Path, default=DEFAULT_RESULT_DIR)
    parser.add_argument("--random-scenes", type=Path, default=DEFAULT_RANDOM_SCENES)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--smooth-window", type=int, default=5)
    args = parser.parse_args()
    if args.smooth_window < 1 or args.smooth_window % 2 == 0:
        raise SystemExit("--smooth-window must be a positive odd number")

    run_config = json.loads((args.result_dir / "run_config.json").read_text(encoding="utf-8"))
    model_meta = json.loads((args.result_dir / "bandit_model.json").read_text(encoding="utf-8"))
    n_actions = int(run_config["n_actions"])
    action_feature_dim = int(run_config["action_feature_dim"])
    feature_dim = int(run_config["linear_feature_dim"])
    interval = int(run_config["args"]["checkpoint_interval"])
    lam = float(model_meta["agent_cfg"]["lam"])
    rho = float(model_meta["agent_cfg"]["rho"])
    if (n_actions, action_feature_dim, feature_dim) != (2541, 274, 1925):
        raise ValueError(
            "unexpected action/feature dimensions in this run: "
            f"actions={n_actions}, action_features={action_feature_dim}, linear_features={feature_dim}"
        )

    # Checkpoint/evaluation files are written while training continues. Ignore
    # only a possibly partial final JSONL line, and anchor the chart to the
    # latest complete checkpoint pair found below.
    training_rows = read_jsonl(args.result_dir / "bandit_metrics.json", allow_incomplete_tail=True)
    training_steps = [int(row["t"]) for row in training_rows]
    if training_steps != list(range(len(training_rows))):
        raise ValueError("training metrics must contain a contiguous t=0..N-1 prefix")

    checkpoint_files = [
        path for path in (args.result_dir / "checkpoints").glob("model_t*.npz")
        if path.with_suffix(".json").exists()
    ]
    checkpoint_files.sort(key=lambda path: int(re.search(r"model_t(\d+)", path.stem).group(1)))
    checkpoint_steps = [int(re.search(r"model_t(\d+)", path.stem).group(1)) for path in checkpoint_files]
    if not checkpoint_steps:
        raise ValueError("no complete model checkpoint pairs found")
    latest_checkpoint_step = checkpoint_steps[-1]
    expected_steps = list(range(interval, latest_checkpoint_step + 1, interval))
    if checkpoint_steps != expected_steps:
        raise ValueError(f"expected checkpoint steps {expected_steps}, found {checkpoint_steps}")
    if len(training_rows) < latest_checkpoint_step:
        raise ValueError(
            f"latest checkpoint is step {latest_checkpoint_step}, but the training log has only "
            f"{len(training_rows)} complete records"
        )
    checkpoint_training_rows = training_rows[:latest_checkpoint_step]
    if any(not 0 <= int(row["a_idx"]) < n_actions for row in checkpoint_training_rows):
        raise ValueError("training log contains an action index outside the action set")
    if any(len(row["context"]) != 6 or not np.isfinite(float(row["reward"]))
           for row in checkpoint_training_rows):
        raise ValueError("training log contains an invalid context or non-finite reward")

    effective_dimension = []
    for path, step in zip(checkpoint_files, checkpoint_steps):
        checkpoint = np.load(path)
        inv = checkpoint["A_inv"]
        dim = int(checkpoint["dim"][0])
        saved_step = int(checkpoint["t"][0])
        if dim != feature_dim or saved_step != step or inv.shape != (feature_dim, feature_dim):
            raise ValueError(f"checkpoint metadata mismatch at step {step}")
        if not np.isfinite(inv).all():
            raise ValueError(f"non-finite posterior inverse at step {step}")
        # A_t = lambda*I + S_t, where S_t is the exponentially discounted
        # feature information matrix. tr(S_t A_t^-1) = d - lambda*tr(A_t^-1).
        d_eff = float(dim - lam * np.trace(inv))
        if not -1e-5 <= d_eff <= dim + 1e-5:
            raise ValueError(f"effective dimension outside [0, {dim}] at step {step}: {d_eff}")
        effective_dimension.append(max(0.0, min(float(dim), d_eff)))

    # Evaluations run asynchronously, so the latest completed evaluation can
    # lag behind the latest saved model checkpoint.
    eval_rows = read_jsonl(args.result_dir / "evaluation_metrics.jsonl", allow_incomplete_tail=True)
    eval_by_step = {}
    for row in eval_rows:
        bandit = row["bandit"]
        step = int(bandit["step"])
        if step in eval_by_step:
            raise ValueError(f"duplicate evaluation result at step {step}")
        if step not in set(checkpoint_steps):
            raise ValueError(f"evaluation at step {step} has no matching model checkpoint")
        if step % interval != 0:
            raise ValueError(f"evaluation step {step} is not aligned to checkpoint interval {interval}")
        eval_by_step[step] = bandit
        if (int(bandit["sender_count"]) != 39 or int(bandit["records"]) != 780
                or int(bandit["repeats_per_sender"]) != 20 or not bandit["repeat_counts_valid"]):
            raise ValueError(f"incomplete or inconsistent evaluation at step {step}")
    evaluated_steps = sorted(eval_by_step)
    if not evaluated_steps:
        raise ValueError("no completed policy evaluations are available")

    per_sender_rows = read_csv(args.result_dir / "oracle_regret_per_sender.csv")
    sender_regrets: dict[int, dict[int, float]] = {}
    oracle_by_sender: dict[int, float] = {}
    for row in per_sender_rows:
        step = int(row["checkpoint_step"])
        sid = int(row["sender_id"])
        if int(row["repeat_count"]) != 20:
            raise ValueError(f"expected 20 policy repeats for sender {sid} at step {step}")
        sender_regrets.setdefault(step, {})[sid] = float(row["regret"])
        value = float(row["oracle_reward"])
        if sid in oracle_by_sender and not np.isclose(oracle_by_sender[sid], value, atol=1e-12):
            raise ValueError(f"Oracle reward changed across checkpoints for sender {sid}")
        oracle_by_sender[sid] = value
    sender_ids = set(oracle_by_sender)
    if len(sender_ids) != 39 or set(sender_regrets) != set(evaluated_steps):
        raise ValueError("per-sender regret table does not match the completed evaluations")
    if any(set(values) != sender_ids for values in sender_regrets.values()):
        raise ValueError("sender cohort changes across evaluation checkpoints")

    summary_rows = read_csv(args.result_dir / "oracle_regret_summary.csv")
    summary_rows.sort(key=lambda row: int(row["checkpoint_step"]))
    summary_steps = [int(row["checkpoint_step"]) for row in summary_rows]
    if summary_steps != evaluated_steps:
        raise ValueError("Oracle regret summary does not match the completed evaluation checkpoints")
    mean_regret = np.asarray([float(row["mean_regret"]) for row in summary_rows], dtype=np.float64)
    for row, step, reported_mean in zip(summary_rows, evaluated_steps, mean_regret):
        vals = np.asarray(list(sender_regrets[int(step)].values()), dtype=np.float64)
        if int(row["scenes"]) != len(sender_ids) or int(row["excluded_all_minus_one_senders"]) != 0:
            raise ValueError(f"unexpected sender count/exclusions at step {step}")
        if not np.isclose(float(vals.mean()), reported_mean, atol=1e-10):
            raise ValueError(f"summary mean does not reconcile at step {step}")

    random_rows = read_csv(args.random_scenes)
    random_by_sender = {int(row["sender_id"]): float(row["random_reward"]) for row in random_rows}
    if not sender_ids.issubset(random_by_sender):
        raise ValueError("random baseline is missing senders from the evaluation cohort")
    random_regret = float(np.mean([
        oracle_by_sender[sid] - random_by_sender[sid] for sid in sorted(sender_ids)
    ]))
    checkpoint_steps_array = np.asarray(checkpoint_steps, dtype=np.int64)
    evaluation_steps = np.asarray(evaluated_steps, dtype=np.int64)
    smoothed_regret = centered_mean(mean_regret, args.smooth_window)
    d_eff = np.asarray(effective_dimension, dtype=np.float64)
    dimension_by_step = dict(zip(checkpoint_steps, d_eff))
    mean_regret_by_step = dict(zip(evaluated_steps, mean_regret))
    smoothed_regret_by_step = dict(zip(evaluated_steps, smoothed_regret))

    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.ticker import MultipleLocator

    fig, (ax_dim, ax_regret) = plt.subplots(
        2, 1, figsize=(9.2, 6.6), sharex=True,
        gridspec_kw={"height_ratios": [1.0, 1.15]},
    )
    fig.suptitle(
        "Bandit learning: effective feature dimension and Oracle regret",
        fontsize=14,
        y=0.985,
    )
    fig.text(
        0.5, 0.952,
        f"{n_actions:,} candidate actions · {feature_dim:,}-D feature map · 39 GE senders × 20 repeats/checkpoint",
        ha="center", va="top", fontsize=9, color="#444444",
    )
    fig.text(
        0.5, 0.929,
        f"Effective dimension through checkpoint {latest_checkpoint_step:,} · Oracle regret through completed evaluation {int(evaluation_steps[-1]):,}",
        ha="center", va="top", fontsize=8.5, color="#555555",
    )

    ax_dim.plot(checkpoint_steps_array, d_eff, color="#155b88", linewidth=2.0, marker="o",
                markersize=2.5, markevery=5)
    ax_dim.axvline(2100, color="#777777", linewidth=0.9, linestyle=":")
    ax_dim.set_ylabel(f"Effective feature dimension\n(of {feature_dim:,})")
    ax_dim.set_ylim(0, max(600, float(np.ceil(d_eff.max() / 100) * 100)))
    ax_dim.yaxis.set_major_locator(MultipleLocator(100))
    ax_dim.grid(True, axis="y", color="#d0d0d0", linewidth=0.7, alpha=0.8)

    ax_regret.plot(evaluation_steps, smoothed_regret, color="#155b88", linewidth=2.2, label="BC-DIR")
    ax_regret.axhline(random_regret, color="#ff7f0e", linewidth=1.8, linestyle="--",
                      label=f"Random ({random_regret:.3f})")
    ax_regret.axvline(2100, color="#777777", linewidth=0.9, linestyle=":")
    ax_regret.set_ylabel("Mean Oracle regret")
    ax_regret.set_xlabel("Training step")
    ax_regret.set_ylim(bottom=0)
    ax_regret.xaxis.set_major_locator(MultipleLocator(1000))
    ax_regret.grid(True, axis="y", color="#d0d0d0", linewidth=0.7, alpha=0.8)
    ax_regret.legend(loc="upper right", frameon=True, framealpha=1.0)

    ax_regret.set_xlim(0, latest_checkpoint_step)
    fig.subplots_adjust(left=0.13, right=0.97, bottom=0.10, top=0.90, hspace=0.12)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(args.output, dpi=180, bbox_inches="tight")
    plt.close(fig)

    csv_output = args.output.with_suffix(".csv")
    with csv_output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow([
            "checkpoint_step", "effective_feature_dimension", "feature_dimension",
            "mean_oracle_regret", "mean_oracle_regret_sma", "random_mean_oracle_regret",
            "sender_count", "repeats_per_sender", "smoothing_window",
        ])
        for step in checkpoint_steps:
            raw_regret = mean_regret_by_step.get(step)
            smoothed_value = smoothed_regret_by_step.get(step)
            writer.writerow([
                int(step), float(dimension_by_step[step]), feature_dim,
                "" if raw_regret is None else float(raw_regret),
                "" if smoothed_value is None else float(smoothed_value),
                random_regret, len(sender_ids), 20,
                args.smooth_window,
            ])

    post = evaluation_steps >= 2100
    post_slope = float(np.polyfit(evaluation_steps[post], smoothed_regret[post], 1)[0] * 1000)
    report = {
        "result_dir": str(args.result_dir.resolve()),
        "n_actions": n_actions,
        "action_feature_dim": action_feature_dim,
        "linear_feature_dim": feature_dim,
        "lambda": lam,
        "rho": rho,
        "effective_dimension_formula": "d_eff = tr((A-lambda*I) A^-1) = d - lambda*tr(A^-1)",
        "interpretation": "Regularized effective number of feature directions informed by discounted observations; not itself a reward or convergence measure.",
        "checkpoint_count": len(checkpoint_steps),
        "latest_checkpoint_step": latest_checkpoint_step,
        "training_updates_at_latest_checkpoint": latest_checkpoint_step,
        "latest_completed_evaluation_step": int(evaluation_steps[-1]),
        "evaluation_checkpoint_count": len(evaluation_steps),
        "sender_count": len(sender_ids),
        "evaluation_repeats_per_sender": 20,
        "random_mean_oracle_regret_same_cohort": random_regret,
        "smoothing": f"centered {args.smooth_window}-checkpoint moving average; edge windows shrink",
        "post_2100_smoothed_regret_mean": float(smoothed_regret[post].mean()),
        "post_2100_smoothed_regret_sample_std": float(smoothed_regret[post].std(ddof=1)),
        "post_2100_smoothed_regret_slope_per_1000_steps": post_slope,
        "effective_dimension_at_2100": float(dimension_by_step[2100]),
        "effective_dimension_at_5000": float(dimension_by_step[5000]),
        "effective_dimension_at_latest_checkpoint": float(d_eff[-1]),
        "source_checkpoints": str((args.result_dir / "checkpoints").resolve()),
        "source_oracle_regret": str((args.result_dir / "oracle_regret_per_sender.csv").resolve()),
        "source_random_baseline": str(args.random_scenes.resolve()),
    }
    json_output = args.output.with_name(args.output.stem + "_metrics.json")
    json_output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(args.output)
    print(csv_output)
    print(json_output)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
