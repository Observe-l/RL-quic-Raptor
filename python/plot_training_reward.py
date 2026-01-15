#!/usr/bin/env python3

import argparse
import json
from pathlib import Path
from typing import Dict, List, Tuple, Optional

import numpy as np
import matplotlib

# Headless-friendly backend (works on servers / CI)
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402


def moving_average(x: np.ndarray, window: int) -> np.ndarray:
    if window <= 1:
        return x
    window = int(window)
    if window <= 1:
        return x
    if x.size < window:
        # Not enough points; return flat mean
        return np.full_like(x, x.mean() if x.size else 0.0, dtype=float)
    kernel = np.ones(window, dtype=float) / float(window)
    return np.convolve(x, kernel, mode="valid")


def load_step_metrics_jsonl(path: Path) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    steps: List[int] = []
    epis: List[int] = []
    rewards: List[float] = []

    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj: Dict = json.loads(line)
            except json.JSONDecodeError:
                # Skip malformed lines
                continue

            # common keys seen in your log: t, epi, reward
            t = obj.get("t")
            epi = obj.get("epi")
            r = obj.get("reward")

            if t is None or epi is None or r is None:
                # Try a few common alternatives (robustness)
                t = obj.get("step", t)
                epi = obj.get("episode", epi)
                r = obj.get("rew", r)

            if t is None or epi is None or r is None:
                continue

            try:
                steps.append(int(t))
                epis.append(int(epi))
                rewards.append(float(r))
            except (TypeError, ValueError):
                continue

    if not steps:
        raise RuntimeError(f"No valid metrics found in {path}")

    return np.asarray(steps), np.asarray(epis), np.asarray(rewards)


def episode_returns(epis: np.ndarray, rewards: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
    # Aggregate sum reward per episode id, in ascending epi order
    uniq = np.unique(epis)
    uniq.sort()
    returns = np.zeros_like(uniq, dtype=float)
    for i, e in enumerate(uniq):
        returns[i] = rewards[epis == e].sum()
    return uniq, returns


def main() -> None:
    parser = argparse.ArgumentParser(description="Plot training reward from step_metrics.jsonl")
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("python/results/run-20250907-232947/step_metrics.jsonl"),
        help="Path to step_metrics.jsonl",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Output image path (default: alongside input as training_reward.png)",
    )
    parser.add_argument(
        "--smooth",
        type=int,
        default=200,
        help="Moving-average window over step reward (0/1 disables).",
    )
    parser.add_argument(
        "--episode-smooth",
        type=int,
        default=20,
        help="Moving-average window over episode returns (0/1 disables).",
    )
    args = parser.parse_args()

    input_path: Path = args.input
    if not input_path.exists():
        raise SystemExit(f"Input not found: {input_path}")

    out_path: Path
    if args.out is None:
        out_path = input_path.parent / "training_reward.png"
    else:
        out_path = args.out
        if out_path.is_dir():
            out_path = out_path / "training_reward.png"

    steps, epis, rewards = load_step_metrics_jsonl(input_path)

    # Step reward smoothing
    rewards_ma = moving_average(rewards, args.smooth)
    steps_ma = steps[(args.smooth - 1) :] if args.smooth and args.smooth > 1 else steps

    # Episode returns
    epi_ids, epi_ret = episode_returns(epis, rewards)
    epi_ret_ma = moving_average(epi_ret, args.episode_smooth)
    epi_ids_ma = (
        epi_ids[(args.episode_smooth - 1) :] if args.episode_smooth and args.episode_smooth > 1 else epi_ids
    )

    fig, axes = plt.subplots(2, 1, figsize=(12, 8), constrained_layout=True)

    ax = axes[0]
    ax.plot(steps, rewards, linewidth=0.5, alpha=0.35, label="step reward")
    if rewards_ma.size:
        ax.plot(steps_ma, rewards_ma, linewidth=1.5, label=f"step reward MA({args.smooth})")
    ax.set_title("Training reward (per step)")
    ax.set_xlabel("t (step)")
    ax.set_ylabel("reward")
    ax.grid(True, alpha=0.25)
    ax.legend(loc="best")

    ax = axes[1]
    ax.plot(epi_ids, epi_ret, marker=".", linestyle="-", linewidth=0.8, alpha=0.6, label="episode return (sum)")
    if epi_ret_ma.size:
        ax.plot(
            epi_ids_ma,
            epi_ret_ma,
            linewidth=2.0,
            label=f"episode return MA({args.episode_smooth})",
        )
    ax.set_title("Training return (per episode)")
    ax.set_xlabel("epi (episode)")
    ax.set_ylabel("sum reward")
    ax.grid(True, alpha=0.25)
    ax.legend(loc="best")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, dpi=180)

    # Also save PDF for zoom-friendly viewing
    pdf_path = out_path.with_suffix(".pdf")
    fig.savefig(pdf_path)

    print(f"Wrote: {out_path}")
    print(f"Wrote: {pdf_path}")


if __name__ == "__main__":
    main()
