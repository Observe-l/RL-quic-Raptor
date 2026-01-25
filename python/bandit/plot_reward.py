#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple


@dataclass
class Series:
    t: List[int]
    reward: List[float]


def _iter_json_lines(path: str) -> Iterable[dict]:
    with open(path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            s = line.strip()
            if not s:
                continue
            try:
                obj = json.loads(s)
            except Exception:
                # Best-effort skip broken lines
                continue
            if isinstance(obj, dict):
                yield obj


def load_reward_series(log_path: str) -> Series:
    t: List[int] = []
    r: List[float] = []
    for rec in _iter_json_lines(log_path):
        tv = rec.get("t")
        rv = rec.get("reward")
        if tv is None or rv is None:
            continue
        try:
            t.append(int(tv))
            r.append(float(rv))
        except Exception:
            continue
    return Series(t=t, reward=r)


def rolling_mean(y: List[float], window: int) -> List[Optional[float]]:
    if window <= 1:
        return [float(v) for v in y]
    out: List[Optional[float]] = [None] * len(y)
    s = 0.0
    q: List[float] = []
    for i, v in enumerate(y):
        q.append(float(v))
        s += float(v)
        if len(q) > window:
            s -= q.pop(0)
        if len(q) == window:
            out[i] = s / window
    return out


def episode_mean(series: Series, episode_steps: int) -> Tuple[List[int], List[float]]:
    if episode_steps <= 0:
        raise ValueError("episode_steps must be > 0")
    # Group by episode index = t // episode_steps
    ep_sum = {}
    ep_cnt = {}
    for t, r in zip(series.t, series.reward):
        ep = int(t) // int(episode_steps)
        ep_sum[ep] = float(ep_sum.get(ep, 0.0)) + float(r)
        ep_cnt[ep] = int(ep_cnt.get(ep, 0)) + 1
    eps = sorted(ep_sum.keys())
    xs = []
    ys = []
    for ep in eps:
        c = ep_cnt.get(ep, 0)
        if c <= 0:
            continue
        xs.append(int(ep))
        ys.append(float(ep_sum[ep]) / float(c))
    return xs, ys


def _ensure_out_dir(p: str) -> str:
    p = os.path.abspath(p)
    os.makedirs(p, exist_ok=True)
    return p


def main() -> int:
    ap = argparse.ArgumentParser(description="Plot reward curves from bandit_metrics.json (JSON-lines)")
    ap.add_argument("--log-path", required=True, help="path to bandit_metrics.json")
    ap.add_argument("--episode-steps", type=int, default=50, help="steps per episode (default 50)")
    ap.add_argument("--warmup", type=int, default=20, help="warmup steps (default 20)")
    ap.add_argument("--out-dir", default=None, help="output directory (default: log dir)")
    ap.add_argument("--rolling", type=int, default=200, help="rolling mean window (steps)")
    ap.add_argument("--rolling-episode", type=int, default=10, help="rolling mean window (episodes)")
    args = ap.parse_args()

    log_path = os.path.abspath(str(args.log_path))
    if not os.path.exists(log_path):
        raise FileNotFoundError(log_path)

    out_dir = args.out_dir
    if not out_dir:
        out_dir = os.path.dirname(log_path)
    out_dir = _ensure_out_dir(str(out_dir))

    series = load_reward_series(log_path)
    if not series.t:
        raise RuntimeError(f"no reward records parsed from {log_path}")

    # Matplotlib import late so the script can still be used to parse without it.
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    # 1) Step-level reward
    fig = plt.figure(figsize=(12, 4.5), dpi=150)
    ax = fig.add_subplot(1, 1, 1)
    ax.plot(series.t, series.reward, color="#4C78A8", linewidth=0.8, alpha=0.35, label="reward (per step)")

    rm = rolling_mean(series.reward, int(args.rolling))
    xs_rm = [x for x, y in zip(series.t, rm) if y is not None]
    ys_rm = [y for y in rm if y is not None]
    if xs_rm:
        ax.plot(xs_rm, ys_rm, color="#F58518", linewidth=1.5, alpha=0.9, label=f"rolling mean ({int(args.rolling)} steps)")

    # Warmup marker (t < warmup): policy is random there.
    warm = int(args.warmup)
    if warm > 0:
        ax.axvline(warm, color="#54A24B", linestyle="--", linewidth=1.2, alpha=0.9, label=f"warmup end (t={warm})")

    ax.set_title("Bandit training reward (step-level)")
    ax.set_xlabel("t (step index)")
    ax.set_ylabel("reward")
    ax.grid(True, which="both", linestyle=":", linewidth=0.6, alpha=0.6)
    ax.legend(loc="best", fontsize=9)

    out1 = os.path.join(out_dir, "reward_step.png")
    fig.tight_layout()
    fig.savefig(out1)
    plt.close(fig)

    # 2) Episode-level mean reward
    ep_x, ep_y = episode_mean(series, episode_steps=int(args.episode_steps))
    fig2 = plt.figure(figsize=(12, 4.5), dpi=150)
    ax2 = fig2.add_subplot(1, 1, 1)
    ax2.plot(ep_x, ep_y, color="#4C78A8", linewidth=1.2, alpha=0.8, label="episode mean reward")

    ep_rm = rolling_mean(ep_y, int(args.rolling_episode))
    xs_ep_rm = [x for x, y in zip(ep_x, ep_rm) if y is not None]
    ys_ep_rm = [y for y in ep_rm if y is not None]
    if xs_ep_rm:
        ax2.plot(
            xs_ep_rm,
            ys_ep_rm,
            color="#F58518",
            linewidth=2.0,
            alpha=0.95,
            label=f"rolling mean ({int(args.rolling_episode)} episodes)",
        )

    # Warmup affects only first 20 steps; mark the episode boundary after warmup.
    if warm > 0:
        warm_ep = warm // int(args.episode_steps)
        ax2.axvline(
            warm_ep,
            color="#54A24B",
            linestyle="--",
            linewidth=1.2,
            alpha=0.9,
            label=f"warmup end (~ep {warm_ep})",
        )

    ax2.set_title(f"Bandit training reward (episode mean, episode_steps={int(args.episode_steps)})")
    ax2.set_xlabel("episode index")
    ax2.set_ylabel("mean reward")
    ax2.grid(True, which="both", linestyle=":", linewidth=0.6, alpha=0.6)
    ax2.legend(loc="best", fontsize=9)

    out2 = os.path.join(out_dir, "reward_episode.png")
    fig2.tight_layout()
    fig2.savefig(out2)
    plt.close(fig2)

    # Also dump a compact CSV for quick grepping.
    csv_path = os.path.join(out_dir, "reward_step.csv")
    with open(csv_path, "w", encoding="utf-8") as f:
        f.write("t,reward\n")
        for t, r in zip(series.t, series.reward):
            f.write(f"{int(t)},{float(r)}\n")

    print(out1)
    print(out2)
    print(csv_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
