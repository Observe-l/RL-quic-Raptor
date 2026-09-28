from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional

import numpy as np

# Allow running as a script from the repository root or this directory.
_THIS_DIR = os.path.dirname(__file__)
_PYTHON_DIR = os.path.abspath(os.path.join(_THIS_DIR, ".."))
if _PYTHON_DIR not in sys.path:
    sys.path.insert(0, _PYTHON_DIR)

from bandit.action_set import ActionSet  # noqa: E402
from bandit.context import ContextBuilder, ContextConfig  # noqa: E402
from bandit.features import phi as phi_fn  # noqa: E402
from bandit.lints import LinTS, LinTSConfig  # noqa: E402


def _load_observation_pool(path: str) -> List[Dict[str, Any]]:
    pool: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
                info = rec.get("env_info") or {}
                raw_obs = info.get("raw_obs") or {}
                reward = float(rec["reward"])
                if not isinstance(raw_obs, dict) or not np.isfinite(reward):
                    continue
                if int(info.get("step_valid", 1)) == 0:
                    continue
                pool.append(rec)
            except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
                raise ValueError(f"invalid metrics record at {path}:{line_no}: {exc}") from exc
    if not pool:
        raise ValueError(f"no usable observations found in {path}")
    return pool


def _raw_obs_vector(raw_obs: Dict[str, Any]) -> np.ndarray:
    """Convert logged policy-safe raw_obs fields to ContextBuilder's 5-vector."""
    done_flag = raw_obs.get("done_flag")
    if done_flag is None:
        done_flag = 1.0 - float(np.clip(float(raw_obs.get("timeout_flag", 0.0)), 0.0, 1.0))
    values = np.asarray(
        [
            float(raw_obs.get("goodput", raw_obs.get("goodput_mbps", 0.0))),
            float(raw_obs.get("fec_overhead", raw_obs.get("fec_overhead_pct_arrival", 0.0))),
            float(raw_obs.get("ctrl_tx_nack_msgs", 0.0)),
            float(done_flag),
            float(raw_obs.get("fec_rate", 0.0)),
        ],
        dtype=np.float64,
    )
    if not np.isfinite(values).all():
        raise ValueError("non-finite value in logged raw_obs")
    return values


def _stats(values_ns: List[int]) -> Dict[str, Any]:
    values_ms = np.asarray(values_ns, dtype=np.float64) / 1e6
    n = int(values_ms.size)
    return {
        "n": n,
        "mean_ms": float(np.mean(values_ms)) if n else None,
        "std_ms": float(np.std(values_ms, ddof=1)) if n > 1 else (0.0 if n == 1 else None),
        "sum_ms": float(np.sum(values_ms)) if n else None,
    }


def _write_json(path: str, value: Any) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(value, f, ensure_ascii=False, indent=2)
        f.write("\n")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Compute-only LinTS replay benchmark using observations from bandit_metrics.json"
    )
    ap.add_argument("--metrics-jsonl", required=True, help="source bandit_metrics.json")
    ap.add_argument("--steps", type=int, default=2000)
    ap.add_argument("--warmup", type=int, default=20)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--result-dir", required=True)
    ap.add_argument("--ctx-alpha", type=float, default=0.2)
    ap.add_argument("--ctx-window", type=int, default=50)
    ap.add_argument("--lints-lam", type=float, default=1.0)
    ap.add_argument("--lints-sigma", type=float, default=0.2)
    ap.add_argument("--lints-rho", type=float, default=0.99)
    ap.add_argument("--lints-recompute", type=int, default=100)
    args = ap.parse_args()

    steps = int(args.steps)
    warmup = int(args.warmup)
    if steps <= 0:
        raise ValueError("--steps must be positive")
    if warmup < 0 or warmup >= steps:
        raise ValueError("--warmup must be in [0, steps)")

    source_path = os.path.abspath(args.metrics_jsonl)
    output_dir = os.path.abspath(args.result_dir)
    if os.path.exists(output_dir):
        raise FileExistsError(f"result directory already exists: {output_dir}")
    os.makedirs(output_dir)

    pool = _load_observation_pool(source_path)
    action_set = ActionSet()
    action_features = np.asarray(
        [action_set.get_onehot(i) for i in range(len(action_set))], dtype=np.float64
    )
    ctx_cfg = ContextConfig(ewma_alpha=float(args.ctx_alpha), window=int(args.ctx_window))
    ctx = ContextBuilder(ctx_cfg)
    x0 = ctx.get_context()
    dim = 1 + int(x0.size) + int(action_set.onehot_dim) + int(x0.size) * int(action_set.onehot_dim)
    lints_cfg = LinTSConfig(
        lam=float(args.lints_lam),
        sigma=float(args.lints_sigma),
        rho=float(args.lints_rho),
        recompute_inv_every=int(args.lints_recompute),
        seed=int(args.seed),
    )
    agent = LinTS(dim=dim, cfg=lints_cfg)

    observation_rng = np.random.RandomState(int(args.seed) + 1)
    warmup_rng = np.random.RandomState(int(args.seed) + 2)
    timing_records: List[Dict[str, Any]] = []
    exact_update_wall: List[int] = []
    regular_update_wall: List[int] = []

    timing_path = os.path.join(output_dir, "bandit_timings.jsonl")
    replay_path = os.path.join(output_dir, "offline_replay.jsonl")
    run_wall_start = time.perf_counter_ns()
    run_cpu_start = time.process_time_ns()

    with open(timing_path, "w", encoding="utf-8") as timing_file, open(
        replay_path, "w", encoding="utf-8"
    ) as replay_file:
        for t in range(steps):
            # Context uses only observations replayed before this decision.
            x = ctx.get_context()
            scoring_wall_ns: Optional[int] = None
            scoring_cpu_ns: Optional[int] = None
            if t < warmup:
                a_idx = int(warmup_rng.randint(0, len(action_set)))
            else:
                wall_start = time.perf_counter_ns()
                cpu_start = time.process_time_ns()
                a_idx, _theta = agent.select_action_features(
                    x=x,
                    action_features=action_features,
                )
                scoring_wall_ns = time.perf_counter_ns() - wall_start
                scoring_cpu_ns = time.process_time_ns() - cpu_start

            # Sample with replacement after choosing an action, like receiving
            # an environment response. No FecEnv/network operation is called.
            sample_idx = int(observation_rng.randint(0, len(pool)))
            sample = pool[sample_idx]
            sample_info = sample.get("env_info") or {}
            raw_obs = sample_info.get("raw_obs") or {}
            obs = _raw_obs_vector(raw_obs)
            reward = float(sample["reward"])
            ctx.update_from_obs(obs=obs)

            feature_wall_ns: Optional[int] = None
            feature_cpu_ns: Optional[int] = None
            update_wall_ns: Optional[int] = None
            update_cpu_ns: Optional[int] = None
            exact_inverse_due: Optional[bool] = None
            if t >= warmup:
                wall_start = time.perf_counter_ns()
                cpu_start = time.process_time_ns()
                ph = phi_fn(x=x, a_onehot=action_set.get_onehot(a_idx))
                feature_wall_ns = time.perf_counter_ns() - wall_start
                feature_cpu_ns = time.process_time_ns() - cpu_start

                exact_inverse_due = ((agent.t + 1) % int(lints_cfg.recompute_inv_every)) == 0
                wall_start = time.perf_counter_ns()
                cpu_start = time.process_time_ns()
                agent.update(phi=ph, reward=reward)
                update_wall_ns = time.perf_counter_ns() - wall_start
                update_cpu_ns = time.process_time_ns() - cpu_start
                (exact_update_wall if exact_inverse_due else regular_update_wall).append(update_wall_ns)

            timing_rec = {
                "t": int(t),
                "warmup": bool(t < warmup),
                "sampled_metrics_t": sample.get("t"),
                "step_valid": True,
                "exact_inverse_due": exact_inverse_due,
                "action_scoring_wall_ns": scoring_wall_ns,
                "action_scoring_cpu_ns": scoring_cpu_ns,
                "feature_map_wall_ns": feature_wall_ns,
                "feature_map_cpu_ns": feature_cpu_ns,
                "posterior_update_wall_ns": update_wall_ns,
                "posterior_update_cpu_ns": update_cpu_ns,
            }
            timing_records.append(timing_rec)
            timing_file.write(json.dumps(timing_rec, ensure_ascii=False) + "\n")

            action = action_set.get_action(a_idx)
            replay_rec = {
                "t": int(t),
                "warmup": bool(t < warmup),
                "context": [float(v) for v in x.tolist()],
                "selected_action_idx": int(a_idx),
                "selected_action": {
                    "k_idx": int(action.k_idx),
                    "r0_idx": int(action.r0_idx),
                    "rstep_idx": int(action.rstep_idx),
                },
                "sampled_metrics_t": sample.get("t"),
                "sampled_logged_action_idx": sample.get("a_idx"),
                "replayed_reward": reward,
                "observation": [float(v) for v in obs.tolist()],
            }
            replay_file.write(json.dumps(replay_rec, ensure_ascii=False) + "\n")
            if (t + 1) % 50 == 0:
                timing_file.flush()
                replay_file.flush()
            if (t + 1) % 100 == 0 or t + 1 == steps:
                elapsed = (time.perf_counter_ns() - run_wall_start) / 1e9
                print(f"[offline] step={t + 1}/{steps} elapsed={elapsed:.1f}s", flush=True)

    run_wall_ns = time.perf_counter_ns() - run_wall_start
    run_cpu_ns = time.process_time_ns() - run_cpu_start

    fields = (
        ("action_scoring", "action_scoring_wall_ns", "action_scoring_cpu_ns"),
        ("feature_map", "feature_map_wall_ns", "feature_map_cpu_ns"),
        ("posterior_update", "posterior_update_wall_ns", "posterior_update_cpu_ns"),
    )
    summary_rows: List[Dict[str, Any]] = []
    for name, wall_key, cpu_key in fields:
        wall_values = [int(r[wall_key]) for r in timing_records if r[wall_key] is not None]
        cpu_values = [int(r[cpu_key]) for r in timing_records if r[cpu_key] is not None]
        wall_stats = _stats(wall_values)
        cpu_stats = _stats(cpu_values)
        summary_rows.append(
            {
                "operation": name,
                "samples": wall_stats["n"],
                "wall_mean_ms": wall_stats["mean_ms"],
                "wall_std_ms": wall_stats["std_ms"],
                "wall_sum_ms": wall_stats["sum_ms"],
                "process_cpu_mean_ms": cpu_stats["mean_ms"],
                "process_cpu_std_ms": cpu_stats["std_ms"],
                "process_cpu_sum_ms": cpu_stats["sum_ms"],
            }
        )

    exact_stats = _stats(exact_update_wall)
    regular_stats = _stats(regular_update_wall)
    summary = {
        "experiment": "offline_lints_compute_replay",
        "steps": steps,
        "warmup_steps": warmup,
        "observation_pool_size": len(pool),
        "observation_sampling": "uniform with replacement, seeded",
        "source_metrics_jsonl": source_path,
        "network_transfers": 0,
        "action_count": len(action_set),
        "action_feature_dim": int(action_set.onehot_dim),
        "context_dim": int(x0.size),
        "lin_ts_dim": dim,
        "seed": int(args.seed),
        "context_config": {
            "ewma_alpha": float(args.ctx_alpha),
            "window": int(args.ctx_window),
        },
        "lints_config": {
            "lam": float(args.lints_lam),
            "sigma": float(args.lints_sigma),
            "rho": float(args.lints_rho),
            "recompute_inv_every": int(args.lints_recompute),
        },
        "timing_summary": summary_rows,
        "posterior_update_wall_stratified": {
            "periodic_exact_inverse": exact_stats,
            "Sherman_Morrison_update": regular_stats,
        },
        "loop_wall_time_ms": float(run_wall_ns / 1e6),
        "loop_process_cpu_time_ms": float(run_cpu_ns / 1e6),
        "interpretation_note": (
            "Compute-only replay, not an offline policy-performance estimate: each newly selected action is paired "
            "with a uniformly sampled logged observation and its logged reward, which was originally generated "
            "under the logged action."
        ),
    }
    _write_json(os.path.join(output_dir, "timing_summary.json"), summary)
    with open(os.path.join(output_dir, "timing_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(summary_rows[0].keys()))
        writer.writeheader()
        writer.writerows(summary_rows)

    print(f"wrote {timing_path}")
    print(f"wrote {replay_path}")
    print(f"wrote {os.path.join(output_dir, 'timing_summary.csv')}")
    print(f"wrote {os.path.join(output_dir, 'timing_summary.json')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
