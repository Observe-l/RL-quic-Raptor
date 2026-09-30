from __future__ import annotations

import argparse
import csv
from concurrent.futures import Future, ThreadPoolExecutor
import json
import os
import subprocess
import sys
import time
from dataclasses import asdict
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

# Allow running as a script:
#   python3 bandit/run_lints_ge_schedule.py ...
# by ensuring the project root (python/) is on sys.path.
_THIS_DIR = os.path.dirname(__file__)
_ROOT_DIR = os.path.abspath(os.path.join(_THIS_DIR, ".."))
if _ROOT_DIR not in sys.path:
    sys.path.insert(0, _ROOT_DIR)

_REPO_ROOT = os.path.abspath(os.path.join(_ROOT_DIR, ".."))

from bandit.action_set import ActionSet  # noqa: E402
from bandit.context import ContextBuilder, ContextConfig  # noqa: E402
from bandit.lints import LinTS, LinTSConfig  # noqa: E402
from bandit.model_io import load_checkpoint, save_checkpoint  # noqa: E402


_DEFAULT_PRIV_HELPER = "/usr/local/libexec/quicfec-net-helper"


def _eval_reward(record: Dict[str, Any], *, capacity_mbps: float) -> float:
    env_info = record.get("env_info") if isinstance(record.get("env_info"), dict) else {}
    if (
        int(env_info.get("is_timeout", 0) or 0)
        or int(env_info.get("is_md5_fail", 0) or 0)
        or int(env_info.get("step_valid", 1) or 0) == 0
    ):
        return -1.0
    raw = env_info.get("raw_obs") if isinstance(env_info.get("raw_obs"), dict) else {}
    run = env_info.get("extra", {}).get("run", {}) if isinstance(env_info.get("extra"), dict) else {}
    try:
        goodput = float(raw.get("goodput", 0.0) or 0.0)
        overhead = max(0.0, float(raw.get("fec_overhead", 0.0) or 0.0))
        done = min(1.0, max(0.0, float(raw.get("done_flag", 0.0) or 0.0)))
        attempts = float(run.get("arq_attempts", 0.0) or 0.0)
        clusters = float(run.get("arq_clusters", 0.0) or 0.0)
        arq_mean = attempts / clusters if clusters > 0 else 0.0
    except (TypeError, ValueError):
        return -1.0
    return (
        goodput / max(1e-6, float(capacity_mbps))
        + 0.3 / (1.0 + (overhead / 0.25) ** 2)
        - 0.1 * min(1.0, max(0.0, arq_mean / 2.0))
        - 0.3 * (1.0 - done)
    )


def _evaluate_checkpoint(
    *,
    step: int,
    policy: str,
    repeats: int,
    checkpoint_prefix: str,
    result_dir: str,
    args: argparse.Namespace,
) -> Dict[str, Any]:
    """Run one isolated testbed evaluation process on the full GE sender set."""
    evaluator = os.path.join(_ROOT_DIR, "experiments", "eval_bandit_model_on_testbed.py")
    policy_tag = "r" if policy == "random" else "p"
    run_tag = f"{policy_tag}{int(step):06d}"[-8:]
    eval_dir_base = os.path.join(result_dir, "evaluations", f"step_{int(step)}_{policy}")
    eval_dir = eval_dir_base
    retry = 0
    while os.path.exists(eval_dir):
        retry += 1
        eval_dir = f"{eval_dir_base}_retry{retry}"
    os.makedirs(eval_dir, exist_ok=True)
    log_path = os.path.join(eval_dir, "launcher.log")
    command = [
        sys.executable,
        "-u",
        evaluator,
        "--checkpoint-prefix", checkpoint_prefix,
        "--out-dir", eval_dir,
        "--run-tag", run_tag,
        "--policy", policy,
        # Random baseline does no policy scoring; keep it on CPU so the GPU is
        # available to training and the greedy bandit evaluators.
        "--device", str(args.device if policy != "random" else "cpu"),
        "--seed", str(int(args.seed) + 700_000 + int(step)),
        "--policy-repeats", "1",
        "--ctx-reset", "never",
        "--loss-profile", "ge",
        "--ge-params", str(args.ge_params),
        "--ge-key", str(args.ge_key),
        "--ge-h-pct", str(float(args.ge_h_pct)),
        "--ge-k-pct", str(float(args.ge_k_pct)),
        "--sender-ids", str(args.eval_sender_ids),
        "--bitrate-mbps", str(int(args.bitrate_mbps)),
        "--timeout-transfer-s", str(int(args.timeout_sec)),
        "--timeout-s", str(max(15, int(args.timeout_sec) + 5)),
        "--steps-per-scenario", str(int(repeats)),
        "--file-bytes", str(int(args.train_file_bytes)),
        "--symbol-bytes", "1200",
        "--decode-ddl-ms", "25",
        "--done-deadline-ms", "500",
        "--enable-quic-overhead", "1",
        "--cc", "bbrv2",
    ]
    helper = os.environ.get("QUIC_FEC_PRIV_HELPER", _DEFAULT_PRIV_HELPER)
    env = os.environ.copy()
    # Keep concurrently running testbeds in disjoint, deterministic /24s.
    # The training runner reserves 172.31.220-239; policy evaluations use
    # slots 0..199 (172.31.20-219), and the one-time random baseline uses 199.
    if policy == "random":
        eval_slot = 199
    else:
        interval = max(1, int(args.eval_interval))
        eval_slot = max(0, (int(step) // interval - 1) % 199)
    env.update({
        "QUIC_FEC_PRIV_HELPER": helper,
        "QUICFEC_EVAL_SLOT": str(eval_slot),
        "CONNECT_RETRIES": "1",
        "CONNECT_TIMEOUT_S": str(int(args.timeout_sec)),
        "TIMEOUT_S": str(int(args.timeout_sec)),
        "SRV_TIMEOUT": f"{int(args.timeout_sec)}s",
        "CLI_TIMEOUT": f"{int(args.timeout_sec)}s",
        "POST_WAIT": "0ms",
        "TRANSPORT": "dgram",
        "USE_ARQ": "1",
        "W": "8",
        "MAX_ATTEMPTS": "0",
        "FEC_STATS": "1",
        "TUNE_UDP_BUFFERS": "0",
        "QUIC_FEC_ARQ_DRAIN_CAP_MS": str(int(args.timeout_sec) * 1000),
        "OMP_NUM_THREADS": "1",
        "OPENBLAS_NUM_THREADS": "1",
        "MKL_NUM_THREADS": "1",
        "NUMEXPR_NUM_THREADS": "1",
    })
    with open(log_path, "w", encoding="utf-8") as log:
        log.write("command=" + " ".join(command) + "\n")
        log.flush()
        proc = subprocess.run(command, cwd=_REPO_ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, check=False)

    # Evaluation uses a unique namespace. Remove only this evaluation's resources.
    try:
        subprocess.run(
            ["sudo", "-n", helper, "cleanup", f"qns_{run_tag}", f"vh{run_tag}"],
            cwd=_REPO_ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
            timeout=30,
            check=False,
        )
    except Exception as exc:
        with open(log_path, "a", encoding="utf-8") as log:
            log.write(f"\n[cleanup-exception] {exc!r}\n")
    if proc.returncode != 0:
        raise RuntimeError(f"{policy} evaluation at step {step} failed (exit={proc.returncode}); see {log_path}")

    metrics_path = os.path.join(eval_dir, "bandit_eval_metrics.jsonl")
    rewards: List[float] = []
    successes = 0
    sender_rewards: Dict[int, List[float]] = {}
    sender_successes: Dict[int, int] = {}
    with open(metrics_path, "r", encoding="utf-8") as source:
        for line in source:
            if not line.strip():
                continue
            record = json.loads(line)
            reward = _eval_reward(record, capacity_mbps=float(args.bitrate_mbps))
            rewards.append(reward)
            sender_id = int(record["sender_id"])
            sender_rewards.setdefault(sender_id, []).append(reward)
            env_info = record.get("env_info", {})
            if int(env_info.get("step_valid", 0) or 0) == 1:
                successes += 1
                sender_successes[sender_id] = sender_successes.get(sender_id, 0) + 1
    if not rewards:
        raise RuntimeError(f"{policy} evaluation at step {step} wrote no records: {metrics_path}")
    raw_sender_ids = str(args.eval_sender_ids).strip().lower()
    if raw_sender_ids == "all":
        expected_sender_ids = [sid for sid, _ in _load_senders(str(args.ge_params))]
    else:
        expected_sender_ids = []
        for part in raw_sender_ids.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                lo, hi = (int(v) for v in part.split("-", 1))
                expected_sender_ids.extend(range(min(lo, hi), max(lo, hi) + 1))
            else:
                expected_sender_ids.append(int(part))
        expected_sender_ids = sorted(set(expected_sender_ids))
    bad_repeat_counts = {
        int(sender_id): len(sender_rewards.get(int(sender_id), []))
        for sender_id in expected_sender_ids
        if len(sender_rewards.get(int(sender_id), [])) != int(repeats)
    }
    unexpected_sender_ids = sorted(set(sender_rewards) - set(expected_sender_ids))
    if bad_repeat_counts or unexpected_sender_ids:
        raise RuntimeError(
            f"{policy} evaluation at step {step} did not meet the per-sender repeat contract "
            f"(expected {int(repeats)} each); mismatches={bad_repeat_counts}, "
            f"unexpected_senders={unexpected_sender_ids}, records={len(rewards)}"
        )
    per_sender = []
    for sender_id in expected_sender_ids:
        values = sender_rewards[int(sender_id)]
        per_sender.append({
            "sender_id": int(sender_id),
            "records": len(values),
            "mean_reward": float(np.mean(values)),
            "std_reward": float(np.std(values, ddof=1)) if len(values) > 1 else 0.0,
            "success_rate": float(sender_successes.get(int(sender_id), 0) / len(values)),
        })
    return {
        "step": int(step),
        "policy": policy,
        "repeats_per_sender": int(repeats),
        "records": len(rewards),
        "sender_count": len(expected_sender_ids),
        "repeat_counts_valid": True,
        "per_sender": per_sender,
        "mean_reward": float(np.mean(rewards)),
        "std_reward": float(np.std(rewards, ddof=1)) if len(rewards) > 1 else 0.0,
        "success_rate": float(successes / len(rewards)),
        "eval_dir": eval_dir,
    }


def _write_regret_curve(rows: List[Dict[str, Any]], result_dir: str) -> None:
    if not rows:
        return
    csv_path = os.path.join(result_dir, "regret_vs_random.csv")
    fields = ["step", "bandit_reward", "random_reward", "regret_vs_random", "improvement_vs_random", "success_rate", "bandit_records", "random_records"]
    with open(csv_path, "w", newline="", encoding="utf-8") as target:
        writer = csv.DictWriter(target, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        x = [int(row["step"]) for row in rows]
        y = [float(row["regret_vs_random"]) for row in rows]
        fig, ax = plt.subplots(figsize=(8, 5), dpi=160)
        ax.plot(x, y, color="#1f77b4", marker="o", markersize=3.5, linewidth=1.7, label="Random − bandit baseline")
        ax.axhline(0.0, color="#333333", linestyle="--", linewidth=1.0)
        ax.set_xlabel("Training step")
        ax.set_ylabel("Regret vs random (random reward − bandit reward)")
        ax.grid(True, color="#d0d0d0", linewidth=0.7, alpha=0.8)
        ax.legend(loc="best", frameon=True)
        fig.tight_layout()
        fig.savefig(os.path.join(result_dir, "regret_vs_random.png"), bbox_inches="tight")
        plt.close(fig)
    except Exception as exc:
        print(f"[eval] regret plot skipped: {exc}", file=sys.stderr, flush=True)


def _write_oracle_regret_outputs(
    *,
    policy_results: Dict[int, Dict[str, Any]],
    oracle: Dict[str, Any],
    result_dir: str,
) -> None:
    """Refresh checkpoint regret against the fixed per-sender action oracle."""
    scenes = oracle.get("scenes")
    if not isinstance(scenes, dict):
        raise ValueError("oracle JSON is missing its scenes mapping")

    sender_rows: List[Dict[str, Any]] = []
    excluded_rows: List[Dict[str, Any]] = []
    summary_rows: List[Dict[str, Any]] = []
    for step, result in sorted(policy_results.items()):
        rows_this_step: List[Dict[str, Any]] = []
        policy_by_sender = {
            int(item["sender_id"]): item
            for item in result.get("per_sender", [])
        }
        for sid, policy_row in sorted(policy_by_sender.items()):
            scene = scenes.get(str(sid), scenes.get(sid))
            if not isinstance(scene, dict) or not isinstance(scene.get("oracle"), dict):
                raise ValueError(f"oracle JSON has no oracle result for sender {sid}")
            bandit_reward = float(policy_row["mean_reward"])
            if bandit_reward == -1.0:
                excluded_rows.append({
                    "checkpoint_step": int(step),
                    "sender_id": int(sid),
                    "repeat_count": int(policy_row["records"]),
                    "excluded_reason": "all_repeated_policy_rewards_are_minus_one",
                })
                continue
            oracle_reward = float(scene["oracle"]["mean_reward"])
            row = {
                "checkpoint_step": int(step),
                "sender_id": int(sid),
                "oracle_reward": oracle_reward,
                "bandit_reward": bandit_reward,
                "regret": oracle_reward - bandit_reward,
                "bandit_reward_std": float(policy_row["std_reward"]),
                "bandit_success_rate": float(policy_row["success_rate"]),
                "repeat_count": int(policy_row["records"]),
            }
            rows_this_step.append(row)
            sender_rows.append(row)

        regrets = np.asarray([row["regret"] for row in rows_this_step], dtype=np.float64)
        oracle_rewards = np.asarray([row["oracle_reward"] for row in rows_this_step], dtype=np.float64)
        bandit_rewards = np.asarray([row["bandit_reward"] for row in rows_this_step], dtype=np.float64)
        success_rates = np.asarray([row["bandit_success_rate"] for row in rows_this_step], dtype=np.float64)
        summary_rows.append({
            "checkpoint_step": int(step),
            "scenes": int(len(rows_this_step)),
            "excluded_all_minus_one_senders": int(len(policy_by_sender) - len(rows_this_step)),
            "mean_regret": float(np.mean(regrets)) if regrets.size else float("nan"),
            "median_regret": float(np.median(regrets)) if regrets.size else float("nan"),
            "p10_regret": float(np.percentile(regrets, 10)) if regrets.size else float("nan"),
            "p90_regret": float(np.percentile(regrets, 90)) if regrets.size else float("nan"),
            "positive_regret_fraction": float(np.mean(regrets > 0.0)) if regrets.size else float("nan"),
            "mean_oracle_reward": float(np.mean(oracle_rewards)) if regrets.size else float("nan"),
            "mean_bandit_reward": float(np.mean(bandit_rewards)) if regrets.size else float("nan"),
            "mean_success_rate": float(np.mean(success_rates)) if regrets.size else float("nan"),
        })

    def write_csv(filename: str, rows: List[Dict[str, Any]]) -> None:
        path = os.path.join(result_dir, filename)
        fields = list(rows[0]) if rows else []
        with open(path, "w", newline="", encoding="utf-8") as target:
            writer = csv.DictWriter(target, fieldnames=fields)
            if fields:
                writer.writeheader()
                writer.writerows(rows)

    write_csv("oracle_regret_per_sender.csv", sender_rows)
    write_csv("oracle_regret_summary.csv", summary_rows)
    write_csv("oracle_regret_excluded_senders.csv", excluded_rows)

    analysis = {
        "regret_definition": "per-sender oracle mean reward minus checkpoint policy mean reward",
        "aggregate": "unweighted mean across eligible senders at each checkpoint",
        "all_minus_one_filter": "exclude a sender at a checkpoint when all repeated policy rewards are -1.0",
        "oracle_available_sender_count": len(scenes),
        "policy_evaluation_sender_count": len(policy_results[next(iter(policy_results))].get("per_sender", [])) if policy_results else 0,
        "oracle_completed_trials": oracle.get("completed_trials"),
        "oracle_total_trials": oracle.get("total_trials"),
        "checkpoint_count": len(summary_rows),
        "repeats_per_sender": sorted({
            int(min(row["records"] for row in policy_results[s]["per_sender"]))
            for s in sorted(policy_results)
            if policy_results[s].get("per_sender")
        }),
        "windows": [],
    }
    latest_step = int(summary_rows[-1]["checkpoint_step"])
    for name, low, high in (("early", 100, 1500), ("middle", 1600, 3500), ("late", 3600, latest_step)):
        window = [row for row in summary_rows if low <= int(row["checkpoint_step"]) <= high]
        if window:
            analysis["windows"].append({
                "window": name,
                "step_min": min(int(row["checkpoint_step"]) for row in window),
                "step_max": max(int(row["checkpoint_step"]) for row in window),
                "checkpoint_count": len(window),
                "mean_checkpoint_regret": float(np.mean([float(row["mean_regret"]) for row in window])),
                "mean_policy_reward": float(np.mean([float(row["mean_bandit_reward"]) for row in window])),
            })
    with open(os.path.join(result_dir, "oracle_regret_analysis.json"), "w", encoding="utf-8") as target:
        json.dump(analysis, target, indent=2, ensure_ascii=False, default=_json_default)
        target.write("\n")

    if not summary_rows:
        return
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        steps = np.asarray([int(row["checkpoint_step"]) for row in summary_rows], dtype=np.int64)
        means = np.asarray([float(row["mean_regret"]) for row in summary_rows], dtype=np.float64)
        p10 = np.asarray([float(row["p10_regret"]) for row in summary_rows], dtype=np.float64)
        p90 = np.asarray([float(row["p90_regret"]) for row in summary_rows], dtype=np.float64)
        fig, ax = plt.subplots(figsize=(8.5, 5.5), dpi=160)
        ax.plot(steps, means, color="#1f77b4", marker="o", markersize=3, linewidth=2.0, label="Mean regret")
        ax.fill_between(steps, p10, p90, color="#1f77b4", alpha=0.18, label="Across-sender 10–90th percentile")
        ax.axhline(0.0, color="#333333", linewidth=1.0, linestyle="--", label="Zero regret")
        ax.set_xlabel("Training checkpoint (step)")
        ax.set_ylabel("Reward regret (oracle − bandit)")
        ax.set_title("Bandit policy regret on GE_steady_rp")
        ax.grid(True, color="#d0d0d0", linewidth=0.7, alpha=0.8)
        ax.legend(loc="best", frameon=True)
        fig.tight_layout()
        fig.savefig(os.path.join(result_dir, "oracle_regret_vs_training_step.png"), bbox_inches="tight")
        plt.close(fig)
    except Exception as exc:
        print(f"[eval] oracle regret plot skipped: {exc}", file=sys.stderr, flush=True)


def _json_default(o: Any):
    """JSON fallback encoder for long-running experiments.

    Converts common non-JSON types (bytes, numpy scalars/arrays, exceptions) into
    serializable Python types.
    """

    # bytes frequently appear in subprocess timeout stdout/stderr.
    if isinstance(o, (bytes, bytearray, memoryview)):
        try:
            return bytes(o).decode("utf-8", errors="replace")
        except Exception:
            return repr(o)

    # Numpy types
    try:
        import numpy as _np  # local import to avoid hard dependency in docs

        if isinstance(o, _np.generic):
            return o.item()
        if isinstance(o, _np.ndarray):
            return o.tolist()
    except Exception:
        pass

    # Exceptions and everything else
    try:
        return str(o)
    except Exception:
        return repr(o)


def _ensure_dir(p: str) -> None:
    os.makedirs(p, exist_ok=True)


def _find_latest_saved_prefix(dest_dir: str) -> Optional[str]:
    """Find the latest saved model prefix under a result dir.

    Priority:
      1) newest fixed-interval checkpoint under <dest_dir>/checkpoints/model_t*.json
      2) <dest_dir>/bandit_model.json (latest checkpoint)
    """

    dest_dir = os.path.abspath(dest_dir)
    checkpoint_root = os.path.join(dest_dir, "checkpoints")
    latest_t = None
    latest_prefix = None
    if os.path.isdir(checkpoint_root):
        for fn in os.listdir(checkpoint_root):
            if not (fn.startswith("model_t") and fn.endswith(".json")):
                continue
            try:
                stem = fn[:-5]
                t_val = int(stem[len("model_t") :])
            except Exception:
                continue
            prefix = os.path.join(checkpoint_root, stem)
            if not os.path.exists(prefix + ".npz"):
                continue
            if latest_t is None or t_val > latest_t:
                latest_t = t_val
                latest_prefix = prefix
    if latest_prefix is not None:
        return latest_prefix

    latest = os.path.join(dest_dir, "bandit_model")
    if os.path.exists(latest + ".json") and os.path.exists(latest + ".npz"):
        return latest
    return None


def _load_senders(params_path: str) -> List[Tuple[int, Dict[str, Any]]]:
    with open(params_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    senders = data.get("senders")
    if not isinstance(senders, dict) or not senders:
        raise ValueError(f"invalid GE params file (no senders): {params_path}")

    parsed: List[Tuple[int, Dict[str, Any]]] = []
    for k, v in senders.items():
        try:
            sid = int(k)
        except Exception:
            continue
        if isinstance(v, dict):
            parsed.append((sid, v))

    parsed.sort(key=lambda x: x[0])
    if not parsed:
        raise ValueError(f"no valid senders in GE params file: {params_path}")
    return parsed


def _ge_to_tc_gemodel_loss_mode(
    ge_rp: Dict[str, Any],
    *,
    h_loss_pct: float,
    k_loss_pct: float,
) -> str:
    """Build tc-netem gemodel string from GE params.

    The harness expects:
      LOSS_MODE=gemodel:p,r,h,k  (all in percent)

    `quic_fec_params.json` provides `p_g2b` and `r_b2g` in [0,1].
    We interpret tc-netem gemodel parameters as:
      p = P(good->bad), r = P(bad->good),
      h = loss probability in good state, k = loss probability in bad state.

    """

    if not isinstance(ge_rp, dict):
        raise ValueError("GE params must be a dict")

    p_g2b = ge_rp.get("p_g2b")
    r_b2g = ge_rp.get("r_b2g")
    if p_g2b is None or r_b2g is None:
        raise ValueError(f"GE_steady_rp missing p_g2b/r_b2g: keys={list(ge_rp.keys())}")

    p = float(p_g2b)
    r = float(r_b2g)
    # Convert probabilities to percents if they look like probabilities.
    p_pct = p * 100.0 if 0.0 <= p <= 1.0 else p
    r_pct = r * 100.0 if 0.0 <= r <= 1.0 else r

    # Clamp probabilities to sane ranges.
    # NOTE: Allow 100% bad-state loss when explicitly requested for experiments.
    # This can still blackhole traffic if the qdisc remains in the bad state.
    p_pct = float(np.clip(p_pct, 0.0, 100.0))
    r_pct = float(np.clip(r_pct, 0.0, 100.0))
    h_loss_pct = float(np.clip(float(h_loss_pct), 0.0, 100.0))
    k_loss_pct = float(np.clip(float(k_loss_pct), 0.0, 100.0))

    return f"gemodel:{p_pct:.6f},{r_pct:.6f},{h_loss_pct:.6f},{k_loss_pct:.6f}"


def _auto_hk_from_sender(
    *,
    loss_rate: Optional[float],
    pi_bad: Optional[float],
    k_cap_pct: float,
) -> Tuple[float, float]:
    """Derive (h,k) loss probabilities in percent.

    Uses a simple 2-state mixture model:
      L = (1 - pi_bad) * h + pi_bad * k

    Choose h=0 and solve k = L/pi_bad, then cap k below 100%.
    """

    k_cap_pct = float(np.clip(float(k_cap_pct), 0.0, 100.0))

    if loss_rate is None:
        return 0.0, k_cap_pct

    L = float(loss_rate)
    if not np.isfinite(L) or L < 0.0:
        return 0.0, k_cap_pct
    if L > 1.0:
        # Looks like percent already.
        L = float(np.clip(L / 100.0, 0.0, 1.0))

    pi = None
    if pi_bad is not None:
        try:
            pi = float(pi_bad)
        except Exception:
            pi = None
    if pi is None or (not np.isfinite(pi)) or pi <= 0.0:
        # Fallback: approximate as i.i.d.
        pct = float(np.clip(L * 100.0, 0.0, 100.0))
        return pct, pct

    k = float(np.clip((L / pi) * 100.0, 0.0, k_cap_pct))
    return 0.0, k


def main() -> int:
    # Import here so that other modules can reuse helper functions from this file
    # without requiring optional runtime dependencies (gym/gymnasium).
    from fecenv_env import FecEnv  # noqa: E402

    ap = argparse.ArgumentParser(description="LinTS runner with external GE schedule and fixed-interval checkpoints")

    ap.add_argument("--steps", type=int, default=5000, help="number of bandit steps (transfers)")
    ap.add_argument("--episode-steps", type=int, default=10, help="steps per episode (per GE sender)")
    ap.add_argument("--checkpoint-interval", type=int, default=100, help="save a checkpoint every N valid steps")
    # Retain old flags so existing launch commands fail neither parsing nor startup.
    # They no longer affect checkpoint selection or save frequency.
    ap.add_argument("--block-steps", type=int, default=1000, help=argparse.SUPPRESS)
    ap.add_argument("--save-topk", type=int, default=0, help=argparse.SUPPRESS)
    ap.add_argument("--warmup", type=int, default=0, help="random warmup steps before LinTS; 0 updates policy from the first transfer")
    ap.add_argument("--checkpoint-every-episodes", type=int, default=0, help=argparse.SUPPRESS)

    ap.add_argument(
        "--ge-params",
        type=str,
        default=os.path.join(os.path.dirname(__file__), "quic_fec_params.json"),
        help="path to quic_fec_params.json",
    )
    ap.add_argument("--ge-key", type=str, default="GE_steady_rp", help="which GE field to use per sender")
    ap.add_argument(
        "--ge-h-pct",
        type=float,
        default=0,
        help="override gemodel h (good-state loss prob) percent; default derives from sender steady loss",
    )
    ap.add_argument(
        "--ge-k-pct",
        type=float,
        default=99,
        help="override gemodel k (bad-state loss prob) percent; default derives from sender steady loss",
    )
    ap.add_argument(
        "--ge-k-cap-pct",
        type=float,
        default=99.0,
        help="cap gemodel k below 100%% to avoid permanent blackhole states",
    )

    ap.add_argument("--rtt-ms", type=int, default=50)
    ap.add_argument("--bitrate-mbps", type=int, default=10)
    ap.add_argument("--timeout-sec", type=int, default=1, help="transfer deadline in seconds")
    ap.add_argument("--train-file-bytes", type=int, default=100 * 1024)

    ap.add_argument(
        "--reward-w-goodput",
        type=float,
        default=1.0,
        help="goodput reward weight (tp_term uses goodput/capacity)",
    )
    ap.add_argument("--reward-w-arq", type=float, default=0.1)
    ap.add_argument(
        "--reward-w-overhead",
        type=float,
        default=0.3,
        help="overhead penalty weight (uses fec_overhead = tx_repair_symbols/tx_source_symbols)",
    )
    ap.add_argument(
        "--reward-w-done",
        type=float,
        default=0.3,
        help="done_flag penalty weight (done_term = -w_done*(1-done_flag))",
    )
    ap.add_argument("--reward-variant", type=str, default="qarc_v1")
    ap.add_argument("--reward-residual-binary", type=int, default=1)

    ap.add_argument("--ctx-alpha", type=float, default=0.2)
    ap.add_argument("--ctx-window", type=int, default=50)

    ap.add_argument("--lints-lam", type=float, default=1.0)
    ap.add_argument("--lints-sigma", type=float, default=0.2)
    ap.add_argument("--lints-rho", type=float, default=0.9999)
    ap.add_argument(
        "--lints-recompute",
        type=int,
        default=1,
        help="deprecated compatibility option; exact A inverse is recomputed after every update",
    )
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--device", type=str, default="cuda", help="LinTS compute device (default: cuda)")
    ap.add_argument("--eval-interval", type=int, default=100, help="run a separate-process full-GE evaluation every N training steps; 0 disables")
    ap.add_argument("--eval-repeats", type=int, default=20, help="policy evaluation transfers per GE sender at each checkpoint")
    ap.add_argument("--random-baseline-repeats", type=int, default=20, help="one-time random-policy repeats per GE sender, at the first checkpoint")
    ap.add_argument("--eval-workers", type=int, default=4, help="maximum concurrent background greedy-policy evaluation processes")
    ap.add_argument("--eval-sender-ids", type=str, default="all", help="GE sender IDs used for checkpoint evaluation (default: all)")
    ap.add_argument("--oracle-json", type=str, default=None, help="optional per-sender action-oracle JSON; enables online oracle-regret CSV/plot output")

    ap.add_argument("--result-dir", type=str, default=None, help="directory to write bandit_metrics.json")
    ap.add_argument(
        "--timing-jsonl",
        type=str,
        default=None,
        help="optional per-attempt action-scoring/feature-map/posterior-update timing log",
    )
    ap.add_argument(
        "--checkpoint-prefix",
        type=str,
        default=None,
        help="prefix path for saving/loading model (writes <prefix>.npz and <prefix>.json)",
    )
    ap.add_argument("--resume", action="store_true", help="resume from --checkpoint-prefix if present")

    args = ap.parse_args()

    total_steps = int(args.steps)
    episode_steps = int(args.episode_steps)
    checkpoint_interval = int(args.checkpoint_interval)
    warmup = int(args.warmup)
    eval_interval = int(args.eval_interval)

    if episode_steps <= 0:
        raise ValueError("--episode-steps must be > 0")
    if checkpoint_interval <= 0:
        raise ValueError("--checkpoint-interval must be > 0")
    if eval_interval < 0:
        raise ValueError("--eval-interval must be >= 0")
    if int(args.eval_repeats) <= 0 or int(args.random_baseline_repeats) <= 0:
        raise ValueError("evaluation repeat counts must be positive")
    if int(args.eval_workers) <= 0:
        raise ValueError("--eval-workers must be positive")
    if total_steps <= 0:
        raise ValueError("--steps must be > 0")
    if total_steps % episode_steps != 0:
        raise ValueError("--steps must be divisible by --episode-steps to align resets")

    # Load senders (cycled sequentially).
    senders = _load_senders(str(args.ge_params))
    ge_key = str(args.ge_key)
    oracle_data: Optional[Dict[str, Any]] = None
    if args.oracle_json:
        with open(os.path.abspath(str(args.oracle_json)), "r", encoding="utf-8") as oracle_file:
            oracle_data = json.load(oracle_file)
        oracle_scenes = oracle_data.get("scenes") if isinstance(oracle_data, dict) else None
        if not isinstance(oracle_scenes, dict):
            raise ValueError(f"oracle JSON has no scenes mapping: {args.oracle_json}")
        sender_ids_from_ge = {int(sid) for sid, _ in senders}
        sender_ids_from_oracle = {int(sid) for sid in oracle_scenes}
        if not sender_ids_from_ge.issubset(sender_ids_from_oracle):
            raise ValueError(
                "Oracle is missing GE training senders: "
                f"GE-only={sorted(sender_ids_from_ge - sender_ids_from_oracle)}"
            )
        missing_oracle_rows = [
            sid for sid in sorted(sender_ids_from_ge)
            if not isinstance(oracle_scenes[str(sid)].get("oracle"), dict)
            or "mean_reward" not in oracle_scenes[str(sid)]["oracle"]
        ]
        if missing_oracle_rows:
            raise ValueError(f"Oracle JSON has incomplete sender rows: {missing_oracle_rows}")

    # Logging
    dest_dir = args.result_dir or os.environ.get("QUICFEC_RESULT_DIR")
    if not dest_dir:
        ts = time.strftime("%Y%m%d-%H%M%S")
        dest_dir = os.path.join(_REPO_ROOT, "python/results", f"bandit-ge-run-{ts}")
    dest_dir = os.path.abspath(dest_dir)
    _ensure_dir(dest_dir)

    log_path = os.path.join(dest_dir, "bandit_metrics.json")
    timing_path = os.path.abspath(args.timing_jsonl) if args.timing_jsonl else None
    if timing_path:
        _ensure_dir(os.path.dirname(timing_path))
    timing_rows: List[Dict[str, Any]] = []

    save_ckpt_prefix = args.checkpoint_prefix
    if not save_ckpt_prefix:
        save_ckpt_prefix = os.path.join(dest_dir, "bandit_model")

    # Initialize or resume model.
    start_t = 0
    loaded_from: Optional[str] = None
    if bool(args.resume):
        load_prefix = None
        # Prefer explicit prefix if it exists.
        if args.checkpoint_prefix and os.path.exists(os.path.abspath(args.checkpoint_prefix) + ".json"):
            load_prefix = os.path.abspath(args.checkpoint_prefix)
        else:
            load_prefix = _find_latest_saved_prefix(dest_dir)

        if load_prefix and os.path.exists(os.path.abspath(load_prefix) + ".json"):
            agent, lints_cfg, ctx, ctx_cfg, action_set, start_t = load_checkpoint(path_prefix=load_prefix, device=str(args.device))
            loaded_from = str(load_prefix)
        else:
            # Resume requested but no checkpoint found; fall back to fresh init.
            load_prefix = None

    if loaded_from is None:
        action_set = ActionSet()
        ctx_cfg = ContextConfig(ewma_alpha=float(args.ctx_alpha), window=int(args.ctx_window))
        ctx = ContextBuilder(ctx_cfg)

        x0 = ctx.get_context()
        m = action_set.onehot_dim
        dim = 1 + int(x0.size) + int(m) + int(x0.size) * int(m)

        lints_cfg = LinTSConfig(
            lam=float(args.lints_lam),
            sigma=float(args.lints_sigma),
            rho=float(args.lints_rho),
            recompute_inv_every=int(args.lints_recompute),
            seed=int(args.seed),
        )
        agent = LinTS(dim=dim, cfg=lints_cfg, device=str(args.device))

    # Action set summary (bandit decides the action space; env must follow).
    try:
        n_actions = int(len(action_set))
        k_n = int(len(action_set.k_values))
        r0_n = int(len(getattr(action_set, "r0_values", [])))
        rs_n = int(len(action_set.rstep_values))
        print(
            f"[bandit] action_set: n={n_actions} = K({k_n})*R0({r0_n})*RSTEP({rs_n})"
        )
    except Exception:
        pass

    # Env configured so that we only reset (and switch net params) every episode_steps.
    # DDL is generated by the sender from the current QUIC pacing estimate.
    env_cfg: Dict[str, Any] = {
        "episode_step": int(episode_steps),
        "rtt_ms": int(args.rtt_ms),
        "loss_pct": 0,
        # Will be overridden per-episode via reset(options).
        "loss_mode": "iid:0",
        "bitrate_mbps": int(args.bitrate_mbps),
        "timeout_sec": int(args.timeout_sec),
        "train_file_bytes": int(args.train_file_bytes),
        "k_values": list(action_set.k_values),
        "r0_values": list(getattr(action_set, "r0_values", [])),
        "rstep_values": list(action_set.rstep_values),
        "reward_variant": str(args.reward_variant),
        "reward_w_goodput": float(args.reward_w_goodput),
        "reward_w_arq": float(args.reward_w_arq),
        "reward_w_overhead": float(args.reward_w_overhead),
        "reward_w_done": float(getattr(args, "reward_w_done", 0.3)),
        "reward_residual_binary": bool(int(args.reward_residual_binary)),
        "log_obs_vec": False,
        # Avoid curriculum overriding our externally supplied schedule.
        "randomize_net_params_enabled": False,
        # Bandit should only consume the environment observation (no debug info).
        "normalize_obs": False,
    }

    # Clarify metric semantics for overhead shaping.
    print(
        "note: reward overhead term uses fec_overhead = quic_overhead_ratio = max(0,(quic_sent_bytes-file_bytes)/file_bytes)"
    )

    # Action features are context-independent. Cache the compact matrix and
    # avoid constructing a full [num_actions, 1925] Phi on every step.
    action_features = np.asarray(
        [action_set.get_onehot(i) for i in range(len(action_set))],
        dtype=np.float64,
    )
    action_features_device = agent.tensor(action_features)

    # The helper is intentionally explicit: this run must use the user's scoped
    # network helper rather than silently fall back to broad sudo privileges.
    helper_path = os.environ.get("QUIC_FEC_PRIV_HELPER", _DEFAULT_PRIV_HELPER)
    if not os.path.isfile(helper_path):
        raise RuntimeError(f"network helper is not installed at {helper_path}")
    os.environ["QUIC_FEC_PRIV_HELPER"] = helper_path
    # Reserve disjoint subnets from evaluator slots (172.31.20-219). This lets
    # the live training namespace and background evaluation namespaces coexist.
    os.environ["QUICFEC_TRAIN_NET_SUBNET_START"] = "220"
    os.environ["QUICFEC_TRAIN_NET_SUBNET_END"] = "239"

    run_manifest: Dict[str, Any] = {
        "args": vars(args),
        "ge_params": os.path.abspath(str(args.ge_params)),
        "ge_key": ge_key,
        "full_ge_sender_count": len(senders),
        "n_actions": int(len(action_set)),
        "action_feature_dim": int(action_set.onehot_dim),
        "linear_feature_dim": int(agent.dim),
        "network_helper": helper_path,
        "compute_device": str(agent.device),
        "transfer_timeout_sec": int(args.timeout_sec),
        "evaluation_execution": "asynchronous_background_workers",
        "policy_eval_workers": int(args.eval_workers),
        "baseline_eval_workers": 1,
        "oracle_json": os.path.abspath(str(args.oracle_json)) if args.oracle_json else None,
        "oracle_available_sender_count": len(oracle_data["scenes"]) if oracle_data is not None else None,
        "oracle_compared_sender_count": len(senders) if oracle_data is not None else None,
        "posterior_matrix_update": "exact_inverse_recomputed_after_every_update",
        "training_net_subnet_pool": "172.31.220.0/24-172.31.239.0/24",
    }
    try:
        import torch

        if torch.cuda.is_available() and str(args.device).startswith("cuda"):
            run_manifest["cuda_device_name"] = torch.cuda.get_device_name(agent.device)
    except Exception:
        pass
    with open(os.path.join(dest_dir, "run_config.json"), "w", encoding="utf-8") as manifest_file:
        json.dump(run_manifest, manifest_file, indent=2, ensure_ascii=False)
        manifest_file.write("\n")

    env = FecEnv(env_cfg)

    # Breakpoint semantics: --steps is treated as the *target total step index*.
    # If we resume from step_t, run [start_t, total_steps).
    start_t = int(start_t)
    if start_t < 0:
        start_t = 0
    if start_t > 0 and start_t >= total_steps:
        print(f"resume step_t={start_t} >= target --steps={total_steps}; nothing to do")
        print(f"wrote {log_path}")
        return 0

    # We can only safely resume at episode boundaries because we do not snapshot the env state.
    # Ensure start_t aligns to an episode boundary. If not, skip forward to the next boundary.
    if start_t % episode_steps != 0:
        start_t_aligned = int(((start_t + episode_steps - 1) // episode_steps) * episode_steps)
        if start_t_aligned != start_t:
            print(
                f"warning: resume step_t={start_t} not aligned to episode boundary; "
                f"skipping forward to {start_t_aligned} (episode_steps={episode_steps})"
            )
            start_t = start_t_aligned

    checkpoint_root = os.path.join(dest_dir, "checkpoints")
    _ensure_dir(checkpoint_root)

    def save_periodic_checkpoint(step_t: int, *, note: str) -> None:
        """Persist a fixed-step checkpoint and update the latest alias."""

        periodic_prefix = os.path.join(checkpoint_root, f"model_t{int(step_t)}")
        meta = {
            "env_cfg": env_cfg,
            "dest_dir": dest_dir,
            "note": str(note),
            "checkpoint_interval": int(checkpoint_interval),
            "checkpoint_selection": "fixed_interval",
            "compute_device": str(args.device),
            "transfer_timeout_sec": int(args.timeout_sec),
        }
        save_checkpoint(
            path_prefix=periodic_prefix,
            agent=agent,
            agent_cfg=lints_cfg,
            ctx=ctx,
            ctx_cfg=ctx_cfg,
            action_set=action_set,
            step_t=int(step_t),
            extra_meta=meta,
        )
        save_checkpoint(
            path_prefix=str(save_ckpt_prefix),
            agent=agent,
            agent_cfg=lints_cfg,
            ctx=ctx,
            ctx_cfg=ctx_cfg,
            action_set=action_set,
            step_t=int(step_t),
            extra_meta={**meta, "note": "latest"},
        )
        print(f"[checkpoint] step={int(step_t)} path={periodic_prefix}")

    evaluation_rows: List[Dict[str, Any]] = []
    random_baseline: Optional[Dict[str, Any]] = None
    policy_results: Dict[int, Dict[str, Any]] = {}
    eval_jobs: List[Tuple[str, int, Future]] = []
    # Evaluation never blocks the training loop. A bounded pool lets checkpoint
    # evaluations overlap without flooding the emulated network; the one-time
    # random baseline has its own worker so it cannot delay policy evaluation.
    # Each worker launches a fresh testbed evaluator process.
    policy_eval_executor = ThreadPoolExecutor(max_workers=int(args.eval_workers), thread_name_prefix="bandit-policy-eval")
    baseline_eval_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="bandit-random-eval")
    baseline_path = os.path.join(dest_dir, "random_baseline.json")
    if os.path.exists(baseline_path):
        with open(baseline_path, "r", encoding="utf-8") as baseline_file:
            random_baseline = json.load(baseline_file)

    # A resumed run shares the original result directory. Restore completed
    # evaluations before accepting new ones so that refreshing the regret
    # artifacts keeps the full history instead of replacing it with only the
    # post-resume checkpoints.
    eval_metrics_path = os.path.join(dest_dir, "evaluation_metrics.jsonl")
    if os.path.exists(eval_metrics_path):
        with open(eval_metrics_path, "r", encoding="utf-8") as eval_file:
            for line_no, line in enumerate(eval_file, start=1):
                if not line.strip():
                    continue
                prior = json.loads(line)
                result = prior.get("bandit")
                if not isinstance(result, dict) or result.get("policy") != "greedy":
                    raise ValueError(
                        f"invalid existing evaluation record at {eval_metrics_path}:{line_no}"
                    )
                step_t = int(prior.get("step", result.get("step", -1)))
                if int(result.get("step", -2)) != step_t or step_t in policy_results:
                    raise ValueError(
                        f"duplicate or inconsistent existing evaluation step {step_t} "
                        f"at {eval_metrics_path}:{line_no}"
                    )
                policy_results[step_t] = result
                if random_baseline is None and isinstance(prior.get("random_baseline"), dict):
                    random_baseline = prior["random_baseline"]

    def _run_random_baseline(step_t: int) -> Dict[str, Any]:
        checkpoint_prefix = os.path.join(checkpoint_root, f"model_t{int(step_t)}")
        return _evaluate_checkpoint(
            step=int(step_t),
            policy="random",
            repeats=int(args.random_baseline_repeats),
            checkpoint_prefix=checkpoint_prefix,
            result_dir=dest_dir,
            args=args,
        )

    def _run_policy_evaluation(step_t: int) -> Dict[str, Any]:
        checkpoint_prefix = os.path.join(checkpoint_root, f"model_t{int(step_t)}")
        return _evaluate_checkpoint(
            step=int(step_t),
            policy="greedy",
            repeats=int(args.eval_repeats),
            checkpoint_prefix=checkpoint_prefix,
            result_dir=dest_dir,
            args=args,
        )

    def _refresh_regret_outputs() -> None:
        nonlocal evaluation_rows
        if oracle_data is not None and policy_results:
            _write_oracle_regret_outputs(
                policy_results=policy_results,
                oracle=oracle_data,
                result_dir=dest_dir,
            )
        if random_baseline is None:
            return
        random_reward = float(random_baseline["mean_reward"])
        evaluation_rows = []
        for step_t, policy_result in sorted(policy_results.items()):
            bandit_reward = float(policy_result["mean_reward"])
            evaluation_rows.append({
                "step": int(step_t),
                "bandit_reward": bandit_reward,
                "random_reward": random_reward,
                "regret_vs_random": random_reward - bandit_reward,
                "improvement_vs_random": bandit_reward - random_reward,
                "success_rate": float(policy_result["success_rate"]),
                "bandit_records": int(policy_result["records"]),
                "random_records": int(random_baseline["records"]),
            })
        _write_regret_curve(evaluation_rows, dest_dir)
        eval_metrics_path = os.path.join(dest_dir, "evaluation_metrics.jsonl")
        with open(eval_metrics_path, "w", encoding="utf-8") as eval_file:
            for row in evaluation_rows:
                eval_file.write(json.dumps({
                    "bandit": policy_results[int(row["step"])],
                    "random_baseline": random_baseline,
                    **row,
                }, ensure_ascii=False) + "\n")

    def _collect_finished_evaluations() -> None:
        nonlocal random_baseline
        unfinished: List[Tuple[str, int, Future]] = []
        for kind, step_t, future in eval_jobs:
            if not future.done():
                unfinished.append((kind, step_t, future))
                continue
            try:
                result = future.result()
            except Exception as exc:
                error = {"kind": kind, "step": int(step_t), "error": repr(exc)}
                with open(os.path.join(dest_dir, "evaluation_errors.jsonl"), "a", encoding="utf-8") as error_file:
                    error_file.write(json.dumps(error, ensure_ascii=False) + "\n")
                print(f"[eval] {kind} step={step_t} failed: {exc!r}", file=sys.stderr, flush=True)
                continue
            if kind == "random":
                random_baseline = result
                baseline_path = os.path.join(dest_dir, "random_baseline.json")
                tmp_path = baseline_path + ".tmp"
                with open(tmp_path, "w", encoding="utf-8") as baseline_file:
                    json.dump(random_baseline, baseline_file, indent=2, ensure_ascii=False)
                    baseline_file.write("\n")
                os.replace(tmp_path, baseline_path)
                print(
                    f"[eval] random baseline ready reward={random_baseline['mean_reward']:.6f} "
                    f"success={random_baseline['success_rate']:.3f}",
                    flush=True,
                )
            else:
                policy_results[int(step_t)] = result
                print(
                    f"[eval] policy result ready step={step_t} reward={result['mean_reward']:.6f} "
                    f"success={result['success_rate']:.3f}",
                    flush=True,
                )
            _refresh_regret_outputs()
        eval_jobs[:] = unfinished

    def _schedule_evaluation(step_t: int) -> None:
        if int(step_t) in policy_results:
            print(f"[eval] checkpoint step={step_t} already present; reusing saved result", flush=True)
            return
        if random_baseline is None and not os.path.exists(baseline_path) and not any(kind == "random" for kind, _, _ in eval_jobs):
            print(
                f"[eval] queue random baseline: sender_ids={args.eval_sender_ids} "
                f"repeats={int(args.random_baseline_repeats)} timeout={int(args.timeout_sec)}s",
                flush=True,
            )
            eval_jobs.append(("random", int(step_t), baseline_eval_executor.submit(_run_random_baseline, int(step_t))))
        print(f"[eval] queue policy checkpoint step={int(step_t)}", flush=True)
        eval_jobs.append(("greedy", int(step_t), policy_eval_executor.submit(_run_policy_evaluation, int(step_t))))

    # Start at the correct sender offset if resuming.
    # We align episode boundaries to t % episode_steps == 0.
    sender_idx = 0
    if int(start_t) > 0:
        sender_idx = (int(start_t) // episode_steps) % len(senders)

    def _episode_reset() -> Tuple[int, str, float, float]:
        nonlocal sender_idx
        sid, sdata = senders[int(sender_idx)]
        sender_idx = (sender_idx + 1) % len(senders)

        ge_rp = sdata.get(ge_key)
        if not isinstance(ge_rp, dict):
            raise ValueError(f"sender {sid} missing {ge_key}")

        # Derive per-sender h/k from steady loss rate + pi_bad unless overridden.
        loss_rate = sdata.get("loss_rate_steady_rp")
        pi_bad = ge_rp.get("pi_bad")

        if args.ge_h_pct is not None and args.ge_k_pct is not None:
            h_pct = float(args.ge_h_pct)
            k_pct = float(args.ge_k_pct)
        else:
            h_pct, k_pct = _auto_hk_from_sender(
                loss_rate=(float(loss_rate) if loss_rate is not None else None),
                pi_bad=(float(pi_bad) if pi_bad is not None else None),
                k_cap_pct=float(args.ge_k_cap_pct),
            )
            if args.ge_h_pct is not None:
                h_pct = float(args.ge_h_pct)
            if args.ge_k_pct is not None:
                k_pct = float(args.ge_k_pct)

        loss_mode = _ge_to_tc_gemodel_loss_mode(ge_rp, h_loss_pct=float(h_pct), k_loss_pct=float(k_pct))

        # Requested: per-sender RTT from the GE params JSON (fallback to CLI arg).
        sender_rtt_ms = sdata.get("rtt_ms")
        try:
            rtt_ms = int(sender_rtt_ms) if sender_rtt_ms is not None else int(args.rtt_ms)
        except Exception:
            rtt_ms = int(args.rtt_ms)

        obs, _ = env.reset(
            options={
                "rtt_ms": int(rtt_ms),
                "bitrate_mbps": int(args.bitrate_mbps),
                "loss_mode": str(loss_mode),
                "loss_pct": 0,
            }
        )
        return sid, loss_mode, float(h_pct), float(k_pct)

    # Initial reset (episode 0)
    sender_id, active_loss_mode, active_h_pct, active_k_pct = _episode_reset()
    if eval_interval > 0 and start_t > 0 and start_t % eval_interval == 0:
        _schedule_evaluation(start_t)

    dim = int(getattr(agent, "dim", 0))
    last_t = int(start_t)

    max_invalid_skips = int(os.environ.get("BANDIT_INVALID_SKIP_CAP", "500"))
    invalid_skips = 0

    try:
        t = int(start_t)
        while int(t) < int(total_steps):
            _collect_finished_evaluations()
            last_t = int(t)
            attempt_idx = invalid_skips + 1

            x = ctx.get_context()
            action_score_wall_ns: Optional[int] = None
            action_score_cpu_ns: Optional[int] = None

            if int(t) < warmup:
                a_idx = int(np.random.RandomState(int(args.seed) + t).randint(0, len(action_set)))
                theta = None
            else:
                if timing_path:
                    score_wall_start = time.perf_counter_ns()
                    score_cpu_start = time.process_time_ns()
                a_idx, theta = agent.select_action_features(
                    x=x,
                    action_features=action_features_device,
                )
                if timing_path:
                    agent.synchronize()
                    action_score_wall_ns = time.perf_counter_ns() - score_wall_start
                    action_score_cpu_ns = time.process_time_ns() - score_cpu_start

            a = action_set.get_action(a_idx)
            env_action = a.to_env_action()

            obs, reward, terminated, truncated, info = env.step(env_action)

            # Ignore invalid transfers: do not feed them into the bandit update nor stats.
            step_valid = True
            try:
                step_valid = bool(int((info or {}).get("step_valid", 1)))
            except Exception:
                step_valid = True
            if not step_valid:
                invalid_skips += 1
                if invalid_skips > max_invalid_skips:
                    raise RuntimeError(
                        f"too many invalid transfers skipped (>{max_invalid_skips}); last info={info}"
                    )
                if timing_path:
                    timing_rows.append({
                        "t": int(t),
                        "attempt": int(attempt_idx),
                        "step_valid": False,
                        "warmup": bool(int(t) < warmup),
                        "action_scoring_wall_ns": action_score_wall_ns,
                        "action_scoring_cpu_ns": action_score_cpu_ns,
                        "feature_map_wall_ns": None,
                        "feature_map_cpu_ns": None,
                        "posterior_update_wall_ns": None,
                        "posterior_update_cpu_ns": None,
                    })
                # Do not advance t.
                continue
            invalid_skips = 0

            ctx.update_from_obs(obs=obs)

            feature_map_wall_ns: Optional[int] = None
            feature_map_cpu_ns: Optional[int] = None
            posterior_update_wall_ns: Optional[int] = None
            posterior_update_cpu_ns: Optional[int] = None
            if int(t) >= warmup:
                if timing_path:
                    feature_wall_start = time.perf_counter_ns()
                    feature_cpu_start = time.process_time_ns()
                action_onehot = action_features_device[a_idx]
                ph = agent.build_phi(x=x, a_onehot=action_onehot)
                if timing_path:
                    agent.synchronize()
                    feature_map_wall_ns = time.perf_counter_ns() - feature_wall_start
                    feature_map_cpu_ns = time.process_time_ns() - feature_cpu_start
                    update_wall_start = time.perf_counter_ns()
                    update_cpu_start = time.process_time_ns()
                agent.update(phi=ph, reward=float(reward))
                if timing_path:
                    agent.synchronize()
                    posterior_update_wall_ns = time.perf_counter_ns() - update_wall_start
                    posterior_update_cpu_ns = time.process_time_ns() - update_cpu_start

            if timing_path:
                timing_rows.append({
                    "t": int(t),
                    "attempt": int(attempt_idx),
                    "step_valid": True,
                    "warmup": bool(int(t) < warmup),
                    "action_scoring_wall_ns": action_score_wall_ns,
                    "action_scoring_cpu_ns": action_score_cpu_ns,
                    "feature_map_wall_ns": feature_map_wall_ns,
                    "feature_map_cpu_ns": feature_map_cpu_ns,
                    "posterior_update_wall_ns": posterior_update_wall_ns,
                    "posterior_update_cpu_ns": posterior_update_cpu_ns,
                })

            rec: Dict[str, Any] = {
                "t": int(t),
                "reward": float(reward),
                "a_idx": int(a_idx),
                "action": {
                    "k_idx": int(a.k_idx),
                    "r0_idx": int(a.r0_idx),
                    "rstep_idx": int(a.rstep_idx),
                },
                "context": [float(v) for v in x.tolist()],
                "env_info": info,
                "sender_id": int(sender_id),
                "active_loss_mode": str(active_loss_mode),
                "gemodel_h_pct": float(active_h_pct),
                "gemodel_k_pct": float(active_k_pct),
                "checkpoint_idx": int((int(t) + 1) // checkpoint_interval),
                "ctx_cfg": asdict(ctx_cfg) if t == int(start_t) else None,
                "lints_cfg": asdict(lints_cfg) if t == int(start_t) else None,
                "resume_from": str(loaded_from) if (t == int(start_t) and loaded_from is not None) else None,
            }
            if theta is not None:
                rec["theta_norm"] = float(np.linalg.norm(theta))

            with open(log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False, default=_json_default) + "\n")

            # Checkpointing is purely step-based. Reward is deliberately not used
            # for selecting, replacing, or deleting checkpoints.
            step_done = int(t) + 1
            save_due = step_done % checkpoint_interval == 0 or (
                eval_interval > 0 and step_done % eval_interval == 0
            )
            if save_due:
                save_periodic_checkpoint(step_done, note="fixed_interval")
            if eval_interval > 0 and step_done % eval_interval == 0:
                _schedule_evaluation(step_done)

            if step_done % max(1, min(25, checkpoint_interval)) == 0:
                print(f"[train] completed={step_done}/{total_steps} valid_updates={agent.t}", flush=True)

            if bool(terminated) or bool(truncated):
                sender_id, active_loss_mode, active_h_pct, active_k_pct = _episode_reset()

            # Count only valid transfers.
            t += 1
            _collect_finished_evaluations()

    except KeyboardInterrupt:
        pass
    finally:
        final_step = int(last_t) + 1
        try:
            # Preserve the final state even when the run ends between intervals.
            # This is also step-based and never depends on reward.
            if final_step > 0 and final_step % checkpoint_interval != 0:
                save_periodic_checkpoint(final_step, note="final")
        except Exception:
            pass
        if timing_path:
            with open(timing_path, "w", encoding="utf-8") as timing_file:
                for timing_rec in timing_rows:
                    timing_file.write(
                        json.dumps(timing_rec, ensure_ascii=False, default=_json_default) + "\n"
                    )
        # This run owns its per-process namespace/veth; release only those
        # resources on normal completion or Ctrl-C.
        try:
            cleanup = subprocess.run(
                ["sudo", "-n", helper_path, "cleanup", str(env._runner.ns), str(env._runner._veth_host)],
                cwd=_REPO_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=30,
                check=False,
            )
            print(f"[network] cleanup rc={cleanup.returncode} ns={env._runner.ns}", flush=True)
        except Exception as exc:
            print(f"[network] cleanup warning: {exc}", file=sys.stderr, flush=True)

    # Drain background evaluations only after training ends. They never pause
    # the training loop; this final wait ensures regret artifacts are complete.
    print(f"[eval] training finished; draining {len(eval_jobs)} queued/running evaluations", flush=True)
    policy_eval_executor.shutdown(wait=True)
    baseline_eval_executor.shutdown(wait=True)
    _collect_finished_evaluations()

    print(f"wrote {log_path}")
    if timing_path:
        print(f"wrote {timing_path}")
    print(f"saved fixed-interval checkpoints under {os.path.abspath(checkpoint_root)}")
    print(f"saved latest model to {os.path.abspath(str(save_ckpt_prefix))}.npz/.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
