#!/usr/bin/env python3
"""Evaluate all available bandit checkpoints on GE_steady_rp and plot regret.

Each checkpoint is evaluated with the existing testbed evaluator.  A task owns
one network slot while it runs, and the task cleans that namespace afterward.
The output is resumable: completed checkpoint directories are reused.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from statistics import mean, median
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
PYTHON = sys.executable
EVALUATOR = Path(__file__).resolve().with_name("eval_bandit_model_on_testbed.py")
DEFAULT_CHECKPOINT_DIR = ROOT / "python" / "results" / "ge-100kb-bandit-model-step500-100k" / "checkpoints"
DEFAULT_ORACLE = ROOT / "python" / "results" / "ge-100kb-oracle-all-actions-20x-2s-par121-20260918" / "oracle.json"
DEFAULT_MANIFEST = ROOT / "python" / "results" / "ge-100kb-oracle-all-actions-20x-2s-par121-20260918" / "manifest.json"
DEFAULT_OUT = ROOT / "python" / "results" / "ge-100kb-bandit-checkpoint-eval-20x-2s-regret-20260917"
HELPER = "/usr/local/libexec/quicfec-net-helper"


def _checkpoint_steps(checkpoint_dir: Path) -> List[int]:
    steps: List[int] = []
    for path in checkpoint_dir.glob("model_t*.json"):
        match = re.fullmatch(r"model_t([0-9]+)\.json", path.name)
        if not match:
            continue
        step = int(match.group(1))
        if path.with_suffix(".npz").exists():
            steps.append(step)
    return sorted(set(steps))


def _read_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        obj = json.load(f)
    if not isinstance(obj, dict):
        raise ValueError(f"expected JSON object: {path}")
    return obj


def _parse_sender_ids(oracle: Dict[str, Any]) -> List[int]:
    scenes = oracle.get("scenes")
    if not isinstance(scenes, dict):
        raise ValueError("oracle.json has no scenes object")
    return sorted(int(sid) for sid in scenes)


def _tag_for_step(step: int) -> str:
    # The evaluator sanitizes and truncates tags to eight characters.
    return f"c{int(step)}"


def _net_names(tag: str) -> Tuple[str, str]:
    clean = re.sub(r"[^0-9a-zA-Z]+", "", str(tag or ""))[:8]
    return f"qns_{clean}", ("vh" + clean)[:15]


def _expected_records(sender_ids: Sequence[int], repeats: int) -> int:
    return len(sender_ids) * int(repeats)


def _checkpoint_is_complete(out_dir: Path, *, expected_records: int, step: int) -> bool:
    meta_path = out_dir / "meta.json"
    jsonl_path = out_dir / "bandit_eval_metrics.jsonl"
    if not meta_path.exists() or not jsonl_path.exists():
        return False
    try:
        meta = _read_json(meta_path)
        if int(meta.get("checkpoint_step_t", -1)) != int(step):
            return False
        count = sum(1 for line in jsonl_path.open("r", encoding="utf-8") if line.strip())
        return count == int(expected_records)
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return False


def _cleanup_network(*, tag: str, log_path: Path) -> None:
    ns, veth_host = _net_names(tag)
    try:
        proc = subprocess.run(
            ["sudo", "-n", HELPER, "cleanup", ns, veth_host],
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30,
            check=False,
        )
        with log_path.open("a", encoding="utf-8") as f:
            f.write(f"\n[cleanup] rc={proc.returncode}\n{proc.stdout or ''}")
    except Exception as exc:
        with log_path.open("a", encoding="utf-8") as f:
            f.write(f"\n[cleanup] exception={exc!r}\n")


def _run_checkpoint(
    *,
    step: int,
    slot: int,
    checkpoint_dir: Path,
    out_root: Path,
    expected_records: int,
    repeats: int,
    timeout_transfer_s: int,
    timeout_s: int,
    file_bytes: int,
    bitrate_mbps: int,
    decode_ddl_ms: int,
    done_deadline_ms: int,
    sender_ids: Sequence[int],
    device: str,
) -> Tuple[int, int, str]:
    prefix = checkpoint_dir / f"model_t{int(step)}"
    out_dir = out_root / f"checkpoint_t{int(step)}"
    out_dir.mkdir(parents=True, exist_ok=True)
    tag = _tag_for_step(step)
    log_path = out_dir / "launcher.log"

    command = [
        PYTHON,
        "-u",
        str(EVALUATOR),
        "--checkpoint-prefix",
        str(prefix),
        "--device",
        str(device),
        "--out-dir",
        str(out_dir),
        "--run-tag",
        tag,
        "--policy",
        "greedy",
        "--seed",
        "0",
        "--policy-repeats",
        "1",
        "--ctx-reset",
        "never",
        "--loss-profile",
        "ge",
        "--ge-params",
        str(ROOT / "python" / "bandit" / "quic_fec_params.json"),
        "--ge-key",
        "GE_steady_rp",
        "--sender-ids",
        "all",
        "--bitrate-mbps",
        str(int(bitrate_mbps)),
        "--timeout-transfer-s",
        str(int(timeout_transfer_s)),
        "--timeout-s",
        str(int(timeout_s)),
        "--steps-per-scenario",
        str(int(repeats)),
        "--file-bytes",
        str(int(file_bytes)),
        "--symbol-bytes",
        "1200",
        "--decode-ddl-ms",
        str(int(decode_ddl_ms)),
        "--done-deadline-ms",
        str(int(done_deadline_ms)),
        "--enable-quic-overhead",
        "1",
        "--cc",
        "bbrv2",
    ]
    env = os.environ.copy()
    env.update(
        {
            "QUIC_FEC_PRIV_HELPER": HELPER,
            "QUICFEC_EVAL_SLOT": str(int(slot)),
            "CONNECT_RETRIES": "1",
            "CONNECT_TIMEOUT_S": str(int(timeout_transfer_s)),
            "TIMEOUT_S": str(int(timeout_transfer_s)),
            "SRV_TIMEOUT": f"{int(timeout_transfer_s)}s",
            "CLI_TIMEOUT": f"{int(timeout_transfer_s)}s",
            "POST_WAIT": "0ms",
            "TRANSPORT": "dgram",
            "USE_ARQ": "1",
            "W": "8",
            "MAX_ATTEMPTS": "0",
            "FEC_STATS": "1",
            "TUNE_UDP_BUFFERS": "0",
            "QUIC_FEC_ARQ_DRAIN_CAP_MS": str(int(timeout_transfer_s) * 1000),
            "OMP_NUM_THREADS": "1",
            "OPENBLAS_NUM_THREADS": "1",
            "MKL_NUM_THREADS": "1",
            "NUMEXPR_NUM_THREADS": "1",
        }
    )

    with log_path.open("w", encoding="utf-8") as log:
        log.write("command=" + " ".join(command) + "\n")
        log.write(f"slot={slot} tag={tag} expected_records={expected_records}\n")
        log.flush()
        try:
            proc = subprocess.run(
                command,
                cwd=str(ROOT),
                env=env,
                stdout=log,
                stderr=subprocess.STDOUT,
                timeout=None,
                check=False,
            )
            code = int(proc.returncode)
        except Exception as exc:
            log.write(f"\n[launcher-exception] {exc!r}\n")
            code = 125
    _cleanup_network(tag=tag, log_path=log_path)
    return int(step), code, str(out_dir)


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        value = float(value)
        return value if math.isfinite(value) else float(default)
    except (TypeError, ValueError):
        return float(default)


def _reward_from_record(record: Dict[str, Any], *, env_cfg: Dict[str, Any]) -> float:
    env_info = record.get("env_info") if isinstance(record.get("env_info"), dict) else {}
    if int(env_info.get("is_timeout", 0) or 0) or int(env_info.get("is_md5_fail", 0) or 0):
        return -1.0

    raw = env_info.get("raw_obs") if isinstance(env_info.get("raw_obs"), dict) else {}
    goodput = _to_float(raw.get("goodput", 0.0))
    overhead = max(0.0, _to_float(raw.get("fec_overhead", 0.0)))
    done_flag = min(1.0, max(0.0, _to_float(raw.get("done_flag", 0.0))))
    run = env_info.get("extra", {}).get("run", {}) if isinstance(env_info.get("extra"), dict) else {}
    attempts = _to_float(run.get("arq_attempts", 0.0)) if isinstance(run, dict) else 0.0
    clusters = _to_float(run.get("arq_clusters", 0.0)) if isinstance(run, dict) else 0.0
    arq_mean = attempts / clusters if clusters > 0.0 else 0.0

    variant = str(env_cfg.get("reward_variant", "qarc_v1"))
    capacity = max(1e-6, _to_float(env_cfg.get("bitrate_mbps", 10.0), 10.0))
    w_goodput = _to_float(env_cfg.get("reward_w_goodput", 1.0), 1.0)
    w_overhead = _to_float(env_cfg.get("reward_w_overhead", 0.3), 0.3)
    w_arq = _to_float(env_cfg.get("reward_w_arq", 0.0), 0.0)
    w_done = _to_float(env_cfg.get("reward_w_done", 0.3), 0.3)

    if variant == "legacy":
        tp_term = min(1.0, max(0.0, goodput / capacity))
        oh_term = -0.3 * max(0.0, (overhead - 0.5) / 1.5)
        arq_term = -min(0.3, 0.08 * arq_mean)
        done_term = -w_done * (1.0 - done_flag)
        return float(tp_term + oh_term + arq_term + done_term)

    tp_term = w_goodput * (goodput / capacity)
    oh_term = w_overhead * (1.0 / (1.0 + (overhead / 0.25) ** 2))
    arq_term = -w_arq * min(1.0, max(0.0, arq_mean / 2.0))
    done_term = -w_done * (1.0 - done_flag)
    return float(tp_term + oh_term + arq_term + done_term)


def _load_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSONL at {path}:{line_no}") from exc
            if isinstance(obj, dict):
                rows.append(obj)
    return rows


def _summarize_checkpoint(
    *,
    step: int,
    out_dir: Path,
    sender_ids: Sequence[int],
    repeats: int,
    oracle: Dict[str, Any],
    env_cfg: Dict[str, Any],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    records = _load_jsonl(out_dir / "bandit_eval_metrics.jsonl")
    expected = _expected_records(sender_ids, repeats)
    if len(records) != expected:
        raise ValueError(f"checkpoint t={step}: expected {expected} records, found {len(records)}")

    by_sender: Dict[int, List[Dict[str, Any]]] = {int(sid): [] for sid in sender_ids}
    for record in records:
        sid = int(record.get("sender_id", -1))
        if sid not in by_sender:
            raise ValueError(f"checkpoint t={step}: unexpected sender_id={sid}")
        by_sender[sid].append(record)

    rows: List[Dict[str, Any]] = []
    excluded: List[Dict[str, Any]] = []
    scenes = oracle.get("scenes", {})
    for sid in sender_ids:
        reps = by_sender[sid]
        if len(reps) != int(repeats):
            raise ValueError(f"checkpoint t={step}, sender={sid}: expected {repeats}, found {len(reps)}")
        rewards = [_reward_from_record(r, env_cfg=env_cfg) for r in reps]
        if all(reward == -1.0 for reward in rewards):
            excluded.append(
                {
                    "checkpoint_step": int(step),
                    "sender_id": int(sid),
                    "repeat_count": len(rewards),
                    "timeout_repeats": sum(
                        int(r.get("env_info", {}).get("is_timeout", 0) or 0) == 1 for r in reps
                    ),
                    "md5_fail_repeats": sum(
                        int(r.get("env_info", {}).get("is_md5_fail", 0) or 0) == 1 for r in reps
                    ),
                    "excluded_reason": "all_repeat_rewards_are_minus_one",
                }
            )
            continue
        oracle_scene = scenes[str(sid)]["oracle"]
        oracle_reward = _to_float(oracle_scene.get("mean_reward"))
        action_counts: Dict[int, int] = {}
        for record in reps:
            aid = int(record.get("action", {}).get("a_idx", record.get("a_idx", -1)))
            action_counts[aid] = action_counts.get(aid, 0) + 1
        modal_a_idx = min(action_counts, key=lambda aid: (-action_counts[aid], aid))
        modal = next(
            (
                r.get("action", {})
                for r in reps
                if int(r.get("action", {}).get("a_idx", r.get("a_idx", -1))) == modal_a_idx
            ),
            {},
        )
        successes = [
            1.0
            if int(r.get("env_info", {}).get("step_valid", 0) or 0) == 1
            and int(r.get("env_info", {}).get("is_timeout", 0) or 0) == 0
            and int(r.get("env_info", {}).get("is_md5_fail", 0) or 0) == 0
            else 0.0
            for r in reps
        ]
        rows.append(
            {
                "checkpoint_step": int(step),
                "sender_id": int(sid),
                "oracle_reward": oracle_reward,
                "bandit_reward": float(mean(rewards)),
                "regret": float(oracle_reward - mean(rewards)),
                "bandit_reward_std": float(np.std(rewards, ddof=1)) if len(rewards) > 1 else 0.0,
                "bandit_success_rate": float(mean(successes)),
                "mean_duration_ms": float(mean(_to_float(r.get("env_info", {}).get("dur_ms", 0.0)) for r in reps)),
                "mean_goodput_mbps": float(mean(_to_float(r.get("env_info", {}).get("goodput_mbps", 0.0)) for r in reps)),
                "mean_overhead": float(mean(_to_float(r.get("env_info", {}).get("quic_overhead_ratio", 0.0)) for r in reps)),
                "modal_a_idx": int(modal_a_idx),
                "modal_action_count": int(action_counts[modal_a_idx]),
                "distinct_actions": int(len(action_counts)),
                "modal_K": int(modal.get("K", 0) or 0),
                "modal_R0": int(modal.get("R0", 0) or 0),
                "modal_RSTEP": int(modal.get("RSTEP", 0) or 0),
            }
        )

    scene_fields = [
        "checkpoint_step", "sender_id", "oracle_reward", "bandit_reward", "regret",
        "bandit_reward_std", "bandit_success_rate", "mean_duration_ms",
        "mean_goodput_mbps", "mean_overhead", "modal_a_idx", "modal_action_count",
        "distinct_actions", "modal_K", "modal_R0", "modal_RSTEP",
    ]
    with (out_dir / "checkpoint_scene_regret.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=scene_fields)
        writer.writeheader()
        writer.writerows(rows)
    excluded_fields = [
        "checkpoint_step", "sender_id", "repeat_count", "timeout_repeats",
        "md5_fail_repeats", "excluded_reason",
    ]
    with (out_dir / "excluded_all_minus_one_senders.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=excluded_fields)
        writer.writeheader()
        writer.writerows(excluded)
    return rows, excluded


def _percentile(values: Iterable[float], q: float) -> float:
    values = list(values)
    return float(np.percentile(np.asarray(values, dtype=np.float64), q)) if values else 0.0


def _write_aggregate(
    rows: Sequence[Dict[str, Any]],
    excluded_rows: Sequence[Dict[str, Any]],
    out_root: Path,
) -> Tuple[Path, Path, Path]:
    by_step: Dict[int, List[Dict[str, Any]]] = {}
    for row in rows:
        by_step.setdefault(int(row["checkpoint_step"]), []).append(row)
    excluded_by_step: Dict[int, List[Dict[str, Any]]] = {}
    for row in excluded_rows:
        excluded_by_step.setdefault(int(row["checkpoint_step"]), []).append(row)

    scene_path = out_root / "per_scene_regret.csv"
    with scene_path.open("w", newline="", encoding="utf-8") as f:
        if rows:
            writer = csv.DictWriter(f, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)

    summary: List[Dict[str, Any]] = []
    all_steps = sorted(set(by_step) | set(excluded_by_step))
    for step in all_steps:
        group = by_step.get(step, [])
        regrets = [float(r["regret"]) for r in group]
        summary.append(
            {
                "checkpoint_step": int(step),
                "scenes": int(len(group)),
                "excluded_all_minus_one_senders": int(len(excluded_by_step.get(step, []))),
                "mean_regret": float(mean(regrets)) if regrets else float("nan"),
                "median_regret": float(median(regrets)) if regrets else float("nan"),
                "p10_regret": _percentile(regrets, 10),
                "p90_regret": _percentile(regrets, 90),
                "positive_regret_fraction": float(mean(1.0 if x > 0 else 0.0 for x in regrets)) if regrets else float("nan"),
                "mean_oracle_reward": float(mean(_to_float(r["oracle_reward"]) for r in group)) if group else float("nan"),
                "mean_bandit_reward": float(mean(_to_float(r["bandit_reward"]) for r in group)) if group else float("nan"),
                "mean_success_rate": float(mean(_to_float(r["bandit_success_rate"]) for r in group)) if group else float("nan"),
                "mean_duration_ms": float(mean(_to_float(r["mean_duration_ms"]) for r in group)) if group else float("nan"),
                "mean_goodput_mbps": float(mean(_to_float(r["mean_goodput_mbps"]) for r in group)) if group else float("nan"),
                "mean_overhead": float(mean(_to_float(r["mean_overhead"]) for r in group)) if group else float("nan"),
            }
        )

    summary_path = out_root / "regret_summary.csv"
    with summary_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(summary[0]) if summary else ["checkpoint_step"])
        writer.writeheader()
        writer.writerows(summary)
    excluded_path = out_root / "excluded_all_minus_one_senders.csv"
    excluded_fields = [
        "checkpoint_step", "sender_id", "repeat_count", "timeout_repeats",
        "md5_fail_repeats", "excluded_reason",
    ]
    with excluded_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=excluded_fields)
        writer.writeheader()
        writer.writerows(excluded_rows)
    return scene_path, summary_path, excluded_path


def _plot_results(*, summary_path: Path, scene_path: Path, out_root: Path) -> Tuple[Path, Path]:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    with summary_path.open("r", newline="", encoding="utf-8") as f:
        summary = list(csv.DictReader(f))
    with scene_path.open("r", newline="", encoding="utf-8") as f:
        scene_rows = list(csv.DictReader(f))

    steps = np.asarray([int(r["checkpoint_step"]) for r in summary], dtype=np.int64)
    mean_regret = np.asarray([float(r["mean_regret"]) for r in summary], dtype=np.float64)
    p10 = np.asarray([float(r["p10_regret"]) for r in summary], dtype=np.float64)
    p90 = np.asarray([float(r["p90_regret"]) for r in summary], dtype=np.float64)

    fig, ax = plt.subplots(figsize=(8.5, 5.5), dpi=160)
    ax.plot(steps, mean_regret, color="#1f77b4", linewidth=2.0, label="Mean regret")
    ax.fill_between(steps, p10, p90, color="#1f77b4", alpha=0.18, label="Across-scene 10–90th percentile")
    ax.axhline(0.0, color="#333333", linewidth=1.0, linestyle="--", label="Zero regret")
    ax.set_xlabel("Training checkpoint (step)")
    ax.set_ylabel("Reward regret (oracle − bandit)")
    ax.set_title("Bandit policy regret on GE_steady_rp")
    ax.grid(True, color="#d0d0d0", linewidth=0.7, alpha=0.8)
    ax.legend(loc="best", frameon=True)
    fig.tight_layout()
    line_path = out_root / "regret_vs_training_step.png"
    fig.savefig(line_path, bbox_inches="tight")
    plt.close(fig)

    scene_ids = sorted({int(r["sender_id"]) for r in scene_rows})
    step_ids = sorted({int(r["checkpoint_step"]) for r in scene_rows})
    matrix = np.full((len(scene_ids), len(step_ids)), np.nan, dtype=np.float64)
    row_pos = {sid: i for i, sid in enumerate(scene_ids)}
    col_pos = {step: i for i, step in enumerate(step_ids)}
    for row in scene_rows:
        matrix[row_pos[int(row["sender_id"])], col_pos[int(row["checkpoint_step"])]] = float(row["regret"])

    fig, ax = plt.subplots(figsize=(11, 8), dpi=160)
    finite = matrix[np.isfinite(matrix)]
    limit = max(0.05, float(np.percentile(np.abs(finite), 98))) if finite.size else 1.0
    image = ax.imshow(matrix, aspect="auto", interpolation="nearest", cmap="coolwarm", vmin=-limit, vmax=limit)
    ax.set_xlabel("Training checkpoint (step)")
    ax.set_ylabel("GE sender ID")
    ax.set_title("Per-scene reward regret (oracle − bandit)")
    x_ticks = np.linspace(0, len(step_ids) - 1, min(10, len(step_ids)), dtype=int)
    ax.set_xticks(x_ticks)
    ax.set_xticklabels([str(step_ids[i]) for i in x_ticks])
    y_ticks = np.linspace(0, len(scene_ids) - 1, min(12, len(scene_ids)), dtype=int)
    ax.set_yticks(y_ticks)
    ax.set_yticklabels([str(scene_ids[i]) for i in y_ticks])
    fig.colorbar(image, ax=ax, label="Reward regret")
    fig.tight_layout()
    heatmap_path = out_root / "regret_heatmap.png"
    fig.savefig(heatmap_path, bbox_inches="tight")
    plt.close(fig)
    return line_path, heatmap_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkpoint-dir", type=Path, default=DEFAULT_CHECKPOINT_DIR)
    parser.add_argument("--oracle-json", type=Path, default=DEFAULT_ORACLE)
    parser.add_argument("--oracle-manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--workers", type=int, default=21)
    parser.add_argument("--repeats", type=int, default=20)
    parser.add_argument("--timeout-transfer-s", type=int, default=2)
    parser.add_argument("--timeout-s", type=int, default=60)
    parser.add_argument("--file-bytes", type=int, default=102400)
    parser.add_argument("--bitrate-mbps", type=int, default=10)
    parser.add_argument("--decode-ddl-ms", type=int, default=25)
    parser.add_argument("--done-deadline-ms", type=int, default=500)
    parser.add_argument("--device", type=str, default="cuda", help="device for checkpoint policy scoring")
    parser.add_argument("--steps", type=str, default="all", help="all, a comma list, or inclusive ranges such as 500-59500")
    args = parser.parse_args()

    checkpoint_dir = args.checkpoint_dir.resolve()
    oracle_path = args.oracle_json.resolve()
    manifest_path = args.oracle_manifest.resolve()
    out_root = args.out_dir.resolve()
    out_root.mkdir(parents=True, exist_ok=True)

    oracle = _read_json(oracle_path)
    oracle_manifest = _read_json(manifest_path)
    sender_ids = _parse_sender_ids(oracle)
    all_steps = _checkpoint_steps(checkpoint_dir)
    if not all_steps:
        raise SystemExit(f"no checkpoint pairs found in {checkpoint_dir}")

    if str(args.steps).strip().lower() == "all":
        steps = all_steps
    else:
        selected: set[int] = set()
        for part in str(args.steps).split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                lo, hi = (int(x) for x in part.split("-", 1))
                selected.update(x for x in all_steps if min(lo, hi) <= x <= max(lo, hi))
            else:
                selected.add(int(part))
        steps = [x for x in all_steps if x in selected]
    if not steps:
        raise SystemExit("requested steps do not exist")

    env_cfg = oracle_manifest.get("env_cfg") if isinstance(oracle_manifest.get("env_cfg"), dict) else {}
    expected_records = _expected_records(sender_ids, args.repeats)
    done_steps = [
        step
        for step in steps
        if _checkpoint_is_complete(out_root / f"checkpoint_t{step}", expected_records=expected_records, step=step)
    ]
    pending = [step for step in steps if step not in set(done_steps)]

    run_manifest = {
        "checkpoint_dir": str(checkpoint_dir),
        "oracle_json": str(oracle_path),
        "oracle_manifest": str(manifest_path),
        "steps": steps,
        "checkpoint_count": len(steps),
        "available_checkpoint_range": [min(all_steps), max(all_steps)],
        "sender_ids": sender_ids,
        "scenes": len(sender_ids),
        "repeats_per_scene": int(args.repeats),
        "expected_transfers_per_checkpoint": int(expected_records),
        "total_expected_transfers": int(len(steps) * expected_records),
        "workers": int(args.workers),
        "device": str(args.device),
        "file_bytes": int(args.file_bytes),
        "bitrate_mbps": int(args.bitrate_mbps),
        "timeout_transfer_s": int(args.timeout_transfer_s),
        "decode_ddl_ms": int(args.decode_ddl_ms),
        "done_deadline_ms": int(args.done_deadline_ms),
        "policy": "greedy",
        "ctx_reset": "never",
        "network_state_policy": "configure tc qdisc on the first transfer of each scenario and reuse it for the scenario repeats",
        "cc": "bbrv2",
        "reward_definition": "exact qarc_v1 formula reconstructed from evaluator raw_obs and run counters; regret=oracle_mean_reward-bandit_mean_reward",
        "all_minus_one_filter": "for each checkpoint, exclude a sender from both policy and oracle aggregates if all repeated policy rewards for that sender equal -1; raw records are retained",
        "oracle_completed_trials": oracle.get("completed_trials"),
        "oracle_total_trials": oracle.get("total_trials"),
        "completed_steps_before_run": done_steps,
    }
    (out_root / "manifest.json").write_text(json.dumps(run_manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(
        f"checkpoints={len(steps)} available_range={min(all_steps)}..{max(all_steps)} "
        f"scenes={len(sender_ids)} repeats={args.repeats} expected_transfers={len(steps)*expected_records} "
        f"pending={len(pending)} workers={args.workers}",
        flush=True,
    )
    if pending:
        workers = max(1, min(int(args.workers), 199, len(pending)))
        slots: queue.Queue[int] = queue.Queue()
        for slot in range(workers):
            slots.put(slot)
        print_lock = threading.Lock()

        def run_with_slot(step: int) -> Tuple[int, int, str]:
            slot = slots.get()
            try:
                with print_lock:
                    print(f"START checkpoint_t{step} slot={slot}", flush=True)
                return _run_checkpoint(
                    step=step,
                    slot=slot,
                    checkpoint_dir=checkpoint_dir,
                    out_root=out_root,
                    expected_records=expected_records,
                    repeats=args.repeats,
                    timeout_transfer_s=args.timeout_transfer_s,
                    timeout_s=args.timeout_s,
                    file_bytes=args.file_bytes,
                    bitrate_mbps=args.bitrate_mbps,
                    decode_ddl_ms=args.decode_ddl_ms,
                    done_deadline_ms=args.done_deadline_ms,
                    sender_ids=sender_ids,
                    device=args.device,
                )
            finally:
                slots.put(slot)

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(run_with_slot, step) for step in pending]
            for future in as_completed(futures):
                step, code, out_dir = future.result()
                with print_lock:
                    print(f"EXIT checkpoint_t{step} code={code} out={out_dir}", flush=True)
                if code != 0:
                    raise SystemExit(f"checkpoint t={step} evaluator failed with code {code}; see {out_dir}/launcher.log")

    all_scene_rows: List[Dict[str, Any]] = []
    all_excluded_rows: List[Dict[str, Any]] = []
    failed_summaries: List[int] = []
    for step in steps:
        out_dir = out_root / f"checkpoint_t{step}"
        try:
            scene_rows, excluded_rows = _summarize_checkpoint(
                step=step,
                out_dir=out_dir,
                sender_ids=sender_ids,
                repeats=args.repeats,
                oracle=oracle,
                env_cfg=env_cfg,
            )
            all_scene_rows.extend(scene_rows)
            all_excluded_rows.extend(excluded_rows)
        except Exception as exc:
            failed_summaries.append(step)
            print(f"SUMMARY_FAILED checkpoint_t{step}: {exc}", file=sys.stderr, flush=True)

    if failed_summaries:
        raise SystemExit(f"could not summarize checkpoints: {failed_summaries}")
    if not all_scene_rows:
        raise SystemExit("no valid sender/checkpoint comparisons remain after the all-minus-one filter")
    scene_path, summary_path, excluded_path = _write_aggregate(all_scene_rows, all_excluded_rows, out_root)
    line_path, heatmap_path = _plot_results(summary_path=summary_path, scene_path=scene_path, out_root=out_root)
    print(f"OUT: {out_root}")
    print(f"- {summary_path}")
    print(f"- {scene_path}")
    print(f"- {excluded_path}")
    print(f"- {line_path}")
    print(f"- {heatmap_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
