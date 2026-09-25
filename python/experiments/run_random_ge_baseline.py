#!/usr/bin/env python3
"""Evaluate a per-transfer random FEC policy on all GE scenes.

The experiment uses the same testbed settings as the checkpoint evaluation:
100 KB, 10 Mbps, BBRv2, 2 s transfer timeout, 500 ms completion deadline,
20 transfers per GE scene, and 21 independent network slots.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import queue
import re
import subprocess
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from statistics import mean
from typing import Any, Dict, Iterable, List, Sequence, Tuple

import numpy as np

from run_bandit_checkpoint_ge_regret import _reward_from_record


ROOT = Path(__file__).resolve().parents[2]
EVALUATOR = Path(__file__).resolve().with_name("eval_bandit_model_on_testbed.py")
HELPER = "/usr/local/libexec/quicfec-net-helper"
DEFAULT_ORACLE = ROOT / "python" / "results" / "ge-100kb-oracle-5x-top20-20x-2s-par21-20260915" / "oracle.json"
DEFAULT_ORACLE_MANIFEST = ROOT / "python" / "results" / "ge-100kb-oracle-5x-top20-20x-2s-par21-20260915" / "manifest.json"
DEFAULT_CHECKPOINT = ROOT / "python" / "results" / "ge-100kb-bandit-model-step500-100k" / "checkpoints" / "model_t500"
DEFAULT_OUT = ROOT / "python" / "results" / "ge-100kb-random-baseline-20x-2s-par21-20260918"


def read_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        obj = json.load(handle)
    if not isinstance(obj, dict):
        raise ValueError(f"expected JSON object: {path}")
    return obj


def sender_ids_from_oracle(oracle: Dict[str, Any]) -> List[int]:
    scenes = oracle.get("scenes")
    if not isinstance(scenes, dict):
        raise ValueError("oracle.json has no scenes object")
    return sorted(int(sid) for sid in scenes)


def split_scenes(sender_ids: Sequence[int], workers: int) -> List[List[int]]:
    chunks = [[] for _ in range(int(workers))]
    for index, sender_id in enumerate(sender_ids):
        chunks[index % int(workers)].append(int(sender_id))
    return [chunk for chunk in chunks if chunk]


def network_names(tag: str) -> Tuple[str, str]:
    clean = re.sub(r"[^0-9a-zA-Z]+", "", str(tag or ""))[:8]
    return f"qns_{clean}", ("vh" + clean)[:15]


def cleanup_network(*, tag: str, log_path: Path) -> None:
    namespace, veth_host = network_names(tag)
    try:
        proc = subprocess.run(
            ["sudo", "-n", HELPER, "cleanup", namespace, veth_host],
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30,
            check=False,
        )
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(f"\n[cleanup] rc={proc.returncode}\n{proc.stdout or ''}")
    except Exception as exc:
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(f"\n[cleanup] exception={exc!r}\n")


def jsonl_count(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open("r", encoding="utf-8") as handle:
        return sum(1 for line in handle if line.strip())


def worker_complete(out_dir: Path, expected_records: int) -> bool:
    meta_path = out_dir / "meta.json"
    jsonl_path = out_dir / "bandit_eval_metrics.jsonl"
    return meta_path.exists() and jsonl_path.exists() and jsonl_count(jsonl_path) == int(expected_records)


def run_worker(
    *,
    slot: int,
    sender_ids: Sequence[int],
    out_root: Path,
    checkpoint_prefix: Path,
    ge_params: Path,
    repeats: int,
    timeout_transfer_s: int,
    timeout_s: int,
    file_bytes: int,
    bitrate_mbps: int,
    done_deadline_ms: int,
) -> Tuple[int, int, str]:
    out_dir = out_root / f"worker_{int(slot):02d}"
    out_dir.mkdir(parents=True, exist_ok=True)
    expected = len(sender_ids) * int(repeats)
    if worker_complete(out_dir, expected):
        return int(slot), 0, str(out_dir)

    tag = f"r{int(slot):03d}"
    sender_arg = ",".join(str(int(sid)) for sid in sender_ids)
    command = [
        sys.executable,
        "-u",
        str(EVALUATOR),
        "--checkpoint-prefix",
        str(checkpoint_prefix),
        "--out-dir",
        str(out_dir),
        "--run-tag",
        tag,
        "--policy",
        "random",
        "--seed",
        str(20260918 + int(slot)),
        "--policy-repeats",
        "1",
        "--ctx-reset",
        "never",
        "--loss-profile",
        "ge",
        "--ge-params",
        str(ge_params),
        "--ge-key",
        "GE_steady_rp",
        "--sender-ids",
        sender_arg,
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
        "25",
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

    log_path = out_dir / "launcher.log"
    with log_path.open("w", encoding="utf-8") as log:
        log.write("command=" + " ".join(command) + "\n")
        log.write(f"slot={slot} tag={tag} sender_ids={sender_arg} expected_records={expected}\n")
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
    cleanup_network(tag=tag, log_path=log_path)
    return int(slot), code, str(out_dir)


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSONL at {path}:{line_no}") from exc
            if isinstance(row, dict):
                rows.append(row)
    return rows


def aggregate(
    *,
    out_root: Path,
    worker_dirs: Sequence[Path],
    oracle: Dict[str, Any],
    oracle_manifest: Dict[str, Any],
    repeats: int,
) -> None:
    records: List[Dict[str, Any]] = []
    csv_rows: List[Dict[str, Any]] = []
    for worker_dir in worker_dirs:
        records.extend(load_jsonl(worker_dir / "bandit_eval_metrics.jsonl"))
        csv_path = worker_dir / "bandit_eval_results.csv"
        if csv_path.exists():
            with csv_path.open("r", newline="", encoding="utf-8") as handle:
                csv_rows.extend(csv.DictReader(handle))

    records.sort(key=lambda row: (int(row.get("sender_id", -1)), int(row.get("t", -1))))
    expected = len(oracle.get("scenes", {})) * int(repeats)
    if len(records) != expected:
        raise SystemExit(f"random baseline expected {expected} records, found {len(records)}")

    jsonl_path = out_root / "random_eval_metrics.jsonl"
    with jsonl_path.open("w", encoding="utf-8") as handle:
        for row in records:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    csv_path = out_root / "random_eval_results.csv"
    if csv_rows:
        with csv_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(csv_rows[0]))
            writer.writeheader()
            writer.writerows(csv_rows)

    env_cfg = oracle_manifest.get("env_cfg") if isinstance(oracle_manifest.get("env_cfg"), dict) else {}
    by_sender: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    for record in records:
        by_sender[int(record["sender_id"])].append(record)

    scene_rows: List[Dict[str, Any]] = []
    for sender_id in sorted(by_sender):
        reps = by_sender[sender_id]
        rewards = [_reward_from_record(record, env_cfg=env_cfg) for record in reps]
        oracle_reward = float(oracle["scenes"][str(sender_id)]["oracle"]["mean_reward"])
        successes = [
            1.0
            if int(record.get("env_info", {}).get("step_valid", 0) or 0) == 1
            and int(record.get("env_info", {}).get("is_timeout", 0) or 0) == 0
            and int(record.get("env_info", {}).get("is_md5_fail", 0) or 0) == 0
            else 0.0
            for record in reps
        ]
        scene_rows.append(
            {
                "sender_id": sender_id,
                "oracle_reward": oracle_reward,
                "random_reward": mean(rewards),
                "random_regret": oracle_reward - mean(rewards),
                "random_reward_std": float(np.std(rewards, ddof=1)) if len(rewards) > 1 else 0.0,
                "random_success_rate": mean(successes),
                "mean_duration_ms": mean(float(record.get("env_info", {}).get("dur_ms", 0.0) or 0.0) for record in reps),
                "mean_goodput_mbps": mean(float(record.get("env_info", {}).get("goodput_mbps", 0.0) or 0.0) for record in reps),
                "mean_overhead": mean(float(record.get("env_info", {}).get("quic_overhead_ratio", 0.0) or 0.0) for record in reps),
                "distinct_actions": len({int(record.get("a_idx", -1)) for record in reps}),
            }
        )

    scene_path = out_root / "random_scene_summary.csv"
    with scene_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(scene_rows[0]))
        writer.writeheader()
        writer.writerows(scene_rows)

    summary = {
        "policy": "random_per_transfer",
        "scenes": len(scene_rows),
        "repeats_per_scene": int(repeats),
        "mean_reward": mean(float(row["random_reward"]) for row in scene_rows),
        "median_reward": float(np.median([float(row["random_reward"]) for row in scene_rows])),
        "mean_regret_vs_original_oracle": mean(float(row["random_regret"]) for row in scene_rows),
        "median_regret_vs_original_oracle": float(np.median([float(row["random_regret"]) for row in scene_rows])),
        "positive_regret_fraction_vs_original_oracle": mean(1.0 if float(row["random_regret"]) > 0 else 0.0 for row in scene_rows),
        "mean_success_rate": mean(float(row["random_success_rate"]) for row in scene_rows),
        "mean_duration_ms": mean(float(row["mean_duration_ms"]) for row in scene_rows),
        "mean_goodput_mbps": mean(float(row["mean_goodput_mbps"]) for row in scene_rows),
        "mean_overhead": mean(float(row["mean_overhead"]) for row in scene_rows),
    }
    (out_root / "random_summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--oracle-json", type=Path, default=DEFAULT_ORACLE)
    parser.add_argument("--oracle-manifest", type=Path, default=DEFAULT_ORACLE_MANIFEST)
    parser.add_argument("--checkpoint-prefix", type=Path, default=DEFAULT_CHECKPOINT)
    parser.add_argument("--ge-params", type=Path, default=ROOT / "python" / "bandit" / "quic_fec_params.json")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--workers", type=int, default=21)
    parser.add_argument("--repeats", type=int, default=20)
    parser.add_argument("--timeout-transfer-s", type=int, default=2)
    parser.add_argument("--timeout-s", type=int, default=60)
    parser.add_argument("--file-bytes", type=int, default=100 * 1024)
    parser.add_argument("--bitrate-mbps", type=int, default=10)
    parser.add_argument("--done-deadline-ms", type=int, default=500)
    args = parser.parse_args()

    out_root = args.out_dir.resolve()
    out_root.mkdir(parents=True, exist_ok=True)
    oracle = read_json(args.oracle_json.resolve())
    oracle_manifest = read_json(args.oracle_manifest.resolve())
    sender_ids = sender_ids_from_oracle(oracle)
    workers = max(1, min(int(args.workers), len(sender_ids), 199))
    chunks = split_scenes(sender_ids, workers)

    manifest = {
        "policy": "random_per_transfer",
        "oracle_json": str(args.oracle_json.resolve()),
        "oracle_manifest": str(args.oracle_manifest.resolve()),
        "checkpoint_prefix_for_action_space": str(args.checkpoint_prefix.resolve()),
        "ge_params": str(args.ge_params.resolve()),
        "ge_key": "GE_steady_rp",
        "sender_ids": sender_ids,
        "scenes": len(sender_ids),
        "repeats_per_scene": int(args.repeats),
        "expected_transfers": len(sender_ids) * int(args.repeats),
        "workers": workers,
        "network_slots": list(range(workers)),
        "file_bytes": int(args.file_bytes),
        "bitrate_mbps": int(args.bitrate_mbps),
        "timeout_transfer_s": int(args.timeout_transfer_s),
        "done_deadline_ms": int(args.done_deadline_ms),
        "ctx_reset": "never",
        "network_state_policy": "configure tc qdisc on the first transfer of each scenario and reuse it for the scenario repeats",
        "cc": "bbrv2",
        "randomization": "one uniformly random action independently at each transfer",
    }
    (out_root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    jobs = []
    for slot, chunk in enumerate(chunks):
        jobs.append((slot, chunk))
    print(
        f"scenes={len(sender_ids)} repeats={args.repeats} expected_transfers={len(sender_ids) * int(args.repeats)} "
        f"workers={workers} slots=0..{workers - 1}",
        flush=True,
    )

    results: List[Tuple[int, int, str]] = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(
                run_worker,
                slot=slot,
                sender_ids=chunk,
                out_root=out_root,
                checkpoint_prefix=args.checkpoint_prefix.resolve(),
                ge_params=args.ge_params.resolve(),
                repeats=int(args.repeats),
                timeout_transfer_s=int(args.timeout_transfer_s),
                timeout_s=int(args.timeout_s),
                file_bytes=int(args.file_bytes),
                bitrate_mbps=int(args.bitrate_mbps),
                done_deadline_ms=int(args.done_deadline_ms),
            ): slot
            for slot, chunk in jobs
        }
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            slot, code, out_dir = result
            print(f"EXIT worker={slot} code={code} out={out_dir}", flush=True)
            if code != 0:
                raise SystemExit(f"random worker {slot} failed; see {out_dir}/launcher.log")

    worker_dirs = [out_root / f"worker_{slot:02d}" for slot, _ in jobs]
    aggregate(
        out_root=out_root,
        worker_dirs=worker_dirs,
        oracle=oracle,
        oracle_manifest=oracle_manifest,
        repeats=int(args.repeats),
    )
    print(f"completed out={out_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
