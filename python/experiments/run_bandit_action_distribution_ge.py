#!/usr/bin/env python3
"""Evaluate a frozen LinTS policy for action distribution and completion.

The run is split across independent evaluator processes, each with its own
network namespace and a disjoint subset of GE senders. Context is reset at the
start of each sender and updated after every repetition within that sender.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[2]
EVALUATOR = Path(__file__).resolve().with_name("eval_bandit_model_on_testbed.py")
HELPER = "/usr/local/libexec/quicfec-net-helper"
DEFAULT_CHECKPOINT = (
    ROOT
    / "python/results/ge-lints-under40-5000-2s-rho9999-exactinv-eval12-oracle-20260929/checkpoints/model_t15000"
)
DEFAULT_GE_PARAMS = ROOT / "python/bandit/quic_fec_params.json"
DEFAULT_OUT = ROOT / "python/results/ge-lints-under40-action-distribution-128kb-61x30-21par-20260930"
DEADLINES_MS = (200, 300, 400, 500)


def _sender_ids(ge_params: Path, ge_key: str) -> List[int]:
    payload = json.loads(ge_params.read_text(encoding="utf-8"))
    senders = payload.get("senders")
    if not isinstance(senders, dict) or not senders:
        raise ValueError(f"GE file has no sender map: {ge_params}")
    missing = [sid for sid, entry in senders.items() if not isinstance(entry, dict) or not isinstance(entry.get(ge_key), dict)]
    if missing:
        raise ValueError(f"GE sender entries missing {ge_key}: {missing}")
    return sorted(int(sid) for sid in senders)


def _checkpoint_step(checkpoint: Path) -> int:
    metadata = json.loads(checkpoint.with_suffix(".json").read_text(encoding="utf-8"))
    context_state = metadata.get("context_state")
    if isinstance(context_state, dict) and context_state.get("t") is not None:
        return int(context_state["t"])
    raise ValueError(f"checkpoint metadata has no training step: {checkpoint}.json")


def _partition(items: Sequence[int], workers: int) -> List[List[int]]:
    buckets: List[List[int]] = [[] for _ in range(workers)]
    for idx, item in enumerate(items):
        buckets[idx % workers].append(int(item))
    return [bucket for bucket in buckets if bucket]


def _ensure_go_binaries() -> None:
    """Build once before parallel evaluators inspect source/binary timestamps."""
    go = shutil.which("go")
    if not go:
        raise RuntimeError("Go toolchain not found on PATH")
    bin_dir = ROOT / "go/bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    for target, package in (
        (bin_dir / "quicfec-server", "./cmd/quicfec-server"),
        (bin_dir / "quicfec-client", "./cmd/quicfec-client"),
    ):
        cmd = [go, "build", "-o", str(target), package]
        print(f"[build] {' '.join(cmd)}", flush=True)
        subprocess.run(cmd, cwd=ROOT / "go", check=True)


def _cleanup_network(tag: str, log_path: Path) -> int:
    clean_tag = "".join(ch for ch in tag if ch.isalnum())[:8]
    ns = f"qns_{clean_tag}"
    veth_host = ("vh" + clean_tag)[:15]
    try:
        proc = subprocess.run(
            ["sudo", "-n", "--", HELPER, "cleanup", ns, veth_host],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=60,
            check=False,
        )
        with log_path.open("a", encoding="utf-8") as log:
            log.write(f"\n[cleanup] rc={proc.returncode}\n{proc.stdout or ''}")
        return int(proc.returncode)
    except Exception as exc:
        with log_path.open("a", encoding="utf-8") as log:
            log.write(f"\n[cleanup] exception={exc!r}\n")
        return 125


def _run_worker(
    *,
    worker_idx: int,
    senders: Sequence[int],
    args: argparse.Namespace,
    out_root: Path,
) -> Tuple[int, int, int, str]:
    tag = f"act{worker_idx:05d}"  # exactly eight alphanumeric characters
    worker_dir = out_root / f"worker_{worker_idx:02d}"
    worker_dir.mkdir(parents=True, exist_ok=False)
    log_path = worker_dir / "launcher.log"
    command = [
        sys.executable,
        "-u",
        str(EVALUATOR),
        "--checkpoint-prefix",
        str(args.checkpoint),
        "--device",
        args.device,
        "--out-dir",
        str(worker_dir),
        "--run-tag",
        tag,
        "--policy",
        "greedy",
        "--seed",
        str(args.seed),
        "--policy-repeats",
        "1",
        "--ctx-reset",
        args.ctx_reset,
        "--loss-profile",
        "ge",
        "--ge-params",
        str(args.ge_params),
        "--ge-key",
        args.ge_key,
        "--ge-h-pct",
        str(args.ge_h_pct),
        "--ge-k-pct",
        str(args.ge_k_pct),
        "--sender-ids",
        ",".join(str(sid) for sid in senders),
        "--bitrate-mbps",
        str(args.bitrate_mbps),
        "--timeout-transfer-s",
        str(args.timeout_transfer_s),
        "--timeout-s",
        str(args.timeout_s),
        "--steps-per-scenario",
        str(args.repeats),
        "--file-bytes",
        str(args.file_bytes),
        "--symbol-bytes",
        str(args.symbol_bytes),
        "--decode-ddl-ms",
        str(args.decode_ddl_ms),
        "--done-deadline-ms",
        str(args.done_deadline_ms),
        "--enable-quic-overhead",
        "1",
        "--cc",
        "bbrv2",
    ]
    env = os.environ.copy()
    env.update(
        {
            "QUIC_FEC_PRIV_HELPER": HELPER,
            "QUICFEC_EVAL_SLOT": str(worker_idx),
            "CONNECT_RETRIES": "1",
            "CONNECT_TIMEOUT_S": str(args.timeout_transfer_s),
            "TIMEOUT_S": str(args.timeout_transfer_s),
            "SRV_TIMEOUT": f"{args.timeout_transfer_s}s",
            "CLI_TIMEOUT": f"{args.timeout_transfer_s}s",
            "POST_WAIT": "0ms",
            "TRANSPORT": "dgram",
            "USE_ARQ": "1",
            "W": "8",
            "MAX_ATTEMPTS": "0",
            "FEC_STATS": "1",
            "TUNE_UDP_BUFFERS": "0",
            "QUIC_FEC_ARQ_DRAIN_CAP_MS": str(args.timeout_transfer_s * 1000),
            "OMP_NUM_THREADS": "1",
            "OPENBLAS_NUM_THREADS": "1",
            "MKL_NUM_THREADS": "1",
            "NUMEXPR_NUM_THREADS": "1",
        }
    )

    print(
        f"[worker {worker_idx:02d}] start senders={list(senders)} trials={len(senders) * args.repeats}",
        flush=True,
    )
    code = 125
    with log_path.open("w", encoding="utf-8") as log:
        log.write("command=" + " ".join(command) + "\n")
        log.write(f"slot={worker_idx} tag={tag} sender_ids={list(senders)}\n")
        log.flush()
        try:
            proc = subprocess.run(
                command,
                cwd=ROOT,
                env=env,
                stdout=log,
                stderr=subprocess.STDOUT,
                timeout=args.worker_timeout_s,
                check=False,
            )
            code = int(proc.returncode)
        except Exception as exc:
            log.write(f"\n[launcher-exception] {exc!r}\n")
    cleanup_code = _cleanup_network(tag, log_path)
    print(
        f"[worker {worker_idx:02d}] done rc={code} cleanup_rc={cleanup_code} dir={worker_dir}",
        flush=True,
    )
    return int(worker_idx), int(code), int(cleanup_code), str(worker_dir)


def _read_worker_outputs(worker_dirs: Sequence[Path], sender_ids: Sequence[int], repeats: int) -> Tuple[List[Dict[str, Any]], List[Dict[str, str]]]:
    records: List[Dict[str, Any]] = []
    csv_rows: List[Dict[str, str]] = []
    for worker_dir in worker_dirs:
        jsonl_path = worker_dir / "bandit_eval_metrics.jsonl"
        csv_path = worker_dir / "bandit_eval_results.csv"
        if not jsonl_path.exists() or not csv_path.exists():
            raise RuntimeError(f"missing worker outputs under {worker_dir}")
        with jsonl_path.open("r", encoding="utf-8") as source:
            records.extend(json.loads(line) for line in source if line.strip())
        with csv_path.open("r", newline="", encoding="utf-8") as source:
            reader = csv.DictReader(source)
            csv_rows.extend(dict(row) for row in reader)

    expected = len(sender_ids) * int(repeats)
    if len(records) != expected or len(csv_rows) != expected:
        raise RuntimeError(f"expected {expected} trial records, got jsonl={len(records)} csv={len(csv_rows)}")
    by_sender: Dict[int, int] = Counter(int(row["sender_id"]) for row in csv_rows)
    if set(by_sender) != set(int(sid) for sid in sender_ids):
        raise RuntimeError("evaluated sender coverage does not match the requested GE sender set")
    bad_counts = {sid: count for sid, count in by_sender.items() if count != int(repeats)}
    if bad_counts:
        raise RuntimeError(f"per-sender repetition counts differ from {repeats}: {bad_counts}")
    if any(int(row["file_bytes"]) != 131072 for row in records):
        raise RuntimeError("record payload size differs from 128 KiB")
    return records, csv_rows


def _write_csv(path: Path, fieldnames: Sequence[str], rows: Iterable[Dict[str, Any]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=list(fieldnames))
        writer.writeheader()
        writer.writerows(rows)


def _summarize(records: Sequence[Dict[str, Any]], csv_rows: Sequence[Dict[str, str]], out_root: Path) -> None:
    n_total = len(csv_rows)
    deadline_rows: List[Dict[str, Any]] = []
    for deadline in DEADLINES_MS:
        completed = 0
        for row in csv_rows:
            success = int(float(row.get("success", 0) or 0)) == 1
            delay = float(row.get("e2e_delay_ms", "nan"))
            if success and math.isfinite(delay) and 0 < delay <= deadline:
                completed += 1
        deadline_rows.append(
            {
                "deadline_ms": deadline,
                "completed_trials": completed,
                "total_trials": n_total,
                "completion_ratio": completed / n_total if n_total else float("nan"),
            }
        )
    _write_csv(
        out_root / "completion_by_deadline.csv",
        ["deadline_ms", "completed_trials", "total_trials", "completion_ratio"],
        deadline_rows,
    )

    grouped: Dict[int, List[Dict[str, str]]] = defaultdict(list)
    for row in csv_rows:
        grouped[int(row["sender_id"])].append(row)
    sender_rows: List[Dict[str, Any]] = []
    for sid in sorted(grouped):
        rows = grouped[sid]
        counts: Counter[Tuple[int, int, int]] = Counter(
            (int(r["K"]), int(r["R0"]), int(r["RSTEP"])) for r in rows
        )
        modal_action, modal_n = min(counts.items(), key=lambda item: (-item[1], item[0]))
        row: Dict[str, Any] = {
            "sender_id": sid,
            "trials": len(rows),
            "successful_transfers": sum(int(r["success"]) == 1 for r in rows),
            "distinct_actions": len(counts),
            "modal_K": modal_action[0],
            "modal_R0": modal_action[1],
            "modal_delta_R": modal_action[2],
            "modal_count": modal_n,
            "modal_share": modal_n / len(rows),
        }
        for deadline in DEADLINES_MS:
            completed = sum(
                int(r["success"]) == 1
                and math.isfinite(float(r.get("e2e_delay_ms", "nan")))
                and 0 < float(r["e2e_delay_ms"]) <= deadline
                for r in rows
            )
            row[f"completion_{deadline}ms"] = completed / len(rows) if rows else float("nan")
            row[f"completed_{deadline}ms"] = completed
        sender_rows.append(row)
    _write_csv(out_root / "completion_by_sender.csv", list(sender_rows[0]), sender_rows)

    overall_actions: Counter[Tuple[int, int, int]] = Counter()
    actions_by_sender: Dict[Tuple[int, int, int, int], int] = Counter()
    for record in records:
        action = record.get("action", {})
        key = (int(action["K"]), int(action["R0"]), int(action["RSTEP"]))
        sid = int(record["sender_id"])
        overall_actions[key] += 1
        actions_by_sender[(sid, *key)] += 1
    action_rows = [
        {
            "K": key[0],
            "R0": key[1],
            "delta_R": key[2],
            "count": count,
            "share": count / n_total if n_total else float("nan"),
            "senders_using_action": sum((sid, *key) in actions_by_sender for sid in grouped),
        }
        for key, count in sorted(overall_actions.items(), key=lambda item: (-item[1], item[0]))
    ]
    _write_csv(
        out_root / "action_distribution.csv",
        ["K", "R0", "delta_R", "count", "share", "senders_using_action"],
        action_rows,
    )
    sender_action_rows = [
        {"sender_id": sid, "K": k, "R0": r0, "delta_R": dr, "count": count, "share_within_sender": count / len(grouped[sid])}
        for (sid, k, r0, dr), count in sorted(actions_by_sender.items())
    ]
    _write_csv(
        out_root / "action_distribution_by_sender.csv",
        ["sender_id", "K", "R0", "delta_R", "count", "share_within_sender"],
        sender_action_rows,
    )

    summary = {
        "total_trials": n_total,
        "sender_count": len(grouped),
        "repetitions_per_sender": int(n_total / len(grouped)) if grouped else 0,
        "action_count": len(overall_actions),
        "action_distribution": action_rows,
        "completion_by_deadline": deadline_rows,
    }
    (out_root / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--checkpoint", type=Path, default=DEFAULT_CHECKPOINT, help="Checkpoint prefix (without .npz/.json)")
    ap.add_argument("--ge-params", type=Path, default=DEFAULT_GE_PARAMS)
    ap.add_argument("--ge-key", default="GE_steady_rp")
    ap.add_argument("--ge-h-pct", type=float, default=0.0)
    ap.add_argument("--ge-k-pct", type=float, default=99.0)
    ap.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--workers", type=int, default=21)
    ap.add_argument("--repeats", type=int, default=30)
    ap.add_argument("--file-bytes", type=int, default=128 * 1024)
    ap.add_argument("--bitrate-mbps", type=int, default=10)
    ap.add_argument("--timeout-transfer-s", type=int, default=2)
    ap.add_argument("--timeout-s", type=int, default=60)
    ap.add_argument("--worker-timeout-s", type=int, default=1800)
    ap.add_argument("--decode-ddl-ms", type=int, default=25)
    ap.add_argument("--done-deadline-ms", type=int, default=500)
    ap.add_argument("--symbol-bytes", type=int, default=1200)
    ap.add_argument("--device", default="cuda")
    ap.add_argument("--ctx-reset", choices=["per_scenario", "never"], default="per_scenario")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    args.checkpoint = args.checkpoint.resolve()
    args.ge_params = args.ge_params.resolve()
    args.out_dir = args.out_dir.resolve()
    if not args.checkpoint.with_suffix(".npz").exists() or not args.checkpoint.with_suffix(".json").exists():
        raise FileNotFoundError(f"checkpoint pair not found: {args.checkpoint}.npz/.json")
    if args.file_bytes != 128 * 1024:
        raise ValueError("this experiment is pinned to the 128 KiB task (131072 bytes)")
    if not 1 <= args.workers <= 200:
        raise ValueError("workers must be in [1, 200]")
    if args.workers > 21:
        raise ValueError("the helper's reserved evaluator slot range for this run is 0..20")
    senders = _sender_ids(args.ge_params, args.ge_key)
    checkpoint_step = _checkpoint_step(args.checkpoint)
    workers = _partition(senders, args.workers)
    if args.out_dir.exists():
        raise FileExistsError(f"refusing to reuse existing result directory: {args.out_dir}")

    print(
        f"checkpoint_step={checkpoint_step} sender_count={len(senders)} repeats={args.repeats} "
        f"expected_trials={len(senders) * args.repeats} workers={len(workers)} file_bytes={args.file_bytes}",
        flush=True,
    )
    helper = subprocess.run(
        ["sudo", "-n", "--", HELPER, "self-test"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if helper.returncode != 0:
        raise RuntimeError(f"network helper self-test failed: {helper.stdout}{helper.stderr}")
    print(f"network_helper={helper.stdout.strip() or 'ok'}", flush=True)

    args.out_dir.mkdir(parents=True, exist_ok=False)
    args.out_dir.joinpath("run_config.json").write_text(
        json.dumps(
            {
                "checkpoint_prefix": str(args.checkpoint),
                "checkpoint_step": checkpoint_step,
                "ge_params": str(args.ge_params),
                "ge_key": args.ge_key,
                "sender_ids": senders,
                "sender_count": len(senders),
                "repetitions_per_sender": args.repeats,
                "expected_trials": len(senders) * args.repeats,
                "workers": len(workers),
                "payload_bytes": args.file_bytes,
                "bitrate_mbps": args.bitrate_mbps,
                "transfer_timeout_s": args.timeout_transfer_s,
                "timeout_s": args.timeout_s,
                "cc": "bbrv2",
                "device": args.device,
                "policy": "greedy",
                "posterior_updates": False,
                "context_reset": args.ctx_reset,
                "context_updates_within_sender": True,
                "decode_ddl_ms": args.decode_ddl_ms,
                "completion_deadlines_ms": list(DEADLINES_MS),
                "completion_definition": "success == 1 and 0 < e2e_delay_ms <= deadline; denominator includes every trial",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    _ensure_go_binaries()
    worker_dirs: List[Path] = []
    failures: List[Tuple[int, int, int, str]] = []
    with ThreadPoolExecutor(max_workers=len(workers)) as pool:
        futures = {
            pool.submit(_run_worker, worker_idx=i, senders=part, args=args, out_root=args.out_dir): i
            for i, part in enumerate(workers)
        }
        for future in as_completed(futures):
            result = future.result()
            worker_idx, code, cleanup_code, worker_dir = result
            worker_dirs.append(Path(worker_dir))
            if code != 0 or cleanup_code != 0:
                failures.append(result)
    if failures:
        raise RuntimeError(f"worker failures (worker, eval_rc, cleanup_rc, dir): {failures}")

    worker_dirs.sort()
    records, csv_rows = _read_worker_outputs(worker_dirs, senders, args.repeats)
    records.sort(key=lambda r: (int(r["sender_id"]), int(r.get("t", 0))))
    csv_rows.sort(key=lambda r: (int(r["sender_id"]), int(r["rep"])))
    with (args.out_dir / "bandit_eval_metrics.jsonl").open("w", encoding="utf-8") as output:
        for record in records:
            output.write(json.dumps(record, ensure_ascii=False) + "\n")
    csv_fields = list(csv_rows[0]) if csv_rows else []
    _write_csv(args.out_dir / "bandit_eval_results.csv", csv_fields, csv_rows)
    _summarize(records, csv_rows, args.out_dir)
    print(f"completed_trials={len(csv_rows)} results={args.out_dir}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
