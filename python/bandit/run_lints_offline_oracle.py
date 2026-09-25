#!/usr/bin/env python3
"""Train LinTS from the exhaustive GE/action Oracle trial table.

This is an offline bootstrap simulator, not a replacement for the online
runner. At each synthetic decision it selects an action, samples one stored
Oracle trial for that (GE scene, action), synthesizes the missing NACK count
from the configured distribution, then updates LinTS and ContextBuilder.
No network namespaces or QUIC transfers are started.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sqlite3
import sys
import time
from collections import OrderedDict, Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
PYTHON_DIR = ROOT / "python"
if str(PYTHON_DIR) not in sys.path:
    sys.path.insert(0, str(PYTHON_DIR))

from bandit.action_set import ActionSet  # noqa: E402
from bandit.context import ContextBuilder, ContextConfig  # noqa: E402
from bandit.features import phi as phi_fn  # noqa: E402
from bandit.lints import LinTS, LinTSConfig  # noqa: E402
from bandit.model_io import save_checkpoint  # noqa: E402


DEFAULT_ORACLE_DIR = ROOT / "python/results/ge-100kb-oracle-all-actions-20x-2s-par121-20260918"
DEFAULT_GE_PARAMS = ROOT / "python/bandit/quic_fec_params.json"
DEFAULT_OUT_DIR = ROOT / "python/results/ge-100kb-bandit-offline-oracle-rho9999-100k-20260924"
REQUIRED_COLUMNS = {
    "sender", "action", "repeat", "reward", "success", "is_timeout", "md5_ok",
    "duration_ms", "goodput_mbps", "overhead", "wall_seconds", "timestamp",
}


def _read_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        value = json.load(f)
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object in {path}")
    return value


def _load_ge_senders(path: Path, ge_key: str) -> List[Tuple[int, Dict[str, Any]]]:
    data = _read_json(path)
    senders = data.get("senders")
    if not isinstance(senders, dict):
        raise ValueError(f"missing 'senders' object in {path}")
    result = []
    for key, sender in senders.items():
        if not isinstance(sender, dict) or not isinstance(sender.get(ge_key), dict):
            continue
        result.append((int(key), sender))
    result.sort(key=lambda item: item[0])
    if not result:
        raise ValueError(f"no senders have GE key {ge_key!r} in {path}")
    return result


def _readonly_connection(path: Path) -> sqlite3.Connection:
    uri = f"file:{path.resolve().as_posix()}?mode=ro"
    db = sqlite3.connect(uri, uri=True, timeout=30.0)
    db.execute("PRAGMA query_only=ON")
    return db


class OracleTrialStore:
    """Read-only, validated access to the per-worker Oracle SQLite tables."""

    def __init__(
        self,
        *,
        oracle_dir: Path,
        manifest: Mapping[str, Any],
        sender_ids: Sequence[int],
        action_count: int,
        repeats: int,
    ) -> None:
        self.root = oracle_dir
        self.manifest = manifest
        self.sender_ids = set(int(x) for x in sender_ids)
        self.action_count = int(action_count)
        self.repeats = int(repeats)
        self.connections: Dict[int, sqlite3.Connection] = {}
        self.action_worker: Dict[int, int] = {}
        self.cache: OrderedDict[Tuple[int, int], List[Tuple[Any, ...]]] = OrderedDict()
        self.cache_limit = 4096
        self.audit = self._validate_all()

    def _validate_all(self) -> Dict[str, Any]:
        workers = int(self.manifest["workers"])
        groups_raw = self.manifest.get("action_groups")
        if not isinstance(groups_raw, dict) or len(groups_raw) != workers:
            raise ValueError("Oracle action_groups does not match manifest worker count")

        expected_actions = set(range(self.action_count))
        assigned_actions: set[int] = set()
        groups: Dict[int, set[int]] = {}
        for worker in range(workers):
            raw = groups_raw.get(str(worker))
            if not isinstance(raw, list):
                raise ValueError(f"Oracle manifest has no action group for worker {worker}")
            action_ids = set(int(x) for x in raw)
            if len(action_ids) != int(self.manifest["actions_per_worker"]):
                raise ValueError(f"worker {worker} has an unexpected action-group size")
            if assigned_actions & action_ids:
                raise ValueError(f"Oracle action groups overlap at worker {worker}")
            assigned_actions |= action_ids
            groups[worker] = action_ids
            for action_id in action_ids:
                self.action_worker[action_id] = worker
        if assigned_actions != expected_actions:
            raise ValueError("Oracle action groups do not partition the current ActionSet")

        total_rows = 0
        checked_groups = 0
        reward_min = math.inf
        reward_max = -math.inf
        expected_group_keys = {
            (sender, action)
            for sender in self.sender_ids
            for action in expected_actions
        }

        for worker, action_ids in groups.items():
            db_path = self.root / f"worker_{worker:03d}" / "trials.sqlite3"
            if not db_path.is_file():
                raise ValueError(f"missing Oracle database: {db_path}")
            db = _readonly_connection(db_path)
            columns = {row[1] for row in db.execute("PRAGMA table_info(trials)")}
            if not REQUIRED_COLUMNS.issubset(columns):
                db.close()
                raise ValueError(f"Oracle database has missing trial columns: {db_path}")

            count = int(db.execute("SELECT COUNT(*) FROM trials").fetchone()[0])
            total_rows += count
            invalid = int(
                db.execute(
                    """SELECT COUNT(*) FROM trials WHERE
                       reward IS NULL OR goodput_mbps IS NULL OR overhead IS NULL OR duration_ms IS NULL OR
                       repeat < 0 OR repeat >= ? OR
                       success NOT IN (0,1) OR is_timeout NOT IN (0,1) OR md5_ok NOT IN (0,1) OR
                       duration_ms < 0 OR goodput_mbps < 0 OR overhead < 0 OR wall_seconds < 0 OR
                       success != CASE WHEN md5_ok=1 AND is_timeout=0 THEN 1 ELSE 0 END""",
                    (self.repeats,),
                ).fetchone()[0]
            )
            if invalid:
                db.close()
                raise ValueError(f"worker {worker} has {invalid} invalid trial rows")

            found: set[Tuple[int, int]] = set()
            aggregates = db.execute(
                """SELECT sender, action, COUNT(*), COUNT(DISTINCT repeat),
                          MIN(repeat), MAX(repeat), MIN(reward), MAX(reward)
                   FROM trials GROUP BY sender, action"""
            )
            for sender, action, n, distinct_repeats, lo, hi, rmin, rmax in aggregates:
                key = (int(sender), int(action))
                found.add(key)
                checked_groups += 1
                if key[0] not in self.sender_ids or key[1] not in action_ids:
                    db.close()
                    raise ValueError(f"unexpected sender/action pair {key} in worker {worker}")
                if (int(n), int(distinct_repeats), int(lo), int(hi)) != (
                    self.repeats, self.repeats, 0, self.repeats - 1
                ):
                    db.close()
                    raise ValueError(f"incomplete repeats for sender/action {key}: n={n}, ids={lo}..{hi}")
                reward_min = min(reward_min, float(rmin))
                reward_max = max(reward_max, float(rmax))
            expected_worker_keys = {
                (sender, action)
                for sender in self.sender_ids
                for action in action_ids
            }
            if found != expected_worker_keys:
                db.close()
                raise ValueError(f"worker {worker} has missing sender/action pairs")
            db.close()

        expected_rows = len(expected_group_keys) * self.repeats
        if total_rows != expected_rows or total_rows != int(self.manifest["total_trials"]):
            raise ValueError(f"Oracle row count mismatch: got {total_rows}, expected {expected_rows}")
        if checked_groups != len(expected_group_keys):
            raise ValueError(f"Oracle group count mismatch: got {checked_groups}, expected {len(expected_group_keys)}")
        return {
            "workers": workers,
            "sender_count": len(self.sender_ids),
            "action_count": self.action_count,
            "sender_action_pairs": checked_groups,
            "repeats_per_pair": self.repeats,
            "rows": total_rows,
            "reward_min": reward_min,
            "reward_max": reward_max,
            "status": "passed",
        }

    def _connection(self, worker: int) -> sqlite3.Connection:
        if worker not in self.connections:
            path = self.root / f"worker_{worker:03d}" / "trials.sqlite3"
            self.connections[worker] = _readonly_connection(path)
        return self.connections[worker]

    def sample(self, *, sender: int, action: int, rng: np.random.RandomState) -> Tuple[Any, ...]:
        key = (int(sender), int(action))
        rows = self.cache.get(key)
        if rows is None:
            worker = self.action_worker.get(key[1])
            if worker is None:
                raise KeyError(f"action {key[1]} is not assigned in the Oracle manifest")
            rows = self._connection(worker).execute(
                """SELECT repeat, reward, success, is_timeout, md5_ok, duration_ms,
                          goodput_mbps, overhead
                   FROM trials WHERE sender=? AND action=? ORDER BY repeat""",
                key,
            ).fetchall()
            if len(rows) != self.repeats:
                raise ValueError(f"expected {self.repeats} rows for sender/action {key}, got {len(rows)}")
            self.cache[key] = rows
            if len(self.cache) > self.cache_limit:
                self.cache.popitem(last=False)
        else:
            self.cache.move_to_end(key)
        return rows[int(rng.randint(0, len(rows)))]

    def close(self) -> None:
        for db in self.connections.values():
            db.close()
        self.connections.clear()


def _draw_nack(rng: np.random.RandomState, low_group_probability: float) -> int:
    if float(rng.random_sample()) < float(low_group_probability):
        return int(rng.randint(0, 4))
    return int(rng.randint(4, 7))


def _atomic_json(path: Path, payload: Mapping[str, Any]) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline LinTS training using exhaustive Oracle trials")
    parser.add_argument("--oracle-dir", type=Path, default=DEFAULT_ORACLE_DIR)
    parser.add_argument("--ge-params", type=Path, default=DEFAULT_GE_PARAMS)
    parser.add_argument("--ge-key", default="GE_steady_rp")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--steps", type=int, default=100_000)
    parser.add_argument("--episode-steps", type=int, default=10)
    parser.add_argument("--checkpoint-interval", type=int, default=500)
    parser.add_argument("--warmup", type=int, default=20)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--rho", type=float, default=0.9999)
    parser.add_argument("--sigma", type=float, default=0.2)
    parser.add_argument("--lam", type=float, default=1.0)
    parser.add_argument("--recompute-inv-every", type=int, default=100)
    parser.add_argument("--ctx-alpha", type=float, default=0.2)
    parser.add_argument("--ctx-window", type=int, default=50)
    parser.add_argument("--nack-low-group-probability", type=float, default=0.87)
    parser.add_argument("--file-bytes", type=int, default=102_400)
    parser.add_argument("--done-deadline-ms", type=int, default=500)
    args = parser.parse_args()

    if args.steps <= 0 or args.episode_steps <= 0 or args.checkpoint_interval <= 0:
        parser.error("steps, episode-steps, and checkpoint-interval must be positive")
    if args.steps % args.episode_steps != 0:
        parser.error("steps must be divisible by episode-steps to preserve the GE schedule")
    if not 0.0 <= args.nack_low_group_probability <= 1.0:
        parser.error("nack-low-group-probability must be in [0,1]")
    if args.file_bytes != 102_400 and args.done_deadline_ms == 500:
        parser.error("the default 500ms done deadline is defined here for the 100KB Oracle experiment")

    oracle_dir = args.oracle_dir.resolve()
    ge_path = args.ge_params.resolve()
    out_dir = args.out_dir.resolve()
    if not (oracle_dir / "manifest.json").is_file():
        parser.error(f"Oracle manifest not found under {oracle_dir}")
    if not ge_path.is_file():
        parser.error(f"GE parameter file not found: {ge_path}")
    oracle_manifest = _read_json(oracle_dir / "manifest.json")
    ge_senders = _load_ge_senders(ge_path, args.ge_key)
    sender_ids = [sid for sid, _ in ge_senders]
    oracle_scenes = {int(row["sender_id"]): row for row in oracle_manifest.get("scenes", [])}
    if set(oracle_scenes) != set(sender_ids):
        parser.error("Oracle scene IDs do not match the configured GE sender IDs")
    for sid, sender_data in ge_senders:
        recorded = oracle_scenes[sid].get(args.ge_key)
        if recorded != sender_data.get(args.ge_key):
            parser.error(f"Oracle GE parameters differ from {ge_path} for sender {sid}")

    env_cfg = oracle_manifest.get("env_cfg", {})
    action_set = ActionSet(
        k_values=env_cfg.get("k_values"),
        r0_values=env_cfg.get("r0_values"),
        rstep_values=env_cfg.get("rstep_values"),
    )
    if len(action_set) != int(oracle_manifest.get("actions", -1)):
        parser.error("Current ActionSet size does not match the Oracle action space")
    expected_levels = {
        "k_values": list(action_set.k_values),
        "r0_values": list(action_set.r0_values),
        "rstep_values": list(action_set.rstep_values),
    }
    if any(list(env_cfg.get(key, [])) != value for key, value in expected_levels.items()):
        parser.error("Oracle action levels do not match the current ActionSet")

    store = OracleTrialStore(
        oracle_dir=oracle_dir,
        manifest=oracle_manifest,
        sender_ids=sender_ids,
        action_count=len(action_set),
        repeats=int(oracle_manifest["repeats"]),
    )
    print(f"[data-audit] {json.dumps(store.audit, sort_keys=True)}", flush=True)

    ctx_cfg = ContextConfig(ewma_alpha=float(args.ctx_alpha), window=int(args.ctx_window))
    ctx = ContextBuilder(ctx_cfg)
    lints_cfg = LinTSConfig(
        lam=float(args.lam),
        sigma=float(args.sigma),
        rho=float(args.rho),
        recompute_inv_every=int(args.recompute_inv_every),
        seed=int(args.seed),
    )
    x0 = ctx.get_context()
    action_dim = int(action_set.onehot_dim)
    dim = 1 + int(x0.size) + action_dim + int(x0.size) * action_dim
    agent = LinTS(dim=dim, cfg=lints_cfg)
    action_features = np.asarray(
        [action_set.get_onehot(i) for i in range(len(action_set))], dtype=np.float64
    )

    # Separate random streams keep action warm-up, Oracle row selection, and
    # synthetic NACK draws reproducible without coupling them to LinTS samples.
    oracle_rng = np.random.RandomState(int(args.seed) + 104_729)
    nack_rng = np.random.RandomState(int(args.seed) + 130_363)
    nack_counts: Counter[int] = Counter()
    nack_group_counts = Counter()
    source_repeat_counts: Counter[int] = Counter()
    reward_sum = 0.0
    started_at = time.time()
    started_clock = time.perf_counter()

    # Never overwrite prior results: each run gets its own output directory.
    out_dir.mkdir(parents=True, exist_ok=False)
    checkpoints_dir = out_dir / "checkpoints"
    checkpoints_dir.mkdir()
    metrics_path = out_dir / "offline_bandit_metrics.jsonl"
    status_path = out_dir / "status.json"
    progress_manifest = {
        "experiment": "offline_lints_oracle_replay",
        "oracle_dir": str(oracle_dir),
        "oracle_manifest": str(oracle_dir / "manifest.json"),
        "oracle_source_commit": oracle_manifest.get("git_commit"),
        "oracle_source_sha256": oracle_manifest.get("source_sha256"),
        "ge_params": str(ge_path),
        "ge_key": args.ge_key,
        "steps": int(args.steps),
        "episode_steps": int(args.episode_steps),
        "checkpoint_interval": int(args.checkpoint_interval),
        "warmup_steps": int(args.warmup),
        "sender_ids": sender_ids,
        "action_count": len(action_set),
        "file_bytes": int(args.file_bytes),
        "done_deadline_ms": int(args.done_deadline_ms),
        "agent_cfg": {
            "lam": float(lints_cfg.lam), "sigma": float(lints_cfg.sigma),
            "rho": float(lints_cfg.rho),
            "recompute_inv_every": int(lints_cfg.recompute_inv_every),
            "seed": int(args.seed),
        },
        "ctx_cfg": {
            "ewma_alpha": float(ctx_cfg.ewma_alpha), "window": int(ctx_cfg.window),
            "goodput_ref_mbps": float(ctx_cfg.goodput_ref_mbps),
            "overhead_ref_pct": float(ctx_cfg.overhead_ref_pct),
            "nack_ref": float(ctx_cfg.nack_ref),
        },
        "nack_synthesis": {
            "low_group_probability": float(args.nack_low_group_probability),
            "low_group_values": [0, 1, 2, 3],
            "high_group_values": [4, 5, 6],
            "within_group_sampling": "uniform",
            "independent_of_oracle_trial": True,
            "seed": int(args.seed) + 130_363,
        },
        "oracle_sampling": {
            "grain": "sender/action/repeat trial",
            "with_replacement": True,
            "seed": int(args.seed) + 104_729,
            "context_order": "get context, choose action, sample outcome, then update context",
            "limitation": "empirical per-action outcomes do not replay a shared Markov GE packet-loss trace",
        },
        "oracle_quality_audit": store.audit,
        "reward_source": "stored Oracle reward; no reward recomputation",
        "created_at_unix": started_at,
    }
    (out_dir / "manifest.json").write_text(
        json.dumps(progress_manifest, indent=2, sort_keys=True), encoding="utf-8"
    )

    def save_at(step_done: int) -> None:
        extra = {
            "experiment": "offline_lints_oracle_replay",
            "oracle_dir": str(oracle_dir),
            "nack_synthesis": progress_manifest["nack_synthesis"],
            "oracle_sampling": progress_manifest["oracle_sampling"],
            "training_step": int(step_done),
        }
        save_checkpoint(
            path_prefix=str(checkpoints_dir / f"model_t{int(step_done)}"),
            agent=agent,
            agent_cfg=lints_cfg,
            ctx=ctx,
            ctx_cfg=ctx_cfg,
            action_set=action_set,
            step_t=int(step_done),
            extra_meta=extra,
        )

    completed = 0
    try:
        with metrics_path.open("w", encoding="utf-8") as metrics:
            for t in range(int(args.steps)):
                sender_id = sender_ids[(t // int(args.episode_steps)) % len(sender_ids)]
                scene = oracle_scenes[sender_id]
                x = ctx.get_context()

                if t < int(args.warmup):
                    # Preserve the current online runner's seeded warm-up rule.
                    a_idx = int(
                        np.random.RandomState(int(args.seed) + t).randint(0, len(action_set))
                    )
                    theta_sampled = False
                else:
                    a_idx, _theta = agent.select_action_features(
                        x=x, action_features=action_features
                    )
                    theta_sampled = True

                spec = action_set.get_action(a_idx)
                K = int(action_set.k_values[spec.k_idx])
                R0 = int(action_set.r0_values[spec.r0_idx])
                RSTEP = int(action_set.rstep_values[spec.rstep_idx])
                trial = store.sample(sender=sender_id, action=a_idx, rng=oracle_rng)
                repeat_id, reward, success, is_timeout, md5_ok, duration_ms, goodput, overhead = trial
                nack = _draw_nack(nack_rng, float(args.nack_low_group_probability))
                nack_counts[nack] += 1
                nack_group_counts["0-3" if nack <= 3 else "4-6"] += 1
                source_repeat_counts[int(repeat_id)] += 1

                done_flag = int(
                    float(duration_ms) > 0.0
                    and float(duration_ms) <= float(args.done_deadline_ms)
                    and not bool(is_timeout)
                    and bool(md5_ok)
                )
                fec_rate = float(min(max(R0, 0), K)) / float(max(1, K))
                raw_obs = np.asarray(
                    [float(goodput), float(overhead), float(nack), float(done_flag), fec_rate],
                    dtype=np.float64,
                )

                # Keep the online ordering: posterior update uses pre-outcome x;
                # that outcome only changes the next decision's context.
                ctx.update_from_obs(obs=raw_obs)
                if t >= int(args.warmup):
                    agent.update(
                        phi=phi_fn(x=x, a_onehot=action_set.get_onehot(a_idx)),
                        reward=float(reward),
                    )

                reward_sum += float(reward)
                record = {
                    "t": int(t),
                    "policy": "lints" if theta_sampled else "random_warmup",
                    "sender_id": int(sender_id),
                    "loss_mode": str(scene.get("loss_mode", "")),
                    "rtt_ms": int(scene.get("rtt_ms", 0)),
                    "a_idx": int(a_idx),
                    "action": {"K": K, "R0": R0, "RSTEP": RSTEP},
                    "context": [float(v) for v in x.tolist()],
                    "reward": float(reward),
                    "source_repeat": int(repeat_id),
                    "env_info": {
                        "step_valid": 1,
                        "md5_ok": int(md5_ok),
                        "is_timeout": int(is_timeout),
                        "is_md5_fail": int(not bool(md5_ok)),
                        "dur_ms": float(duration_ms),
                        "goodput_mbps": float(goodput),
                        "fec_overhead": float(overhead),
                        "ctrl_tx_nack_msgs": int(nack),
                        "done_flag": int(done_flag),
                        "fec_rate": float(fec_rate),
                        "nack_synthetic": True,
                        "raw_obs": {
                            "goodput": float(goodput),
                            "fec_overhead": float(overhead),
                            "ctrl_tx_nack_msgs": int(nack),
                            "done_flag": int(done_flag),
                            "fec_rate": float(fec_rate),
                        },
                    },
                }
                metrics.write(json.dumps(record, separators=(",", ":")) + "\n")
                completed = t + 1

                if completed % int(args.checkpoint_interval) == 0:
                    metrics.flush()
                    save_at(completed)
                    elapsed = time.perf_counter() - started_clock
                    rate = completed / max(elapsed, 1e-9)
                    eta_s = (int(args.steps) - completed) / max(rate, 1e-9)
                    status = {
                        "state": "running" if completed < int(args.steps) else "complete",
                        "completed_steps": completed,
                        "total_steps": int(args.steps),
                        "agent_updates": int(agent.t),
                        "current_sender_id": int(sender_id),
                        "mean_reward_so_far": reward_sum / completed,
                        "nack_counts": {str(k): int(v) for k, v in sorted(nack_counts.items())},
                        "nack_group_counts": dict(nack_group_counts),
                        "elapsed_seconds": elapsed,
                        "steps_per_second": rate,
                        "estimated_remaining_seconds": eta_s,
                        "last_checkpoint": str(checkpoints_dir / f"model_t{completed}"),
                    }
                    _atomic_json(status_path, status)
                    print(
                        f"[progress] {completed}/{args.steps} updates={agent.t} "
                        f"mean_reward={status['mean_reward_so_far']:.4f} "
                        f"rate={rate:.2f} steps/s eta={eta_s / 3600:.2f}h",
                        flush=True,
                    )

        final_extra = {
            "experiment": "offline_lints_oracle_replay",
            "oracle_dir": str(oracle_dir),
            "nack_synthesis": progress_manifest["nack_synthesis"],
            "oracle_sampling": progress_manifest["oracle_sampling"],
            "training_step": completed,
        }
        save_checkpoint(
            path_prefix=str(out_dir / "bandit_model"),
            agent=agent,
            agent_cfg=lints_cfg,
            ctx=ctx,
            ctx_cfg=ctx_cfg,
            action_set=action_set,
            step_t=completed,
            extra_meta=final_extra,
        )
        elapsed = time.perf_counter() - started_clock
        final_status = {
            "state": "complete",
            "completed_steps": completed,
            "total_steps": int(args.steps),
            "agent_updates": int(agent.t),
            "mean_reward": reward_sum / max(1, completed),
            "nack_counts": {str(k): int(v) for k, v in sorted(nack_counts.items())},
            "nack_group_counts": dict(nack_group_counts),
            "source_repeat_counts": {str(k): int(v) for k, v in sorted(source_repeat_counts.items())},
            "elapsed_seconds": elapsed,
            "steps_per_second": completed / max(elapsed, 1e-9),
            "completed_at_unix": time.time(),
            "final_model_prefix": str(out_dir / "bandit_model"),
        }
        _atomic_json(status_path, final_status)
        print(f"[complete] {json.dumps(final_status, sort_keys=True)}", flush=True)
    except BaseException:
        elapsed = time.perf_counter() - started_clock
        _atomic_json(
            status_path,
            {
                "state": "failed_or_interrupted",
                "completed_steps": completed,
                "total_steps": int(args.steps),
                "elapsed_seconds": elapsed,
                "last_checkpoint_step": completed - (completed % int(args.checkpoint_interval)),
            },
        )
        raise
    finally:
        store.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
