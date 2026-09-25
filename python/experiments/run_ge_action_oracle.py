"""Exhaustive GE oracle with one isolated network worker per action group.

The experiment has 2541 actions, 61 GE scenes, and 20 repetitions per
action/scene pair.  With the default 121 workers, each worker owns exactly 21
actions and evaluates those actions over all scenes.  Each worker has its own
network namespace/veth pair and its own SQLite database, so workers never
share a network or a write lock.
"""
from __future__ import annotations

import argparse
import csv
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import time
import traceback
from typing import Any, Dict, Iterable, List, Tuple

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "python"))

from bandit.action_set import ActionSet  # noqa: E402
from bandit.run_lints_ge_schedule import _ge_to_tc_gemodel_loss_mode, _load_senders  # noqa: E402
import fecenv_env  # noqa: E402


HELPER = "/usr/local/libexec/quicfec-net-helper"
DEFAULT_WORKERS = 121
DEFAULT_REPEATS = 20
DEFAULT_TIMEOUT_SEC = 2
DEFAULT_TRAIN_BYTES = 102400


def atomic_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, allow_nan=False))
    os.replace(tmp, path)


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def setup_runner_class():
    class SetupRunner(fecenv_env.QuicFecRunner):
        """Serialize privileged setup while keeping trial execution parallel."""

        def configure_network(self, **kwargs):
            lock_path = os.environ["ORACLE_SETUP_LOCK"]
            with Path(lock_path).open("a") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                previous = self.timeout_sec
                self.timeout_sec = 60
                try:
                    return super().configure_network(**kwargs)
                finally:
                    self.timeout_sec = previous

    return SetupRunner


def connect_db(path: Path) -> sqlite3.Connection:
    db = sqlite3.connect(path, timeout=60)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=NORMAL")
    db.execute(
        """CREATE TABLE IF NOT EXISTS trials (
            sender INTEGER NOT NULL,
            action INTEGER NOT NULL,
            repeat INTEGER NOT NULL,
            reward REAL NOT NULL,
            success INTEGER NOT NULL,
            is_timeout INTEGER NOT NULL,
            md5_ok INTEGER NOT NULL,
            duration_ms REAL NOT NULL,
            goodput_mbps REAL NOT NULL,
            overhead REAL NOT NULL,
            wall_seconds REAL NOT NULL,
            timestamp REAL NOT NULL,
            PRIMARY KEY(sender, action, repeat)
        )"""
    )
    db.commit()
    return db


def action_values(actions: ActionSet, aid: int) -> Dict[str, int]:
    a = actions.get_action(int(aid))
    return {
        "K": int(actions.k_values[a.k_idx]),
        "R0": int(actions.r0_values[a.r0_idx]),
        "RSTEP": int(actions.rstep_values[a.rstep_idx]),
    }


def summarize_rows(rows: Iterable[Tuple[Any, ...]], actions: ActionSet, worker_id: int | None = None):
    out = []
    for sender, aid, n, mean, square, success, duration, goodput, overhead in rows:
        mean = float(mean)
        n = int(n)
        std = math.sqrt(max(0.0, float(square) - mean * mean) * n / (n - 1)) if n > 1 else None
        rec = {
            "worker_id": worker_id,
            "sender_id": int(sender),
            "a_idx": int(aid),
            **action_values(actions, int(aid)),
            "n": n,
            "mean_reward": mean,
            "reward_std": std,
            "success_rate": float(success),
            "mean_duration_ms": float(duration),
            "mean_goodput_mbps": float(goodput),
            "mean_overhead": float(overhead),
        }
        out.append(rec)
    return out


def export_worker_summary(db: sqlite3.Connection, dest: Path, actions: ActionSet, worker_id: int) -> int:
    rows = db.execute(
        """SELECT sender, action, COUNT(*), AVG(reward), AVG(reward*reward),
                  AVG(success), AVG(duration_ms), AVG(goodput_mbps), AVG(overhead)
             FROM trials GROUP BY sender, action ORDER BY sender, action"""
    ).fetchall()
    records = summarize_rows(rows, actions, worker_id)
    path = dest / "action_summary.csv"
    tmp = path.with_suffix(path.suffix + ".tmp")
    fields = [
        "worker_id", "sender_id", "a_idx", "K", "R0", "RSTEP", "n",
        "mean_reward", "reward_std", "success_rate", "mean_duration_ms",
        "mean_goodput_mbps", "mean_overhead",
    ]
    with tmp.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(records)
    os.replace(tmp, path)
    return int(sum(int(r[2]) for r in rows)) if rows else 0


def worker_progress(
    dest: Path,
    *,
    worker_id: int,
    action_ids: List[int],
    completed: int,
    total: int,
    started: float,
    current: Dict[str, Any] | None = None,
    state: str = "running",
    error: str | None = None,
) -> None:
    elapsed = max(1e-9, time.monotonic() - started)
    rate = float(completed) / elapsed
    payload = {
        "worker_id": int(worker_id),
        "state": state,
        "action_ids": action_ids,
        "completed_trials": int(completed),
        "total_trials": int(total),
        "rate_trials_per_sec": rate,
        "elapsed_sec": elapsed,
        "current": current or {},
        "error": error,
        "updated_unix": time.time(),
    }
    atomic_json(dest / "progress.json", payload)


def worker(args: argparse.Namespace) -> int:
    root = args.result_dir.resolve()
    manifest = json.loads((root / "manifest.json").read_text())
    worker_id = int(args.worker_id)
    groups = manifest["action_groups"]
    action_ids = [int(x) for x in groups[str(worker_id)]]
    net = manifest["networks"][str(worker_id)]
    dest = root / f"worker_{worker_id:03d}"
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "tmp").mkdir(exist_ok=True)
    (dest / "received").mkdir(exist_ok=True)

    obs_path = dest / "current_observation.json"
    controls = {
        "QUIC_FEC_PRIV_HELPER": HELPER,
        "QUICFEC_NS": net["namespace"],
        "QUICFEC_VETH_HOST": net["veth_host"],
        "QUICFEC_VETH_NS": net["veth_ns"],
        "QUICFEC_HOST_IP": net["host_ip"],
        "QUICFEC_NS_IP": net["ns_ip"],
        "QUICFEC_OUT_DIR": str(dest / "received"),
        "QUICFEC_OBS_JSON": str(obs_path),
        "QUICFEC_RESULT_DIR": str(dest),
        "QUICFEC_ISOLATE_KEY": net["namespace"],
        "TMPDIR": str(dest / "tmp"),
        "ORACLE_SETUP_LOCK": str(root / "setup.lock"),
        "TUNE_UDP_BUFFERS": "0",
        "TIMEOUT_S": str(manifest["timeout_sec"]),
        "SRV_TIMEOUT": f"{manifest['timeout_sec']}s",
        "CLI_TIMEOUT": f"{manifest['timeout_sec']}s",
        "CONNECT_TIMEOUT_S": str(manifest["timeout_sec"]),
        "CONNECT_RETRIES": "1",
        "OBS_WAIT_SECS": str(manifest["timeout_sec"]),
        "TRANSPORT": "dgram",
        "USE_ARQ": "1",
        "W": "8",
        "MAX_ATTEMPTS": "0",
        "DECODE_DDL_MS": "25",
        "POST_WAIT": "0ms",
        "SKIP_MD5": "0",
        "FEC_STATS": "1",
        "BG": "0",
        "FORCE_BUILD": "0",
        "QUIC_FEC_ARQ_DRAIN_CAP_MS": str(manifest["timeout_sec"] * 1000),
    }
    os.environ.update(controls)

    db = connect_db(dest / "trials.sqlite3")
    actions = ActionSet()
    senders = [(int(scene["sender_id"]), scene) for scene in manifest["scenes"]]
    expected = len(action_ids) * len(senders) * int(manifest["repeats"])
    existing = int(db.execute("SELECT COUNT(*) FROM trials").fetchone()[0])
    started = time.monotonic()
    SetupRunner = setup_runner_class()
    fecenv_env.QuicFecRunner = SetupRunner
    env = None

    def stop(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    worker_progress(dest, worker_id=worker_id, action_ids=action_ids, completed=existing,
                    total=expected, started=started, state="starting")

    try:
        env = fecenv_env.FecEnv(manifest["env_cfg"])
        done = {(int(s), int(a), int(r)) for s, a, r in db.execute("SELECT sender, action, repeat FROM trials")}
        pending_since_commit = 0
        rng_base = int(manifest["seed"]) + worker_id * 1000003

        for action_pos, aid in enumerate(action_ids):
            # Different workers/actions use deterministic but different scene orders,
            # avoiding a synchronized qdisc reconfiguration wave at every scene.
            scene_order = list(senders)
            import random
            random.Random(rng_base + int(aid)).shuffle(scene_order)
            for scene_pos, (sid, scene) in enumerate(scene_order):
                pending_reps = [r for r in range(int(manifest["repeats"])) if (sid, aid, r) not in done]
                if not pending_reps:
                    continue

                loss = _ge_to_tc_gemodel_loss_mode(scene["GE_steady_rp"], h_loss_pct=0, k_loss_pct=99)
                # Setup is allowed 60 seconds; individual transfers use the 2s
                # experiment timeout after the episode network is ready.
                env._runner.timeout_sec = 60
                env.reset(options=dict(
                    rtt_ms=int(scene.get("rtt_ms", 50)),
                    loss_mode=loss,
                    loss_pct=0,
                    bitrate_mbps=int(manifest["env_cfg"]["bitrate_mbps"]),
                ))
                env._runner.timeout_sec = int(manifest["timeout_sec"])

                for rep in pending_reps:
                    obs_path.write_text("")
                    tick = time.monotonic()
                    _, reward, _, _, info = env.step(actions.get_action(aid).to_env_action())
                    error = str(info.get("error") or "")
                    if error and not error.lower().startswith("timeout"):
                        raise RuntimeError(f"infrastructure error worker={worker_id} sender={sid} action={aid} repeat={rep}: {info}")

                    is_timeout = int(bool(info.get("is_timeout")) or error.lower().startswith("timeout"))
                    md5_ok = int(info.get("md5_ok", 0))
                    success = int(bool(md5_ok) and not is_timeout)
                    db.execute(
                        "INSERT OR REPLACE INTO trials VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            sid, aid, rep, float(reward), success, is_timeout, md5_ok,
                            float(info.get("dur_ms", 0.0)), float(info.get("goodput_mbps", 0.0)),
                            float(info.get("quic_overhead_ratio", 0.0)),
                            time.monotonic() - tick, time.time(),
                        ),
                    )
                    done.add((sid, aid, rep))
                    pending_since_commit += 1
                    if pending_since_commit >= 25:
                        db.commit()
                        pending_since_commit = 0
                    completed = len(done)
                    if completed % 25 == 0 or completed == expected:
                        worker_progress(
                            dest, worker_id=worker_id, action_ids=action_ids,
                            completed=completed, total=expected, started=started,
                            current={"action": aid, "action_pos": action_pos,
                                     "sender": sid, "scene_pos": scene_pos, "repeat": rep},
                        )
                        print(
                            f"worker={worker_id:03d} completed={completed}/{expected} "
                            f"action={aid} sender={sid} repeat={rep}", flush=True
                        )

        db.commit()
        export_worker_summary(db, dest, actions, worker_id)
        worker_progress(dest, worker_id=worker_id, action_ids=action_ids,
                        completed=expected, total=expected, started=started, state="complete")
        print(f"COMPLETE worker={worker_id:03d} trials={expected}", flush=True)
        return 0
    except KeyboardInterrupt:
        db.commit()
        export_worker_summary(db, dest, actions, worker_id)
        worker_progress(dest, worker_id=worker_id, action_ids=action_ids,
                        completed=int(db.execute("SELECT COUNT(*) FROM trials").fetchone()[0]),
                        total=expected, started=started, state="stopped")
        raise
    except Exception as exc:
        db.commit()
        export_worker_summary(db, dest, actions, worker_id)
        worker_progress(dest, worker_id=worker_id, action_ids=action_ids,
                        completed=int(db.execute("SELECT COUNT(*) FROM trials").fetchone()[0]),
                        total=expected, started=started, state="failed",
                        error=f"{type(exc).__name__}: {exc}")
        (dest / "error.log").write_text(traceback.format_exc())
        print(f"FAILED worker={worker_id:03d}: {exc}", file=sys.stderr, flush=True)
        raise
    finally:
        try:
            if env is not None and hasattr(env, "close"):
                env.close()
        except Exception:
            pass
        db.close()
        subprocess.run(
            ["sudo", "-n", HELPER, "cleanup", net["namespace"], net["veth_host"]],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30,
        )


def build_manifest(args: argparse.Namespace) -> Dict[str, Any]:
    actions = ActionSet()
    senders = _load_senders(str(args.ge_params))
    if len(actions) != int(args.workers) * int(args.actions_per_worker):
        raise ValueError(
            f"exact partition required: actions={len(actions)} != workers*actions_per_worker="
            f"{args.workers}*{args.actions_per_worker}"
        )
    meta = json.loads(args.training_meta.read_text())
    for key in ("k_values", "r0_values", "rstep_values"):
        if meta["action_set"][key] != getattr(actions, key):
            raise ValueError(f"training/current action space mismatch: {key}")

    cfg = dict(meta["extra"]["env_cfg"])
    cfg.update(
        timeout_sec=60,
        train_file_bytes=DEFAULT_TRAIN_BYTES,
        episode_step=1,
        normalize_obs=False,
        randomize_net_params=False,
    )
    token = hashlib.sha256(str(args.result_dir.resolve()).encode()).hexdigest()[:6]
    networks = {}
    for wid in range(int(args.workers)):
        networks[str(wid)] = {
            "namespace": f"qa{token}w{wid:03d}",
            "veth_host": f"qah{token}w{wid:03d}"[:15],
            "veth_ns": f"qan{token}w{wid:03d}"[:15],
            "host_ip": f"10.231.{wid + 1}.1/24",
            "ns_ip": f"10.231.{wid + 1}.2/24",
        }
    action_groups = {
        str(wid): list(range(wid * int(args.actions_per_worker), (wid + 1) * int(args.actions_per_worker)))
        for wid in range(int(args.workers))
    }
    sources = [
        Path(__file__).resolve(), ROOT / "python/fecenv_env.py",
        ROOT / "python/bandit/action_set.py", ROOT / "python/bandit/run_lints_ge_schedule.py",
        ROOT / "scripts/quicfec_run_once.sh", args.ge_params, args.training_meta,
    ]
    sources += sorted((ROOT / "go").rglob("*.go"))
    source_hash = hashlib.sha256(b"".join(file_sha256(p).encode() for p in sources)).hexdigest()
    scenes = []
    for sid, scene in senders:
        scenes.append({
            "sender_id": int(sid),
            "rtt_ms": int(scene.get("rtt_ms", 50)),
            "GE_steady_rp": scene["GE_steady_rp"],
            "loss_mode": _ge_to_tc_gemodel_loss_mode(scene["GE_steady_rp"], h_loss_pct=0, k_loss_pct=99),
        })
    total = len(actions) * len(scenes) * int(args.repeats)
    return {
        "experiment": "ge_action_oracle",
        "git_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "source_sha256": source_hash,
        "ge_sha256": file_sha256(args.ge_params),
        "training_meta_sha256": file_sha256(args.training_meta),
        "workers": int(args.workers),
        "actions_per_worker": int(args.actions_per_worker),
        "actions": len(actions),
        "scenes": scenes,
        "repeats": int(args.repeats),
        "timeout_sec": int(args.timeout_sec),
        "total_trials": total,
        "seed": int(args.seed),
        "env_cfg": cfg,
        "action_groups": action_groups,
        "networks": networks,
        "objective": "maximum mean training reward over 20 repetitions for each GE scene",
    }


def collect_status(root: Path, manifest: Dict[str, Any], started: float, baseline: int) -> Dict[str, Any]:
    workers = []
    completed = 0
    completed_workers = 0
    failed = []
    for wid in range(int(manifest["workers"])):
        path = root / f"worker_{wid:03d}" / "progress.json"
        if not path.exists():
            workers.append({"worker_id": wid, "state": "not_started", "completed_trials": 0,
                            "total_trials": len(manifest["action_groups"][str(wid)]) * len(manifest["scenes"]) * manifest["repeats"]})
            continue
        try:
            p = json.loads(path.read_text())
        except Exception:
            p = {"worker_id": wid, "state": "unreadable", "completed_trials": 0}
        workers.append(p)
        completed += int(p.get("completed_trials", 0))
        if p.get("state") == "complete":
            completed_workers += 1
        if p.get("state") == "failed":
            failed.append(wid)
    elapsed = max(1e-9, time.monotonic() - started)
    rate = max(0.0, float(completed - baseline) / elapsed)
    eta = (int(manifest["total_trials"]) - completed) / rate / 3600 if rate > 0 else None
    payload = {
        "completed_trials": completed,
        "total_trials": int(manifest["total_trials"]),
        "progress": completed / int(manifest["total_trials"]),
        "active_workers": sum(1 for p in workers if p.get("state") in {"starting", "running"}),
        "completed_workers": completed_workers,
        "failed_workers": failed,
        "trials_per_sec_since_start": rate,
        "eta_hours_since_start": eta,
        "updated_unix": time.time(),
        "workers": workers,
    }
    atomic_json(root / "status.json", payload)
    return payload


def export_global(root: Path, manifest: Dict[str, Any]) -> None:
    actions = ActionSet()
    aggregate: Dict[Tuple[int, int], List[float]] = {}
    stats: Dict[Tuple[int, int], List[float]] = {}
    all_records: List[Dict[str, Any]] = []
    for wid in range(int(manifest["workers"])):
        db_path = root / f"worker_{wid:03d}" / "trials.sqlite3"
        if not db_path.exists():
            continue
        db = sqlite3.connect(db_path)
        rows = db.execute(
            """SELECT sender, action, COUNT(*), AVG(reward), AVG(reward*reward),
                      AVG(success), AVG(duration_ms), AVG(goodput_mbps), AVG(overhead)
                 FROM trials GROUP BY sender, action ORDER BY sender, action"""
        ).fetchall()
        for rec in summarize_rows(rows, actions, wid):
            all_records.append(rec)
        db.close()

    fields = [
        "worker_id", "sender_id", "a_idx", "K", "R0", "RSTEP", "n",
        "mean_reward", "reward_std", "success_rate", "mean_duration_ms",
        "mean_goodput_mbps", "mean_overhead",
    ]
    tmp = root / "action_summary.csv.tmp"
    with tmp.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(sorted(all_records, key=lambda r: (r["sender_id"], r["a_idx"])))
    os.replace(tmp, root / "action_summary.csv")

    scenes: Dict[str, Dict[str, Any]] = {}
    for sid in [int(x["sender_id"]) for x in manifest["scenes"]]:
        candidates = [r for r in all_records if r["sender_id"] == sid and r["n"] == int(manifest["repeats"])]
        candidates.sort(key=lambda r: (-float(r["mean_reward"]), int(r["a_idx"])))
        best = candidates[0] if candidates else None
        scenes[str(sid)] = {
            "complete": len(candidates) == int(manifest["actions"]),
            "evaluated_actions": len(candidates),
            "total_actions": int(manifest["actions"]),
            "best_so_far": best,
            "oracle": best if len(candidates) == int(manifest["actions"]) else None,
        }
    completed = sum(1 for r in all_records for _ in range(1) if r["n"] == int(manifest["repeats"]))
    payload = {
        "objective": manifest["objective"],
        "interpretation": "empirical offline best; every action is evaluated 20 times",
        "completed_trials": sum(int(r["n"]) for r in all_records),
        "total_trials": int(manifest["total_trials"]),
        "completed_scenes": sum(1 for v in scenes.values() if v["complete"]),
        "scenes": scenes,
    }
    atomic_json(root / "oracle.json", payload)


def coordinator(args: argparse.Namespace) -> int:
    root = args.result_dir.resolve()
    root.mkdir(parents=True, exist_ok=True)
    lock = (root / "run.lock").open("a")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)

    manifest = build_manifest(args)
    mp = root / "manifest.json"
    if mp.exists():
        existing = json.loads(mp.read_text())
        if existing != manifest:
            raise ValueError("existing manifest differs; use a new result directory")
    else:
        routes = subprocess.check_output(["ip", "-4", "route", "show"], text=True)
        if "10.231." in routes:
            raise RuntimeError("10.231 worker subnet range already in use")
        atomic_json(mp, manifest)

    subprocess.run(["sudo", "-n", HELPER, "self-test"], check=True)
    subprocess.run(["sudo", "-n", HELPER, "buffers"], check=True)
    (root / "setup.lock").touch()

    total = int(manifest["total_trials"])
    baseline = 0
    for wid in range(int(manifest["workers"])):
        p = root / f"worker_{wid:03d}" / "progress.json"
        if p.exists():
            try:
                baseline += int(json.loads(p.read_text()).get("completed_trials", 0))
            except Exception:
                pass
    processes: Dict[int, Tuple[subprocess.Popen, Any]] = {}
    attempts = {wid: 0 for wid in range(int(manifest["workers"]))}
    failed: List[int] = []
    started = time.monotonic()

    def spawn(wid: int) -> None:
        dest = root / f"worker_{wid:03d}"
        dest.mkdir(exist_ok=True)
        log = (dest / "run.log").open("a")
        env = dict(os.environ, OMP_NUM_THREADS="1", OPENBLAS_NUM_THREADS="1",
                   MKL_NUM_THREADS="1", NUMEXPR_NUM_THREADS="1", GOMAXPROCS="1")
        cmd = [sys.executable, "-u", str(Path(__file__).resolve()),
               "--result-dir", str(root), "--worker-id", str(wid)]
        proc = subprocess.Popen(cmd, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
        processes[wid] = (proc, log)

    print(
        f"START action-oracle workers={manifest['workers']} actions={manifest['actions']} "
        f"actions_per_worker={manifest['actions_per_worker']} scenes={len(manifest['scenes'])} "
        f"repeats={manifest['repeats']} total_trials={total}", flush=True
    )
    for wid in range(int(manifest["workers"])):
        spawn(wid)
    try:
        while processes:
            for wid, (proc, log) in list(processes.items()):
                code = proc.poll()
                if code is None:
                    continue
                log.close()
                del processes[wid]
                if code == 0:
                    print(f"EXIT worker={wid:03d} code=0", flush=True)
                elif attempts[wid] < 3:
                    attempts[wid] += 1
                    print(f"RESTART worker={wid:03d} code={code} attempt={attempts[wid]}", flush=True)
                    time.sleep(2)
                    spawn(wid)
                else:
                    failed.append(wid)
                    print(f"FAILED permanently worker={wid:03d} code={code}", flush=True)
            status = collect_status(root, manifest, started, baseline)
            print(
                f"progress={status['completed_trials']}/{total} "
                f"({100.0*status['progress']:.3f}%) active={status['active_workers']} "
                f"complete_workers={status['completed_workers']} "
                f"rate={status['trials_per_sec_since_start']:.3f}/s "
                f"eta_hours={status['eta_hours_since_start']}", flush=True
            )
            if status["completed_trials"] >= total and not processes:
                break
            if failed:
                raise RuntimeError(f"workers failed permanently: {failed}")
            time.sleep(15)
    except KeyboardInterrupt:
        print("STOP requested; terminating action workers", flush=True)
        raise
    finally:
        for proc, _ in processes.values():
            if proc.poll() is None:
                proc.terminate()
        deadline = time.monotonic() + 30
        for wid, (proc, log) in list(processes.items()):
            remaining = max(0.1, deadline - time.monotonic())
            try:
                proc.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            log.close()
        collect_status(root, manifest, started, baseline)

    export_global(root, manifest)
    status = collect_status(root, manifest, started, baseline)
    status["failed_workers"] = failed
    atomic_json(root / "status.json", status)
    if failed:
        raise RuntimeError(f"workers failed permanently: {failed}")
    print("COMPLETE: action-level GE oracle exported", flush=True)
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--result-dir", type=Path, required=True)
    p.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    p.add_argument("--actions-per-worker", type=int, default=21)
    p.add_argument("--repeats", type=int, default=DEFAULT_REPEATS)
    p.add_argument("--timeout-sec", type=int, default=DEFAULT_TIMEOUT_SEC)
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--ge-params", type=Path, default=ROOT / "python/bandit/quic_fec_params.json")
    p.add_argument("--training-meta", type=Path, default=ROOT / "python/results/ge-100kb-bandit-model-step500-100k/bandit_model.json")
    p.add_argument("--worker-id", type=int)
    args = p.parse_args()
    if min(args.workers, args.actions_per_worker, args.repeats, args.timeout_sec) < 1:
        p.error("workers, actions-per-worker, repeats, and timeout must be positive")
    if args.worker_id is not None:
        return worker(args)
    return coordinator(args)


if __name__ == "__main__":
    raise SystemExit(main())
