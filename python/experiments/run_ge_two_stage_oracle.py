"""Two-stage GE oracle with isolated process workers and resumable scene databases."""
from __future__ import annotations

import argparse
import csv
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import random
import signal
import sqlite3
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "python"))
from bandit.action_set import ActionSet
from bandit.run_lints_ge_schedule import _load_senders, _ge_to_tc_gemodel_loss_mode
import fecenv_env

HELPER = "/usr/local/libexec/quicfec-net-helper"


def atomic_json(path, data):
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, allow_nan=False))
    os.replace(tmp, path)


def connect(path):
    db = sqlite3.connect(path)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    db.execute("""CREATE TABLE IF NOT EXISTS trials (
        stage TEXT, action INTEGER, repeat INTEGER, reward REAL,
        success INTEGER, duration_ms REAL, goodput REAL, overhead REAL,
        wall_seconds REAL, timestamp REAL, details TEXT,
        PRIMARY KEY(stage,action,repeat))""")
    db.commit()
    return db


def ranked(db, stage, repeats):
    return db.execute("""SELECT action, COUNT(*), AVG(reward), AVG(reward*reward),
        AVG(success), AVG(duration_ms), AVG(goodput), AVG(overhead)
        FROM trials WHERE stage=? GROUP BY action HAVING COUNT(*)=?
        ORDER BY AVG(reward) DESC, action ASC""", (stage, repeats)).fetchall()


def describe(row, actions):
    aid, n, mean, sq, success, duration, goodput, overhead = row
    a = actions.get_action(aid)
    return dict(a_idx=aid, K=actions.k_values[a.k_idx], R0=actions.r0_values[a.r0_idx],
                RSTEP=actions.rstep_values[a.rstep_idx], n=n, mean_reward=mean,
                reward_std=math.sqrt(max(0, sq-mean*mean)*n/(n-1)) if n > 1 else None,
                success_rate=success, mean_duration_ms=duration,
                mean_goodput_mbps=goodput, mean_overhead=overhead)


def export_scene(db, dest, manifest, sid, actions):
    screening = ranked(db, "screen", manifest["screen_repeats"])
    final = ranked(db, "final", manifest["final_repeats"])
    stage1_done = len(screening) == manifest["actions"]
    top = [describe(r, actions) for r in screening[:manifest["top_k"]]] if stage1_done else []
    complete = stage1_done and len(final) == manifest["top_k"]
    n, wall = db.execute("SELECT COUNT(*), COALESCE(SUM(wall_seconds),0) FROM trials").fetchone()
    result = dict(sender_id=sid, complete=complete, completed_trials=n,
                  planned_trials=manifest["trials_per_scene"], trial_wall_seconds=wall,
                  screening_complete=stage1_done, screened_actions=len(screening),
                  finalists_complete=len(final), shortlist=top,
                  best_so_far=describe(final[0], actions) if final else None,
                  oracle=describe(final[0], actions) if complete else None)
    atomic_json(dest / "oracle.json", result)
    rows = db.execute("""SELECT stage, action, COUNT(*), AVG(reward), AVG(reward*reward),
        AVG(success), AVG(duration_ms), AVG(goodput), AVG(overhead)
        FROM trials GROUP BY stage,action ORDER BY stage, action""").fetchall()
    with (dest / "action_summary.csv.tmp").open("w", newline="") as f:
        writer = None
        for stage, *row in rows:
            record = dict(sender_id=sid, stage=stage, **describe(row, actions))
            if writer is None:
                writer = csv.DictWriter(f, fieldnames=list(record))
                writer.writeheader()
            writer.writerow(record)
    os.replace(dest / "action_summary.csv.tmp", dest / "action_summary.csv")
    return result


class SetupRunner(fecenv_env.QuicFecRunner):
    """Serialize shared binary checks/setup; retain a 60s setup allowance."""
    def configure_network(self, **kwargs):
        with Path(os.environ["ORACLE_SETUP_LOCK"]).open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            previous = self.timeout_sec
            self.timeout_sec = 60
            try:
                return super().configure_network(**kwargs)
            finally:
                self.timeout_sec = previous


def worker(args):
    def stop(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop)
    root = args.result_dir.resolve()
    manifest = json.loads((root / "manifest.json").read_text())
    sid = args.sender_id
    dest = root / f"sender_{sid}"
    dest.mkdir(exist_ok=True)
    (dest / "tmp").mkdir(exist_ok=True)
    net = manifest["networks"][args.slot]
    obs_path = dest / "current_observation.json"
    timeout = manifest["timeout_sec"]
    controls = dict(QUIC_FEC_PRIV_HELPER=HELPER, QUICFEC_NS=net["namespace"],
                    QUICFEC_VETH_HOST=net["veth_host"], QUICFEC_VETH_NS=net["veth_ns"],
                    QUICFEC_HOST_IP=net["host_ip"], QUICFEC_NS_IP=net["ns_ip"],
                    QUICFEC_OUT_DIR=str(dest / "received"), QUICFEC_OBS_JSON=str(obs_path),
                    QUICFEC_RESULT_DIR=str(dest),
                    QUICFEC_ISOLATE_KEY=net["namespace"], TMPDIR=str(dest / "tmp"),
                    ORACLE_SETUP_LOCK=str(root / "setup.lock"), TUNE_UDP_BUFFERS="0",
                    TIMEOUT_S=str(timeout), SRV_TIMEOUT=f"{timeout}s", CLI_TIMEOUT=f"{timeout}s",
                    CONNECT_TIMEOUT_S=str(timeout), CONNECT_RETRIES="1", OBS_WAIT_SECS=str(timeout),
                    TRANSPORT="dgram", USE_ARQ="1", W="8", MAX_ATTEMPTS="0", DECODE_DDL_MS="25",
                    POST_WAIT="0ms", SKIP_MD5="0", FEC_STATS="1", BG="0", FORCE_BUILD="0",
                    QUIC_FEC_ARQ_DRAIN_CAP_MS=str(timeout*1000))
    os.environ.update(controls)
    (dest / "received").mkdir(exist_ok=True)
    lock = (dest / "run.lock").open("a")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    scene = manifest["scenes"][str(sid)]
    actions = ActionSet()
    db = connect(dest / "trials.sqlite3")
    atomic_json(dest / "network.json", dict(slot=args.slot, **net, controls=controls))
    fecenv_env.QuicFecRunner = SetupRunner
    env = fecenv_env.FecEnv(manifest["env_cfg"])
    options = dict(rtt_ms=scene["rtt_ms"], loss_mode=scene["loss_mode"], loss_pct=0,
                   bitrate_mbps=manifest["env_cfg"]["bitrate_mbps"])
    added = 0
    try:
        env.reset(options=options)
        for stage, repeats in (("screen", manifest["screen_repeats"]), ("final", manifest["final_repeats"])):
            if stage == "screen":
                order = list(range(manifest["actions"]))
            else:
                ranked_screen = ranked(db, "screen", manifest["screen_repeats"])
                if len(ranked_screen) != manifest["actions"]:
                    raise RuntimeError("screening incomplete")
                order = [r[0] for r in ranked_screen[:manifest["top_k"]]]
                atomic_json(dest / "shortlist.json", [describe(r, actions) for r in ranked_screen[:manifest["top_k"]]])
                # Fresh network state for the independent finalist evaluation.
                env._runner._net_cfg_key = None
                env.reset(options=options)
            rng = random.Random(manifest["seed"] + sid + (100000 if stage == "final" else 0))
            done = set(db.execute("SELECT action, repeat FROM trials WHERE stage=?", (stage,)))
            # A shuffled sweep per repetition distributes each action's trials in time.
            for rep in range(repeats):
                rng.shuffle(order)
                for aid in order:
                    if (aid, rep) in done:
                        continue
                    obs_path.write_text("")
                    tick = time.monotonic()
                    _, reward, _, _, info = env.step(actions.get_action(aid).to_env_action())
                    error = str(info.get("error") or "")
                    if not info.get("step_valid") or (error and not error.lower().startswith("timeout")):
                        raise RuntimeError(f"infrastructure error {sid}/{stage}/{aid}/{rep}: {info}")
                    logs = sorted((dest / "tmp").glob("quic_fec_*.log"))
                    detail = dict(info=info, raw_observation=obs_path.read_text(),
                                  harness_logs={x.name: x.read_text(errors="replace") for x in logs})
                    db.execute("INSERT INTO trials VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                               (stage, aid, rep, float(reward), int(bool(info["md5_ok"]) and not info["is_timeout"]), float(info["dur_ms"]),
                                float(info["goodput_mbps"]), float(info["quic_overhead_ratio"]),
                                time.monotonic()-tick, time.time(), json.dumps(detail)))
                    db.commit()
                    for log in logs:
                        log.unlink(missing_ok=True)
                    added += 1
                    if added % 25 == 0:
                        print(f"sender={sid} stage={stage} new_trials={added} repeat={rep}", flush=True)
                        export_scene(db, dest, manifest, sid, actions)
            export_scene(db, dest, manifest, sid, actions)
        print(f"COMPLETE sender={sid}", flush=True)
    finally:
        export_scene(db, dest, manifest, sid, actions)
        db.close()
        subprocess.run(["sudo", "-n", HELPER, "cleanup", net["namespace"], net["veth_host"]], timeout=30)


def collect(root, manifest, active, start, baseline, failed):
    scenes = {}
    for sid in manifest["scenes"]:
        path = root / f"sender_{sid}" / "oracle.json"
        if path.exists():
            scenes[sid] = json.loads(path.read_text())
    n = sum(s["completed_trials"] for s in scenes.values())
    elapsed = time.monotonic()-start
    rate = (n-baseline)/elapsed if elapsed else 0
    result = dict(completed_trials=n, total_trials=manifest["total_trials"],
                  completed_scenes=sum(s["complete"] for s in scenes.values()),
                  active_senders=[v[0] for v in active.values()], failed_senders=failed,
                  trials_per_second=rate, eta_hours=(manifest["total_trials"]-n)/rate/3600 if rate > 0 else None,
                  scenes=scenes)
    atomic_json(root / "oracle.json", result)
    with (root / "action_summary.csv.tmp").open("w", newline="") as out:
        header = False
        for sid in scenes:
            path = root / f"sender_{sid}" / "action_summary.csv"
            if not path.exists():
                continue
            with path.open() as src:
                first = src.readline()
                if not first:
                    continue
                if not header:
                    out.write(first)
                    header = True
                for line in src:
                    out.write(line)
    os.replace(root / "action_summary.csv.tmp", root / "action_summary.csv")
    print(f"progress={n}/{manifest['total_trials']} active={len(active)} completed_scenes={result['completed_scenes']} rate={rate:.3f}/s eta_hours={result['eta_hours']}", flush=True)


def coordinator(args):
    root = args.result_dir.resolve()
    root.mkdir(parents=True, exist_ok=True)
    lock = (root / "run.lock").open("a")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    actions = ActionSet()
    n_actions = args.action_limit or len(actions)
    if not 1 <= args.top_k <= n_actions <= len(actions):
        raise ValueError("invalid action limit/top-k")
    senders = _load_senders(str(ROOT / "python/bandit/quic_fec_params.json"))
    if args.scene_limit:
        senders = senders[:args.scene_limit]
    meta = json.loads((ROOT / "python/results/ge-100kb-bandit-model-step500-100k/bandit_model.json").read_text())
    for key in ("k_values", "r0_values", "rstep_values"):
        if meta["action_set"][key] != getattr(actions, key):
            raise ValueError(f"action space mismatch: {key}")
    cfg = dict(meta["extra"]["env_cfg"])
    cfg.update(timeout_sec=args.timeout_sec, train_file_bytes=102400, normalize_obs=False,
               randomize_net_params=False, episode_step=1000000)
    available_kb = int(next(line.split()[1] for line in Path("/proc/meminfo").read_text().splitlines() if line.startswith("MemAvailable:")))
    workers = min(args.workers, len(senders), os.cpu_count() or 1, max(1, (available_kb-2*1024**2)//(600*1024)))
    token = hashlib.sha256(str(root).encode()).hexdigest()[:6]
    networks = [dict(namespace=f"qo{token}w{i}", veth_host=f"qh{token}w{i}", veth_ns=f"qn{token}w{i}",
                     host_ip=f"10.231.{i+1}.1/24", ns_ip=f"10.231.{i+1}.2/24") for i in range(workers)]
    sources = [Path(__file__), ROOT / "python/fecenv_env.py", ROOT / "python/bandit/action_set.py",
               ROOT / "scripts/quicfec_run_once.sh", ROOT / "python/bandit/quic_fec_params.json"]
    sources += sorted((ROOT / "go").rglob("*.go"))
    per_scene = n_actions*args.screen_repeats + args.top_k*args.final_repeats
    manifest = dict(workers=workers, requested_workers=args.workers, actions=n_actions, screen_repeats=args.screen_repeats,
                    top_k=args.top_k, final_repeats=args.final_repeats, timeout_sec=args.timeout_sec,
                    trials_per_scene=per_scene, total_trials=len(senders)*per_scene, seed=args.seed,
                    env_cfg=cfg, networks=networks, objective="mean training reward, final stage only; ties smallest a_idx",
                    source_sha256=hashlib.sha256(b"".join(p.read_bytes() for p in sources)).hexdigest(),
                    git_commit=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                    scenes={str(sid): dict(rtt_ms=int(s.get("rtt_ms",50)), GE_steady_rp=s["GE_steady_rp"],
                            loss_mode=_ge_to_tc_gemodel_loss_mode(s["GE_steady_rp"], h_loss_pct=0,k_loss_pct=99)) for sid,s in senders})
    mp = root / "manifest.json"
    if mp.exists():
        existing = json.loads(mp.read_text())
        # Memory availability can change between starts; keep the saved slot map.
        manifest["workers"] = existing["workers"]
        manifest["networks"] = existing["networks"]
        workers = existing["workers"]
        if existing != manifest:
            raise ValueError("code/config changed; use a new directory")
    else:
        routes = subprocess.check_output(["ip", "-4", "route", "show"], text=True)
        if "10.231." in routes:
            raise RuntimeError("10.231 worker subnet range already in use")
        atomic_json(mp, manifest)
    subprocess.run(["sudo", "-n", HELPER, "self-test"], check=True)
    subprocess.run(["sudo", "-n", HELPER, "buffers"], check=True)
    queue = []
    baseline = 0
    for sid, _ in senders:
        path = root / f"sender_{sid}" / "oracle.json"
        state = json.loads(path.read_text()) if path.exists() else {}
        baseline += state.get("completed_trials", 0)
        if not state.get("complete"):
            queue.append(sid)
    active = {}
    failed = []
    start = time.monotonic()
    print(f"START workers={workers} scenes={len(senders)} total_trials={manifest['total_trials']}", flush=True)
    def stop(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop)
    try:
        while queue or active:
            for slot in range(workers):
                if slot in active or not queue:
                    continue
                sid = queue.pop(0)
                dest = root / f"sender_{sid}"
                dest.mkdir(exist_ok=True)
                log = (dest / "run.log").open("a")
                env = dict(os.environ, OMP_NUM_THREADS="1", OPENBLAS_NUM_THREADS="1", MKL_NUM_THREADS="1",
                           NUMEXPR_NUM_THREADS="1", GOMAXPROCS="1")
                cmd = [sys.executable, "-u", str(Path(__file__).resolve()), "--result-dir", str(root),
                       "--sender-id", str(sid), "--slot", str(slot)]
                proc = subprocess.Popen(cmd, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
                active[slot] = (sid, proc, log)
            for slot, (sid, proc, log) in list(active.items()):
                code = proc.poll()
                if code is not None:
                    log.close()
                    del active[slot]
                    print(f"EXIT sender={sid} code={code}", flush=True)
                    if code:
                        failed.append(sid)
            collect(root, manifest, active, start, baseline, failed)
            if active:
                time.sleep(15)
    finally:
        for sid, proc, log in active.values():
            if proc.poll() is None:
                proc.terminate()
        for sid, proc, log in active.values():
            try:
                proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            log.close()
        collect(root, manifest, {}, start, baseline, failed)
    if failed:
        raise RuntimeError(f"failed senders: {failed}; inspect per-sender run.log and resume")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--result-dir", type=Path, required=True)
    p.add_argument("--workers", type=int, default=21)
    p.add_argument("--screen-repeats", type=int, default=5)
    p.add_argument("--top-k", type=int, default=20)
    p.add_argument("--final-repeats", type=int, default=20)
    p.add_argument("--timeout-sec", type=int, default=2)
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--action-limit", type=int, default=0, help="smoke test only")
    p.add_argument("--scene-limit", type=int, default=0, help="smoke test only")
    p.add_argument("--sender-id", type=int)
    p.add_argument("--slot", type=int, default=0)
    args = p.parse_args()
    if min(args.workers,args.screen_repeats,args.top_k,args.final_repeats,args.timeout_sec) < 1:
        p.error("counts and timeout must be positive")
    worker(args) if args.sender_id is not None else coordinator(args)


if __name__ == "__main__":
    main()
