"""Exhaustive, resumable GE action sweep using the training reward implementation."""
from __future__ import annotations

import argparse
import csv
import fcntl
import hashlib
import json
import os
from pathlib import Path
import random
import sqlite3
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "python"))
from bandit.action_set import ActionSet
from bandit.run_lints_ge_schedule import _load_senders, _ge_to_tc_gemodel_loss_mode
from fecenv_env import FecEnv


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def export_results(db, dest, actions, senders, repeats):
    rows = db.execute("""SELECT sender, action, COUNT(*), AVG(reward),
        AVG(reward*reward), AVG(success), AVG(duration_ms), AVG(goodput), AVG(overhead)
        FROM trials GROUP BY sender, action ORDER BY sender, action""").fetchall()
    best = {}
    counts = {}
    with (dest / "action_summary.csv.tmp").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["sender_id", "a_idx", "K", "R0", "RSTEP", "n", "mean_reward",
                    "reward_std", "success_rate", "mean_duration_ms", "mean_goodput_mbps", "mean_overhead"])
        for sid, aid, n, mean, square, success, duration, goodput, overhead in rows:
            a = actions.get_action(aid)
            cfg = dict(K=actions.k_values[a.k_idx], R0=actions.r0_values[a.r0_idx],
                       RSTEP=actions.rstep_values[a.rstep_idx])
            std = (max(0, square-mean*mean)*n/(n-1))**0.5 if n > 1 else None
            w.writerow([sid, aid, *cfg.values(), n, mean, std, success, duration, goodput, overhead])
            if n == repeats:
                counts[sid] = counts.get(sid, 0) + 1
                if sid not in best or mean > best[sid]["mean_reward"]:
                    best[sid] = dict(a_idx=aid, **cfg, n=n, mean_reward=mean,
                                     reward_std=std, success_rate=success,
                                     mean_duration_ms=duration, mean_goodput_mbps=goodput)
    os.replace(dest / "action_summary.csv.tmp", dest / "action_summary.csv")
    result = {str(sid): dict(complete=counts.get(sid, 0) == len(actions),
                            evaluated_actions=counts.get(sid, 0), total_actions=len(actions),
                            best_so_far=best.get(sid)) for sid, _ in senders}
    payload = dict(objective="maximum mean training reward; ties use smallest a_idx",
                   interpretation="empirical offline best, not a guaranteed true oracle",
                   completed_trials=db.execute("SELECT COUNT(*) FROM trials").fetchone()[0],
                   total_trials=len(senders)*len(actions)*repeats, scenes=result)
    (dest / "oracle.json.tmp").write_text(json.dumps(payload, indent=2))
    os.replace(dest / "oracle.json.tmp", dest / "oracle.json")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--result-dir", required=True, type=Path)
    p.add_argument("--ge-params", type=Path, default=ROOT / "python/bandit/quic_fec_params.json")
    p.add_argument("--training-meta", type=Path, default=ROOT / "python/results/ge-100kb-bandit-model-step500-100k/bandit_model.json")
    p.add_argument("--repeats", type=int, default=20)
    p.add_argument("--timeout-sec", type=int, default=2)
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--max-new-trials", type=int, default=0, help="bounded smoke run; 0 means full sweep")
    args = p.parse_args()
    if args.repeats < 1 or args.timeout_sec < 1 or args.max_new_trials < 0:
        p.error("invalid repeat/timeout/trial limit")
    dest = args.result_dir.resolve()
    dest.mkdir(parents=True, exist_ok=True)
    lock = (dest / "run.lock").open("a")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    actions = ActionSet()
    senders = _load_senders(str(args.ge_params))
    meta = json.loads(args.training_meta.read_text())
    for key in ("k_values", "r0_values", "rstep_values"):
        if meta["action_set"][key] != getattr(actions, key):
            raise ValueError(f"training/current action space mismatch: {key}")
    cfg = dict(meta["extra"]["env_cfg"])
    # Setup/build has a separate allowance. Transfer limits are set below.
    cfg.update(timeout_sec=60, train_file_bytes=102400, episode_step=len(actions)*args.repeats,
               normalize_obs=False, randomize_net_params=False)
    controls = dict(TIMEOUT_S=str(args.timeout_sec), SRV_TIMEOUT=f"{args.timeout_sec}s",
                    CLI_TIMEOUT=f"{args.timeout_sec}s", CONNECT_TIMEOUT_S=str(args.timeout_sec),
                    CONNECT_RETRIES="1", OBS_WAIT_SECS=str(args.timeout_sec), TRANSPORT="dgram",
                    USE_ARQ="1", W="8", MAX_ATTEMPTS="0", DECODE_DDL_MS="25",
                    POST_WAIT="0ms", SKIP_MD5="0", FEC_STATS="1",
                    QUIC_FEC_ARQ_DRAIN_CAP_MS=str(args.timeout_sec*1000),
                    QUICFEC_OBS_JSON=str(dest / "current_observation.json"),
                    TMPDIR=str(dest / "tmp"))
    (dest / "tmp").mkdir(exist_ok=True)
    os.environ.update(controls)
    sources = [ROOT / "python/fecenv_env.py", ROOT / "python/bandit/action_set.py",
               ROOT / "scripts/quicfec_run_once.sh", Path(__file__).resolve()]
    sources += sorted((ROOT / "go").rglob("*.go"))
    source_hash = hashlib.sha256("".join(digest(x) for x in sources).encode()).hexdigest()
    manifest = dict(git_commit=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                    source_hash=source_hash, ge_sha256=digest(args.ge_params),
                    training_meta_sha256=digest(args.training_meta), env_cfg=cfg,
                    controls=controls, seed=args.seed, repeats=args.repeats,
                    ge_key="GE_steady_rp", good_loss_pct=0, bad_loss_pct=99,
                    actions=len(actions), scenes=len(senders), total_trials=len(senders)*len(actions)*args.repeats)
    mp = dest / "manifest.json"
    if mp.exists():
        if json.loads(mp.read_text()) != manifest:
            raise ValueError("configuration or code changed; use a new result directory")
    else:
        mp.write_text(json.dumps(manifest, indent=2))
    db = sqlite3.connect(dest / "trials.sqlite3")
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    db.execute("""CREATE TABLE IF NOT EXISTS trials (
        sender INTEGER, action INTEGER, repeat INTEGER, reward REAL,
        success INTEGER, duration_ms REAL, goodput REAL, overhead REAL,
        wall_seconds REAL, timestamp REAL, details TEXT,
        PRIMARY KEY(sender,action,repeat))""")
    db.commit()
    env = FecEnv(cfg)
    started = time.monotonic()
    added = 0
    print(json.dumps(manifest), flush=True)
    try:
        for sid, scene in senders:
            done = set(db.execute("SELECT action, repeat FROM trials WHERE sender=?", (sid,)))
            if len(done) == len(actions)*args.repeats:
                continue
            loss = _ge_to_tc_gemodel_loss_mode(scene["GE_steady_rp"], h_loss_pct=0, k_loss_pct=99)
            env._runner.timeout_sec = 60
            env.reset(options=dict(rtt_ms=int(scene.get("rtt_ms", 50)), loss_mode=loss,
                                   loss_pct=0, bitrate_mbps=int(cfg["bitrate_mbps"])))
            env._runner.timeout_sec = args.timeout_sec
            order = list(range(len(actions)))
            random.Random(args.seed + sid).shuffle(order)
            for aid in order:
                for rep in range(args.repeats):
                    if (aid, rep) in done:
                        continue
                    # Prevent stale observations and repeated scans of growing logs.
                    Path(controls["QUICFEC_OBS_JSON"]).write_text("")
                    tick = time.monotonic()
                    _, reward, _, _, info = env.step(actions.get_action(aid).to_env_action())
                    if not info.get("step_valid") or info.get("error"):
                        raise RuntimeError(f"infrastructure error at {sid}/{aid}/{rep}: {info}")
                    raw = Path(controls["QUICFEC_OBS_JSON"]).read_text()
                    # Retain failed harness logs in the database without accumulating
                    # millions of small files. TMPDIR belongs solely to this run.
                    log_files = sorted((dest / "tmp").glob("quic_fec_*.log"))
                    logs = {x.name: x.read_text(errors="replace") for x in log_files}
                    details = json.dumps(dict(info=info, raw_observation=raw, loss_mode=loss,
                                              harness_logs=logs))
                    db.execute("INSERT INTO trials VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                               (sid, aid, rep, float(reward), int(info["md5_ok"]),
                                float(info["dur_ms"]), float(info["goodput_mbps"]),
                                float(info["quic_overhead_ratio"]), time.monotonic()-tick, time.time(), details))
                    db.commit()
                    for log_file in log_files:
                        log_file.unlink(missing_ok=True)
                    added += 1
                    if added % 20 == 0:
                        print(f"new_trials={added} sender={sid} action={aid} repeat={rep} seconds_per_trial={(time.monotonic()-started)/added:.3f}", flush=True)
                    if added == 20 or added % 500 == 0:
                        export_results(db, dest, actions, senders, args.repeats)
                    if args.max_new_trials and added >= args.max_new_trials:
                        return
            export_results(db, dest, actions, senders, args.repeats)
        print("COMPLETE: all scenes/actions/repeats evaluated", flush=True)
    finally:
        export_results(db, dest, actions, senders, args.repeats)
        db.close()


if __name__ == "__main__":
    main()
