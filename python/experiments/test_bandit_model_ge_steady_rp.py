#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from statistics import mean, median
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

_PY_ROOT = Path(__file__).resolve().parents[1]
_REPO_ROOT = Path(__file__).resolve().parents[2]

import sys

if str(_PY_ROOT) not in sys.path:
    sys.path.insert(0, str(_PY_ROOT))

from bandit.action_set import ActionSet  # noqa: E402
from bandit.context import ContextBuilder  # noqa: E402
from bandit.features import phi as phi_fn  # noqa: E402
from bandit.model_io import load_checkpoint  # noqa: E402
from bandit.run_lints_ge_schedule import _ge_to_tc_gemodel_loss_mode  # noqa: E402


@dataclass
class Trial:
    rep: int
    goodput_mbps: float
    dur_ms: float
    e2e_delay_ms: float
    delay_ms_avg: float
    md5_ok: int
    timed_out: int
    ddl_ms: int
    bandit_action_idx: int


def _aligned_obs_vec_from_rl_observation(*, rl_obs: Dict[str, Any], failed: bool) -> np.ndarray:
    """Construct the exact training observation vector.

    Layout must match `python/fecenv_env.py` (new):
      [goodput, fec_overhead, ctrl_tx_nack_msgs, done_flag, fec_rate]
    """

    if failed:
        goodput = 0.0
        fec_overhead = 0.0
        ctrl_tx_nack_msgs = 0.0
        done_flag = 0.0
        fec_rate = 0.0
    else:
        def _f(k: str, default: float = 0.0) -> float:
            try:
                return float(rl_obs.get(k, default))
            except Exception:
                return default

        goodput = _f(
            "goodput",
            _f("goodput_mbps", _f("goodput_arrival_mbps", _f("goodput_decode_mbps", 0.0))),
        )
        fec_overhead = _f("fec_overhead", _f("fec_overhead_pct_arrival", 0.0))
        ctrl_tx_nack_msgs = _f("ctrl_tx_nack_msgs", 0.0)
        done_flag = _f("done_flag", 1.0)
        fec_rate = _f("fec_rate", 0.0)

    return np.asarray(
        [
            float(goodput),
            float(fec_overhead),
            float(ctrl_tx_nack_msgs),
            float(np.clip(float(done_flag), 0.0, 1.0)),
            float(np.clip(float(fec_rate), 0.0, 1.0)),
        ],
        dtype=np.float32,
    )


_RUN_LINE_PREFIX = "[run]"
_DELAY_PREFIX = "[delay]"
_OBS_PREFIX = "[rl-observation]"


def _load_sender_ge(*, params_path: Path, sender_id: int, ge_key: str) -> Dict[str, Any]:
    data = json.loads(params_path.read_text(encoding="utf-8"))
    senders = data.get("senders")
    if not isinstance(senders, dict):
        raise ValueError("invalid 'senders' in ge params")
    s = senders.get(str(sender_id))
    if not isinstance(s, dict):
        raise ValueError(f"sender_id={sender_id} not found")
    ge = s.get(ge_key)
    if not isinstance(ge, dict):
        raise ValueError(f"sender_id={sender_id} missing {ge_key}")
    return ge


def _load_sender_data(*, params_path: Path, sender_id: int) -> Dict[str, Any]:
    data = json.loads(params_path.read_text(encoding="utf-8"))
    senders = data.get("senders")
    if not isinstance(senders, dict):
        raise ValueError("invalid 'senders' in ge params")
    s = senders.get(str(sender_id))
    if not isinstance(s, dict):
        raise ValueError(f"sender_id={sender_id} not found")
    return s


def _extract_last_line(prefix: str, s: str) -> Optional[str]:
    last = None
    for line in s.splitlines():
        if line.startswith(prefix):
            last = line
    return last


def _extract_last_run_line(stderr: str) -> Optional[str]:
    return _extract_last_line(_RUN_LINE_PREFIX, stderr)


def _extract_last_rl_observation(stderr: str) -> Optional[Dict[str, Any]]:
    line = _extract_last_line(_OBS_PREFIX, stderr)
    if not line:
        return None
    # Format: [rl-observation] {json}
    try:
        j = line[len(_OBS_PREFIX) :].strip()
        return json.loads(j)
    except Exception:
        return None


def _parse_kv_from_run_line(run_line: str) -> Dict[str, str]:
    # Example: [run] proto=... dur_ms=... timed_out=0 md5_ok=1 s_mbps=...
    out: Dict[str, str] = {}
    for tok in (run_line or "").split():
        if "=" not in tok:
            continue
        k, v = tok.split("=", 1)
        if k.startswith("["):
            continue
        out[k.strip()] = v.strip()
    return out


def _bandit_select_action_mean(*, agent, action_set: ActionSet, ctx: ContextBuilder) -> Tuple[int, Dict[str, Any]]:
    x = ctx.get_context()
    Phi = np.zeros((len(action_set), agent.dim), dtype=np.float32)
    for i, _a in action_set.iter_actions():
        Phi[i, :] = phi_fn(x=x, a_onehot=action_set.get_onehot(i))

    theta = np.asarray(agent.theta_hat, dtype=np.float64).reshape(-1)
    scores = Phi.astype(np.float64) @ theta
    a_idx = int(np.argmax(scores))
    return a_idx, {"x": x.tolist(), "a_idx": a_idx, "score": float(scores[a_idx])}


def _action_to_env_vars(*, action_set: ActionSet, a_idx: int) -> Dict[str, str]:
    spec = action_set.get_action(a_idx)
    env_action = spec.to_env_action()
    k_idx, r0_idx, rstep_idx = (int(env_action[0]), int(env_action[1]), int(env_action[2]))

    # New ActionSet semantics: indices are factor-level indices.
    K = int(action_set.k_values[int(k_idx)])
    R0 = int(action_set.r0_values[int(r0_idx)])
    RSTEP = int(action_set.rstep_values[int(rstep_idx)])

    return {
        "K": str(int(K)),
        "SYMBOL_BYTES": "1200",
        "R0": str(int(R0)),
        "W": os.environ.get("W", "8"),
        "RSTEP": str(int(RSTEP)),
        "MAX_ATTEMPTS": os.environ.get("MAX_ATTEMPTS", "5"),
        "USE_ARQ": os.environ.get("USE_ARQ", "1"),
        "QUIC_FEC_CC_BYPASS": "0",
        "QUIC_FEC_CC_ALGO": "bbrv2",
        "PACE_US": "0",
    }


def _run_script(*, script: Path, env: Dict[str, str], timeout_s: int) -> Tuple[str, str]:
    try:
        p = subprocess.run(
            ["bash", str(script)],
            cwd=str(_REPO_ROOT),
            env={**os.environ, **env},
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
        return p.stdout, p.stderr
    except subprocess.TimeoutExpired as e:
        # Treat Python-side timeout as a failure and continue.
        # quicfec_run_once.sh should normally respect TIMEOUT_S, but if something
        # wedges (e.g., server cleanup), we don't want the whole eval to abort.
        out = e.stdout or ""
        err = e.stderr or ""
        # Ensure downstream parsing sees a [run] line.
        err = (
            err
            + "\n"
            + "[run] proto=quic_fec dur_ms=0 timed_out=1 md5_ok=0 s_mbps=0\n"
        )
        return out, err


def main() -> int:
    ap = argparse.ArgumentParser(description="Evaluate a trained LinTS bandit model under GE_steady_rp")
    ap.add_argument(
        "--model-prefix",
        type=str,
        required=True,
        help="Bandit model prefix (no .json/.npz). Example: python/results/bandit-ge-run-.../bandit_model",
    )
    ap.add_argument("--ge-params", type=str, default=str(_REPO_ROOT / "python" / "bandit" / "quic_fec_params.json"))
    ap.add_argument("--sender-id", type=int, default=28)
    ap.add_argument("--ge-key", type=str, default="GE_steady_rp")
    ap.add_argument("--ge-h-pct", type=float, default=0.0)
    ap.add_argument("--ge-k-pct", type=float, default=99.0)

    ap.add_argument("--bitrate-mbps", type=int, default=50)
    ap.add_argument("--rtt-ms", type=int, default=25)
    ap.add_argument("--file-bytes", type=int, default=3 * 1024 * 1024)

    ap.add_argument("--reps", type=int, default=20)
    ap.add_argument("--timeout-s", type=int, default=90)
    ap.add_argument("--timeout-transfer-s", type=int, default=15)

    ap.add_argument(
        "--force-a-idx",
        type=int,
        default=-1,
        help="If set (>=0), forces using this discrete action index for all reps (still respects --fixed-ddl-ms override).",
    )

    ap.add_argument("--out-dir", type=str, default="")
    args = ap.parse_args()

    model_prefix = str(args.model_prefix)
    if model_prefix.endswith(".json"):
        model_prefix = model_prefix[:-5]
    if model_prefix.endswith(".npz"):
        model_prefix = model_prefix[:-4]

    params_path = Path(args.ge_params)
    ge = _load_sender_ge(params_path=params_path, sender_id=int(args.sender_id), ge_key=str(args.ge_key))
    sender_data = _load_sender_data(params_path=params_path, sender_id=int(args.sender_id))
    rtt_ms = int(sender_data.get("rtt_ms", int(args.rtt_ms)))
    loss_mode = _ge_to_tc_gemodel_loss_mode(ge, h_loss_pct=float(args.ge_h_pct), k_loss_pct=float(args.ge_k_pct))

    file_path = _REPO_ROOT / "go" / "test_data" / f"eval_{int(args.file_bytes)}B.bin"
    file_path.parent.mkdir(parents=True, exist_ok=True)
    if not file_path.exists() or file_path.stat().st_size != int(args.file_bytes):
        with open("/dev/urandom", "rb") as src, open(file_path, "wb") as dst:
            dst.write(src.read(int(args.file_bytes)))

    agent, _cfg, ctx, _ctx_cfg, action_set, _t0 = load_checkpoint(path_prefix=model_prefix)
    ctx.reset()

    ts = time.strftime("%Y%m%d-%H%M%S")
    out_dir = Path(args.out_dir) if args.out_dir else (_REPO_ROOT / "python" / "results" / f"bandit-eval-ge-steady-rp-{ts}")
    out_dir.mkdir(parents=True, exist_ok=True)

    trials: List[Trial] = []
    action_rows: List[Dict[str, Any]] = []

    interrupted = False
    try:
        for rep in range(int(args.reps)):
            if int(args.force_a_idx) >= 0:
                a_idx = int(args.force_a_idx)
                bandit_debug = {"x": ctx.get_context().tolist(), "a_idx": int(a_idx), "score": float("nan"), "forced": True}
            else:
                a_idx, bandit_debug = _bandit_select_action_mean(agent=agent, action_set=action_set, ctx=ctx)
            bandit_env = _action_to_env_vars(action_set=action_set, a_idx=a_idx)

            common_env = {
                "BITRATE_MBPS": str(int(args.bitrate_mbps)),
                "RTT_MS": str(int(rtt_ms)),
                "LOSS_MODE": str(loss_mode),
                "LOSS_PCT": "0",
                "FILE": str(file_path),
                "TIMEOUT_S": str(int(args.timeout_transfer_s)),
                "POST_WAIT": "0ms",
            }

            env = {**common_env, **bandit_env}
            _stdout, stderr = _run_script(script=_REPO_ROOT / "scripts" / "quicfec_run_once.sh", env=env, timeout_s=int(args.timeout_s))

            run_line = _extract_last_run_line(stderr) or ""
            kv = _parse_kv_from_run_line(run_line)

            goodput = 0.0
            try:
                goodput = float(kv.get("s_mbps", "0"))
            except Exception:
                goodput = 0.0

            md5_ok = 0
            try:
                md5_ok = int(float(kv.get("md5_ok", "0")))
            except Exception:
                md5_ok = 0

            timed_out = 0
            try:
                timed_out = int(float(kv.get("timed_out", "0")))
            except Exception:
                timed_out = 0

            dur_ms = 0.0
            try:
                dur_ms = float(kv.get("dur_ms", "0"))
            except Exception:
                dur_ms = 0.0

            e2e_delay_ms = float(dur_ms) + float(rtt_ms) / 2.0

            obs = _extract_last_rl_observation(stderr) or {}
            delay_ms_avg = 0.0
            try:
                delay_ms_avg = float(obs.get("decode_latency_mean_ms", 0.0))
            except Exception:
                delay_ms_avg = 0.0

            if timed_out or md5_ok != 1:
                goodput = 0.0
                dur_ms = 0.0
                e2e_delay_ms = 0.0
                delay_ms_avg = 0.0

            ddl_ms = int(float(obs.get("auto_ddl_ms", 0.0) or 0.0))

            # Update context for next run using the *exact* training obs vector.
            failed = bool(timed_out or md5_ok != 1)
            rl_obs = obs if isinstance(obs, dict) else {}
            aligned_obs = _aligned_obs_vec_from_rl_observation(rl_obs=rl_obs, failed=failed)
            ctx.update_from_obs(obs=aligned_obs)

            trials.append(
                Trial(
                    rep=rep,
                    goodput_mbps=goodput,
                    dur_ms=dur_ms,
                    e2e_delay_ms=e2e_delay_ms,
                    delay_ms_avg=delay_ms_avg,
                    md5_ok=md5_ok,
                    timed_out=timed_out,
                    ddl_ms=ddl_ms,
                    bandit_action_idx=a_idx,
                )
            )
            action_rows.append({"rep": rep, **bandit_debug, **bandit_env})

            print(
                f"rep={rep:02d} a_idx={a_idx:04d} ddl_ms={ddl_ms:4d} goodput_mbps={goodput:.3f} dur_ms={dur_ms:.1f} e2e_delay_ms={e2e_delay_ms:.1f} delay_ms_avg={delay_ms_avg:.3f} md5_ok={md5_ok} timed_out={timed_out}"
            )
    except KeyboardInterrupt:
        interrupted = True

    out_trials = out_dir / "trials.csv"
    with out_trials.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(
            f,
            fieldnames=["rep", "bandit_action_idx", "ddl_ms", "goodput_mbps", "dur_ms", "e2e_delay_ms", "delay_ms_avg", "md5_ok", "timed_out"],
        )
        w.writeheader()
        for t in trials:
            w.writerow(
                {
                    "rep": t.rep,
                    "bandit_action_idx": t.bandit_action_idx,
                    "ddl_ms": t.ddl_ms,
                    "goodput_mbps": f"{t.goodput_mbps:.6f}",
                    "dur_ms": f"{t.dur_ms:.3f}",
                    "e2e_delay_ms": f"{t.e2e_delay_ms:.3f}",
                    "delay_ms_avg": f"{t.delay_ms_avg:.6f}",
                    "md5_ok": t.md5_ok,
                    "timed_out": t.timed_out,
                }
            )

    out_actions = out_dir / "actions.csv"
    # Stable field order: rep, a_idx, score, then env vars.
    fieldnames = ["rep", "a_idx", "score", "K", "R0", "RSTEP", "W", "MAX_ATTEMPTS", "USE_ARQ", "SYMBOL_BYTES", "QUIC_FEC_CC_ALGO", "QUIC_FEC_CC_BYPASS", "PACE_US"]
    with out_actions.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for r in action_rows:
            w.writerow(r)

    goodputs = [t.goodput_mbps for t in trials]
    delays = [t.delay_ms_avg for t in trials]
    e2e_delays = [t.e2e_delay_ms for t in trials]
    ok_rate = mean([1.0 if (t.md5_ok == 1 and t.timed_out == 0) else 0.0 for t in trials]) if trials else 0.0

    summary = {
        "method": "fec_bandit_bbrv2",
        "model_prefix": model_prefix,
        "sender_id": int(args.sender_id),
        "ge_key": str(args.ge_key),
        "ge": ge,
        "loss_mode": loss_mode,
        "bitrate_mbps": int(args.bitrate_mbps),
        "rtt_ms": int(rtt_ms),
        "timeout_transfer_s": int(args.timeout_transfer_s),
        "reps": int(args.reps),
        "forced_a_idx": (int(args.force_a_idx) if int(args.force_a_idx) >= 0 else None),
        "fixed_ddl_ms": (int(args.fixed_ddl_ms) if int(args.fixed_ddl_ms) > 0 else None),
        "file": str(file_path),
        "mean_goodput_mbps": mean(goodputs) if goodputs else 0.0,
        "median_goodput_mbps": median(goodputs) if goodputs else 0.0,
        "mean_delay_ms_avg": mean(delays) if delays else 0.0,
        "median_delay_ms_avg": median(delays) if delays else 0.0,
        "mean_e2e_delay_ms": mean(e2e_delays) if e2e_delays else 0.0,
        "median_e2e_delay_ms": median(e2e_delays) if e2e_delays else 0.0,
        "ok_rate": ok_rate,
        "interrupted": bool(interrupted),
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print("\nSummary:")
    print(f"loss_mode={loss_mode}")
    print(f"mean_goodput_mbps={summary['mean_goodput_mbps']:.3f} median_goodput_mbps={summary['median_goodput_mbps']:.3f} ok_rate={ok_rate:.3f}")
    print(f"mean_delay_ms_avg={summary['mean_delay_ms_avg']:.3f} median_delay_ms_avg={summary['median_delay_ms_avg']:.3f}")
    print(f"mean_e2e_delay_ms={summary['mean_e2e_delay_ms']:.3f} median_e2e_delay_ms={summary['median_e2e_delay_ms']:.3f}")
    print("\nOUT:", out_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
