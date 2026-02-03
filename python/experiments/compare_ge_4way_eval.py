#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from statistics import mean
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

_PY_ROOT = Path(__file__).resolve().parents[1]
if str(_PY_ROOT) not in sys.path:
    sys.path.insert(0, str(_PY_ROOT))

from bandit.action_set import ActionSet  # noqa: E402
from bandit.context import ContextBuilder  # noqa: E402
from bandit.features import phi as phi_fn  # noqa: E402
from bandit.model_io import load_checkpoint  # noqa: E402
from bandit.run_lints_ge_schedule import _ge_to_tc_gemodel_loss_mode  # noqa: E402


_REPO_ROOT = Path(__file__).resolve().parents[2]


@dataclass
class TrialResult:
    method: str
    rep: int
    goodput_mbps: float
    delay_ms_avg: float
    md5_ok: int
    extra: Dict[str, Any]


def _load_sender_ge(*, params_path: Path, sender_id: int, ge_key: str) -> Dict[str, Any]:
    data = json.loads(params_path.read_text(encoding="utf-8"))
    senders = data.get("senders")
    if not isinstance(senders, dict):
        raise ValueError(f"invalid senders in {params_path}")
    s = senders.get(str(sender_id))
    if not isinstance(s, dict):
        raise ValueError(f"sender_id={sender_id} not found in {params_path}")
    ge = s.get(ge_key)
    if not isinstance(ge, dict):
        raise ValueError(f"sender_id={sender_id} missing ge_key={ge_key}")
    return ge


def _parse_kv_from_run_line(line: str) -> Dict[str, str]:
    # line: [run] k=v k=v ...
    out: Dict[str, str] = {}
    s = line.strip()
    if s.startswith("[run]"):
        s = s[len("[run]") :].strip()
    for part in s.split():
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def _extract_last_run_line(output: str) -> Optional[str]:
    last = None
    for line in output.splitlines():
        if line.startswith("[run]"):
            last = line
    return last


def _extract_delay_line(output: str) -> Optional[str]:
    last = None
    for line in output.splitlines():
        if line.startswith("[delay]"):
            last = line
    return last


def _extract_last_rl_observation(output: str) -> Optional[Dict[str, Any]]:
    last = None
    for line in output.splitlines():
        if not line.startswith("[rl-observation] "):
            continue
        try:
            last = json.loads(line.split(" ", 1)[1])
        except Exception:
            continue
    return last


def _parse_delay_ms_avg_from_delay_line(line: str) -> float:
    if not line:
        return 0.0
    m = re.search(r"delay_ms_avg=([0-9.]+)", line)
    if not m:
        return 0.0
    try:
        return float(m.group(1))
    except Exception:
        return 0.0


def _run_script(
    *,
    script: Path,
    env: Dict[str, str],
    timeout_s: int,
) -> Tuple[str, str]:
    p = subprocess.run(
        ["bash", str(script)],
        cwd=str(_REPO_ROOT),
        env={**os.environ, **env},
        capture_output=True,
        text=True,
        timeout=timeout_s,
    )
    # Scripts intentionally `|| true` many commands; rely on [run] parsing.
    return p.stdout, p.stderr


def _bandit_select_action_mean(*, agent, action_set: ActionSet, ctx: ContextBuilder) -> Tuple[int, Dict[str, Any]]:
    """Deterministic selection using posterior mean theta_hat (no TS sampling)."""

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

    # Must match `python/fecenv_env.py` action decoding.
    K = 20 + 2 * k_idx
    R0 = int(r0_idx)
    RSTEP = 1 + rstep_idx

    return {
        "K": str(int(K)),
        "SYMBOL_BYTES": "1200",
        "R0": str(int(R0)),
        "W": os.environ.get("W", "8"),
        "RSTEP": str(int(RSTEP)),
        "MAX_ATTEMPTS": os.environ.get("MAX_ATTEMPTS", "5"),
        "USE_ARQ": os.environ.get("USE_ARQ", "1"),
        # Always CC enabled in our comparisons.
        "QUIC_FEC_CC_BYPASS": "0",
        "QUIC_FEC_CC_ALGO": "bbrv2",
        "PACE_US": "0",
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Compare 4 transport variants under a fixed GE model")
    ap.add_argument(
        "--model-prefix",
        type=str,
        required=True,
        help="Bandit model prefix (no .json/.npz), e.g. python/results/.../model_tXXXX_r0pYYYY",
    )
    ap.add_argument("--ge-params", type=str, default=str(_REPO_ROOT / "python/bandit/quic_fec_params.json"))
    ap.add_argument("--sender-id", type=int, default=28)
    ap.add_argument("--ge-key", type=str, default="GE_steady_rp")
    ap.add_argument("--ge-h-pct", type=float, default=0.0)
    ap.add_argument("--ge-k-pct", type=float, default=99.0)

    ap.add_argument("--bitrate-mbps", type=int, default=50)
    ap.add_argument("--rtt-ms", type=int, default=25)
    ap.add_argument("--file-bytes", type=int, default=3 * 1024 * 1024)

    ap.add_argument("--reps", type=int, default=20)
    ap.add_argument("--timeout-s", type=int, default=30, help="Python-side subprocess timeout; must exceed transfer timeout")
    ap.add_argument("--timeout-transfer-s", type=int, default=15, help="Transfer timeout in seconds; timed-out runs count as failure")

    ap.add_argument(
        "--out-dir",
        type=str,
        default="",
        help="Output directory (default: python/results/compare-ge-4way-<ts>)",
    )

    args = ap.parse_args()

    model_prefix = str(args.model_prefix)
    if model_prefix.endswith(".json"):
        model_prefix = model_prefix[:-5]
    if model_prefix.endswith(".npz"):
        model_prefix = model_prefix[:-4]

    params_path = Path(args.ge_params)
    ge = _load_sender_ge(params_path=params_path, sender_id=int(args.sender_id), ge_key=str(args.ge_key))
    loss_mode = _ge_to_tc_gemodel_loss_mode(ge, h_loss_pct=float(args.ge_h_pct), k_loss_pct=float(args.ge_k_pct))

    # Create a deterministic file of requested size.
    file_path = _REPO_ROOT / "go" / "test_data" / f"eval_{args.file_bytes}B.bin"
    file_path.parent.mkdir(parents=True, exist_ok=True)
    if not file_path.exists() or file_path.stat().st_size != int(args.file_bytes):
        # deterministic-ish: /dev/urandom is fine for throughput tests
        with open("/dev/urandom", "rb") as src, open(file_path, "wb") as dst:
            dst.write(src.read(int(args.file_bytes)))

    # Bandit checkpoint (used sequentially for fec-bandit runs).
    agent, _cfg, ctx, _ctx_cfg, action_set, _t0 = load_checkpoint(path_prefix=model_prefix)
    ctx.reset()

    ts = time.strftime("%Y%m%d-%H%M%S")
    out_dir = Path(args.out_dir) if args.out_dir else (_REPO_ROOT / "python" / "results" / f"compare-ge-4way-{ts}")
    out_dir.mkdir(parents=True, exist_ok=True)

    # Methods:
    # - fec_bandit_bbrv2: QUIC-FEC with bandit-selected params + BBRv2
    # - quic_basic: raw QUIC, default CC (cubic)
    # - quic_bbrv2: raw QUIC with env QUIC_FEC_CC_ALGO=bbrv2
    # - tcp: netcat over TCP
    methods = [
        "fec_bandit_bbrv2",
        "quic_basic",
        "quic_bbrv2",
        "tcp",
    ]

    rows: List[TrialResult] = []

    for method in methods:
        for rep in range(int(args.reps)):
            common_env = {
                "BITRATE_MBPS": str(int(args.bitrate_mbps)),
                "RTT_MS": str(int(args.rtt_ms)),
                "LOSS_MODE": str(loss_mode),
                "LOSS_PCT": "0",
                "FILE": str(file_path),
                "TIMEOUT_S": str(int(args.timeout_transfer_s)),
            }

            bandit_debug: Dict[str, Any] = {}
            bandit_env: Dict[str, str] = {}

            if method == "fec_bandit_bbrv2":
                a_idx, bandit_debug = _bandit_select_action_mean(agent=agent, action_set=action_set, ctx=ctx)
                bandit_env = _action_to_env_vars(action_set=action_set, a_idx=a_idx)
                env = {
                    **common_env,
                    **bandit_env,
                    # Ensure no lingering (faster + consistent)
                    "POST_WAIT": "0ms",
                }
                script = _REPO_ROOT / "scripts" / "quicfec_run_once.sh"
            elif method == "quic_basic":
                env = {
                    **common_env,
                    "QUIC_FEC_CC_BYPASS": "0",
                    # leave algo unset => default cubic
                }
                script = _REPO_ROOT / "scripts" / "quicraw_run_once.sh"
            elif method == "quic_bbrv2":
                env = {
                    **common_env,
                    "QUIC_FEC_CC_BYPASS": "0",
                    "QUIC_FEC_CC_ALGO": "bbrv2",
                }
                script = _REPO_ROOT / "scripts" / "quicraw_run_once.sh"
            elif method == "tcp":
                env = {
                    **common_env,
                }
                script = _REPO_ROOT / "scripts" / "tcp_run_once.sh"
            else:
                raise ValueError(f"unknown method: {method}")

            _stdout, stderr = _run_script(script=script, env=env, timeout_s=int(args.timeout_s))
            run_line = _extract_last_run_line(stderr) or ""
            kv = _parse_kv_from_run_line(run_line)

            # Parse goodput from s_mbps when available.
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

            delay_ms_avg = 0.0
            if method == "fec_bandit_bbrv2":
                obs = _extract_last_rl_observation(stderr)
                if isinstance(obs, dict):
                    try:
                        delay_ms_avg = float(obs.get("decode_latency_mean_ms", 0.0))
                    except Exception:
                        delay_ms_avg = 0.0
            else:
                delay_ms_avg = _parse_delay_ms_avg_from_delay_line(_extract_delay_line(stderr) or "")

            if timed_out or md5_ok != 1:
                goodput = 0.0
                delay_ms_avg = 0.0

            extra = {
                "loss_mode": loss_mode,
                "warmup": int(rep == 0),
                "timed_out": timed_out,
                "stderr_tail": "\n".join(stderr.splitlines()[-20:]),
            }
            if method == "fec_bandit_bbrv2":
                extra.update(
                    {
                        "bandit": bandit_debug,
                        "bandit_action": bandit_env,
                        "raw_obs": _extract_last_rl_observation(stderr) or {},
                    }
                )

                # Update context state for next run.
                obs = extra.get("raw_obs") if isinstance(extra.get("raw_obs"), dict) else {}
                # Update bandit context using only observation fields (no debug info).
                raw_obs = obs if isinstance(obs, dict) else {}
                if timed_out or md5_ok != 1:
                    if isinstance(raw_obs, dict):
                        raw_obs = {**raw_obs, "timeout_flag": 1.0}
                ctx.update(info={"raw_obs": raw_obs})

            rows.append(
                TrialResult(
                    method=method,
                    rep=rep,
                    goodput_mbps=goodput,
                    delay_ms_avg=delay_ms_avg,
                    md5_ok=md5_ok,
                    extra=extra,
                )
            )
            print(f"rep={rep:02d} method={method:16s} goodput_mbps={goodput:.3f} delay_ms_avg={delay_ms_avg:.3f} md5_ok={md5_ok}")

    # Write per-trial CSV
    out_csv = out_dir / "trials.csv"
    with out_csv.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["method", "rep", "goodput_mbps", "delay_ms_avg", "md5_ok"])
        w.writeheader()
        for r in rows:
            w.writerow(
                {
                    "method": r.method,
                    "rep": r.rep,
                    "goodput_mbps": f"{r.goodput_mbps:.6f}",
                    "delay_ms_avg": f"{r.delay_ms_avg:.6f}",
                    "md5_ok": r.md5_ok,
                }
            )

    # Summary CSV (also provide mean excluding warmup rep=0)
    out_sum = out_dir / "summary.csv"
    with out_sum.open("w", newline="") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "method",
                "n_all",
                "goodput_mbps_mean_all",
                "delay_ms_avg_mean_all",
                "md5_ok_rate_all",
                "n_no_warmup",
                "goodput_mbps_mean_no_warmup",
                "delay_ms_avg_mean_no_warmup",
                "md5_ok_rate_no_warmup",
            ],
        )
        w.writeheader()
        for m in methods:
            rs_all = [r for r in rows if r.method == m]
            rs = [r for r in rs_all if r.rep != 0]
            ok_all = [r for r in rs_all if r.md5_ok == 1]
            ok = [r for r in rs if r.md5_ok == 1]
            w.writerow(
                {
                    "method": m,
                    "n_all": len(rs_all),
                    "goodput_mbps_mean_all": f"{mean([r.goodput_mbps for r in rs_all]):.6f}" if rs_all else "",
                    "delay_ms_avg_mean_all": f"{mean([r.delay_ms_avg for r in rs_all]):.6f}" if rs_all else "",
                    "md5_ok_rate_all": f"{(len(ok_all) / len(rs_all)):.6f}" if rs_all else "",
                    "n_no_warmup": len(rs),
                    "goodput_mbps_mean_no_warmup": f"{mean([r.goodput_mbps for r in rs]):.6f}" if rs else "",
                    "delay_ms_avg_mean_no_warmup": f"{mean([r.delay_ms_avg for r in rs]):.6f}" if rs else "",
                    "md5_ok_rate_no_warmup": f"{(len(ok) / len(rs)):.6f}" if rs else "",
                }
            )

    meta = {
        "model_prefix": model_prefix,
        "sender_id": int(args.sender_id),
        "ge_key": str(args.ge_key),
        "ge_h_pct": float(args.ge_h_pct),
        "ge_k_pct": float(args.ge_k_pct),
        "loss_mode": loss_mode,
        "bitrate_mbps": int(args.bitrate_mbps),
        "rtt_ms": int(args.rtt_ms),
        "file": str(file_path),
        "file_bytes": int(args.file_bytes),
        "bandit": {"mode": "sequential_mean", "action_set_size": len(action_set)},
        "timeout_transfer_s": int(args.timeout_transfer_s),
    }
    (out_dir / "meta.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print("\nOUT:", out_dir)
    print("trials:", out_csv)
    print("summary:", out_sum)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
