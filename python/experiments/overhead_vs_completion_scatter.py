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
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

_PY_ROOT = Path(__file__).resolve().parents[1]
_REPO_ROOT = Path(__file__).resolve().parents[2]

import sys

if str(_PY_ROOT) not in sys.path:
    sys.path.insert(0, str(_PY_ROOT))

from bandit.action_set import ActionSet  # noqa: E402
from bandit.context import ContextBuilder  # noqa: E402
from bandit.features import phi as phi_fn  # noqa: E402
from bandit.model_io import load_checkpoint  # noqa: E402


_FEC_METHOD_RE = re.compile(r"^fec_k(?P<k>\d+)_r0_(?P<r0>\d+)_rstep_(?P<rstep>\d+)$")


def _now_ts() -> str:
    return time.strftime("%Y%m%d-%H%M%S")


def _parse_int_list(s: str) -> List[int]:
    s = (s or "").strip()
    if not s:
        return []
    if s.lower() == "all":
        return [-1]

    out: List[int] = []
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_s, hi_s = part.split("-", 1)
            lo = int(lo_s)
            hi = int(hi_s)
            if hi < lo:
                lo, hi = hi, lo
            out.extend(list(range(lo, hi + 1)))
        else:
            out.append(int(part))

    seen = set()
    dedup: List[int] = []
    for x in out:
        if x in seen:
            continue
        seen.add(x)
        dedup.append(x)
    return dedup


def _extract_last_line(prefix: str, s: str) -> Optional[str]:
    last = None
    for line in (s or "").splitlines():
        if line.startswith(prefix):
            last = line
    return last


def _parse_kv_from_run_line(line: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for tok in (line or "").strip().split():
        if "=" not in tok:
            continue
        k, v = tok.split("=", 1)
        if k.startswith("["):
            continue
        out[k.strip()] = v.strip()
    return out


def _to_int(d: Dict[str, str], k: str, default: int = 0) -> int:
    try:
        return int(float(d.get(k, str(default))))
    except Exception:
        return default


def _ensure_file_of_size(*, file_path: Path, file_bytes: int) -> None:
    file_path.parent.mkdir(parents=True, exist_ok=True)
    if not file_path.exists() or file_path.stat().st_size != int(file_bytes):
        with open("/dev/urandom", "rb") as src, open(file_path, "wb") as dst:
            dst.write(src.read(int(file_bytes)))


def _run_bash_script(*, script: Path, env: Dict[str, str], timeout_s: int) -> Tuple[str, str]:
    try:
        p = subprocess.run(
            ["bash", str(script)],
            cwd=str(_REPO_ROOT),
            env={**os.environ, **env},
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=int(timeout_s),
        )
        return p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or "") if isinstance(e.stdout, str) else ""
        err = (e.stderr or "") if isinstance(e.stderr, str) else ""
        err = err + "\n" + "[run] proto=timeout dur_ms=0 timed_out=1 md5_ok=0 tx_bytes=0 rx_bytes=0 file_bytes=0\n"
        return out, err


def _require_sudo_cached() -> None:
    """Ensure `sudo -n` works (required by netns/tc scripts).

    We intentionally do NOT attempt interactive sudo here.
    """

    p = subprocess.run(["sudo", "-n", "true"], capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(
            "sudo credentials are not cached (need non-interactive sudo). "
            "Run `sudo -v` in a terminal, then rerun."
        )


def _ge_to_tc_gemodel_loss_mode(
    ge_rp: Dict[str, Any],
    *,
    h_loss_pct: float,
    k_loss_pct: float,
) -> str:
    """Build LOSS_MODE=gemodel:p,r,h,k string (percents) from GE params.

    This is intentionally duplicated from python/bandit/run_lints_ge_schedule.py
    to avoid importing gym / fecenv dependencies in environments where they are
    not installed.
    """

    if not isinstance(ge_rp, dict):
        raise ValueError("GE params must be a dict")

    p_g2b = ge_rp.get("p_g2b")
    r_b2g = ge_rp.get("r_b2g")
    if p_g2b is None or r_b2g is None:
        raise ValueError(f"GE_steady_rp missing p_g2b/r_b2g: keys={list(ge_rp.keys())}")

    p = float(p_g2b)
    r = float(r_b2g)
    p_pct = p * 100.0 if 0.0 <= p <= 1.0 else p
    r_pct = r * 100.0 if 0.0 <= r <= 1.0 else r

    p_pct = float(np.clip(p_pct, 0.0, 100.0))
    r_pct = float(np.clip(r_pct, 0.0, 100.0))
    h_loss_pct = float(np.clip(float(h_loss_pct), 0.0, 100.0))
    k_loss_pct = float(np.clip(float(k_loss_pct), 0.0, 100.0))

    return f"gemodel:{p_pct:.6f},{r_pct:.6f},{h_loss_pct:.6f},{k_loss_pct:.6f}"


def _configure_matplotlib() -> None:
    plt.rcParams.update(
        {
            "figure.figsize": (6.2, 3.6),
            "font.size": 10,
            "axes.labelsize": 10,
            "axes.titlesize": 10,
            "legend.fontsize": 8,
            "xtick.labelsize": 9,
            "ytick.labelsize": 9,
            "axes.grid": True,
            "grid.alpha": 0.25,
            "lines.linewidth": 1.1,
            "savefig.dpi": 500,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
        }
    )


def _bandit_select_action_mean(*, agent, action_set: ActionSet, ctx: ContextBuilder) -> Tuple[int, Dict[str, Any]]:
    x = ctx.get_context()
    Phi = np.zeros((len(action_set), agent.dim), dtype=np.float32)
    for i, _a in action_set.iter_actions():
        Phi[i, :] = phi_fn(x=x, a_onehot=action_set.get_onehot(i))

    theta = np.asarray(agent.theta_hat, dtype=np.float64).reshape(-1)
    scores = Phi.astype(np.float64) @ theta
    a_idx = int(np.argmax(scores))
    return a_idx, {"x": x.tolist(), "a_idx": a_idx, "score": float(scores[a_idx])}


def _extract_last_rl_observation(stderr: str) -> Optional[Dict[str, Any]]:
    line = _extract_last_line("[rl-observation]", stderr)
    if not line:
        return None
    try:
        payload = line.split(" ", 1)[1]
        return json.loads(payload)
    except Exception:
        return None


def _aligned_obs_vec_from_rl_observation(*, rl_obs: Optional[Dict[str, Any]], ddl_ms: int, failed: bool) -> np.ndarray:
    """Map [rl-observation] into the *new* 6-dim obs layout used by ContextBuilder.

    Layout:
      0 goodput
      1 fec_overhead
      2 ctrl_tx_nack_msgs
      3 done_flag
      4 fec_rate
      5 ddl_ms
    """

    if failed or not isinstance(rl_obs, dict):
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
            float(int(ddl_ms)),
        ],
        dtype=np.float32,
    )


def _load_sender_ids(*, params_path: Path, sender_ids_arg: str, ge_key: str) -> List[int]:
    data = json.loads(params_path.read_text(encoding="utf-8"))
    senders = data.get("senders")
    if not isinstance(senders, dict):
        raise ValueError("invalid 'senders' in ge params")

    requested = _parse_int_list(sender_ids_arg)
    if requested == [-1]:
        ids: List[int] = []
        for sid_s, s in senders.items():
            if not isinstance(s, dict):
                continue
            if isinstance(s.get(ge_key), dict):
                try:
                    ids.append(int(sid_s))
                except Exception:
                    continue
        ids.sort()
        return ids

    out: List[int] = []
    for sid in requested:
        s = senders.get(str(sid))
        if not isinstance(s, dict):
            raise ValueError(f"sender_id={sid} not found in {params_path}")
        ge = s.get(ge_key)
        if not isinstance(ge, dict):
            raise ValueError(f"sender_id={sid} missing ge_key={ge_key}")
        out.append(int(sid))
    return out


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


@dataclass
class RunRow:
    sender_id: int
    loss_mode: str
    proto_ddl_ms: int  # protocol rx-ddl used for this run
    method: str
    rep: int
    timed_out: int
    md5_ok: int
    success: int
    dur_ms: int
    tx_bytes: int
    rx_bytes: int
    file_bytes: int
    overhead_ratio: float
    rtt_ms: int
    e2e_delay_ms: float


def _load_runrows_from_runs_csv(runs_csv: Path) -> List[RunRow]:
    out: List[RunRow] = []
    with runs_csv.open("r", encoding="utf-8", newline="") as f:
        r = csv.DictReader(f)
        for row in r:
            try:
                out.append(
                    RunRow(
                        sender_id=int(row.get("sender_id", "0") or "0"),
                        loss_mode=str(row.get("loss_mode", "")),
                        proto_ddl_ms=int(row.get("proto_ddl_ms", "0") or "0"),
                        method=str(row.get("method", "")),
                        rep=int(row.get("rep", "0") or "0"),
                        timed_out=int(row.get("timed_out", "0") or "0"),
                        md5_ok=int(row.get("md5_ok", "0") or "0"),
                        success=int(row.get("success", "0") or "0"),
                        dur_ms=int(row.get("dur_ms", "0") or "0"),
                        rtt_ms=int(row.get("rtt_ms", "0") or "0"),
                        e2e_delay_ms=float(row.get("e2e_delay_ms", row.get("dur_ms", "0")) or "0"),
                        tx_bytes=int(row.get("tx_bytes", "0") or "0"),
                        rx_bytes=int(row.get("rx_bytes", "0") or "0"),
                        file_bytes=int(row.get("file_bytes", "0") or "0"),
                        overhead_ratio=float(row.get("overhead_ratio", "0") or "0"),
                    )
                )
            except Exception:
                continue
    return out


def _load_flec_runrows_from_jsonl(flec_jsonl: Path) -> List[RunRow]:
    """Map flec jsonl into RunRow schema.

    Expected keys per line: sender, trial, ok, e2e_s, tx_total_bytes, tx_data_bytes, overhead.
    """

    out: List[RunRow] = []
    with flec_jsonl.open("r", encoding="utf-8") as f:
        for line in f:
            line = (line or "").strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue
            if not isinstance(d, dict):
                continue
            try:
                sender_id = int(d.get("sender", 0) or 0)
                rep = int(d.get("trial", 0) or 0)
                ok = int(d.get("ok", 0) or 0)
                e2e_s = d.get("e2e_s", None)
                dur_ms = int(float(e2e_s) * 1000.0) if e2e_s is not None else 0
                tx_total = int(d.get("tx_total_bytes", 0) or 0)
                file_bytes = int(d.get("tx_data_bytes", 0) or 0)
                overhead = d.get("overhead", None)
                overhead_ratio = (
                    float(overhead)
                    if overhead is not None
                    else (float(tx_total - file_bytes) / float(file_bytes) if file_bytes > 0 and tx_total > 0 else 0.0)
                )
                p_pct = d.get("p_pct", None)
                r_pct = d.get("r_pct", None)
                if p_pct is not None and r_pct is not None:
                    loss_mode = f"flec:p={float(p_pct):.6f},r={float(r_pct):.6f}"
                else:
                    loss_mode = "flec"
            except Exception:
                continue

            out.append(
                RunRow(
                    sender_id=int(sender_id),
                    loss_mode=str(loss_mode),
                    proto_ddl_ms=0,
                    method="flec",
                    rep=int(rep),
                    timed_out=0 if ok == 1 else 1,
                    md5_ok=int(ok),
                    success=int(ok),
                    dur_ms=int(dur_ms),
                    rtt_ms=0,
                    e2e_delay_ms=float(dur_ms),
                    tx_bytes=int(tx_total),
                    rx_bytes=0,
                    file_bytes=int(file_bytes),
                    overhead_ratio=float(overhead_ratio),
                )
            )
    return out


def _fixed_fec_env(*, ddl_ms: int, symbol_bytes: int, k: int, r0: int, rstep: int) -> Dict[str, str]:
    return {
        "K": str(int(k)),
        "SYMBOL_BYTES": str(int(symbol_bytes)),
        "R0": str(int(r0)),
        "W": os.environ.get("W", "8"),
        "RSTEP": str(int(rstep)),
        "DDL_MS": str(int(ddl_ms)),
        "MAX_ATTEMPTS": os.environ.get("MAX_ATTEMPTS", "5"),
        "USE_ARQ": os.environ.get("USE_ARQ", "1"),
        "QUIC_FEC_CC_BYPASS": "0",
        "QUIC_FEC_CC_ALGO": "bbrv2",
        "PACE_US": "0",
    }


def _action_to_env_vars(
    *,
    action_set: ActionSet,
    a_idx: int,
    symbol_bytes: int,
    ddl_ms_override: int = 0,
) -> Dict[str, str]:
    spec = action_set.get_action(a_idx)
    env_action = spec.to_env_action()
    k_idx, r0_idx, rstep_idx, ddl_idx = (
        int(env_action[0]),
        int(env_action[1]),
        int(env_action[2]),
        int(env_action[3]),
    )

    # New ActionSet semantics: indices are factor-level indices.
    K = int(action_set.k_values[int(k_idx)])
    R0 = int(action_set.r0_values[int(r0_idx)])
    RSTEP = int(action_set.rstep_values[int(rstep_idx)])
    ddl_ms = int(action_set.ddl_ms_values[int(ddl_idx)])
    if int(ddl_ms_override) > 0:
        ddl_ms = int(ddl_ms_override)

    return {
        "K": str(int(K)),
        "SYMBOL_BYTES": str(int(symbol_bytes)),
        "R0": str(int(R0)),
        "W": os.environ.get("W", "8"),
        "RSTEP": str(int(RSTEP)),
        "DDL_MS": str(int(ddl_ms)),
        "MAX_ATTEMPTS": os.environ.get("MAX_ATTEMPTS", "5"),
        "USE_ARQ": os.environ.get("USE_ARQ", "1"),
        "QUIC_FEC_CC_BYPASS": "0",
        "QUIC_FEC_CC_ALGO": "bbrv2",
        "PACE_US": "0",
    }


def _run_one(
    *,
    method: str,
    loss_mode: str,
    bitrate_mbps: int,
    rtt_ms: int,
    timeout_transfer_s: int,
    timeout_s: int,
    file_path: Path,
    fec_env: Optional[Dict[str, str]] = None,
) -> Tuple[Dict[str, Any], str]:
    common_env = {
        "BITRATE_MBPS": str(int(bitrate_mbps)),
        "RTT_MS": str(int(rtt_ms)),
        "LOSS_MODE": str(loss_mode),
        "LOSS_PCT": "0",
        "FILE": str(file_path),
        "TIMEOUT_S": str(int(timeout_transfer_s)),
        "POST_WAIT": "0ms",
    }

    if method == "quic_bbrv2":
        env = {
            **common_env,
            "QUIC_FEC_CC_BYPASS": "0",
            "QUIC_FEC_CC_ALGO": "bbrv2",
        }
        _stdout, stderr = _run_bash_script(
            script=_REPO_ROOT / "scripts" / "quicraw_run_once.sh",
            env=env,
            timeout_s=timeout_s,
        )
    elif method.startswith("fec_") or method == "bandit":
        if not fec_env:
            raise ValueError("fec_env is required for fec/bandit")
        env = {**common_env, **fec_env}
        _stdout, stderr = _run_bash_script(
            script=_REPO_ROOT / "scripts" / "quicfec_run_once.sh",
            env=env,
            timeout_s=timeout_s,
        )
    else:
        raise ValueError(f"unknown method={method}")

    run_line = _extract_last_line("[run]", stderr) or ""
    if not run_line:
        tail = "\n".join((stderr or "").splitlines()[-30:])
        raise RuntimeError(
            f"Missing [run] line from script for method={method}. "
            f"This usually means the bash script exited early (often sudo).\n"
            f"---- stderr tail ----\n{tail}\n---- end ----"
        )
    kv = _parse_kv_from_run_line(run_line)

    dur_ms = _to_int(kv, "dur_ms", 0)
    timed_out = _to_int(kv, "timed_out", 0)
    md5_ok = _to_int(kv, "md5_ok", 0)
    tx_bytes = _to_int(kv, "tx_bytes", 0)
    rx_bytes = _to_int(kv, "rx_bytes", 0)
    file_bytes = _to_int(kv, "file_bytes", int(file_path.stat().st_size))
    success = 1 if (timed_out == 0 and md5_ok == 1) else 0

    overhead_ratio = 0.0
    if file_bytes > 0 and tx_bytes > 0:
        overhead_ratio = max(0.0, (float(tx_bytes) - float(file_bytes)) / float(file_bytes))

    e2e_delay_ms = float(dur_ms) + float(rtt_ms) / 2.0

    return {
        "dur_ms": int(dur_ms),
        "rtt_ms": int(rtt_ms),
        "e2e_delay_ms": float(e2e_delay_ms),
        "timed_out": int(timed_out),
        "md5_ok": int(md5_ok),
        "success": int(success),
        "tx_bytes": int(tx_bytes),
        "rx_bytes": int(rx_bytes),
        "file_bytes": int(file_bytes),
        "overhead_ratio": float(overhead_ratio),
    }, stderr


def main() -> int:
    ap = argparse.ArgumentParser(description="Scatter: Overhead vs completion ratio under GE_steady_rp (128KB)")
    ap.add_argument(
        "--bandit-model-prefix",
        type=str,
        required=False,
        help="Bandit checkpoint prefix (no .json/.npz), e.g. python/results/.../model_tXXXX_r0pYYYY",
    )
    ap.add_argument(
        "--base-runs-csv",
        type=str,
        default="",
        help="Plot-only mode: load existing runs.csv instead of running experiments.",
    )
    ap.add_argument(
        "--flec-jsonl",
        type=str,
        default="",
        help="Optional: overlay flec runs from jsonl (fields: sender,trial,ok,e2e_s,tx_total_bytes,tx_data_bytes,overhead).",
    )
    ap.add_argument("--ge-params", type=str, default=str(_REPO_ROOT / "python" / "bandit" / "quic_fec_params.json"))
    ap.add_argument("--ge-key", type=str, default="GE_steady_rp")
    ap.add_argument("--sender-ids", type=str, default="100", help="Comma list / ranges, or 'all'")
    ap.add_argument("--ge-h-pct", type=float, default=0.0)
    ap.add_argument("--ge-k-pct", type=float, default=99.0)

    ap.add_argument("--bitrate-mbps", type=int, default=10)
    ap.add_argument("--rtt-ms", type=int, default=25)
    ap.add_argument("--timeout-transfer-s", type=int, default=15)
    ap.add_argument("--timeout-s", type=int, default=180)

    ap.add_argument("--file-bytes", type=int, default=128 * 1024)
    ap.add_argument("--reps", type=int, default=100)
    ap.add_argument("--warmup-a-idx", type=int, default=2845)

    ap.add_argument(
        "--ddl-ms",
        type=str,
        default="150,250,350,450",
        help="Comma list of DDL thresholds (ms) used only for completion-ratio calculation / plotting.",
    )
    ap.add_argument(
        "--proto-ddl-ms",
        type=int,
        default=0,
        help="If >0, overrides DDL_MS for all QUIC-FEC runs (bandit + fixed). Default 0 keeps compare-style per-method DDL_MS.",
    )
    ap.add_argument("--symbol-bytes", type=int, default=1200)
    ap.add_argument("--fixed1", type=str, default="20,2,2", help="Fixed FEC #1 as k,r0,rstep (default: 20,2,2)")
    ap.add_argument("--fixed2", type=str, default="20,6,4", help="Fixed FEC #2 as k,r0,rstep (default: 20,6,4)")
    ap.add_argument(
        "--fixed-ddl-ms",
        type=int,
        default=150,
        help="DDL_MS for fixed-FEC baselines (default: 150, to match compare delay experiment)",
    )

    ap.add_argument("--out-dir", type=str, default="")

    args = ap.parse_args()

    plot_only = bool(str(getattr(args, "base_runs_csv", "")).strip())
    if not plot_only:
        _require_sudo_cached()

    model_prefix = str(args.bandit_model_prefix or "")
    if not plot_only and not model_prefix.strip():
        raise SystemExit("--bandit-model-prefix is required unless --base-runs-csv is set")
    if model_prefix.endswith(".json"):
        model_prefix = model_prefix[:-5]
    if model_prefix.endswith(".npz"):
        model_prefix = model_prefix[:-4]

    ddl_list = [int(x.strip()) for x in str(args.ddl_ms).split(",") if x.strip()]
    if not ddl_list:
        raise ValueError("empty --ddl-ms")

    ddl_list = sorted(list({int(x) for x in ddl_list}))
    proto_ddl_ms = int(args.proto_ddl_ms)

    def _parse_fixed(s: str) -> Tuple[int, int, int]:
        parts = [p.strip() for p in str(s).split(",") if p.strip()]
        if len(parts) != 3:
            raise ValueError("expected k,r0,rstep")
        return int(parts[0]), int(parts[1]), int(parts[2])

    fixed1 = _parse_fixed(args.fixed1)
    fixed2 = _parse_fixed(args.fixed2)

    params_path = Path(args.ge_params)

    ts = _now_ts()
    out_dir = Path(args.out_dir) if args.out_dir else (_REPO_ROOT / "python" / "results" / f"paper-overhead-vs-completion-{ts}")
    out_dir.mkdir(parents=True, exist_ok=True)

    rows: List[RunRow] = []

    if plot_only:
        base_runs_csv = Path(str(args.base_runs_csv)).expanduser()
        if not base_runs_csv.exists():
            raise FileNotFoundError(str(base_runs_csv))
        rows.extend(_load_runrows_from_runs_csv(base_runs_csv))

        flec_path_s = str(getattr(args, "flec_jsonl", "")).strip()
        if flec_path_s:
            flec_path = Path(flec_path_s).expanduser()
            if not flec_path.exists():
                raise FileNotFoundError(str(flec_path))
            rows.extend(_load_flec_runrows_from_jsonl(flec_path))

        sender_ids = sorted({int(r.sender_id) for r in rows})

        # Prefer a stable method order.
        all_methods = sorted({str(r.method) for r in rows})
        methods: List[str] = []
        for m in ["bandit", "quic_bbrv2"]:
            if m in all_methods:
                methods.append(m)
        methods.extend(sorted([m for m in all_methods if m.startswith("fec_")]))
        if "flec" in all_methods:
            methods.append("flec")
        for m in all_methods:
            if m not in methods:
                methods.append(m)

        print(f"[plot-only] base_runs_csv={base_runs_csv}")
    else:
        sender_ids = _load_sender_ids(params_path=params_path, sender_ids_arg=str(args.sender_ids), ge_key=str(args.ge_key))

        file_path = _REPO_ROOT / "go" / "test_data" / f"paper_delay_{int(args.file_bytes)}B.bin"
        _ensure_file_of_size(file_path=file_path, file_bytes=int(args.file_bytes))

        # Load bandit checkpoint (we use ctx_cfg/action_set from the checkpoint, but start with a fresh ctx per sender).
        agent, _cfg, _ctx0, ctx_cfg, action_set, _t0 = load_checkpoint(path_prefix=model_prefix)

        method_f1 = f"fec_k{int(fixed1[0])}_r0_{int(fixed1[1])}_rstep_{int(fixed1[2])}"
        method_f2 = f"fec_k{int(fixed2[0])}_r0_{int(fixed2[1])}_rstep_{int(fixed2[2])}"
        methods = ["bandit", "quic_bbrv2", method_f1, method_f2]

    print(f"[ddl-override] {proto_ddl_ms}ms" if int(proto_ddl_ms) > 0 else "[ddl-override] disabled")
    print(f"[ddl-thresholds] {ddl_list}")
    print(f"[senders] {sender_ids}")

    for sender_id in sender_ids:
        if plot_only:
            continue
        sender_data = _load_sender_data(params_path=params_path, sender_id=int(sender_id))
        ge = _load_sender_ge(params_path=params_path, sender_id=int(sender_id), ge_key=str(args.ge_key))
        rtt_ms = int(sender_data.get("rtt_ms", int(args.rtt_ms)))
        loss_mode = _ge_to_tc_gemodel_loss_mode(ge, h_loss_pct=float(args.ge_h_pct), k_loss_pct=float(args.ge_k_pct))
        print(f"\n[sender] {int(sender_id)} rtt_ms={int(rtt_ms)} loss_mode={loss_mode}")

        # Bandit state per sender (single sweep, update context sequentially).
        ctx = ContextBuilder(ctx_cfg)
        ctx.reset()

        # Warmup once to update ctx (excluded from stats)
        warmup_idx = int(args.warmup_a_idx)
        warmup_env = _action_to_env_vars(
            action_set=action_set,
            a_idx=warmup_idx,
            symbol_bytes=int(args.symbol_bytes),
            ddl_ms_override=int(proto_ddl_ms),
        )
        warmup_ddl_ms = int(warmup_env.get("DDL_MS", "150"))
        m_w, stderr_w = _run_one(
            method="bandit",
            loss_mode=loss_mode,
            bitrate_mbps=int(args.bitrate_mbps),
            rtt_ms=int(rtt_ms),
            timeout_transfer_s=int(args.timeout_transfer_s),
            timeout_s=int(args.timeout_s),
            file_path=file_path,
            fec_env=warmup_env,
        )
        rl_obs = _extract_last_rl_observation(stderr_w)
        failed = bool(int(m_w["timed_out"]) or int(m_w["md5_ok"]) != 1)
        obs_vec = _aligned_obs_vec_from_rl_observation(rl_obs=rl_obs, ddl_ms=int(warmup_ddl_ms), failed=failed)
        ctx.update_from_obs(obs=obs_vec, ddl_ms=int(warmup_ddl_ms))

        for rep in range(int(args.reps)):
            # Bandit
            a_idx, _dbg = _bandit_select_action_mean(agent=agent, action_set=action_set, ctx=ctx)
            bandit_env = _action_to_env_vars(
                action_set=action_set,
                a_idx=int(a_idx),
                symbol_bytes=int(args.symbol_bytes),
                ddl_ms_override=int(proto_ddl_ms),
            )
            ddl_ms_used = int(bandit_env.get("DDL_MS", "150"))
            m, stderr = _run_one(
                method="bandit",
                loss_mode=loss_mode,
                bitrate_mbps=int(args.bitrate_mbps),
                rtt_ms=int(rtt_ms),
                timeout_transfer_s=int(args.timeout_transfer_s),
                timeout_s=int(args.timeout_s),
                file_path=file_path,
                fec_env=bandit_env,
            )
            rl_obs2 = _extract_last_rl_observation(stderr)
            failed2 = bool(int(m["timed_out"]) or int(m["md5_ok"]) != 1)
            obs_vec2 = _aligned_obs_vec_from_rl_observation(rl_obs=rl_obs2, ddl_ms=int(ddl_ms_used), failed=failed2)
            ctx.update_from_obs(obs=obs_vec2, ddl_ms=int(ddl_ms_used))
            rows.append(
                RunRow(
                    sender_id=int(sender_id),
                    loss_mode=str(loss_mode),
                    proto_ddl_ms=int(ddl_ms_used),
                    method="bandit",
                    rep=int(rep),
                    timed_out=int(m["timed_out"]),
                    md5_ok=int(m["md5_ok"]),
                    success=int(m["success"]),
                    dur_ms=int(m["dur_ms"]),
                    rtt_ms=int(m.get("rtt_ms", int(rtt_ms))),
                    e2e_delay_ms=float(m.get("e2e_delay_ms", float(m["dur_ms"]))),
                    tx_bytes=int(m["tx_bytes"]),
                    rx_bytes=int(m["rx_bytes"]),
                    file_bytes=int(m["file_bytes"]),
                    overhead_ratio=float(m["overhead_ratio"]),
                )
            )

            # QUIC BBRv2 raw
            m_q, _stderr_q = _run_one(
                method="quic_bbrv2",
                loss_mode=loss_mode,
                bitrate_mbps=int(args.bitrate_mbps),
                rtt_ms=int(rtt_ms),
                timeout_transfer_s=int(args.timeout_transfer_s),
                timeout_s=int(args.timeout_s),
                file_path=file_path,
            )
            rows.append(
                RunRow(
                    sender_id=int(sender_id),
                    loss_mode=str(loss_mode),
                    proto_ddl_ms=int(proto_ddl_ms),
                    method="quic_bbrv2",
                    rep=int(rep),
                    timed_out=int(m_q["timed_out"]),
                    md5_ok=int(m_q["md5_ok"]),
                    success=int(m_q["success"]),
                    dur_ms=int(m_q["dur_ms"]),
                    rtt_ms=int(m_q.get("rtt_ms", int(rtt_ms))),
                    e2e_delay_ms=float(m_q.get("e2e_delay_ms", float(m_q["dur_ms"]))),
                    tx_bytes=int(m_q["tx_bytes"]),
                    rx_bytes=int(m_q["rx_bytes"]),
                    file_bytes=int(m_q["file_bytes"]),
                    overhead_ratio=float(m_q["overhead_ratio"]),
                )
            )

            # Fixed FEC #1
            env_f1 = _fixed_fec_env(
                ddl_ms=int(proto_ddl_ms) if int(proto_ddl_ms) > 0 else int(args.fixed_ddl_ms),
                symbol_bytes=int(args.symbol_bytes),
                k=int(fixed1[0]),
                r0=int(fixed1[1]),
                rstep=int(fixed1[2]),
            )
            ddl_f1 = int(env_f1.get("DDL_MS", str(int(args.fixed_ddl_ms))))
            m_f1, _stderr_f1 = _run_one(
                method=method_f1,
                loss_mode=loss_mode,
                bitrate_mbps=int(args.bitrate_mbps),
                rtt_ms=int(rtt_ms),
                timeout_transfer_s=int(args.timeout_transfer_s),
                timeout_s=int(args.timeout_s),
                file_path=file_path,
                fec_env=env_f1,
            )
            rows.append(
                RunRow(
                    sender_id=int(sender_id),
                    loss_mode=str(loss_mode),
                    proto_ddl_ms=int(ddl_f1),
                    method=method_f1,
                    rep=int(rep),
                    timed_out=int(m_f1["timed_out"]),
                    md5_ok=int(m_f1["md5_ok"]),
                    success=int(m_f1["success"]),
                    dur_ms=int(m_f1["dur_ms"]),
                    rtt_ms=int(m_f1.get("rtt_ms", int(rtt_ms))),
                    e2e_delay_ms=float(m_f1.get("e2e_delay_ms", float(m_f1["dur_ms"]))),
                    tx_bytes=int(m_f1["tx_bytes"]),
                    rx_bytes=int(m_f1["rx_bytes"]),
                    file_bytes=int(m_f1["file_bytes"]),
                    overhead_ratio=float(m_f1["overhead_ratio"]),
                )
            )

            # Fixed FEC #2
            env_f2 = _fixed_fec_env(
                ddl_ms=int(proto_ddl_ms) if int(proto_ddl_ms) > 0 else int(args.fixed_ddl_ms),
                symbol_bytes=int(args.symbol_bytes),
                k=int(fixed2[0]),
                r0=int(fixed2[1]),
                rstep=int(fixed2[2]),
            )
            ddl_f2 = int(env_f2.get("DDL_MS", str(int(args.fixed_ddl_ms))))
            m_f2, _stderr_f2 = _run_one(
                method=method_f2,
                loss_mode=loss_mode,
                bitrate_mbps=int(args.bitrate_mbps),
                rtt_ms=int(rtt_ms),
                timeout_transfer_s=int(args.timeout_transfer_s),
                timeout_s=int(args.timeout_s),
                file_path=file_path,
                fec_env=env_f2,
            )
            rows.append(
                RunRow(
                    sender_id=int(sender_id),
                    loss_mode=str(loss_mode),
                    proto_ddl_ms=int(ddl_f2),
                    method=method_f2,
                    rep=int(rep),
                    timed_out=int(m_f2["timed_out"]),
                    md5_ok=int(m_f2["md5_ok"]),
                    success=int(m_f2["success"]),
                    dur_ms=int(m_f2["dur_ms"]),
                    rtt_ms=int(m_f2.get("rtt_ms", int(rtt_ms))),
                    e2e_delay_ms=float(m_f2.get("e2e_delay_ms", float(m_f2["dur_ms"]))),
                    tx_bytes=int(m_f2["tx_bytes"]),
                    rx_bytes=int(m_f2["rx_bytes"]),
                    file_bytes=int(m_f2["file_bytes"]),
                    overhead_ratio=float(m_f2["overhead_ratio"]),
                )
            )

            if rep % 10 == 0:
                print(
                    f"  rep={rep:03d} "
                    f"bandit ok={m['success']} dur={m['dur_ms']} ovh={m['overhead_ratio']:.3f} | "
                    f"quic ok={m_q['success']} dur={m_q['dur_ms']} ovh={m_q['overhead_ratio']:.3f} | "
                    f"fec1 ok={m_f1['success']} dur={m_f1['dur_ms']} ovh={m_f1['overhead_ratio']:.3f} | "
                    f"fec2 ok={m_f2['success']} dur={m_f2['dur_ms']} ovh={m_f2['overhead_ratio']:.3f}"
                )

    # Save raw per-run CSV
    out_csv = out_dir / "runs.csv"
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "sender_id",
                "loss_mode",
                "proto_ddl_ms",
                "method",
                "rep",
                "timed_out",
                "md5_ok",
                "success",
                "dur_ms",
                "rtt_ms",
                "e2e_delay_ms",
                "tx_bytes",
                "rx_bytes",
                "file_bytes",
                "overhead_ratio",
            ],
        )
        w.writeheader()
        for r in rows:
            w.writerow(
                {
                    "sender_id": r.sender_id,
                    "loss_mode": r.loss_mode,
                    "proto_ddl_ms": r.proto_ddl_ms,
                    "method": r.method,
                    "rep": r.rep,
                    "timed_out": r.timed_out,
                    "md5_ok": r.md5_ok,
                    "success": r.success,
                    "dur_ms": r.dur_ms,
                    "rtt_ms": r.rtt_ms,
                    "e2e_delay_ms": f"{r.e2e_delay_ms:.3f}",
                    "tx_bytes": r.tx_bytes,
                    "rx_bytes": r.rx_bytes,
                    "file_bytes": r.file_bytes,
                    "overhead_ratio": f"{r.overhead_ratio:.6f}",
                }
            )

    # Aggregate per (sender_id, method), compute completion ratio for each ddl threshold.
    def _group(sender_id: int, method: str) -> List[RunRow]:
        return [r for r in rows if r.sender_id == sender_id and r.method == method]

    agg_rows: List[Dict[str, Any]] = []
    for sender_id in sender_ids:
        for method in methods:
            rs = _group(int(sender_id), str(method))
            if not rs:
                continue

            # Overhead is defined as extra transmitted bytes over payload.
            # We compute overhead stats over successful runs only.
            overheads_ok = [float(r.overhead_ratio) for r in rs if r.success == 1 and np.isfinite(r.overhead_ratio)]
            overhead_mean = float(np.mean(overheads_ok)) if overheads_ok else 0.0
            overhead_median = float(np.median(overheads_ok)) if overheads_ok else 0.0

            for ddl_ms in ddl_list:
                complete_n = 0
                for r in rs:
                    if r.success == 1 and r.e2e_delay_ms > 0 and float(r.e2e_delay_ms) <= float(ddl_ms):
                        complete_n += 1
                complete_ratio = float(complete_n) / float(len(rs))

                agg_rows.append(
                    {
                        "sender_id": int(sender_id),
                        "ddl_ms": int(ddl_ms),
                        "method": str(method),
                        "n": int(len(rs)),
                        "complete_n": int(complete_n),
                        "complete_ratio": float(complete_ratio),
                        "overhead_mean": float(overhead_mean),
                        "overhead_median": float(overhead_median),
                        "loss_mode": rs[0].loss_mode,
                    }
                )

    out_agg = out_dir / "scatter.csv"
    with out_agg.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "sender_id",
                "ddl_ms",
                "method",
                "n",
                "complete_n",
                "complete_ratio",
                "overhead_mean",
                "overhead_median",
                "loss_mode",
            ],
        )
        w.writeheader()
        for r in agg_rows:
            w.writerow(
                {
                    "sender_id": r["sender_id"],
                    "ddl_ms": r["ddl_ms"],
                    "method": r["method"],
                    "n": r["n"],
                    "complete_n": r["complete_n"],
                    "complete_ratio": f"{r['complete_ratio']:.6f}",
                    "overhead_mean": f"{r['overhead_mean']:.6f}",
                    "overhead_median": f"{r['overhead_median']:.6f}",
                    "loss_mode": r["loss_mode"],
                }
            )

    meta: Dict[str, Any] = {
        "ddl_ms": ddl_list,
        "methods": methods,
        "overhead_definition": "(tx_bytes - file_bytes)/file_bytes using host veth0 tx_bytes delta; includes headers",
        "complete_definition": "success && e2e_delay_ms <= ddl_ms (e2e_delay_ms = dur_ms + rtt_ms/2)",
        "plot_only": bool(plot_only),
    }
    if plot_only:
        meta.update(
            {
                "base_runs_csv": str(getattr(args, "base_runs_csv", "")),
                "flec_jsonl": str(getattr(args, "flec_jsonl", "")),
            }
        )
    else:
        meta.update(
            {
                "bandit_model_prefix": model_prefix,
                "ge_params": str(params_path),
                "ge_key": str(args.ge_key),
                "sender_ids": sender_ids,
                "bitrate_mbps": int(args.bitrate_mbps),
                "rtt_ms": "per-sender (from ge_params['senders'][sid]['rtt_ms']); fallback to --rtt-ms",
                "timeout_transfer_s": int(args.timeout_transfer_s),
                "timeout_s": int(args.timeout_s),
                "file_bytes": int(args.file_bytes),
                "reps": int(args.reps),
                "ddl_override_ms": int(proto_ddl_ms),
                "fixed_ddl_ms": int(args.fixed_ddl_ms),
                "symbol_bytes": int(args.symbol_bytes),
                "warmup_a_idx": int(args.warmup_a_idx),
                "fixed1": {"k": int(fixed1[0]), "r0": int(fixed1[1]), "rstep": int(fixed1[2])},
                "fixed2": {"k": int(fixed2[0]), "r0": int(fixed2[1]), "rstep": int(fixed2[2])},
            }
        )
    (out_dir / "meta.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    method_labels: Dict[str, str] = {
        "bandit": "QUIC-FEC-Bandit",
        "quic_bbrv2": "QUIC",
        "flec": "FLEC",
    }
    method_colors: Dict[str, str] = {
        "bandit": "#1f77b4",
        "quic_bbrv2": "#ff7f0e",
        "flec": "#9467bd",
    }
    method_markers: Dict[str, str] = {
        "bandit": "o",
        "quic_bbrv2": "^",
        "flec": "x",
    }

    fec_methods = sorted({str(m) for m in methods if str(m).startswith("fec_")})
    fec_palette = ["#2ca02c", "#d62728", "#17becf", "#bcbd22", "#8c564b", "#e377c2"]
    fec_markers = ["s", "D", "P", "X", "v", "<"]
    for i, m in enumerate(fec_methods):
        mm = _FEC_METHOD_RE.match(m)
        if mm:
            method_labels[m] = (
                f"QUIC-FEC(K={int(mm.group('k'))},R0={int(mm.group('r0'))},Rstep={int(mm.group('rstep'))})"
            )
        else:
            method_labels[m] = m
        method_colors.setdefault(m, fec_palette[i % len(fec_palette)])
        method_markers.setdefault(m, fec_markers[i % len(fec_markers)])

    # Plot: 2x2 subplots (one per ddl), each subplot overlays 4 methods.
    _configure_matplotlib()
    fig, axes = plt.subplots(2, 2, figsize=(7.2, 6.0), sharex=False, sharey=True)
    axes_flat = list(axes.flatten())

    for i, ddl_ms in enumerate(ddl_list[:4]):
        ax = axes_flat[i]
        for method in methods:
            pts = [r for r in agg_rows if int(r["ddl_ms"]) == int(ddl_ms) and str(r["method"]) == str(method)]
            xs = [float(r["overhead_mean"]) for r in pts]
            ys = [float(r["complete_ratio"]) for r in pts]
            ax.scatter(
                xs,
                ys,
                s=26,
                alpha=0.85,
                marker=method_markers.get(str(method), "o"),
                color=method_colors.get(str(method), None),
                label=method_labels.get(str(method), str(method)),
            )
        ax.set_title(f"DDL={int(ddl_ms)}ms")
        ax.set_xlabel("overhead")
        ax.set_ylim(-0.02, 1.02)
        if i % 2 == 0:
            ax.set_ylabel("Completion ratio")
        ax.legend(loc="lower right", frameon=True)

    # Hide any unused axes
    for j in range(len(ddl_list[:4]), 4):
        axes_flat[j].axis("off")

    fig.tight_layout()
    out_fig = out_dir / "fig_overhead_vs_completion_2x2.pdf"
    fig.savefig(out_fig)
    fig.savefig(out_fig.with_suffix(".png"))
    plt.close(fig)

    # Also save per-DDL single plots
    for ddl_ms in ddl_list:
        _configure_matplotlib()
        fig1, ax1 = plt.subplots()
        for method in methods:
            pts = [r for r in agg_rows if int(r["ddl_ms"]) == int(ddl_ms) and str(r["method"]) == str(method)]
            xs = [float(r["overhead_mean"]) for r in pts]
            ys = [float(r["complete_ratio"]) for r in pts]
            ax1.scatter(
                xs,
                ys,
                s=28,
                alpha=0.85,
                marker=method_markers.get(str(method), "o"),
                color=method_colors.get(str(method), None),
                label=method_labels.get(str(method), str(method)),
            )
        ax1.set_xlabel("overhead")
        ax1.set_ylabel("Completion ratio")
        ax1.set_ylim(-0.02, 1.02)
        ax1.set_title(f"Overhead vs completion ratio (DDL={int(ddl_ms)}ms)")
        ax1.legend(loc="lower right", frameon=True)
        fig1.tight_layout()
        p = out_dir / f"fig_overhead_vs_completion_ddl{int(ddl_ms)}.pdf"
        fig1.savefig(p)
        fig1.savefig(p.with_suffix(".png"))
        plt.close(fig1)

    print("\nOUT:", out_dir)
    print("- runs:", out_csv)
    print("- scatter:", out_agg)
    print("- fig:", out_fig)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
