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
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import numpy as np

# matplotlib is used only for plotting (paper-style figures)
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
from bandit.run_lints_ge_schedule import _ge_to_tc_gemodel_loss_mode  # noqa: E402


# ---------------------------
# Parsing / utils
# ---------------------------


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
    # de-dup, preserve order
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
    # Example: [run] proto=... dur_ms=... timed_out=0 md5_ok=1 s_mbps=...
    out: Dict[str, str] = {}
    for tok in (line or "").strip().split():
        if "=" not in tok:
            continue
        k, v = tok.split("=", 1)
        if k.startswith("["):
            continue
        out[k.strip()] = v.strip()
    return out


def _to_float(d: Dict[str, str], k: str, default: float = 0.0) -> float:
    try:
        return float(d.get(k, str(default)))
    except Exception:
        return default


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
            capture_output=True,
            text=True,
            timeout=int(timeout_s),
        )
        return p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired as e:
        # Ensure downstream sees a [run] line.
        out = (e.stdout or "") if isinstance(e.stdout, str) else ""
        err = (e.stderr or "") if isinstance(e.stderr, str) else ""
        err = err + "\n" + "[run] proto=timeout dur_ms=0 timed_out=1 md5_ok=0 s_mbps=0\n"
        return out, err


def _extract_last_rl_observation(stderr: str) -> Optional[Dict[str, Any]]:
    line = _extract_last_line("[rl-observation]", stderr)
    if not line:
        return None
    try:
        payload = line.split(" ", 1)[1]
        return json.loads(payload)
    except Exception:
        return None


# ---------------------------
# Bandit helpers
# ---------------------------


def _bandit_select_action_mean(*, agent, action_set: ActionSet, ctx: ContextBuilder) -> Tuple[int, Dict[str, Any]]:
    x = ctx.get_context()
    Phi = np.zeros((len(action_set), agent.dim), dtype=np.float32)
    for i, _a in action_set.iter_actions():
        Phi[i, :] = phi_fn(x=x, a_onehot=action_set.get_onehot(i))

    theta = np.asarray(agent.theta_hat, dtype=np.float64).reshape(-1)
    scores = Phi.astype(np.float64) @ theta
    a_idx = int(np.argmax(scores))
    return a_idx, {"x": x.tolist(), "a_idx": a_idx, "score": float(scores[a_idx])}


def _action_to_env_vars(*, action_set: ActionSet, a_idx: int, symbol_bytes: int) -> Dict[str, str]:
    spec = action_set.get_action(a_idx)
    env_action = spec.to_env_action()
    k_idx, r0_idx, rstep_idx, ddl_idx = (int(env_action[0]), int(env_action[1]), int(env_action[2]), int(env_action[3]))

    K = 10 + k_idx
    r0_pct = 0.05 * float(r0_idx)
    R0 = int(float(K) * r0_pct)
    RSTEP = 1 + rstep_idx
    ddl_ms_values = [100, 150, 200, 250, 300, 350]
    DDL_MS = int(ddl_ms_values[int(ddl_idx)])

    return {
        "K": str(int(K)),
        "SYMBOL_BYTES": str(int(symbol_bytes)),
        "R0": str(int(R0)),
        "W": os.environ.get("W", "8"),
        "RSTEP": str(int(RSTEP)),
        "DDL_MS": str(int(DDL_MS)),
        "ALPHA": os.environ.get("ALPHA", "0.6"),
        "MAX_ATTEMPTS": os.environ.get("MAX_ATTEMPTS", "5"),
        "USE_ARQ": os.environ.get("USE_ARQ", "1"),
        "QUIC_FEC_CC_BYPASS": "0",
        "QUIC_FEC_CC_ALGO": "bbrv2",
        "PACE_US": "0",
    }


def _aligned_obs_vec_from_rl_observation(*, rl_obs: Optional[Dict[str, Any]], ddl_ms: int, failed: bool) -> np.ndarray:
    """Construct training observation vector.

    Layout matches python/fecenv_env.py:
      [goodput, decode_latency_p95_ms, fec_overhead_pct_arrival,
       ctrl_tx_nack_msgs, arq_attempts_mean, residual_erasures,
       fec_rate, ddl_ms]
    """

    if failed or not isinstance(rl_obs, dict):
        goodput_mbps = 0.0
        decode_latency_p95_ms = 0.0
        fec_overhead_pct_arrival = 0.0
        ctrl_tx_nack_msgs = 0.0
        arq_attempts_mean = 2.0
        residual_erasures = 1.0
        fec_rate = 0.0
    else:
        def _f(k: str, default: float = 0.0) -> float:
            try:
                return float(rl_obs.get(k, default))
            except Exception:
                return default

        goodput_mbps = _f("goodput", _f("goodput_mbps", _f("goodput_arrival_mbps", _f("goodput_decode_mbps", 0.0))))
        decode_latency_p95_ms = _f("decode_latency_p95_ms", 0.0)
        fec_overhead_pct_arrival = _f("fec_overhead_pct_arrival", 0.0)
        ctrl_tx_nack_msgs = _f("ctrl_tx_nack_msgs", 0.0)
        arq_attempts_mean = _f("arq_attempts_mean", 0.0)
        residual_erasures = _f("residual_erasures", 0.0)
        fec_rate = _f("fec_rate", 0.0)

    return np.asarray(
        [
            float(goodput_mbps),
            float(decode_latency_p95_ms),
            float(fec_overhead_pct_arrival),
            float(ctrl_tx_nack_msgs),
            float(arq_attempts_mean),
            float(residual_erasures),
            float(np.clip(float(fec_rate), 0.0, 1.0)),
            float(int(ddl_ms)),
        ],
        dtype=np.float32,
    )


# ---------------------------
# Experiment
# ---------------------------


@dataclass
class Row:
    task: str  # delay_128kb | goodput_3mb
    method: str
    sender_id: int
    loss_mode: str
    rep: int
    is_warmup: int
    timed_out: int
    md5_ok: int
    success: int
    dur_ms: int
    goodput_mbps: float
    a_idx: int
    extra: Dict[str, Any]


_METHOD_ORDER = [
    "bandit",
    "quic_bbrv2",
    "fec_k20_r0_2_rstep_2",
    "fec_k20_r0_6_rstep_4",
]

_METHOD_LABELS = {
    "bandit": "QUIC-FEC-Bandit",
    "quic_bbrv2": "QUIC",
    "fec_k20_r0_2_rstep_2": "QUIC-FEC(K=20,R0=2,Rstep=2)",
    "fec_k20_r0_6_rstep_4": "QUIC-FEC(K=20,R0=6,Rstep=4)",
}

_METHOD_COLORS = {
    "bandit": "#1f77b4",
    "quic_bbrv2": "#ff7f0e",
    "fec_k20_r0_2_rstep_2": "#2ca02c",
    "fec_k20_r0_6_rstep_4": "#d62728",
}


def _configure_matplotlib() -> None:
    plt.rcParams.update(
        {
            "figure.figsize": (6.2, 3.6),
            "font.size": 10,
            "axes.labelsize": 10,
            "axes.titlesize": 10,
            "legend.fontsize": 7,
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


def _ecdf(values: Sequence[float]) -> Tuple[np.ndarray, np.ndarray]:
    x = np.asarray([v for v in values if np.isfinite(v)], dtype=np.float64)
    if x.size == 0:
        return np.asarray([], dtype=np.float64), np.asarray([], dtype=np.float64)
    x = np.sort(x)
    y = np.arange(1, x.size + 1, dtype=np.float64) / float(x.size)
    return x, y


def _plot_cdf(
    *,
    out_path: Path,
    title: str,
    xlabel: str,
    series: List[Tuple[str, Sequence[float], float]],
    xlim: Optional[Tuple[float, float]] = None,
    show_ok_n_in_legend: bool = True,
) -> None:
    _configure_matplotlib()
    fig, ax = plt.subplots()

    for method, values, ok_rate in series:
        x, y = _ecdf(values)
        if x.size == 0:
            continue
        if show_ok_n_in_legend:
            label = f"{_METHOD_LABELS.get(method, method)} (ok={ok_rate:.2f}, n={len(x)})"
        else:
            label = f"{_METHOD_LABELS.get(method, method)}"
        ax.plot(x, y, label=label, color=_METHOD_COLORS.get(method, None))

    if title:
        ax.set_title(title)
    ax.set_xlabel(xlabel)
    ax.set_ylabel("CDF")
    ax.set_ylim(0.0, 1.0)
    if xlim is not None:
        ax.set_xlim(float(xlim[0]), float(xlim[1]))
    ax.legend(loc="lower right", frameon=True)
    fig.tight_layout()

    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path)
    if out_path.suffix.lower() != ".png":
        fig.savefig(out_path.with_suffix(".png"))
    plt.close(fig)


def _plot_goodput_box(
    *,
    out_path: Path,
    title: str,
    xlabel: str,
    data_by_method: List[Tuple[str, Sequence[float], float]],
) -> None:
    _configure_matplotlib()
    fig, ax = plt.subplots()

    methods = [m for m, _vals, _ok in data_by_method]
    values = [np.asarray(list(vals), dtype=np.float64) for _m, vals, _ok in data_by_method]
    ok_rates = [float(ok) for _m, _vals, ok in data_by_method]

    positions = np.arange(1, len(methods) + 1, dtype=np.float64)
    bp = ax.boxplot(
        values,
        positions=positions,
        widths=0.6,
        patch_artist=True,
        showfliers=True,
        medianprops={"color": "black", "linewidth": 1.3},
        whiskerprops={"linewidth": 1.0},
        capprops={"linewidth": 1.0},
    )
    for patch, method in zip(bp["boxes"], methods):
        patch.set_facecolor(_METHOD_COLORS.get(method, "#cccccc"))
        patch.set_alpha(0.35)
        patch.set_edgecolor(_METHOD_COLORS.get(method, "#333333"))

    for x, vals, ok in zip(positions, values, ok_rates):
        if vals.size > 0:
            ax.plot([x], [float(np.mean(vals))], marker="o", markersize=4, color="black")
        ax.text(x, 1.02, f"ok={ok:.2f}", ha="center", va="bottom", transform=ax.get_xaxis_transform())

    ax.set_title(title)
    ax.set_ylabel(xlabel)
    ax.set_xticks(positions)
    ax.set_xticklabels([_METHOD_LABELS.get(m, m) for m in methods], rotation=12, ha="right")
    ax.set_ylim(bottom=0.0)
    fig.tight_layout()

    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path)
    if out_path.suffix.lower() != ".png":
        fig.savefig(out_path.with_suffix(".png"))
    plt.close(fig)


def _load_sender_ids(*, params_path: Path, sender_ids_arg: str, ge_key: str) -> List[int]:
    data = json.loads(params_path.read_text(encoding="utf-8"))
    senders = data.get("senders")
    if not isinstance(senders, dict):
        raise ValueError("invalid 'senders' in ge params")

    requested = _parse_int_list(sender_ids_arg)
    if requested == [-1]:
        # all senders with ge_key
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

    # explicit
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


def _method_env_fixed_fec(*, k: int, r0: int, rstep: int, ddl_ms: int, symbol_bytes: int) -> Dict[str, str]:
    return {
        "K": str(int(k)),
        "SYMBOL_BYTES": str(int(symbol_bytes)),
        "R0": str(int(r0)),
        "W": os.environ.get("W", "8"),
        "RSTEP": str(int(rstep)),
        "DDL_MS": str(int(ddl_ms)),
        "ALPHA": os.environ.get("ALPHA", "0.6"),
        "MAX_ATTEMPTS": os.environ.get("MAX_ATTEMPTS", "5"),
        "USE_ARQ": os.environ.get("USE_ARQ", "1"),
        "QUIC_FEC_CC_BYPASS": "0",
        "QUIC_FEC_CC_ALGO": "bbrv2",
        "PACE_US": "0",
    }


def _run_one(
    *,
    method: str,
    task: str,
    loss_mode: str,
    bitrate_mbps: int,
    rtt_ms: int,
    timeout_transfer_s: int,
    timeout_s: int,
    file_path: Path,
    fec_env: Optional[Dict[str, str]] = None,
) -> Tuple[Dict[str, Any], str]:
    """Run one trial, return parsed metrics + raw stderr."""

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
        _stdout, stderr = _run_bash_script(script=_REPO_ROOT / "scripts" / "quicraw_run_once.sh", env=env, timeout_s=timeout_s)
    elif method.startswith("fec_") or method == "bandit":
        if not fec_env:
            raise ValueError("fec_env is required for fec/bandit methods")
        env = {**common_env, **fec_env}
        _stdout, stderr = _run_bash_script(script=_REPO_ROOT / "scripts" / "quicfec_run_once.sh", env=env, timeout_s=timeout_s)
    else:
        raise ValueError(f"unknown method={method}")

    run_line = _extract_last_line("[run]", stderr) or ""
    kv = _parse_kv_from_run_line(run_line)

    dur_ms = _to_int(kv, "dur_ms", 0)
    timed_out = _to_int(kv, "timed_out", 0)
    md5_ok = _to_int(kv, "md5_ok", 0)
    goodput = _to_float(kv, "s_mbps", 0.0)

    # Failures -> goodput=0. For delay task we use success-only samples downstream.
    if timed_out or md5_ok != 1:
        goodput = 0.0

    return {
        "dur_ms": int(dur_ms),
        "timed_out": int(timed_out),
        "md5_ok": int(md5_ok),
        "goodput_mbps": float(goodput),
    }, stderr


def main() -> int:
    ap = argparse.ArgumentParser(description="Paper-style comparison under GE_steady_rp (E2E delay and/or goodput)")
    ap.add_argument(
        "--bandit-model-prefix",
        type=str,
        required=True,
        help="Trained bandit model prefix (no .json/.npz), e.g. python/results/.../model_tXXXX_r0pYYYY",
    )
    ap.add_argument("--ge-params", type=str, default=str(_REPO_ROOT / "python" / "bandit" / "quic_fec_params.json"))
    ap.add_argument("--ge-key", type=str, default="GE_steady_rp")
    ap.add_argument("--sender-ids", type=str, default="100", help="Comma list / ranges, e.g. 100,106,112 or 100-160 or 'all'")
    ap.add_argument("--ge-h-pct", type=float, default=0.0)
    ap.add_argument("--ge-k-pct", type=float, default=99.0)

    ap.add_argument("--bitrate-mbps", type=int, default=10)
    ap.add_argument("--rtt-ms", type=int, default=25)
    ap.add_argument("--timeout-transfer-s", type=int, default=15)
    ap.add_argument("--timeout-s", type=int, default=180, help="Python-side subprocess timeout; must exceed transfer timeout")

    ap.add_argument("--reps", type=int, default=10)
    ap.add_argument("--warmup-a-idx", type=int, default=2845)

    ap.add_argument("--delay-file-bytes", type=int, default=128 * 1024)
    ap.add_argument("--goodput-file-bytes", type=int, default=3 * 1024 * 1024)

    ap.add_argument(
        "--symbol-bytes",
        type=int,
        default=1200,
        help="SYMBOL_BYTES for QUIC-FEC datagrams (default: 1200)",
    )

    ap.add_argument(
        "--which",
        type=str,
        default="both",
        choices=["delay", "goodput", "both"],
        help="Which experiments to run: delay (128KB), goodput (3MB), or both.",
    )

    ap.add_argument("--out-dir", type=str, default="")

    args = ap.parse_args()

    model_prefix = str(args.bandit_model_prefix)
    if model_prefix.endswith(".json"):
        model_prefix = model_prefix[:-5]
    if model_prefix.endswith(".npz"):
        model_prefix = model_prefix[:-4]

    params_path = Path(args.ge_params)
    sender_ids = _load_sender_ids(params_path=params_path, sender_ids_arg=str(args.sender_ids), ge_key=str(args.ge_key))

    # Files
    file_delay = _REPO_ROOT / "go" / "test_data" / f"paper_delay_{int(args.delay_file_bytes)}B.bin"
    file_goodput = _REPO_ROOT / "go" / "test_data" / f"paper_goodput_{int(args.goodput_file_bytes)}B.bin"
    _ensure_file_of_size(file_path=file_delay, file_bytes=int(args.delay_file_bytes))
    _ensure_file_of_size(file_path=file_goodput, file_bytes=int(args.goodput_file_bytes))

    # Load bandit checkpoint
    agent, _cfg, _ctx0, ctx_cfg, action_set, _t0 = load_checkpoint(path_prefix=model_prefix)

    ts = _now_ts()
    out_dir = Path(args.out_dir) if args.out_dir else (_REPO_ROOT / "python" / "results" / f"paper-ge-steady-rp-{ts}")
    out_dir.mkdir(parents=True, exist_ok=True)

    rows: List[Row] = []

    which = str(args.which).strip().lower()
    if which == "delay":
        tasks = [("delay_128kb", file_delay)]
    elif which == "goodput":
        tasks = [("goodput_3mb", file_goodput)]
    else:
        tasks = [
            ("delay_128kb", file_delay),
            ("goodput_3mb", file_goodput),
        ]
    ran_tasks = {t for t, _p in tasks}

    for sender_id in sender_ids:
        ge = _load_sender_ge(params_path=params_path, sender_id=int(sender_id), ge_key=str(args.ge_key))
        loss_mode = _ge_to_tc_gemodel_loss_mode(ge, h_loss_pct=float(args.ge_h_pct), k_loss_pct=float(args.ge_k_pct))
        print(f"[ge] sender_id={sender_id} loss_mode={loss_mode}")

        for task, file_path in tasks:
            print(f"[task] {task} file={file_path.name}")

            # Bandit state is per-(sender,task) sequence.
            ctx = ContextBuilder(cfg=ctx_cfg)
            ctx.reset()

            # Bandit warmup (excluded from stats): run a_idx=warmup-a-idx once.
            warmup_idx = int(args.warmup_a_idx)
            warmup_env = _action_to_env_vars(action_set=action_set, a_idx=warmup_idx, symbol_bytes=int(args.symbol_bytes))
            warmup_ddl_ms = int(warmup_env.get("DDL_MS", "150"))
            m, stderr = _run_one(
                method="bandit",
                task=task,
                loss_mode=loss_mode,
                bitrate_mbps=int(args.bitrate_mbps),
                rtt_ms=int(args.rtt_ms),
                timeout_transfer_s=int(args.timeout_transfer_s),
                timeout_s=int(args.timeout_s),
                file_path=file_path,
                fec_env=warmup_env,
            )
            rl_obs = _extract_last_rl_observation(stderr)
            failed = bool(int(m["timed_out"]) or int(m["md5_ok"]) != 1)
            obs_vec = _aligned_obs_vec_from_rl_observation(rl_obs=rl_obs, ddl_ms=warmup_ddl_ms, failed=failed)
            ctx.update_from_obs(obs=obs_vec, ddl_ms=warmup_ddl_ms)
            rows.append(
                Row(
                    task=task,
                    method="bandit",
                    sender_id=int(sender_id),
                    loss_mode=str(loss_mode),
                    rep=-1,
                    is_warmup=1,
                    timed_out=int(m["timed_out"]),
                    md5_ok=int(m["md5_ok"]),
                    success=1 if (int(m["timed_out"]) == 0 and int(m["md5_ok"]) == 1) else 0,
                    dur_ms=int(m["dur_ms"]),
                    goodput_mbps=float(m["goodput_mbps"]),
                    a_idx=int(warmup_idx),
                    extra={"warmup": True},
                )
            )

            # Measured runs
            for rep in range(int(args.reps)):
                # Bandit
                a_idx, dbg = _bandit_select_action_mean(agent=agent, action_set=action_set, ctx=ctx)
                fec_env = _action_to_env_vars(action_set=action_set, a_idx=a_idx, symbol_bytes=int(args.symbol_bytes))
                ddl_ms = int(fec_env.get("DDL_MS", "150"))

                m, stderr = _run_one(
                    method="bandit",
                    task=task,
                    loss_mode=loss_mode,
                    bitrate_mbps=int(args.bitrate_mbps),
                    rtt_ms=int(args.rtt_ms),
                    timeout_transfer_s=int(args.timeout_transfer_s),
                    timeout_s=int(args.timeout_s),
                    file_path=file_path,
                    fec_env=fec_env,
                )
                rl_obs = _extract_last_rl_observation(stderr)
                failed = bool(int(m["timed_out"]) or int(m["md5_ok"]) != 1)
                obs_vec = _aligned_obs_vec_from_rl_observation(rl_obs=rl_obs, ddl_ms=ddl_ms, failed=failed)
                ctx.update_from_obs(obs=obs_vec, ddl_ms=ddl_ms)

                rows.append(
                    Row(
                        task=task,
                        method="bandit",
                        sender_id=int(sender_id),
                        loss_mode=str(loss_mode),
                        rep=int(rep),
                        is_warmup=0,
                        timed_out=int(m["timed_out"]),
                        md5_ok=int(m["md5_ok"]),
                        success=1 if (int(m["timed_out"]) == 0 and int(m["md5_ok"]) == 1) else 0,
                        dur_ms=int(m["dur_ms"]),
                        goodput_mbps=float(m["goodput_mbps"]),
                        a_idx=int(a_idx),
                        extra={"bandit": dbg},
                    )
                )

                # QUIC BBRv2 (raw)
                m2, _stderr2 = _run_one(
                    method="quic_bbrv2",
                    task=task,
                    loss_mode=loss_mode,
                    bitrate_mbps=int(args.bitrate_mbps),
                    rtt_ms=int(args.rtt_ms),
                    timeout_transfer_s=int(args.timeout_transfer_s),
                    timeout_s=int(args.timeout_s),
                    file_path=file_path,
                )
                rows.append(
                    Row(
                        task=task,
                        method="quic_bbrv2",
                        sender_id=int(sender_id),
                        loss_mode=str(loss_mode),
                        rep=int(rep),
                        is_warmup=0,
                        timed_out=int(m2["timed_out"]),
                        md5_ok=int(m2["md5_ok"]),
                        success=1 if (int(m2["timed_out"]) == 0 and int(m2["md5_ok"]) == 1) else 0,
                        dur_ms=int(m2["dur_ms"]),
                        goodput_mbps=float(m2["goodput_mbps"]),
                        a_idx=-1,
                        extra={},
                    )
                )

                # Fixed FEC #1
                env_f1 = _method_env_fixed_fec(k=20, r0=2, rstep=2, ddl_ms=150, symbol_bytes=int(args.symbol_bytes))
                m3, _stderr3 = _run_one(
                    method="fec_k20_r0_2_rstep_2",
                    task=task,
                    loss_mode=loss_mode,
                    bitrate_mbps=int(args.bitrate_mbps),
                    rtt_ms=int(args.rtt_ms),
                    timeout_transfer_s=int(args.timeout_transfer_s),
                    timeout_s=int(args.timeout_s),
                    file_path=file_path,
                    fec_env=env_f1,
                )
                rows.append(
                    Row(
                        task=task,
                        method="fec_k20_r0_2_rstep_2",
                        sender_id=int(sender_id),
                        loss_mode=str(loss_mode),
                        rep=int(rep),
                        is_warmup=0,
                        timed_out=int(m3["timed_out"]),
                        md5_ok=int(m3["md5_ok"]),
                        success=1 if (int(m3["timed_out"]) == 0 and int(m3["md5_ok"]) == 1) else 0,
                        dur_ms=int(m3["dur_ms"]),
                        goodput_mbps=float(m3["goodput_mbps"]),
                        a_idx=-1,
                        extra={"fec": {"K": 20, "R0": 2, "RSTEP": 2, "DDL_MS": 150}},
                    )
                )

                # Fixed FEC #2
                env_f2 = _method_env_fixed_fec(k=20, r0=6, rstep=4, ddl_ms=150, symbol_bytes=int(args.symbol_bytes))
                m4, _stderr4 = _run_one(
                    method="fec_k20_r0_6_rstep_4",
                    task=task,
                    loss_mode=loss_mode,
                    bitrate_mbps=int(args.bitrate_mbps),
                    rtt_ms=int(args.rtt_ms),
                    timeout_transfer_s=int(args.timeout_transfer_s),
                    timeout_s=int(args.timeout_s),
                    file_path=file_path,
                    fec_env=env_f2,
                )
                rows.append(
                    Row(
                        task=task,
                        method="fec_k20_r0_6_rstep_4",
                        sender_id=int(sender_id),
                        loss_mode=str(loss_mode),
                        rep=int(rep),
                        is_warmup=0,
                        timed_out=int(m4["timed_out"]),
                        md5_ok=int(m4["md5_ok"]),
                        success=1 if (int(m4["timed_out"]) == 0 and int(m4["md5_ok"]) == 1) else 0,
                        dur_ms=int(m4["dur_ms"]),
                        goodput_mbps=float(m4["goodput_mbps"]),
                        a_idx=-1,
                        extra={"fec": {"K": 20, "R0": 6, "RSTEP": 4, "DDL_MS": 150}},
                    )
                )

                print(
                    f"rep={rep:02d} bandit(a={a_idx}) dur_ms={m['dur_ms']} ok={1-int(m['timed_out'])==1 and int(m['md5_ok'])==1} | "
                    f"quic_bbrv2 dur_ms={m2['dur_ms']} | fec1 dur_ms={m3['dur_ms']} | fec2 dur_ms={m4['dur_ms']}"
                )

    # Save raw results
    out_jsonl = out_dir / "results.jsonl"
    with out_jsonl.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(
                json.dumps(
                    {
                        "task": r.task,
                        "method": r.method,
                        "sender_id": r.sender_id,
                        "loss_mode": r.loss_mode,
                        "rep": r.rep,
                        "is_warmup": r.is_warmup,
                        "timed_out": r.timed_out,
                        "md5_ok": r.md5_ok,
                        "success": r.success,
                        "dur_ms": r.dur_ms,
                        "goodput_mbps": r.goodput_mbps,
                        "a_idx": r.a_idx,
                        "extra": r.extra,
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )

    out_csv = out_dir / "results.csv"
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "task",
                "method",
                "sender_id",
                "loss_mode",
                "rep",
                "is_warmup",
                "timed_out",
                "md5_ok",
                "success",
                "dur_ms",
                "goodput_mbps",
                "a_idx",
            ],
        )
        w.writeheader()
        for r in rows:
            w.writerow(
                {
                    "task": r.task,
                    "method": r.method,
                    "sender_id": r.sender_id,
                    "loss_mode": r.loss_mode,
                    "rep": r.rep,
                    "is_warmup": r.is_warmup,
                    "timed_out": r.timed_out,
                    "md5_ok": r.md5_ok,
                    "success": r.success,
                    "dur_ms": r.dur_ms,
                    "goodput_mbps": f"{r.goodput_mbps:.6f}",
                    "a_idx": r.a_idx,
                }
            )

    meta = {
        "bandit_model_prefix": model_prefix,
        "ge_params": str(params_path),
        "ge_key": str(args.ge_key),
        "sender_ids": sender_ids,
        "bitrate_mbps": int(args.bitrate_mbps),
        "rtt_ms": int(args.rtt_ms),
        "timeout_transfer_s": int(args.timeout_transfer_s),
        "timeout_s": int(args.timeout_s),
        "reps": int(args.reps),
        "warmup_a_idx": int(args.warmup_a_idx),
        "delay_file_bytes": int(args.delay_file_bytes),
        "goodput_file_bytes": int(args.goodput_file_bytes),
        "symbol_bytes": int(args.symbol_bytes),
        "which": which,
        "tasks": sorted(list(ran_tasks)),
        "methods": _METHOD_ORDER,
    }
    (out_dir / "meta.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    # Aggregate plots across all sender_ids.
    def _filter_rows(task_name: str, method: str) -> List[Row]:
        return [r for r in rows if r.task == task_name and r.method == method and r.is_warmup == 0]

    if "delay_128kb" in ran_tasks:
        # Delay CDF: success-only samples (completion time).
        delay_series: List[Tuple[str, Sequence[float], float]] = []
        for m in _METHOD_ORDER:
            rs = _filter_rows("delay_128kb", m)
            d_ok = [float(r.dur_ms) for r in rs if r.success == 1 and r.dur_ms > 0]
            ok_rate = (sum([1 for r in rs if r.success == 1]) / float(len(rs))) if rs else 0.0
            delay_series.append((m, d_ok, ok_rate))

        _plot_cdf(
            out_path=out_dir / "fig_delay_cdf.pdf",
            title="",
            xlabel="E2E delay per message (ms)",
            series=delay_series,
            xlim=(0.0, 300.0),
            show_ok_n_in_legend=False,
        )

    gp_series: List[Tuple[str, Sequence[float], float]] = []
    if "goodput_3mb" in ran_tasks:
        # Goodput CDF: include failures as 0 Mbps.
        for m in _METHOD_ORDER:
            rs = _filter_rows("goodput_3mb", m)
            gp = [float(r.goodput_mbps) for r in rs]
            ok_rate = (sum([1 for r in rs if r.success == 1]) / float(len(rs))) if rs else 0.0
            gp_series.append((m, gp, ok_rate))

        _plot_cdf(
            out_path=out_dir / "fig_goodput_cdf.pdf",
            title="Goodput CDF (3MB transfer)",
            xlabel="Goodput (Mbps)",
            series=gp_series,
            xlim=(0.0, max([max(v) for _m, v, _ok in gp_series if len(v) > 0] + [1.0])),
        )

        _plot_goodput_box(
            out_path=out_dir / "fig_goodput_box.pdf",
            title="Goodput (3MB transfer)",
            xlabel="Goodput (Mbps)",
            data_by_method=gp_series,
        )

    # Summary stats (for paper tables / quick sanity)
    summary: Dict[str, Any] = {}
    if "delay_128kb" in ran_tasks:
        summary["delay_128kb"] = {}
    if "goodput_3mb" in ran_tasks:
        summary["goodput_3mb"] = {}

    def _stats(xs: Sequence[float]) -> Dict[str, float]:
        v = np.asarray([x for x in xs if np.isfinite(x)], dtype=np.float64)
        if v.size == 0:
            return {"n": 0.0}
        return {
            "n": float(v.size),
            "mean": float(np.mean(v)),
            "median": float(np.median(v)),
            "p05": float(np.quantile(v, 0.05)),
            "p95": float(np.quantile(v, 0.95)),
        }

    for m in _METHOD_ORDER:
        if "delay_128kb" in ran_tasks:
            rs_d = _filter_rows("delay_128kb", m)
            ok_rate_d = (sum([1 for r in rs_d if r.success == 1]) / float(len(rs_d))) if rs_d else 0.0
            d_ok = [float(r.dur_ms) for r in rs_d if r.success == 1 and r.dur_ms > 0]
            summary["delay_128kb"][m] = {"ok_rate": float(ok_rate_d), **_stats(d_ok)}

        if "goodput_3mb" in ran_tasks:
            rs_g = _filter_rows("goodput_3mb", m)
            ok_rate_g = (sum([1 for r in rs_g if r.success == 1]) / float(len(rs_g))) if rs_g else 0.0
            gp_all = [float(r.goodput_mbps) for r in rs_g]
            summary["goodput_3mb"][m] = {"ok_rate": float(ok_rate_g), **_stats(gp_all)}

    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print("\nOUT:", out_dir)
    print("- results:", out_jsonl)
    figs: List[Path] = []
    if "delay_128kb" in ran_tasks:
        figs.append(out_dir / "fig_delay_cdf.pdf")
    if "goodput_3mb" in ran_tasks:
        figs.extend([out_dir / "fig_goodput_box.pdf", out_dir / "fig_goodput_cdf.pdf"])
    if figs:
        print("- figs:   ", ", ".join([str(p) for p in figs]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
