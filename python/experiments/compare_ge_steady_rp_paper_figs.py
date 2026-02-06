#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import csv
import json
import os
import re
import subprocess
import time
import zlib
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
from bandit.context import ContextBuilder, ContextConfig  # noqa: E402
from bandit.features import phi as phi_fn  # noqa: E402
from bandit.model_io import load_checkpoint  # noqa: E402
from bandit.run_lints_ge_schedule import _ge_to_tc_gemodel_loss_mode  # noqa: E402


# ---------------------------
# Parsing / utils
# ---------------------------


def _now_ts() -> str:
    return time.strftime("%Y%m%d-%H%M%S")


def _default_run_tag() -> str:
    # Short, process-unique-ish tag to avoid netns/veth/IP collisions across concurrent runs.
    pid = os.getpid()
    t = int(time.time() * 1000)
    raw = f"{pid:x}{t:x}"
    raw = re.sub(r"[^0-9a-zA-Z]+", "", raw)
    return raw[:8] or "run"


def _netns_env_for_tag(tag: str) -> Dict[str, str]:
    tag = re.sub(r"[^0-9a-zA-Z]+", "", str(tag or ""))
    tag = tag[:8] if tag else _default_run_tag()

    # Linux iface name limit is 15 chars.
    veth_host = ("vh" + tag)[:15]
    veth_ns = ("vn" + tag)[:15]

    # Use a per-tag /24 to avoid host-side IP collisions between concurrent runs.
    subnet = 20 + (zlib.crc32(tag.encode("utf-8")) % 200)
    host_ip = f"10.10.{subnet}.1/24"
    ns_ip = f"10.10.{subnet}.2/24"

    return {
        "NS": f"qns_{tag}",
        "VETH_HOST": veth_host,
        "VETH_NS": veth_ns,
        "HOST_IP": host_ip,
        "NS_IP": ns_ip,
    }


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


def _parse_float_list(s: str) -> List[float]:
    s = (s or "").strip()
    if not s:
        return []
    out: List[float] = []
    for part in s.split(","):
        part = (part or "").strip()
        if not part:
            continue
        if part.endswith("%"):
            part = part[:-1]
        try:
            out.append(float(part))
        except Exception:
            continue
    return out


def _choose_rtt_ms(*, mode: str, fixed_rtt_ms: int, candidates: Sequence[int], seed32: int) -> int:
    mode = str(mode or "fixed").strip().lower()
    if mode != "random":
        return int(fixed_rtt_ms)
    cand = [int(x) for x in candidates if int(x) > 0]
    if not cand:
        return int(fixed_rtt_ms)
    rs = np.random.RandomState(int(seed32 & 0xFFFFFFFF))
    return int(cand[int(rs.randint(0, len(cand)))])


def _extract_last_line(prefix: str, s: str) -> Optional[str]:
        """Return the last line that starts with prefix.

        Notes:
            - When QUIC stats / progress logging is enabled, stderr may contain carriage
                returns ("\r") that can prefix or embed log lines. Normalize these so we
                don't miss the final "[run]" summary.
            - Some bash tooling can also emit leading whitespace; accept that.
        """

        last: Optional[str] = None
        normalized = (s or "").replace("\r", "\n")
        for raw_line in normalized.splitlines():
                line = (raw_line or "").lstrip()
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


def _overhead_ratio_from_run_kv(*, kv: Dict[str, str], file_path: Path) -> float:
    """Compute overhead as extra QUIC attempted send bytes over payload bytes.

    Prefer QUIC-layer stats emitted by scripts (pre-qdisc):
      - raw_quic_overhead_ratio / fec_quic_overhead_ratio
      - raw_quic_sent_bytes / fec_quic_sent_bytes

    Fall back to veth tx_bytes if QUIC stats are missing.
    """

    file_bytes = _to_int(kv, "file_bytes", int(file_path.stat().st_size))

    for key in ("raw_quic_overhead_ratio", "fec_quic_overhead_ratio"):
        if key in kv:
            v = _to_float(kv, key, 0.0)
            if np.isfinite(v) and v >= 0.0:
                return float(v)

    for sent_key in ("raw_quic_sent_bytes", "fec_quic_sent_bytes"):
        if sent_key in kv:
            sent_bytes = _to_int(kv, sent_key, 0)
            if file_bytes > 0 and sent_bytes > 0:
                return float(max(0.0, (float(sent_bytes) - float(file_bytes)) / float(file_bytes)))

    tx_bytes = _to_int(kv, "tx_bytes", 0)
    if file_bytes > 0 and tx_bytes > 0:
        return float(max(0.0, (float(tx_bytes) - float(file_bytes)) / float(file_bytes)))
    return 0.0


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
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=int(timeout_s),
        )
        return "", p.stderr or ""
    except subprocess.TimeoutExpired as e:
        # Ensure downstream sees a [run] line.
        out = ""
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


def _overhead_ratio_from_rl_observation(rl_obs: Optional[Dict[str, Any]]) -> float:
    """Return FEC overhead ratio (repairs/source) from an rl-observation payload."""

    if not isinstance(rl_obs, dict):
        return 0.0

    def _f(k: str, default: float = 0.0) -> float:
        try:
            return float(rl_obs.get(k, default))
        except Exception:
            return default

    # Preferred: direct ratio.
    if "fec_overhead" in rl_obs or "fec_overhead_pct_arrival" in rl_obs:
        overhead = _f("fec_overhead", _f("fec_overhead_pct_arrival", 0.0))
        # Backward-compat: older naming/scaling.
        if overhead > 10.0:
            overhead = overhead / 100.0
        return float(np.clip(overhead, 0.0, 10.0))

    # Fallback: derive from tx symbol counters if available.
    tx_src = _f("tx_source_symbols", _f("tx_source", 0.0))
    tx_rep = _f("tx_repair_symbols", _f("tx_repairs", 0.0))
    if tx_src > 0 and tx_rep >= 0:
        return float(np.clip(tx_rep / tx_src, 0.0, 10.0))

    return 0.0


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


def _bandit_select_action_ts(*, agent, action_set: ActionSet, ctx: ContextBuilder) -> Tuple[int, Dict[str, Any]]:
    """Select action using Thompson sampling (matches training runner behavior)."""

    x = ctx.get_context()
    Phi = np.zeros((len(action_set), agent.dim), dtype=np.float32)
    for i, _a in action_set.iter_actions():
        Phi[i, :] = phi_fn(x=x, a_onehot=action_set.get_onehot(i))

    a_idx, theta = agent.select(Phi)
    dbg: Dict[str, Any] = {"x": x.tolist(), "a_idx": int(a_idx)}
    try:
        if theta is not None:
            dbg["theta_norm"] = float(np.linalg.norm(theta))
    except Exception:
        pass
    return int(a_idx), dbg


def _bandit_select_action_mean_seeded(
    *,
    agent,
    action_set: ActionSet,
    ctx: ContextBuilder,
    seed32: int,
    sigma_scale: float = 1.0,
) -> Tuple[int, Dict[str, Any]]:
    """Deterministic (seeded) posterior draw + greedy argmax.

    This behaves like TS but is reproducible per decision, and tends to react to
    context changes because Phi changes even when the RNG seed is fixed.
    """

    x = ctx.get_context()
    Phi = np.zeros((len(action_set), agent.dim), dtype=np.float32)
    for i, _a in action_set.iter_actions():
        Phi[i, :] = phi_fn(x=x, a_onehot=action_set.get_onehot(i))

    theta_hat = np.asarray(agent.theta_hat, dtype=np.float64).reshape(-1)
    A_inv_raw = getattr(agent, "A_inv", None)
    if A_inv_raw is None:
        scores = Phi.astype(np.float64) @ theta_hat
        a_idx = int(np.argmax(scores))
        return a_idx, {"x": x.tolist(), "a_idx": a_idx, "seed32": int(seed32), "mode": "fallback_mean"}

    A_inv = np.asarray(A_inv_raw, dtype=np.float64)

    # If checkpoint is partial, fall back to greedy mean.
    if A_inv.ndim != 2 or A_inv.shape[0] != theta_hat.size or A_inv.shape[1] != theta_hat.size:
        scores = Phi.astype(np.float64) @ theta_hat
        a_idx = int(np.argmax(scores))
        return a_idx, {"x": x.tolist(), "a_idx": a_idx, "seed32": int(seed32), "mode": "fallback_mean"}

    sigma = float(getattr(getattr(agent, "cfg", None), "sigma", 0.2))
    sigma = float(sigma) * float(sigma_scale)
    if sigma < 0:
        sigma = 0.0

    cov = (sigma**2) * A_inv
    rs = np.random.RandomState(int(seed32) & 0xFFFFFFFF)
    try:
        theta_tilde = rs.multivariate_normal(mean=theta_hat, cov=cov)
    except Exception:
        scores = Phi.astype(np.float64) @ theta_hat
        a_idx = int(np.argmax(scores))
        return a_idx, {"x": x.tolist(), "a_idx": a_idx, "seed32": int(seed32), "mode": "fallback_mean"}

    scores = Phi.astype(np.float64) @ np.asarray(theta_tilde, dtype=np.float64)
    a_idx = int(np.argmax(scores))
    dbg: Dict[str, Any] = {
        "x": x.tolist(),
        "a_idx": int(a_idx),
        "seed32": int(seed32),
        "sigma_scale": float(sigma_scale),
    }
    try:
        dbg["theta_norm"] = float(np.linalg.norm(theta_tilde))
    except Exception:
        pass
    return int(a_idx), dbg


def _bandit_select_action_ts_greedyish(
    *,
    agent,
    action_set: ActionSet,
    ctx: ContextBuilder,
    eps: float,
    sigma_scale: float,
    rs: np.random.RandomState,
) -> Tuple[int, Dict[str, Any]]:
    """Mostly-greedy TS: reduce sampling variance + epsilon exploration."""

    eps = float(np.clip(float(eps), 0.0, 1.0))
    sigma_scale = float(max(0.0, float(sigma_scale)))

    # Occasionally explore a random arm to adapt to non-stationarity.
    if eps > 0 and float(rs.rand()) < eps:
        a_idx = int(rs.randint(0, len(action_set)))
        x = ctx.get_context()
        return int(a_idx), {"x": x.tolist(), "a_idx": int(a_idx), "mode": "eps_random", "eps": eps}

    # Temporarily reduce sigma during selection.
    cfg = getattr(agent, "cfg", None)
    old_sigma = None
    if cfg is not None and hasattr(cfg, "sigma"):
        try:
            old_sigma = float(cfg.sigma)
            cfg.sigma = float(old_sigma) * float(sigma_scale)
        except Exception:
            old_sigma = None

    try:
        a_idx, dbg_ts = _bandit_select_action_ts(agent=agent, action_set=action_set, ctx=ctx)
        dbg: Dict[str, Any] = dict(dbg_ts)
        dbg.update({"mode": "ts_lowvar", "eps": eps, "sigma_scale": sigma_scale})
        return int(a_idx), dbg
    finally:
        if old_sigma is not None and cfg is not None and hasattr(cfg, "sigma"):
            try:
                cfg.sigma = float(old_sigma)
            except Exception:
                pass


def _ckpt_signature(prefix: str) -> Dict[str, Any]:
    """Return a lightweight signature for a checkpoint prefix (.json/.npz)."""

    prefix = os.path.abspath(str(prefix))
    out: Dict[str, Any] = {"prefix": prefix}
    for ext in (".json", ".npz"):
        p = prefix + ext
        try:
            st = os.stat(p)
            rec: Dict[str, Any] = {"path": p, "size": int(st.st_size), "mtime": float(st.st_mtime)}
            with open(p, "rb") as f:
                head = f.read(4096)
            rec["sha256_head4k"] = hashlib.sha256(head).hexdigest()
            out[ext[1:]] = rec
        except FileNotFoundError:
            out[ext[1:]] = {"path": p, "missing": True}
        except Exception as e:
            out[ext[1:]] = {"path": p, "error": str(e)}
    return out


def _verify_loaded_checkpoint(*, agent, ctx_cfg: ContextConfig, action_set: ActionSet) -> Dict[str, Any]:
    """Validate checkpoint consistency with feature construction used by compare."""

    n_actions = int(len(action_set))
    try:
        ddl_ms_values = list(action_set.ddl_ms_values)
    except Exception as e:
        raise RuntimeError("invalid checkpoint: action_set.ddl_ms_values missing") from e
    if n_actions <= 0:
        raise RuntimeError("invalid checkpoint: action_set is empty")
    if not ddl_ms_values:
        raise RuntimeError("invalid checkpoint: action_set.ddl_ms_values missing/empty")

    # Feature dim sanity: 1 + d + m + d*m
    ctx = ContextBuilder(cfg=ctx_cfg)
    x = np.asarray(ctx.get_context(), dtype=np.float64).reshape(-1)
    d = int(x.size)
    m = int(getattr(action_set, "onehot_dim", 0))
    dim_expected = 1 + d + m + d * m
    dim_agent = int(getattr(agent, "dim", 0))
    if dim_agent != dim_expected:
        raise RuntimeError(
            f"checkpoint feature dim mismatch: agent.dim={dim_agent} expected={dim_expected} (d={d}, m={m})"
        )

    # Phi sanity
    ph = np.asarray(phi_fn(x=x.astype(np.float32), a_onehot=action_set.get_onehot(0))).reshape(-1)
    if int(ph.size) != int(dim_agent):
        raise RuntimeError(f"phi dim mismatch: phi.size={int(ph.size)} agent.dim={dim_agent}")

    # ddl_idx mapping sanity for a few actions
    idxs = sorted({0, n_actions - 1, n_actions // 2})
    for i in idxs:
        spec = action_set.get_action(int(i))
        env_action = np.asarray(spec.to_env_action(), dtype=np.int64).reshape(-1)
        if env_action.size != 4:
            raise RuntimeError(f"env_action must have 4 dims, got {env_action}")
        ddl_idx = int(env_action[3])
        if not (0 <= ddl_idx < int(len(ddl_ms_values))):
            raise RuntimeError(
                f"ddl_idx out of range for action {i}: ddl_idx={ddl_idx} len(ddl_ms_values)={len(ddl_ms_values)}"
            )

    return {
        "n_actions": n_actions,
        "ddl_ms_values": [int(x) for x in ddl_ms_values],
        "d": d,
        "m": m,
        "dim_expected": dim_expected,
        "agent_dim": dim_agent,
    }


def _action_to_env_vars(*, action_set: ActionSet, a_idx: int, symbol_bytes: int) -> Dict[str, str]:
    spec = action_set.get_action(a_idx)
    env_action = spec.to_env_action()
    k_idx, r0_idx, rstep_idx, ddl_idx = (int(env_action[0]), int(env_action[1]), int(env_action[2]), int(env_action[3]))

    # New ActionSet semantics: indices are factor-level indices.
    K = int(action_set.k_values[int(k_idx)])
    R0 = int(action_set.r0_values[int(r0_idx)])
    RSTEP = int(action_set.rstep_values[int(rstep_idx)])

    # DDL discretization comes from the bandit checkpoint's ActionSet.
    ddl_ms_values = list(action_set.ddl_ms_values)
    if not (0 <= int(ddl_idx) < int(len(ddl_ms_values))):
        raise IndexError(f"ddl_idx out of range: ddl_idx={int(ddl_idx)} len(ddl_ms_values)={int(len(ddl_ms_values))}")
    DDL_MS = int(ddl_ms_values[int(ddl_idx)])

    return {
        "K": str(int(K)),
        "SYMBOL_BYTES": str(int(symbol_bytes)),
        "R0": str(int(R0)),
        "W": os.environ.get("W", "8"),
        "RSTEP": str(int(RSTEP)),
        "DDL_MS": str(int(DDL_MS)),
        "MAX_ATTEMPTS": os.environ.get("MAX_ATTEMPTS", "5"),
        "USE_ARQ": os.environ.get("USE_ARQ", "1"),
        "QUIC_FEC_CC_BYPASS": "0",
        "QUIC_FEC_CC_ALGO": "bbrv2",
        "PACE_US": "0",
    }


def _aligned_obs_vec_from_rl_observation(*, rl_obs: Optional[Dict[str, Any]], ddl_ms: int, failed: bool) -> np.ndarray:
    """Construct training observation vector.

    Layout matches python/fecenv_env.py (new):
      [goodput, fec_overhead, ctrl_tx_nack_msgs, done_flag, fec_rate, ddl_ms]
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

        goodput = _f("goodput", _f("goodput_mbps", _f("goodput_arrival_mbps", _f("goodput_decode_mbps", 0.0))))
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
    overhead_ratio: float
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
    "flec": "FLEC",
}

_METHOD_COLORS = {
    "bandit": "#1f77b4",
    "quic_bbrv2": "#ff7f0e",
    "fec_k20_r0_2_rstep_2": "#2ca02c",
    "fec_k20_r0_6_rstep_4": "#d62728",
    "flec": "#9467bd",
}


def _load_rows_from_results_jsonl(results_jsonl: Path) -> List[Row]:
    out: List[Row] = []
    with results_jsonl.open("r", encoding="utf-8") as f:
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
                out.append(
                    Row(
                        task=str(d.get("task", "")),
                        method=str(d.get("method", "")),
                        sender_id=int(d.get("sender_id", 0) or 0),
                        loss_mode=str(d.get("loss_mode", "")),
                        rep=int(d.get("rep", 0) or 0),
                        is_warmup=int(d.get("is_warmup", 0) or 0),
                        timed_out=int(d.get("timed_out", 0) or 0),
                        md5_ok=int(d.get("md5_ok", 0) or 0),
                        success=int(d.get("success", 0) or 0),
                        dur_ms=int(d.get("dur_ms", 0) or 0),
                        goodput_mbps=float(d.get("goodput_mbps", 0.0) or 0.0),
                        overhead_ratio=float(d.get("overhead_ratio", 0.0) or 0.0),
                        a_idx=int(d.get("a_idx", -1) or -1),
                        extra=d.get("extra", {}) if isinstance(d.get("extra", {}), dict) else {},
                    )
                )
            except Exception:
                continue
    return out


def _load_flec_delay_ms_from_jsonl(flec_jsonl: Path) -> Tuple[List[float], float]:
    """Return (dur_ms list for ok==1, ok_rate) from flec jsonl."""

    ok_ms: List[float] = []
    n = 0
    ok_n = 0
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

            n += 1
            ok = int(d.get("ok", 0) or 0)
            if ok != 1:
                continue
            e2e_s = d.get("e2e_s", None)
            if e2e_s is None:
                continue
            try:
                dur_ms = float(e2e_s) * 1000.0
            except Exception:
                continue
            if np.isfinite(dur_ms) and dur_ms > 0:
                ok_n += 1
                ok_ms.append(float(dur_ms))

    ok_rate = float(ok_n) / float(n) if n > 0 else 0.0
    return ok_ms, ok_rate


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


def _load_sender_data(*, params_path: Path, sender_id: int) -> Dict[str, Any]:
    data = json.loads(params_path.read_text(encoding="utf-8"))
    senders = data.get("senders")
    if not isinstance(senders, dict):
        raise ValueError("invalid 'senders' in ge params")
    s = senders.get(str(sender_id))
    if not isinstance(s, dict):
        raise ValueError(f"sender_id={sender_id} not found")
    return s


def _method_env_fixed_fec(*, k: int, r0: int, rstep: int, ddl_ms: int, symbol_bytes: int) -> Dict[str, str]:
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
    net_env: Optional[Dict[str, str]] = None,
) -> Tuple[Dict[str, Any], str]:
    """Run one trial, return parsed metrics + raw stderr."""

    # Private control knobs for the bash runners.
    # _COMPARE_FAST is consumed inside this module to decide whether to set SKIP_* flags.
    common_env = {
        "BITRATE_MBPS": str(int(bitrate_mbps)),
        "RTT_MS": str(int(rtt_ms)),
        "LOSS_MODE": str(loss_mode),
        "LOSS_PCT": "0",
        "FILE": str(file_path),
        "TIMEOUT_S": str(int(timeout_transfer_s)),
        "POST_WAIT": "0ms",
        "_COMPARE_FAST": os.environ.get("COMPARE_FAST", "0"),
    }
    if net_env:
        common_env.update({k: str(v) for k, v in net_env.items()})

    if method == "quic_bbrv2":
        env = {
            **common_env,
            "QUIC_FEC_CC_BYPASS": "0",
            "QUIC_FEC_CC_ALGO": "bbrv2",
            # Make overhead reflect QUIC attempted send bytes.
            "RAW_STATS": "1",
        }
        if str(env.get("_COMPARE_FAST", "0")) == "1":
            env.update({"SKIP_BUILD": "1", "SKIP_NETNS_RESET": "1"})
        _stdout, stderr = _run_bash_script(script=_REPO_ROOT / "scripts" / "quicraw_run_once.sh", env=env, timeout_s=timeout_s)
    elif method.startswith("fec_") or method == "bandit":
        if not fec_env:
            raise ValueError("fec_env is required for fec/bandit methods")
        env = {**common_env, **fec_env, "FEC_STATS": "1"}
        _stdout, stderr = _run_bash_script(script=_REPO_ROOT / "scripts" / "quicfec_run_once.sh", env=env, timeout_s=timeout_s)
    else:
        raise ValueError(f"unknown method={method}")

    run_line = _extract_last_line("[run]", stderr) or ""
    kv = _parse_kv_from_run_line(run_line)

    dur_ms = _to_int(kv, "dur_ms", 0)
    dur_ms_client = _to_int(kv, "dur_ms_client", 0)
    timed_out = _to_int(kv, "timed_out", 0)
    md5_ok = _to_int(kv, "md5_ok", 0)
    goodput = _to_float(kv, "s_mbps", 0.0)
    client_ok = _to_int(kv, "client_ok", 1)
    client_rc = _to_int(kv, "client_rc", 0)

    overhead_ratio = _overhead_ratio_from_run_kv(kv=kv, file_path=file_path)
    tx_bytes = _to_int(kv, "tx_bytes", 0)
    rx_bytes = _to_int(kv, "rx_bytes", 0)
    file_bytes = _to_int(kv, "file_bytes", int(file_path.stat().st_size))

    # E2E delay definition for recording/plotting:
    #   e2e_delay_ms = dur_ms + rtt_ms/2
    # (Server-side dur_ms is the transfer completion time excluding full RTT; we add RTT/2.)
    e2e_delay_ms = float(dur_ms) + 0.5 * float(rtt_ms)

    # Failures -> goodput=0. For delay task we use success-only samples downstream.
    if timed_out or md5_ok != 1:
        goodput = 0.0

    return {
        "dur_ms": int(dur_ms),
        "dur_ms_client": int(dur_ms_client),
        "e2e_delay_ms": float(e2e_delay_ms),
        "rtt_ms": int(rtt_ms),
        "timed_out": int(timed_out),
        "md5_ok": int(md5_ok),
        "client_ok": int(client_ok),
        "client_rc": int(client_rc),
        "goodput_mbps": float(goodput),
        "tx_bytes": int(tx_bytes),
        "rx_bytes": int(rx_bytes),
        "file_bytes": int(file_bytes),
        "overhead_ratio": float(overhead_ratio),
    }, stderr


def main() -> int:
    ap = argparse.ArgumentParser(description="Paper-style comparison under GE_steady_rp (E2E delay and/or goodput)")
    ap.add_argument(
        "--bandit-model-prefix",
        type=str,
        required=False,
        help="Trained bandit model prefix (no .json/.npz), e.g. python/results/.../model_tXXXX_r0pYYYY",
    )
    ap.add_argument(
        "--results-jsonl",
        type=str,
        default="",
        help="Plot-only mode: path to existing results.jsonl (output of this script). If set, no experiments are run.",
    )
    ap.add_argument(
        "--flec-jsonl",
        type=str,
        default="",
        help="Plot-only mode: optional flec results jsonl to overlay (fields: ok,e2e_s).",
    )
    ap.add_argument("--ge-params", type=str, default=str(_REPO_ROOT / "python" / "bandit" / "quic_fec_params.json"))
    ap.add_argument("--ge-key", type=str, default="GE_steady_rp")
    ap.add_argument("--sender-ids", type=str, default="100", help="Comma list / ranges, e.g. 100,106,112 or 100-160 or 'all'")
    ap.add_argument("--ge-h-pct", type=float, default=0.0)
    ap.add_argument("--ge-k-pct", type=float, default=99.0)

    ap.add_argument("--bitrate-mbps", type=int, default=10)
    ap.add_argument("--rtt-ms", type=int, default=50, help="RTT in ms when --rtt-mode=fixed")
    ap.add_argument(
        "--rtt-mode",
        type=str,
        default="fixed",
        choices=["fixed", "random"],
        help=(
            "RTT mode for iid loss only: fixed uses --rtt-ms; random samples from --rtt-random-ms (deterministic by --seed). "
            "When --loss-profile=ge, RTT is always taken per-sender from --ge-params (quic_fec_params.json) to match training."
        ),
    )
    ap.add_argument(
        "--rtt-random-ms",
        type=str,
        default="30,50,60,80,100",
        help="Candidate RTT values (ms) when --rtt-mode=random, e.g. '30,50,60,80,100'",
    )

    ap.add_argument(
        "--loss-profile",
        type=str,
        default="ge",
        choices=["ge", "iid"],
        help="Loss profile: ge uses per-sender GE schedule; iid sweeps i.i.d loss rates from --iid-loss-pcts.",
    )
    ap.add_argument(
        "--iid-loss-pcts",
        type=str,
        default="0.1,0.2,0.3,0.4,0.5",
        help="Comma list of i.i.d loss rates in percent (e.g. '0.1,0.2,0.3,0.4,0.5').",
    )
    # Training harness default is 15s (see scripts/quic{raw,fec}_run_once.sh and python/fecenv_env.py).
    ap.add_argument("--timeout-transfer-s", type=int, default=5)
    ap.add_argument("--timeout-s", type=int, default=180, help="Python-side subprocess timeout; must exceed transfer timeout")

    ap.add_argument(
        "--duration-field",
        type=str,
        default="e2e_delay_ms",
        choices=["e2e_delay_ms", "dur_ms", "dur_ms_client"],
        help=(
            "Which duration to record as dur_ms in results/plots. "
            "e2e_delay_ms = dur_ms + rtt_ms/2 (recommended); "
            "dur_ms=server-side completion; "
            "dur_ms_client=client wall-clock total (includes ARQ drain / ack wait)."
        ),
    )

    ap.add_argument(
        "--run-tag",
        type=str,
        default="",
        help=(
            "Unique tag to isolate netns/veth/IP so multiple compares can run concurrently. "
            "Default: auto-generated per process."
        ),
    )

    ap.add_argument(
        "--fast",
        type=int,
        default=1,
        help=(
            "1: speed up by skipping per-trial netns reset and build checks (requires sudo -v, and stable netns). "
            "0: run scripts in fully isolated mode per trial (slower but most reproducible)."
        ),
    )

    ap.add_argument("--reps", type=int, default=10)

    ap.add_argument(
        "--bandit-policy",
        type=str,
        default="ts",
        choices=["mean", "ts", "mean-seeded", "ts-greedyish"],
        help=(
            "Bandit action selection policy: "
            "mean=argmax(theta_hat); ts=Thompson sampling (matches training); "
            "mean-seeded=seeded posterior draw then greedy; "
            "ts-greedyish=TS with lower variance + epsilon exploration"
        ),
    )
    ap.add_argument("--seed", type=int, default=0, help="seed for warmup random actions (policy=ts uses checkpoint RNG)")
    ap.add_argument(
        "--ctx-alpha",
        type=float,
        default=0.15,
        help=(
            "override context EWMA alpha for deployment (default: 0.15). "
            "Set to a negative value to keep the checkpoint ctx_cfg."
        ),
    )
    ap.add_argument(
        "--bandit-eps",
        type=float,
        default=0.02,
        help="epsilon for ts-greedyish (probability of random arm); ignored otherwise",
    )
    ap.add_argument(
        "--bandit-sigma-scale",
        type=float,
        default=0.15,
        help="sigma scale for mean-seeded / ts-greedyish (lower => more greedy). Default 0.15 for deployment.",
    )
    # Legacy warmup behavior: one fixed warmup action (old default was 2845 for the old 6-DDL action set).
    # Use -1 to disable fixed warmup index and instead do random warmup steps (recommended).
    ap.add_argument("--warmup-a-idx", type=int, default=-1)
    ap.add_argument("--warmup-steps", type=int, default=2, help="number of random warmup transfers when --warmup-a-idx < 0")

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

    ap.add_argument(
        "--verify-only",
        type=int,
        default=0,
        help="1: only verify checkpoint loading/consistency and exit (no experiments, no sudo needed)",
    )

    ap.add_argument("--out-dir", type=str, default="")

    args = ap.parse_args()

    # Plot-only mode: read existing results.jsonl and optionally add flec.
    if str(getattr(args, "results_jsonl", "")).strip():
        results_jsonl = Path(str(args.results_jsonl)).expanduser()
        if not results_jsonl.exists():
            raise FileNotFoundError(str(results_jsonl))

        out_dir = Path(args.out_dir).expanduser() if str(args.out_dir).strip() else (
            _REPO_ROOT / "python" / "results" / "paper-flec-compare"
        )
        out_dir.mkdir(parents=True, exist_ok=True)

        rows = _load_rows_from_results_jsonl(results_jsonl)

        def _filter_rows(task_name: str, method: str) -> List[Row]:
            return [r for r in rows if r.task == task_name and r.method == method and r.is_warmup == 0]

        delay_series: List[Tuple[str, Sequence[float], float]] = []
        for m in _METHOD_ORDER:
            rs = _filter_rows("delay_128kb", m)
            d_ok = [float(r.dur_ms) for r in rs if r.success == 1 and r.dur_ms > 0]
            ok_rate = (sum([1 for r in rs if r.success == 1]) / float(len(rs))) if rs else 0.0
            delay_series.append((m, d_ok, ok_rate))

        flec_path_s = str(getattr(args, "flec_jsonl", "")).strip()
        if flec_path_s:
            flec_jsonl = Path(flec_path_s).expanduser()
            if not flec_jsonl.exists():
                raise FileNotFoundError(str(flec_jsonl))
            flec_ms, flec_ok = _load_flec_delay_ms_from_jsonl(flec_jsonl)
            delay_series.append(("flec", flec_ms, float(flec_ok)))

        _plot_cdf(
            out_path=out_dir / "fig_delay_cdf.pdf",
            title="",
            xlabel="E2E delay per message (ms)",
            series=delay_series,
            xlim=(0.0, 300.0),
            show_ok_n_in_legend=False,
        )

        (out_dir / "paper_flec_compare_meta.json").write_text(
            json.dumps(
                {
                    "mode": "plot_only",
                    "results_jsonl": str(results_jsonl),
                    "flec_jsonl": flec_path_s,
                },
                indent=2,
                ensure_ascii=False,
            )
            + "\n",
            encoding="utf-8",
        )

        print("OUT:", out_dir)
        print("- fig:", out_dir / "fig_delay_cdf.pdf")
        return 0

    if not str(getattr(args, "bandit_model_prefix", "") or "").strip():
        raise SystemExit("--bandit-model-prefix is required unless --results-jsonl is set")

    model_prefix = str(args.bandit_model_prefix)
    if model_prefix.endswith(".json"):
        model_prefix = model_prefix[:-5]
    if model_prefix.endswith(".npz"):
        model_prefix = model_prefix[:-4]

    params_path = Path(args.ge_params)

    loss_profile = str(getattr(args, "loss_profile", "ge") or "ge").strip().lower()
    iid_loss_pcts = _parse_float_list(str(getattr(args, "iid_loss_pcts", "") or ""))
    if loss_profile == "iid" and not iid_loss_pcts:
        iid_loss_pcts = [0.1, 0.2, 0.3, 0.4, 0.5]

    # RTT candidates for random mode.
    rtt_mode = str(getattr(args, "rtt_mode", "fixed") or "fixed").strip().lower()
    rtt_candidates = [int(x) for x in _parse_int_list(str(getattr(args, "rtt_random_ms", "") or "")) if int(x) > 0]
    if rtt_mode == "random" and not rtt_candidates:
        rtt_candidates = [30, 50, 60, 80, 100]

    # Scenario list: (scenario_id, loss_mode_string).
    # We keep scenario_id in Row.sender_id for backward compatibility and stable RNG seeding.
    scenarios: List[Tuple[int, str]] = []
    if loss_profile == "iid":
        for pct in iid_loss_pcts:
            sid = int(round(float(pct) * 1000.0))
            scenarios.append((sid, f"iid:{float(pct)}"))
        sender_ids = [sid for sid, _lm in scenarios]
    else:
        sender_ids = _load_sender_ids(params_path=params_path, sender_ids_arg=str(args.sender_ids), ge_key=str(args.ge_key))
        for sid in sender_ids:
            ge = _load_sender_ge(params_path=params_path, sender_id=int(sid), ge_key=str(args.ge_key))
            lm = _ge_to_tc_gemodel_loss_mode(ge, h_loss_pct=float(args.ge_h_pct), k_loss_pct=float(args.ge_k_pct))
            scenarios.append((int(sid), str(lm)))

    def _rtt_ms_for_ge_sender(sender_id: int) -> int:
        sender_data = _load_sender_data(params_path=params_path, sender_id=int(sender_id))
        rtt_ms_sender = sender_data.get("rtt_ms")
        if rtt_ms_sender is None:
            raise ValueError(f"sender_id={int(sender_id)} missing rtt_ms in {params_path}")
        return int(rtt_ms_sender)

    # Load bandit checkpoint
    agent, _cfg, _ctx0, ctx_cfg, action_set, _t0 = load_checkpoint(path_prefix=model_prefix)

    # Print action set summary to make mismatches obvious.
    ddl_vals = list(action_set.ddl_ms_values)
    print(f"[bandit] action_set_n={len(action_set)} ddl_ms_values={ddl_vals}")

    # Verify checkpoint identity & consistency.
    sig = _ckpt_signature(model_prefix)
    print(f"[bandit] checkpoint_signature={json.dumps(sig, ensure_ascii=False)}")
    ver = _verify_loaded_checkpoint(agent=agent, ctx_cfg=ctx_cfg, action_set=action_set)
    print(f"[bandit] checkpoint_consistency=ok details={json.dumps(ver, ensure_ascii=False)}")

    if str(args.bandit_policy) == "mean":
        print(
            "[bandit][warn] --bandit-policy=mean is a greedy argmax policy; it may legitimately pick the same a_idx "
            "for many/most environments once the model has converged. Use --bandit-policy=ts to match training."
        )

    if args.ctx_alpha is not None and float(args.ctx_alpha) >= 0.0:
        try:
            ctx_cfg.ewma_alpha = float(args.ctx_alpha)
            print(f"[bandit] ctx_alpha_overridden={ctx_cfg.ewma_alpha}")
        except Exception:
            pass

    if int(args.verify_only) != 0:
        return 0

    duration_field = str(getattr(args, "duration_field", "dur_ms") or "dur_ms").strip()
    use_fast = bool(int(getattr(args, "fast", 1) or 0) != 0)

    net_env = _netns_env_for_tag(str(getattr(args, "run_tag", "") or ""))
    # Use the effective netns tag for all per-run temporary artifact names.
    run_tag_effective = str(net_env.get("NS", "qns")).removeprefix("qns_") if hasattr(str, "removeprefix") else str(net_env.get("NS", "qns")).replace("qns_", "", 1)
    if not run_tag_effective:
        run_tag_effective = "run"
    # Per-run output directory for server recv files (keeps parallel runs isolated).
    tmp_out_dir = Path("/tmp") / f"rl-quic-out-{str(net_env.get('NS','qns'))}"
    tmp_out_dir.mkdir(parents=True, exist_ok=True)
    run_env = {**net_env, "OUT_DIR": str(tmp_out_dir)}

    # Files (payloads): include run tag to avoid cross-process clobbering.
    file_delay = _REPO_ROOT / "go" / "test_data" / f"paper_delay_{int(args.delay_file_bytes)}B_{run_tag_effective}.bin"
    file_goodput = _REPO_ROOT / "go" / "test_data" / f"paper_goodput_{int(args.goodput_file_bytes)}B_{run_tag_effective}.bin"
    _ensure_file_of_size(file_path=file_delay, file_bytes=int(args.delay_file_bytes))
    _ensure_file_of_size(file_path=file_goodput, file_bytes=int(args.goodput_file_bytes))
    print(
        "[netns] "
        f"ns={net_env.get('NS','')} veth_host={net_env.get('VETH_HOST','')} veth_ns={net_env.get('VETH_NS','')} "
        f"host_ip={net_env.get('HOST_IP','')} ns_ip={net_env.get('NS_IP','')}"
    )
    print(f"[io] out_dir={tmp_out_dir} file_delay={file_delay.name} file_goodput={file_goodput.name}")

    # Plumb fast mode into _run_one via environment (keeps function signatures stable).
    os.environ["COMPARE_FAST"] = "1" if use_fast else "0"

    # One-command workflow: if fast mode is enabled, prepare netns/veth/tc once here.
    # The per-trial bash runners will then run with SKIP_NETNS_RESET=1 to avoid repeated resets.
    if use_fast:
        try:
            subprocess.run(["sudo", "-n", "true"], check=True, capture_output=True, text=True)
        except Exception as e:
            raise RuntimeError("sudo privileges required for --fast=1; run 'sudo -v' once and retry") from e

        setup_rtt_ms = int(args.rtt_ms)
        if loss_profile != "iid" and sender_ids:
            # In GE mode, match training: RTT comes from per-sender data.
            setup_rtt_ms = _rtt_ms_for_ge_sender(int(sender_ids[0]))

        setup_env = {
            "SETUP_ONLY": "1",
            "SKIP_BUILD": "1",
            "BITRATE_MBPS": str(int(args.bitrate_mbps)),
            "RTT_MS": str(int(setup_rtt_ms)),
            # Loss is configured per run; here we just ensure the namespace exists.
            "LOSS_MODE": "none",
        }
        setup_env.update(run_env)
        # quicfec_run_once.sh already knows how to create the namespace + veth and configure tc.
        # (This is a no-op if the user disables --fast.)
        _run_bash_script(script=_REPO_ROOT / "scripts" / "quicfec_run_once.sh", env=setup_env, timeout_s=60)

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

    for scenario_id, loss_mode in scenarios:
        if loss_profile == "iid":
            print(f"[iid] loss_mode={loss_mode}")
        else:
            print(f"[ge] sender_id={scenario_id} loss_mode={loss_mode}")

        for task, file_path in tasks:
            print(f"[task] {task} file={file_path.name}")

            # Stable per-task seed.
            task_seed = 0
            for ch in str(task).encode("utf-8", errors="ignore"):
                task_seed = (task_seed * 131 + int(ch)) % 2_147_483_647

            # RTT selection policy:
            # Keep RTT fixed for the entire group (same loss rate / sender + same task),
            # across warmup + all reps. This makes the bandit environment stationary enough.
            group_seed32 = (int(args.seed) + 9876541 + 1000003 * int(scenario_id) + 9176 * int(task_seed)) & 0xFFFFFFFF
            if loss_profile != "iid":
                # In GE mode, RTT is defined per sender in quic_fec_params.json (match training env).
                rtt_ms_group = _rtt_ms_for_ge_sender(int(scenario_id))
            else:
                rtt_ms_group = _choose_rtt_ms(
                    mode=rtt_mode,
                    fixed_rtt_ms=int(args.rtt_ms),
                    candidates=rtt_candidates,
                    seed32=int(group_seed32),
                )

            # Bandit state is per-(sender,task) sequence.
            ctx = ContextBuilder(cfg=ctx_cfg)
            ctx.reset()

            # Deterministic RNG for seeded policies (and for epsilon exploration).
            pol_rs_seed32 = (int(args.seed) + 1000003 * int(scenario_id) + 9176 * int(task_seed)) & 0xFFFFFFFF
            pol_rs = np.random.RandomState(int(pol_rs_seed32))

            # Bandit warmup (excluded from stats).
            # If --warmup-a-idx >= 0: run that fixed action once (legacy).
            # Else: run --warmup-steps random actions (closer to training warmup behavior).
            warmup_fixed_idx = int(args.warmup_a_idx)
            warmup_steps = int(args.warmup_steps)
            if warmup_steps < 0:
                warmup_steps = 0

            warmup_indices: List[int] = []
            if warmup_fixed_idx >= 0:
                if not (0 <= int(warmup_fixed_idx) < int(len(action_set))):
                    raise ValueError(f"--warmup-a-idx out of range: {warmup_fixed_idx} (action_set_n={len(action_set)})")
                warmup_indices = [int(warmup_fixed_idx)]
            else:
                # numpy RandomState requires 0 <= seed < 2**32.
                seed32 = (int(args.seed) + 1337 * int(scenario_id) + 17 * int(task_seed)) & 0xFFFFFFFF
                rs = np.random.RandomState(int(seed32))
                for _ in range(int(warmup_steps)):
                    warmup_indices.append(int(rs.randint(0, len(action_set))))

            for w_i, warmup_idx in enumerate(warmup_indices):
                warmup_env = _action_to_env_vars(action_set=action_set, a_idx=int(warmup_idx), symbol_bytes=int(args.symbol_bytes))
                warmup_ddl_ms = int(warmup_env.get("DDL_MS", "100"))
                if use_fast:
                    warmup_env.update({"SKIP_BUILD": "1", "SKIP_NETNS_RESET": "1", "SKIP_SYSCTL": "1"})
                m, stderr = _run_one(
                    method="bandit",
                    task=task,
                    loss_mode=loss_mode,
                    bitrate_mbps=int(args.bitrate_mbps),
                    rtt_ms=int(rtt_ms_group),
                    timeout_transfer_s=int(args.timeout_transfer_s),
                    timeout_s=int(args.timeout_s),
                    file_path=file_path,
                    fec_env=warmup_env,
                    net_env=run_env,
                )
                rl_obs = _extract_last_rl_observation(stderr)
                failed = bool(int(m["timed_out"]) or int(m["md5_ok"]) != 1)
                dur_record_ms = float(m.get(duration_field, m.get("dur_ms", 0)) or 0.0)
                dur_record = int(round(dur_record_ms))
                overhead_ratio = float(m.get("overhead_ratio", 0.0) or 0.0)
                fec_overhead_ratio = _overhead_ratio_from_rl_observation(rl_obs)
                obs_vec = _aligned_obs_vec_from_rl_observation(rl_obs=rl_obs, ddl_ms=warmup_ddl_ms, failed=failed)
                ctx.update_from_obs(obs=obs_vec, ddl_ms=warmup_ddl_ms)
                rows.append(
                    Row(
                        task=task,
                        method="bandit",
                        sender_id=int(scenario_id),
                        loss_mode=str(loss_mode),
                        rep=-(int(w_i) + 1),
                        is_warmup=1,
                        timed_out=int(m["timed_out"]),
                        md5_ok=int(m["md5_ok"]),
                        success=1 if (int(m["timed_out"]) == 0 and int(m["md5_ok"]) == 1) else 0,
                        dur_ms=int(dur_record),
                        goodput_mbps=float(m["goodput_mbps"]),
                        overhead_ratio=float(overhead_ratio),
                        a_idx=int(warmup_idx),
                        extra={
                            "warmup": True,
                            "warmup_step": int(w_i),
                            "policy": str(args.bandit_policy),
                            "rtt_ms": int(rtt_ms_group),
                            "e2e_delay_ms": float(m.get("e2e_delay_ms", 0.0) or 0.0),
                            "fec_overhead_ratio": float(fec_overhead_ratio),
                            "dur_ms_server": int(m.get("dur_ms", 0) or 0),
                            "dur_ms_client": int(m.get("dur_ms_client", 0) or 0),
                            "client_ok": int(m.get("client_ok", 1) or 1),
                            "client_rc": int(m.get("client_rc", 0) or 0),
                        },
                    )
                )

            # Measured runs
            for rep in range(int(args.reps)):
                # Bandit
                pol = str(args.bandit_policy)
                if pol == "ts":
                    a_idx, dbg = _bandit_select_action_ts(agent=agent, action_set=action_set, ctx=ctx)
                elif pol == "mean":
                    a_idx, dbg = _bandit_select_action_mean(agent=agent, action_set=action_set, ctx=ctx)
                elif pol == "mean-seeded":
                    # Seed per decision to keep reproducible but still responsive to context changes.
                    base_seed32 = (int(args.seed) + 1000003 * int(scenario_id) + 9176 * int(task_seed)) & 0xFFFFFFFF
                    step_seed32 = (int(base_seed32) ^ (0x9E3779B1 * (int(rep) + 1))) & 0xFFFFFFFF
                    a_idx, dbg = _bandit_select_action_mean_seeded(
                        agent=agent,
                        action_set=action_set,
                        ctx=ctx,
                        seed32=int(step_seed32),
                        sigma_scale=float(args.bandit_sigma_scale),
                    )
                elif pol == "ts-greedyish":
                    a_idx, dbg = _bandit_select_action_ts_greedyish(
                        agent=agent,
                        action_set=action_set,
                        ctx=ctx,
                        eps=float(args.bandit_eps),
                        sigma_scale=float(args.bandit_sigma_scale),
                        rs=pol_rs,
                    )
                else:
                    raise ValueError(f"unknown --bandit-policy: {pol}")
                fec_env = _action_to_env_vars(action_set=action_set, a_idx=a_idx, symbol_bytes=int(args.symbol_bytes))
                ddl_ms = int(fec_env.get("DDL_MS", "100"))
                if use_fast:
                    fec_env.update({"SKIP_BUILD": "1", "SKIP_NETNS_RESET": "1", "SKIP_SYSCTL": "1"})

                m, stderr = _run_one(
                    method="bandit",
                    task=task,
                    loss_mode=loss_mode,
                    bitrate_mbps=int(args.bitrate_mbps),
                    rtt_ms=int(rtt_ms_group),
                    timeout_transfer_s=int(args.timeout_transfer_s),
                    timeout_s=int(args.timeout_s),
                    file_path=file_path,
                    fec_env=fec_env,
                    net_env=run_env,
                )
                rl_obs = _extract_last_rl_observation(stderr)
                failed = bool(int(m["timed_out"]) or int(m["md5_ok"]) != 1)
                dur_record_ms = float(m.get(duration_field, m.get("dur_ms", 0)) or 0.0)
                dur_record = int(round(dur_record_ms))
                overhead_ratio = float(m.get("overhead_ratio", 0.0) or 0.0)
                fec_overhead_ratio = _overhead_ratio_from_rl_observation(rl_obs)
                obs_vec = _aligned_obs_vec_from_rl_observation(rl_obs=rl_obs, ddl_ms=ddl_ms, failed=failed)
                ctx.update_from_obs(obs=obs_vec, ddl_ms=ddl_ms)

                rows.append(
                    Row(
                        task=task,
                        method="bandit",
                        sender_id=int(scenario_id),
                        loss_mode=str(loss_mode),
                        rep=int(rep),
                        is_warmup=0,
                        timed_out=int(m["timed_out"]),
                        md5_ok=int(m["md5_ok"]),
                        success=1 if (int(m["timed_out"]) == 0 and int(m["md5_ok"]) == 1) else 0,
                        dur_ms=int(dur_record),
                        goodput_mbps=float(m["goodput_mbps"]),
                        overhead_ratio=float(overhead_ratio),
                        a_idx=int(a_idx),
                        extra={
                            "bandit": dbg,
                            "policy": str(args.bandit_policy),
                            "rtt_ms": int(rtt_ms_group),
                            "e2e_delay_ms": float(m.get("e2e_delay_ms", 0.0) or 0.0),
                            "fec_overhead_ratio": float(fec_overhead_ratio),
                            "dur_ms_server": int(m.get("dur_ms", 0) or 0),
                            "dur_ms_client": int(m.get("dur_ms_client", 0) or 0),
                            "client_ok": int(m.get("client_ok", 1) or 1),
                            "client_rc": int(m.get("client_rc", 0) or 0),
                        },
                    )
                )

                # QUIC BBRv2 (raw)
                m2, stderr2 = _run_one(
                    method="quic_bbrv2",
                    task=task,
                    loss_mode=loss_mode,
                    bitrate_mbps=int(args.bitrate_mbps),
                    rtt_ms=int(rtt_ms_group),
                    timeout_transfer_s=int(args.timeout_transfer_s),
                    timeout_s=int(args.timeout_s),
                    file_path=file_path,
                    net_env=run_env,
                )
                overhead2 = float(m2.get("overhead_ratio", 0.0) or 0.0)
                dur2_record_ms = float(m2.get(duration_field, m2.get("dur_ms", 0)) or 0.0)
                dur2_record = int(round(dur2_record_ms))
                rows.append(
                    Row(
                        task=task,
                        method="quic_bbrv2",
                        sender_id=int(scenario_id),
                        loss_mode=str(loss_mode),
                        rep=int(rep),
                        is_warmup=0,
                        timed_out=int(m2["timed_out"]),
                        md5_ok=int(m2["md5_ok"]),
                        success=1 if (int(m2["timed_out"]) == 0 and int(m2["md5_ok"]) == 1) else 0,
                        dur_ms=int(dur2_record),
                        goodput_mbps=float(m2["goodput_mbps"]),
                        overhead_ratio=float(overhead2),
                        a_idx=-1,
                        extra={
                            "rtt_ms": int(rtt_ms_group),
                            "e2e_delay_ms": float(m2.get("e2e_delay_ms", 0.0) or 0.0),
                            "dur_ms_server": int(m2.get("dur_ms", 0) or 0),
                            "dur_ms_client": int(m2.get("dur_ms_client", 0) or 0),
                            "client_ok": int(m2.get("client_ok", 1) or 1),
                            "client_rc": int(m2.get("client_rc", 0) or 0),
                        },
                    )
                )

                # Fixed FEC #1
                env_f1 = _method_env_fixed_fec(k=20, r0=2, rstep=2, ddl_ms=100, symbol_bytes=int(args.symbol_bytes))
                if use_fast:
                    env_f1.update({"SKIP_BUILD": "1", "SKIP_NETNS_RESET": "1", "SKIP_SYSCTL": "1"})
                m3, stderr3 = _run_one(
                    method="fec_k20_r0_2_rstep_2",
                    task=task,
                    loss_mode=loss_mode,
                    bitrate_mbps=int(args.bitrate_mbps),
                    rtt_ms=int(rtt_ms_group),
                    timeout_transfer_s=int(args.timeout_transfer_s),
                    timeout_s=int(args.timeout_s),
                    file_path=file_path,
                    fec_env=env_f1,
                    net_env=run_env,
                )
                rl3 = _extract_last_rl_observation(stderr3)
                overhead3 = float(m3.get("overhead_ratio", 0.0) or 0.0)
                fec_overhead3 = _overhead_ratio_from_rl_observation(rl3)
                dur3_record_ms = float(m3.get(duration_field, m3.get("dur_ms", 0)) or 0.0)
                dur3_record = int(round(dur3_record_ms))
                rows.append(
                    Row(
                        task=task,
                        method="fec_k20_r0_2_rstep_2",
                        sender_id=int(scenario_id),
                        loss_mode=str(loss_mode),
                        rep=int(rep),
                        is_warmup=0,
                        timed_out=int(m3["timed_out"]),
                        md5_ok=int(m3["md5_ok"]),
                        success=1 if (int(m3["timed_out"]) == 0 and int(m3["md5_ok"]) == 1) else 0,
                        dur_ms=int(dur3_record),
                        goodput_mbps=float(m3["goodput_mbps"]),
                        overhead_ratio=float(overhead3),
                        a_idx=-1,
                        extra={
                            "fec": {"K": 20, "R0": 2, "RSTEP": 2, "DDL_MS": 100},
                            "fec_overhead_ratio": float(fec_overhead3),
                            "rtt_ms": int(rtt_ms_group),
                            "e2e_delay_ms": float(m3.get("e2e_delay_ms", 0.0) or 0.0),
                            "dur_ms_server": int(m3.get("dur_ms", 0) or 0),
                            "dur_ms_client": int(m3.get("dur_ms_client", 0) or 0),
                            "client_ok": int(m3.get("client_ok", 1) or 1),
                            "client_rc": int(m3.get("client_rc", 0) or 0),
                        },
                    )
                )

                # Fixed FEC #2
                env_f2 = _method_env_fixed_fec(k=20, r0=6, rstep=4, ddl_ms=100, symbol_bytes=int(args.symbol_bytes))
                if use_fast:
                    env_f2.update({"SKIP_BUILD": "1", "SKIP_NETNS_RESET": "1", "SKIP_SYSCTL": "1"})
                m4, stderr4 = _run_one(
                    method="fec_k20_r0_6_rstep_4",
                    task=task,
                    loss_mode=loss_mode,
                    bitrate_mbps=int(args.bitrate_mbps),
                    rtt_ms=int(rtt_ms_group),
                    timeout_transfer_s=int(args.timeout_transfer_s),
                    timeout_s=int(args.timeout_s),
                    file_path=file_path,
                    fec_env=env_f2,
                    net_env=run_env,
                )
                rl4 = _extract_last_rl_observation(stderr4)
                overhead4 = float(m4.get("overhead_ratio", 0.0) or 0.0)
                fec_overhead4 = _overhead_ratio_from_rl_observation(rl4)
                dur4_record_ms = float(m4.get(duration_field, m4.get("dur_ms", 0)) or 0.0)
                dur4_record = int(round(dur4_record_ms))
                rows.append(
                    Row(
                        task=task,
                        method="fec_k20_r0_6_rstep_4",
                        sender_id=int(scenario_id),
                        loss_mode=str(loss_mode),
                        rep=int(rep),
                        is_warmup=0,
                        timed_out=int(m4["timed_out"]),
                        md5_ok=int(m4["md5_ok"]),
                        success=1 if (int(m4["timed_out"]) == 0 and int(m4["md5_ok"]) == 1) else 0,
                        dur_ms=int(dur4_record),
                        goodput_mbps=float(m4["goodput_mbps"]),
                        overhead_ratio=float(overhead4),
                        a_idx=-1,
                        extra={
                            "fec": {"K": 20, "R0": 6, "RSTEP": 4, "DDL_MS": 100},
                            "fec_overhead_ratio": float(fec_overhead4),
                            "rtt_ms": int(rtt_ms_group),
                            "e2e_delay_ms": float(m4.get("e2e_delay_ms", 0.0) or 0.0),
                            "dur_ms_server": int(m4.get("dur_ms", 0) or 0),
                            "dur_ms_client": int(m4.get("dur_ms_client", 0) or 0),
                            "client_ok": int(m4.get("client_ok", 1) or 1),
                            "client_rc": int(m4.get("client_rc", 0) or 0),
                        },
                    )
                )

                print(
                    f"rep={rep:02d} rtt_ms={int(rtt_ms_group)} bandit(a={a_idx}) dur_ms={dur_record} "
                    f"ok={1-int(m['timed_out'])==1 and int(m['md5_ok'])==1} | "
                    f"quic_bbrv2 dur_ms={dur2_record} | fec1 dur_ms={dur3_record} | fec2 dur_ms={dur4_record}"
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
                        "overhead_ratio": r.overhead_ratio,
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
                "overhead_ratio",
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
                    "overhead_ratio": f"{float(r.overhead_ratio):.6f}",
                    "a_idx": r.a_idx,
                }
            )

    meta = {
        "bandit_model_prefix": model_prefix,
        "ge_params": str(params_path),
        "ge_key": str(args.ge_key),
        "sender_ids": sender_ids,
        "run_tag": str(getattr(args, "run_tag", "") or ""),
        "run_tag_effective": str(run_tag_effective),
        "tmp_out_dir": str(tmp_out_dir),
        "file_delay": str(file_delay),
        "file_goodput": str(file_goodput),
        "bitrate_mbps": int(args.bitrate_mbps),
        "rtt_ms": ("per-sender (from ge_params['senders'][sid]['rtt_ms'])" if loss_profile != "iid" else int(args.rtt_ms)),
        "rtt_mode": ("per_sender" if loss_profile != "iid" else str(rtt_mode)),
        "rtt_random_ms": (None if loss_profile != "iid" else rtt_candidates),
        "loss_profile": str(loss_profile),
        "iid_loss_pcts": [float(x) for x in iid_loss_pcts],
        "scenarios": [{"sender_id": int(sid), "loss_mode": str(lm)} for sid, lm in scenarios],
        "timeout_transfer_s": int(args.timeout_transfer_s),
        "timeout_s": int(args.timeout_s),
        "reps": int(args.reps),
        "bandit_policy": str(args.bandit_policy),
        "seed": int(args.seed),
        "ctx_alpha": float(args.ctx_alpha) if args.ctx_alpha is not None else None,
        "bandit_eps": float(args.bandit_eps),
        "bandit_sigma_scale": float(args.bandit_sigma_scale),
        "warmup_a_idx": int(args.warmup_a_idx),
        "warmup_steps": int(args.warmup_steps),
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
