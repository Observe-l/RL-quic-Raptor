#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import subprocess
import time
import zlib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

_REPO_ROOT = Path(__file__).resolve().parents[2]
_PY_ROOT = Path(__file__).resolve().parents[1]

import sys

if str(_PY_ROOT) not in sys.path:
    sys.path.insert(0, str(_PY_ROOT))

from bandit.features import phi as phi_fn  # noqa: E402
from bandit.model_io import load_checkpoint  # noqa: E402
from bandit.run_lints_ge_schedule import _ge_to_tc_gemodel_loss_mode  # noqa: E402


def _now_ts() -> str:
    return time.strftime("%Y%m%d-%H%M%S")


def _default_run_tag() -> str:
    pid = os.getpid()
    t = int(time.time() * 1000)
    raw = f"{pid:x}{t:x}"
    raw = re.sub(r"[^0-9a-zA-Z]+", "", raw)
    return raw[:8] or "run"


def _used_10_10_subnets() -> set[int]:
    used: set[int] = set()
    try:
        p = subprocess.run(
            ["ip", "-4", "-o", "addr", "show"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
        for line in (p.stdout or "").splitlines():
            m = re.search(r"\binet\s+10\.10\.(\d+)\.(\d+)/(\d+)", line)
            if not m:
                continue
            used.add(int(m.group(1)))
    except Exception:
        pass
    return used


def _netns_env_for_tag(tag: str) -> Dict[str, str]:
    tag = re.sub(r"[^0-9a-zA-Z]+", "", str(tag or ""))
    tag = tag[:8] if tag else _default_run_tag()

    veth_host = ("vh" + tag)[:15]
    veth_ns = ("vn" + tag)[:15]

    base = 20 + (zlib.crc32(tag.encode("utf-8")) % 200)
    used = _used_10_10_subnets()
    subnet = base
    for off in range(0, 200):
        cand = 20 + ((base - 20 + off) % 200)
        if cand not in used:
            subnet = cand
            break

    host_ip = f"10.10.{subnet}.1/24"
    ns_ip = f"10.10.{subnet}.2/24"

    return {
        "NS": f"qns_{tag}",
        "VETH_HOST": veth_host,
        "VETH_NS": veth_ns,
        "HOST_IP": host_ip,
        "NS_IP": ns_ip,
    }


def _extract_last_run_record(s: str) -> str:
    text = (s or "").replace("\r", "\n")
    lines = text.split("\n")
    start_idx = -1
    for i, line in enumerate(lines):
        if line.startswith("[run]"):
            start_idx = i
    if start_idx < 0:
        return ""
    parts: List[str] = []
    for j in range(start_idx, len(lines)):
        line = (lines[j] or "").strip()
        if not line:
            continue
        if j != start_idx and line.startswith("["):
            break
        parts.append(line)
    return " ".join(parts).strip()


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


def _to_float(d: Dict[str, str], k: str, default: float = 0.0) -> float:
    try:
        return float(d.get(k, str(default)))
    except Exception:
        return default


def _goodput_mbps_from_file_and_dur(*, file_bytes: int, dur_ms: float) -> float:
    if file_bytes <= 0:
        return 0.0
    if not np.isfinite(float(dur_ms)) or float(dur_ms) <= 0:
        return 0.0
    sec = float(dur_ms) / 1000.0
    return float(file_bytes) * 8.0 / 1e6 / sec


def _overhead_quic_ratio_from_kv(*, kv: Dict[str, str]) -> float:
    for key in (
        "fec_quic_overhead_ratio",
        "quic_overhead_ratio",
        "overhead_ratio",
    ):
        if key in kv:
            try:
                v = float(kv.get(key, "0") or "0")
                if np.isfinite(v) and v >= 0:
                    return float(v)
            except Exception:
                pass

    if "fec_quic_sent_bytes" in kv:
        file_bytes = _to_int(kv, "file_bytes", 0)
        sent_bytes = _to_int(kv, "fec_quic_sent_bytes", 0)
        if file_bytes > 0 and sent_bytes > 0:
            return float(max(0.0, (float(sent_bytes) - float(file_bytes)) / float(file_bytes)))

    tx_bytes = _to_int(kv, "tx_bytes", 0)
    file_bytes = _to_int(kv, "file_bytes", 0)
    if file_bytes > 0 and tx_bytes > 0:
        return float(max(0.0, (float(tx_bytes) - float(file_bytes)) / float(file_bytes)))
    return 0.0


def _ensure_file_of_size(*, file_path: Path, file_bytes: int) -> None:
    file_path.parent.mkdir(parents=True, exist_ok=True)
    if not file_path.exists() or int(file_path.stat().st_size) != int(file_bytes):
        with open("/dev/urandom", "rb") as src, open(file_path, "wb") as dst:
            remaining = int(file_bytes)
            while remaining > 0:
                chunk = src.read(min(1024 * 1024, remaining))
                if not chunk:
                    break
                dst.write(chunk)
                remaining -= len(chunk)


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


def _load_ge_params(params_path: Path) -> Dict[str, Any]:
    with params_path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"invalid GE params json: {params_path}")
    senders = data.get("senders")
    if not isinstance(senders, dict) or not senders:
        raise ValueError(f"invalid GE params json (no senders): {params_path}")
    return data


def _ge_sender_ids(params: Dict[str, Any]) -> List[int]:
    senders = params.get("senders")
    out: List[int] = []
    if isinstance(senders, dict):
        for k in senders.keys():
            try:
                out.append(int(k))
            except Exception:
                continue
    out.sort()
    return out


def _get_sender_entry(params: Dict[str, Any], sender_id: int) -> Dict[str, Any]:
    senders = params.get("senders")
    if not isinstance(senders, dict):
        raise KeyError("senders missing")
    e = senders.get(str(int(sender_id)))
    if not isinstance(e, dict):
        raise KeyError(f"sender_id not found in GE params: {sender_id}")
    return e


def _run_script(*, script: Path, env: Dict[str, str], timeout_s: int) -> str:
    p = subprocess.run(
        ["bash", str(script)],
        cwd=str(_REPO_ROOT),
        env={**os.environ, **env},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        timeout=int(timeout_s),
    )
    return str(p.stderr or "")


def _read_last_rl_observation(obs_json_path: Path) -> Dict[str, Any]:
    last = None
    if obs_json_path.exists():
        with obs_json_path.open("r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("[rl-observation] "):
                    try:
                        last = json.loads(line.split(" ", 1)[1])
                    except Exception:
                        continue
    return last if isinstance(last, dict) else {}


def _pick_policy_action(
    *,
    policy: str,
    rng: np.random.RandomState,
    theta_hat: np.ndarray,
    A_inv: np.ndarray,
    x: np.ndarray,
    action_onehots: np.ndarray,
    sigma: float,
) -> Tuple[int, np.ndarray, np.ndarray]:
    """Return (a_idx, theta_used, scores)."""

    x = np.asarray(x, dtype=np.float32).reshape(-1)
    action_onehots = np.asarray(action_onehots, dtype=np.float32)

    # Build Phi matrix: (n_actions, dim)
    Phi = np.asarray([phi_fn(x=x, a_onehot=ao) for ao in action_onehots], dtype=np.float64)

    if str(policy) == "greedy":
        theta = np.asarray(theta_hat, dtype=np.float64).reshape(-1)
    else:
        cov = (float(sigma) ** 2) * np.asarray(A_inv, dtype=np.float64)
        theta = rng.multivariate_normal(mean=np.asarray(theta_hat, dtype=np.float64).reshape(-1), cov=cov)

    scores = Phi @ theta
    a_idx = int(np.argmax(scores))
    return a_idx, theta.astype(np.float64), scores.astype(np.float64)


@dataclass
class EvalRec:
    t: int
    policy: str
    policy_rep: int
    sender_id: int
    loss_mode: str
    rtt_ms: int
    bitrate_mbps: int
    file_bytes: int
    a_idx: int
    action: Dict[str, Any]
    ddl_ms: int
    context: List[float]
    env_info: Dict[str, Any]


def main() -> int:
    ap = argparse.ArgumentParser(
        description=(
            "Evaluate a saved LinTS bandit checkpoint on the same netns/tc testbed as run_raw_fec1_fec2_baselines.py. "
            "Writes a JSONL log compatible with plot_overhead_and_delay_from_* scripts."
        )
    )

    ap.add_argument("--checkpoint-prefix", type=str, required=True, help="Prefix path for checkpoint (reads <prefix>.npz and <prefix>.json)")
    ap.add_argument("--out-dir", type=str, required=True)
    ap.add_argument("--run-tag", type=str, default="", help="Tag for netns/veth isolation")

    ap.add_argument("--policy", type=str, default="greedy", choices=["greedy", "ts"], help="Action selection policy")
    ap.add_argument("--seed", type=int, default=0, help="Seed for TS sampling (and tie-breaking RNG)")
    ap.add_argument("--policy-repeats", type=int, default=1, help="Repeat evaluation with seed+i and average in plotting")
    ap.add_argument("--ctx-reset", type=str, default="per_scenario", choices=["never", "per_scenario"], help="When to reset context state")

    ap.add_argument("--loss-profile", type=str, default="ge", choices=["ge", "iid"], help="Loss profile")
    ap.add_argument("--iid-loss-pcts", type=str, default="0.1,0.2,0.3,0.4,0.5")
    ap.add_argument("--rtt-ms", type=int, default=30, help="IID mode RTT (ms)")
    ap.add_argument("--ge-params", type=str, default=str(_PY_ROOT / "bandit" / "quic_fec_params.json"))
    ap.add_argument("--ge-key", type=str, default="GE_steady_rp")
    ap.add_argument("--ge-h-pct", type=float, default=0.0)
    ap.add_argument("--ge-k-pct", type=float, default=99.0)
    ap.add_argument("--sender-ids", type=str, default="all")

    ap.add_argument("--bitrate-mbps", type=int, default=10)
    ap.add_argument("--timeout-transfer-s", type=int, default=10)
    ap.add_argument("--timeout-s", type=int, default=60)
    ap.add_argument("--steps-per-scenario", type=int, default=30, help="How many transfers to run per (sender, loss_mode) scenario")

    ap.add_argument(
        "--cc",
        type=str,
        default="bbrv2",
        choices=["bbrv2", "bbr", "bbrv1", "bbr1", "cubic", "reno"],
        help="Congestion control algorithm (passed as QUIC_FEC_CC_ALGO to quicfec_run_once.sh)",
    )

    ap.add_argument("--file-bytes", type=int, default=100 * 1024)
    ap.add_argument("--symbol-bytes", type=int, default=1200)
    ap.add_argument("--decode-ddl-ms", type=int, default=25)

    ap.add_argument("--enable-quic-overhead", type=int, default=1, choices=[0, 1])

    args = ap.parse_args()

    out_dir = Path(str(args.out_dir))
    out_dir.mkdir(parents=True, exist_ok=True)

    # Load checkpoint (agent + ctx + action set).
    agent, lints_cfg, ctx, ctx_cfg, action_set, step_t = load_checkpoint(path_prefix=str(args.checkpoint_prefix))

    # Freeze posterior: never call agent.update(). Override RNG for reproducible evaluation.
    base_seed = int(args.seed)

    # Precompute action onehots and mapping from a_idx to concrete (K,R0,RSTEP,ddl_ms).
    k_values = list(action_set.k_values)
    r0_values = list(getattr(action_set, "r0_values", []))
    rstep_values = list(action_set.rstep_values)
    ddl_ms_values = list(action_set.ddl_ms_values)

    if not k_values or not r0_values or not rstep_values or not ddl_ms_values:
        raise SystemExit("checkpoint action_set missing factor values")

    action_onehots = np.asarray([action_set.get_onehot(i) for i in range(len(action_set))], dtype=np.float32)

    run_tag = str(args.run_tag or "").strip() or _default_run_tag()
    net_env = _netns_env_for_tag(run_tag)

    tmp_out_dir = Path("/tmp") / f"rl-quic-out-{net_env['NS']}"
    tmp_out_dir.mkdir(parents=True, exist_ok=True)

    file_path = _REPO_ROOT / "go" / "test_data" / f"bandit_eval_payload_{int(args.file_bytes)}B_{run_tag}.bin"
    _ensure_file_of_size(file_path=file_path, file_bytes=int(args.file_bytes))

    # Setup netns once using quicfec script.
    obs_json_path = Path("/tmp") / f"bandit_eval_obs_{net_env['NS']}.json"
    if obs_json_path.exists():
        try:
            obs_json_path.unlink()
        except Exception:
            pass

    setup_env = {
        **net_env,
        "OUT_DIR": str(tmp_out_dir),
        "OBS_JSON": str(obs_json_path),
        "SETUP_ONLY": "1",
        "SKIP_NETNS_RESET": "0",
        "SKIP_TC_CONFIG": "0",
        "SKIP_BUILD": "0",
        "BITRATE_MBPS": str(int(args.bitrate_mbps)),
        "RTT_MS": str(int(args.rtt_ms)),
        "LOSS_MODE": "none",
        "TIMEOUT_S": str(int(args.timeout_transfer_s)),
    }
    _run_script(script=_REPO_ROOT / "scripts" / "quicfec_run_once.sh", env=setup_env, timeout_s=60)

    common_env = {
        **net_env,
        "OUT_DIR": str(tmp_out_dir),
        "OBS_JSON": str(obs_json_path),
        "SKIP_NETNS_RESET": "1",
        "SKIP_TC_CONFIG": "0",
        "SKIP_SYSCTL": "1",
        "SKIP_BUILD": "0",
        "BITRATE_MBPS": str(int(args.bitrate_mbps)),
        "TIMEOUT_S": str(int(args.timeout_transfer_s)),
        "QUIC_FEC_CC_BYPASS": "0",
        "QUIC_FEC_CC_ALGO": str(args.cc),
        "FILE": str(file_path),
    }

    # Build scenarios.
    loss_profile = str(args.loss_profile)
    sender_ids = _parse_int_list(str(args.sender_ids))

    ge_params: Optional[Dict[str, Any]] = None
    if loss_profile == "ge":
        ge_params = _load_ge_params(Path(str(args.ge_params)))
        if sender_ids == [-1]:
            sender_ids = _ge_sender_ids(ge_params)

    iid_loss_pcts = _parse_float_list(str(args.iid_loss_pcts))
    if loss_profile == "iid" and not iid_loss_pcts:
        iid_loss_pcts = [0.5]

    scenarios: List[Tuple[int, int, str]] = []
    if loss_profile == "ge":
        assert ge_params is not None
        for sid in sender_ids:
            e = _get_sender_entry(ge_params, int(sid))
            rtt_ms = int(e.get("rtt_ms", int(args.rtt_ms)) or int(args.rtt_ms))
            ge_rp = e.get(str(args.ge_key))
            if not isinstance(ge_rp, dict):
                raise ValueError(f"sender {sid} missing ge key {args.ge_key}")
            loss_mode = _ge_to_tc_gemodel_loss_mode(
                ge_rp,
                h_loss_pct=float(args.ge_h_pct),
                k_loss_pct=float(args.ge_k_pct),
            )
            scenarios.append((int(sid), int(rtt_ms), str(loss_mode)))
    else:
        base_sids = sender_ids if sender_ids and sender_ids != [-1] else [0]
        for sid in base_sids:
            for pct in iid_loss_pcts:
                scenarios.append((int(sid), int(args.rtt_ms), f"iid:{float(pct):g}"))

    task = f"file_{int(args.file_bytes)}B"
    if int(args.file_bytes) == 128 * 1024:
        task = "delay_128kb"

    jsonl_path = out_dir / "bandit_eval_metrics.jsonl"
    csv_path = out_dir / "bandit_eval_results.csv"

    # Write logs.
    csv_rows: List[Dict[str, Any]] = []
    t_global = 0

    with jsonl_path.open("w", encoding="utf-8") as f_jsonl:
        for policy_rep in range(int(args.policy_repeats)):
            # Independent sampling stream for TS.
            rng = np.random.RandomState(int(base_seed) + int(policy_rep))

            for sender_id, rtt_ms, loss_mode in scenarios:
                if str(args.ctx_reset) == "per_scenario":
                    ctx.reset()

                # Start each scenario with the current context.
                for rep in range(int(args.steps_per_scenario)):
                    x = ctx.get_context()

                    # Select action.
                    a_idx, theta_used, scores = _pick_policy_action(
                        policy=str(args.policy),
                        rng=rng,
                        theta_hat=np.asarray(agent.theta_hat, dtype=np.float64),
                        A_inv=np.asarray(agent.A_inv, dtype=np.float64),
                        x=x,
                        action_onehots=action_onehots,
                        sigma=float(getattr(lints_cfg, "sigma", 0.2)),
                    )

                    a_spec = action_set.get_action(int(a_idx))
                    K = int(k_values[int(a_spec.k_idx)])
                    R0 = int(r0_values[int(a_spec.r0_idx)])
                    RSTEP = int(rstep_values[int(a_spec.rstep_idx)])
                    ddl_ms = int(ddl_ms_values[int(a_spec.ddl_idx)])

                    # Ensure OBS file doesn't carry stale observation.
                    try:
                        if obs_json_path.exists():
                            obs_json_path.unlink()
                    except Exception:
                        pass

                    env_fec = {
                        **common_env,
                        "RTT_MS": str(int(rtt_ms)),
                        "LOSS_MODE": str(loss_mode),
                        "K": str(int(K)),
                        "R0": str(int(R0)),
                        "RSTEP": str(int(RSTEP)),
                        "DDL_MS": str(int(ddl_ms)),
                        "DECODE_DDL_MS": str(int(args.decode_ddl_ms)),
                        "SYMBOL_BYTES": str(int(args.symbol_bytes)),
                        "USE_ARQ": "1",
                    }
                    if int(args.enable_quic_overhead) == 1:
                        env_fec["FEC_STATS"] = "1"

                    stderr = _run_script(script=_REPO_ROOT / "scripts" / "quicfec_run_once.sh", env=env_fec, timeout_s=int(args.timeout_s))
                    run_line = _extract_last_run_record(stderr)
                    kv = _parse_kv_from_run_line(run_line)

                    timed_out = _to_int(kv, "timed_out", 0)
                    md5_ok = _to_int(kv, "md5_ok", 0)
                    client_ok = _to_int(kv, "client_ok", 1)
                    step_valid = 1 if (timed_out == 0 and md5_ok == 1 and client_ok == 1) else 0

                    dur_ms = float(_to_float(kv, "dur_ms", 0.0))
                    e2e_delay_ms = float(dur_ms) + float(rtt_ms) / 2.0 if dur_ms > 0 else 0.0
                    goodput_mbps = _goodput_mbps_from_file_and_dur(file_bytes=int(args.file_bytes), dur_ms=dur_ms)
                    overhead_ratio = _overhead_quic_ratio_from_kv(kv=kv) if int(args.enable_quic_overhead) == 1 else 0.0

                    # Read RL observation (policy-safe) from OBS_JSON if present.
                    rl_obs = _read_last_rl_observation(obs_json_path)
                    raw_obs = rl_obs.get("raw_obs") if isinstance(rl_obs.get("raw_obs"), dict) else rl_obs
                    if not isinstance(raw_obs, dict):
                        raw_obs = {}

                    # Normalize required raw_obs fields for plotting and context update.
                    raw_obs.setdefault("goodput", float(goodput_mbps))
                    raw_obs.setdefault("fec_overhead", float(overhead_ratio))
                    raw_obs.setdefault("ctrl_tx_nack_msgs", float(raw_obs.get("ctrl_tx_nack_msgs", 0.0) or 0.0))

                    # done_flag: treat success+on-time as 1.
                    on_time_flag = 1 if (step_valid == 1 and dur_ms > 0 and dur_ms <= float(ddl_ms)) else 0
                    raw_obs.setdefault("done_flag", float(on_time_flag))

                    # fec_rate: best-effort from action.
                    fec_rate = float(R0) / float(max(1, K))
                    raw_obs.setdefault("fec_rate", float(fec_rate))
                    raw_obs.setdefault("ddl_ms", float(ddl_ms))

                    obs_vec = np.asarray(
                        [
                            float(raw_obs.get("goodput", 0.0) or 0.0),
                            float(raw_obs.get("fec_overhead", 0.0) or 0.0),
                            float(raw_obs.get("ctrl_tx_nack_msgs", 0.0) or 0.0),
                            float(raw_obs.get("done_flag", 0.0) or 0.0),
                            float(raw_obs.get("fec_rate", 0.0) or 0.0),
                            float(raw_obs.get("ddl_ms", ddl_ms) or ddl_ms),
                        ],
                        dtype=np.float64,
                    )
                    ctx.update_from_obs(obs=obs_vec, ddl_ms=int(ddl_ms))

                    env_info: Dict[str, Any] = {
                        "step_valid": int(step_valid),
                        "md5_ok": int(md5_ok),
                        "is_timeout": int(1 if timed_out != 0 else 0),
                        "is_md5_fail": int(1 if md5_ok != 1 else 0),
                        "dur_ms": float(dur_ms),
                        "e2e_delay_ms": float(e2e_delay_ms),
                        "goodput_mbps": float(goodput_mbps),
                        "quic_overhead_ratio": float(overhead_ratio),
                        "quic_sent_bytes": int(_to_int(kv, "fec_quic_sent_bytes", 0)),
                        "on_time_flag": int(on_time_flag),
                        "net_params": {
                            "rtt_ms": int(rtt_ms),
                            "loss_mode": str(loss_mode),
                            "bitrate_mbps": int(args.bitrate_mbps),
                        },
                        "fec_cfg": {
                            "K": int(K),
                            "R0": int(R0),
                            "RSTEP": int(RSTEP),
                            "DDL_MS": int(ddl_ms),
                            "DECODE_DDL_MS": int(args.decode_ddl_ms),
                            "SYMBOL_BYTES": int(args.symbol_bytes),
                        },
                        "raw_obs": {
                            "goodput": float(raw_obs.get("goodput", 0.0) or 0.0),
                            "fec_overhead": float(raw_obs.get("fec_overhead", 0.0) or 0.0),
                            "ctrl_tx_nack_msgs": float(raw_obs.get("ctrl_tx_nack_msgs", 0.0) or 0.0),
                            "done_flag": float(raw_obs.get("done_flag", 0.0) or 0.0),
                            "fec_rate": float(raw_obs.get("fec_rate", 0.0) or 0.0),
                            "ddl_ms": float(raw_obs.get("ddl_ms", ddl_ms) or ddl_ms),
                        },
                        "extra": {"run": kv},
                    }

                    rec = EvalRec(
                        t=int(t_global),
                        policy=str(args.policy),
                        policy_rep=int(policy_rep),
                        sender_id=int(sender_id),
                        loss_mode=str(loss_mode),
                        rtt_ms=int(rtt_ms),
                        bitrate_mbps=int(args.bitrate_mbps),
                        file_bytes=int(args.file_bytes),
                        a_idx=int(a_idx),
                        action={
                            "k_idx": int(a_spec.k_idx),
                            "r0_idx": int(a_spec.r0_idx),
                            "rstep_idx": int(a_spec.rstep_idx),
                            "ddl_idx": int(a_spec.ddl_idx),
                            "K": int(K),
                            "R0": int(R0),
                            "RSTEP": int(RSTEP),
                            "ddl_ms": int(ddl_ms),
                        },
                        ddl_ms=int(ddl_ms),
                        context=[float(v) for v in list(np.asarray(x, dtype=np.float64).reshape(-1))],
                        env_info=env_info,
                    )
                    f_jsonl.write(json.dumps(asdict(rec), ensure_ascii=False) + "\n")

                    csv_rows.append(
                        {
                            "task": str(task),
                            "method": "bandit",
                            "policy": str(args.policy),
                            "policy_rep": int(policy_rep),
                            "sender_id": int(sender_id),
                            "loss_mode": str(loss_mode),
                            "rep": int(rep),
                            "success": int(step_valid),
                            "dur_ms": float(dur_ms),
                            "e2e_delay_ms": float(e2e_delay_ms),
                            "goodput_mbps": float(goodput_mbps),
                            "overhead_ratio": float(overhead_ratio),
                            "K": int(K),
                            "R0": int(R0),
                            "RSTEP": int(RSTEP),
                            "ddl_ms": int(ddl_ms),
                        }
                    )

                    t_global += 1

                    # Short progress line.
                    print(
                        f"t={t_global:05d} rep={rep:02d} policy_rep={policy_rep} sender={sender_id} "
                        f"loss={loss_mode} a={a_idx} K={K} R0={R0} RSTEP={RSTEP} ddl={ddl_ms} "
                        f"ok={step_valid} dur_ms={int(dur_ms)} ov={overhead_ratio:.3f}"
                    )

    # CSV summary for convenience.
    with csv_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(
            f,
            fieldnames=list(csv_rows[0].keys()) if csv_rows else ["task"],
        )
        w.writeheader()
        for r in csv_rows:
            w.writerow(r)

    meta = {
        "created": _now_ts(),
        "out_dir": str(out_dir),
        "checkpoint_prefix": str(Path(str(args.checkpoint_prefix)).resolve()),
        "net": net_env,
        "tmp_out_dir": str(tmp_out_dir),
        "task": str(task),
        "args": vars(args),
        "checkpoint_step_t": int(step_t),
        "lints_cfg": asdict(lints_cfg),
        "ctx_cfg": asdict(ctx_cfg),
        "action_set": {
            "k_values": list(k_values),
            "r0_values": list(r0_values),
            "rstep_values": list(rstep_values),
            "ddl_ms_values": list(ddl_ms_values),
            "n_actions": int(len(action_set)),
        },
    }
    (out_dir / "meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(f"OUT: {out_dir}")
    print(f"- bandit_eval_metrics.jsonl: {jsonl_path}")
    print(f"- bandit_eval_results.csv: {csv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
