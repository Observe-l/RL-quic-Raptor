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
from typing import Any, Dict, List, Optional

_PY_ROOT = Path(__file__).resolve().parents[1]
_REPO_ROOT = Path(__file__).resolve().parents[2]

import sys

if str(_PY_ROOT) not in sys.path:
    sys.path.insert(0, str(_PY_ROOT))

from bandit.run_lints_ge_schedule import _ge_to_tc_gemodel_loss_mode  # noqa: E402


@dataclass
class Trial:
    rep: int
    goodput_mbps: float
    delay_ms_avg: float
    md5_ok: int
    timed_out: int


_RUN_RE = re.compile(
    r"^\[run\].*proto=([^ ]+).*dur_ms=([0-9]+).*timed_out=([01]).*md5_ok=([01]).*s_mbps=([0-9.]+)"
)


def _load_ge(*, params_path: Path, sender_id: int, ge_key: str) -> Dict[str, Any]:
    data = json.loads(params_path.read_text(encoding="utf-8"))
    senders = data.get("senders")
    if not isinstance(senders, dict):
        raise ValueError("invalid senders")
    s = senders.get(str(sender_id))
    if not isinstance(s, dict):
        raise ValueError(f"sender_id={sender_id} not found")
    ge = s.get(ge_key)
    if not isinstance(ge, dict):
        raise ValueError(f"sender_id={sender_id} missing {ge_key}")
    return ge


def _extract_last_line(prefix: str, s: str) -> Optional[str]:
    last = None
    for line in s.splitlines():
        if line.startswith(prefix):
            last = line
    return last


def _parse_delay_ms_avg(stderr: str) -> float:
    dline = _extract_last_line("[delay]", stderr) or ""
    m = re.search(r"delay_ms_avg=([0-9.]+)", dline)
    if not m:
        return 0.0
    try:
        return float(m.group(1))
    except Exception:
        return 0.0


def _run_once(*, loss_mode: str, bitrate_mbps: int, rtt_ms: int, timeout_s: int, file_path: Path) -> Trial:
    env = os.environ.copy()
    env.update(
        {
            "BITRATE_MBPS": str(int(bitrate_mbps)),
            "RTT_MS": str(int(rtt_ms)),
            "LOSS_MODE": str(loss_mode),
            "LOSS_PCT": "0",
            "TIMEOUT_S": str(int(timeout_s)),
            "FILE": str(file_path),
            "QUIC_FEC_CC_BYPASS": "0",
            "QUIC_FEC_CC_ALGO": "bbrv2",
        }
    )

    p = subprocess.run(
        ["bash", str(_REPO_ROOT / "scripts" / "quicraw_run_once.sh")],
        cwd=str(_REPO_ROOT),
        env=env,
        text=True,
        capture_output=True,
        timeout=max(30, int(timeout_s) + 15),
    )

    stderr = p.stderr or ""
    run_line = _extract_last_line("[run]", stderr) or ""
    m = _RUN_RE.match(run_line.strip())
    if not m:
        tail = "\n".join(stderr.splitlines()[-120:])
        raise RuntimeError(f"no parsable [run] line\n---tail---\n{tail}")

    timed_out = int(m.group(3))
    md5_ok = int(m.group(4))
    goodput = float(m.group(5))
    delay = _parse_delay_ms_avg(stderr)

    if timed_out or md5_ok != 1:
        goodput = 0.0
        delay = 0.0

    return Trial(rep=-1, goodput_mbps=goodput, delay_ms_avg=delay, md5_ok=md5_ok, timed_out=timed_out)


def main() -> int:
    ap = argparse.ArgumentParser(description="Test quic-bbrv2 under GE_steady_rp parameters")
    ap.add_argument("--ge-params", type=str, default=str(_REPO_ROOT / "python" / "bandit" / "quic_fec_params.json"))
    ap.add_argument("--sender-id", type=int, default=28)
    ap.add_argument("--ge-key", type=str, default="GE_steady_rp")
    ap.add_argument("--bitrate-mbps", type=int, default=50)
    ap.add_argument("--rtt-ms", type=int, default=25)
    ap.add_argument("--timeout-transfer-s", type=int, default=15)
    ap.add_argument("--reps", type=int, default=20)
    ap.add_argument("--file-bytes", type=int, default=3 * 1024 * 1024)
    ap.add_argument("--ge-h-pct", type=float, default=0.0)
    ap.add_argument("--ge-k-pct", type=float, default=99.0)
    ap.add_argument("--out-dir", type=str, default="")
    args = ap.parse_args()

    ge = _load_ge(params_path=Path(args.ge_params), sender_id=int(args.sender_id), ge_key=str(args.ge_key))
    loss_mode = _ge_to_tc_gemodel_loss_mode(ge, h_loss_pct=float(args.ge_h_pct), k_loss_pct=float(args.ge_k_pct))

    file_path = _REPO_ROOT / "go" / "test_data" / f"eval_quic_bbrv2_{args.file_bytes}B.bin"
    file_path.parent.mkdir(parents=True, exist_ok=True)
    if not file_path.exists() or file_path.stat().st_size != int(args.file_bytes):
        with open("/dev/urandom", "rb") as src, open(file_path, "wb") as dst:
            dst.write(src.read(int(args.file_bytes)))

    ts = time.strftime("%Y%m%d-%H%M%S")
    out_dir = Path(args.out_dir) if args.out_dir else (_REPO_ROOT / "python" / "results" / f"quic-bbrv2-ge-steady-rp-{ts}")
    out_dir.mkdir(parents=True, exist_ok=True)

    trials: List[Trial] = []
    for rep in range(int(args.reps)):
        t = _run_once(
            loss_mode=loss_mode,
            bitrate_mbps=int(args.bitrate_mbps),
            rtt_ms=int(args.rtt_ms),
            timeout_s=int(args.timeout_transfer_s),
            file_path=file_path,
        )
        t = Trial(rep=rep, goodput_mbps=t.goodput_mbps, delay_ms_avg=t.delay_ms_avg, md5_ok=t.md5_ok, timed_out=t.timed_out)
        trials.append(t)
        print(
            f"rep={rep:02d} goodput_mbps={t.goodput_mbps:.3f} delay_ms_avg={t.delay_ms_avg:.3f} md5_ok={t.md5_ok} timed_out={t.timed_out}"
        )

    out_csv = out_dir / "trials.csv"
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["rep", "goodput_mbps", "delay_ms_avg", "md5_ok", "timed_out"])
        w.writeheader()
        for t in trials:
            w.writerow(
                {
                    "rep": t.rep,
                    "goodput_mbps": f"{t.goodput_mbps:.6f}",
                    "delay_ms_avg": f"{t.delay_ms_avg:.6f}",
                    "md5_ok": t.md5_ok,
                    "timed_out": t.timed_out,
                }
            )

    goodputs = [t.goodput_mbps for t in trials]
    delays = [t.delay_ms_avg for t in trials]
    ok_rate = mean([1.0 if (t.md5_ok == 1 and t.timed_out == 0) else 0.0 for t in trials]) if trials else 0.0

    summary = {
        "method": "quic_bbrv2",
        "sender_id": int(args.sender_id),
        "ge_key": str(args.ge_key),
        "ge": ge,
        "loss_mode": loss_mode,
        "bitrate_mbps": int(args.bitrate_mbps),
        "rtt_ms": int(args.rtt_ms),
        "timeout_transfer_s": int(args.timeout_transfer_s),
        "reps": int(args.reps),
        "file": str(file_path),
        "mean_goodput_mbps": mean(goodputs) if goodputs else 0.0,
        "median_goodput_mbps": median(goodputs) if goodputs else 0.0,
        "mean_delay_ms_avg": mean(delays) if delays else 0.0,
        "median_delay_ms_avg": median(delays) if delays else 0.0,
        "ok_rate": ok_rate,
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print("\nSummary:")
    print(f"loss_mode={loss_mode}")
    print(f"mean_goodput_mbps={summary['mean_goodput_mbps']:.3f} median_goodput_mbps={summary['median_goodput_mbps']:.3f} ok_rate={ok_rate:.3f}")
    print(f"mean_delay_ms_avg={summary['mean_delay_ms_avg']:.3f} median_delay_ms_avg={summary['median_delay_ms_avg']:.3f}")
    print("\nOUT:", out_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
