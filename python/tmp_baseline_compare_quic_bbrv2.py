#!/usr/bin/env python3
from __future__ import annotations

import csv
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Tuple

# Generates baseline QUIC-raw runs with BBRv2 CC under i.i.d. loss rates.
# Output format matches existing baseline CSVs used by python/compare_methods_4way.py.

REPO_ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = REPO_ROOT / "python" / "results"

LOW_LOSSES = [0.1, 0.2, 0.3, 0.4, 0.5]
HIGH_LOSSES = [1.0, 5.0, 10.0]

REPS = 3
BITRATE = 50
RTT = 20
TIMEOUT_S = 15

RUN_RE = re.compile(r"\[run\].*proto=([^ ]+).*loss=([^ ]+).*dur_ms=([0-9]+).*timed_out=([01]).*md5_ok=([01]).*s_mbps=([0-9.]+)")


def _run_quic_bbrv2(*, loss_pct: float) -> Dict[str, object]:
    env = os.environ.copy()
    env.update(
        {
            "BITRATE_MBPS": str(BITRATE),
            "RTT_MS": str(RTT),
            "LOSS_PCT": str(loss_pct),
            "LOSS_MODE": "",
            "TIMEOUT_S": str(TIMEOUT_S),
            "QUIC_FEC_CC_BYPASS": "0",
            "QUIC_FEC_CC_ALGO": "bbrv2",
        }
    )

    p = subprocess.run(
        ["bash", "scripts/quicraw_run_once.sh"],
        cwd=str(REPO_ROOT),
        env=env,
        text=True,
        capture_output=True,
        timeout=120,
    )

    out = (p.stdout or "") + "\n" + (p.stderr or "")
    m = RUN_RE.search(out)
    if not m:
        tail = "\n".join(out.splitlines()[-120:])
        raise RuntimeError(f"no [run] line found for loss={loss_pct}\n---tail---\n{tail}")

    proto = str(m.group(1)).strip()
    loss_desc = str(m.group(2)).strip()
    dur_ms = int(m.group(3))
    timed_out = int(m.group(4))
    md5_ok = int(m.group(5))
    goodput = float(m.group(6))

    # We want loss_pct column to be numeric i.i.d. loss used.
    # Script prints loss=<LOSS_PCT>% by default when LOSS_MODE is empty.
    _ = proto
    _ = loss_desc

    return {
        "proto": "quic_bbrv2",
        "loss_pct": float(loss_pct),
        "dur_ms": dur_ms,
        "timed_out": timed_out,
        "md5_ok": md5_ok,
        "goodput_mbps": goodput if (md5_ok == 1 and timed_out == 0) else 0.0,
    }


def _run_suite(losses: List[float]) -> List[dict]:
    rows: List[dict] = []
    for loss in losses:
        for rep in range(REPS):
            r = _run_quic_bbrv2(loss_pct=loss)
            r["rep"] = rep
            rows.append(r)
            print(
                f"loss={loss:.1f}% rep={rep} proto=quic_bbrv2 goodput={r['goodput_mbps']:.3f} md5_ok={r['md5_ok']} timed_out={r['timed_out']} dur_ms={r['dur_ms']}"
            )
            time.sleep(0.1)
    return rows


def _write_csv(path: Path, rows: List[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["proto", "loss_pct", "rep", "goodput_mbps", "dur_ms", "md5_ok"])
        w.writeheader()
        for r in rows:
            w.writerow({k: r[k] for k in w.fieldnames})


def main() -> int:
    low_rows = _run_suite(LOW_LOSSES)
    high_rows = _run_suite(HIGH_LOSSES)

    out_low = RESULTS_DIR / "baseline_quicraw_bbrv2_tcp_bw50_loss_0p1_0p5_reps3.csv"
    out_high = RESULTS_DIR / "baseline_quicraw_bbrv2_tcp_bw50_loss_1_5_10_reps3.csv"

    _write_csv(out_low, low_rows)
    _write_csv(out_high, high_rows)

    print("\nCSV low:", out_low)
    print("CSV high:", out_high)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
