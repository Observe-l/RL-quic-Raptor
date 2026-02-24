#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import math
import re
import time
import os
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402


def _now_ts() -> str:
    return time.strftime("%Y%m%d-%H%M%S")


def _configure_matplotlib() -> None:
    plt.rcParams.update(
        {
            "figure.figsize": (6.4, 3.8),
            "font.size": 10,
            "axes.labelsize": 10,
            "axes.titlesize": 10,
            "legend.fontsize": 8,
            "xtick.labelsize": 9,
            "ytick.labelsize": 9,
            "axes.grid": True,
            "grid.alpha": 0.25,
            "savefig.dpi": 500,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
        }
    )


def _goodput_mbps(*, file_bytes: int, dur_ms: int) -> float:
    if file_bytes <= 0 or dur_ms <= 0:
        return 0.0
    # Mbps = (bytes * 8 / 1e6) / (dur_ms/1000)
    return float(file_bytes) * 8.0 * 1000.0 / (1e6 * float(dur_ms))


def _mean(xs: List[float]) -> float:
    if not xs:
        return 0.0
    return float(sum(xs)) / float(len(xs))


def _median(xs: List[float]) -> float:
    if not xs:
        return 0.0
    ys = sorted(xs)
    n = len(ys)
    if n % 2 == 1:
        return float(ys[n // 2])
    return 0.5 * float(ys[n // 2 - 1] + ys[n // 2])


@dataclass
class Run:
    sender_id: int
    method: str
    success: int
    dur_ms: int
    file_bytes: int
    overhead_ratio: float

    @property
    def goodput_mbps(self) -> float:
        return _goodput_mbps(file_bytes=self.file_bytes, dur_ms=self.dur_ms)


def _load_runs(runs_csv: Path) -> List[Run]:
    out: List[Run] = []
    with runs_csv.open("r", encoding="utf-8", newline="") as f:
        r = csv.DictReader(f)
        for row in r:
            try:
                sender_id = int(row.get("sender_id", "0") or "0")
                method = str(row.get("method", ""))
                success = int(row.get("success", "0") or "0")
                dur_ms = int(row.get("dur_ms", "0") or "0")
                file_bytes = int(row.get("file_bytes", "0") or "0")
                overhead_ratio = float(row.get("overhead_ratio", "0") or "0")
            except Exception:
                continue
            if not method:
                continue
            out.append(
                Run(
                    sender_id=sender_id,
                    method=method,
                    success=success,
                    dur_ms=dur_ms,
                    file_bytes=file_bytes,
                    overhead_ratio=overhead_ratio,
                )
            )
    return out


def _load_flec_runs(flec_jsonl: Path) -> List[Run]:
    """Load per-trial flec jsonl and map into the same Run schema."""

    from flec_metrics import flec_corrected_e2e_delay_s, flec_corrected_overhead_ratio

    out: List[Run] = []
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
                ok = int(d.get("ok", 0) or 0)
                delay_s = flec_corrected_e2e_delay_s(d)
                e2e_delay_ms = float(delay_s) * 1000.0 if delay_s is not None else 0.0
                try:
                    rtt_ms = float(d.get("rtt_ms", 0.0) or 0.0)
                except Exception:
                    rtt_ms = 0.0
                # Match Run.goodput_mbps (uses dur_ms): goodput := data_bytes / (e2e_delay - RTT/2)
                dur_ms = int(round(max(0.0, float(e2e_delay_ms) - 0.5 * float(rtt_ms))))
                file_bytes = int(d.get("tx_data_bytes", 0) or 0)
                overhead_ratio = flec_corrected_overhead_ratio(d)
                if overhead_ratio is None:
                    overhead_ratio = 0.0
            except Exception:
                continue

            out.append(
                Run(
                    sender_id=int(sender_id),
                    method="flec",
                    success=int(ok),
                    dur_ms=int(dur_ms),
                    file_bytes=int(file_bytes),
                    overhead_ratio=float(overhead_ratio),
                )
            )
    return out


_FEC_METHOD_RE = re.compile(r"^fec_k(?P<k>\d+)_r0_(?P<r0>\d+)_rstep_(?P<rstep>\d+)$")


def _method_label(method: str) -> str:
    if method == "bandit":
        return "QUIC-FEC-Bandit"
    if method == "quic_bbrv2":
        return "QUIC"
    m = _FEC_METHOD_RE.match(str(method))
    if m:
        return f"QUIC-FEC(K={int(m.group('k'))},R0={int(m.group('r0'))},Rstep={int(m.group('rstep'))})"
    return str(method)


def main() -> int:
    ap = argparse.ArgumentParser(description="Plot goodput vs overhead trade-off from an existing runs.csv")
    ap.add_argument(
        "--runs-csv",
        type=str,
        default="python/results/paper-overhead/runs.csv",
        help="Path to runs.csv (output of overhead_vs_completion_scatter.py)",
    )
    ap.add_argument(
        "--flec-jsonl",
        type=str,
        default="",
        help="Optional: overlay flec points from jsonl (fields: sender,ok,e2e_s,tx_total_bytes,tx_data_bytes,overhead).",
    )
    ap.add_argument(
        "--flec-e2e-offset-ms",
        type=float,
        default=0.0,
        help="FLEC-only: add this offset (ms) to e2e delay (default 0).",
    )
    ap.add_argument("--out-dir", type=str, default="", help="Output directory (default: alongside runs.csv)")
    ap.add_argument(
        "--max-goodput-mbps",
        type=float,
        default=10.0,
        help="Filter out abnormal points with goodput > this threshold",
    )
    ap.add_argument(
        "--include-failures",
        action="store_true",
        help="Include success==0 rows (default: exclude failures)",
    )
    ap.add_argument(
        "--aggregate",
        type=str,
        default="sender_method_mean",
        choices=["none", "sender_method_mean"],
        help="How to build scatter points: per-run or per-(sender,method) mean",
    )

    args = ap.parse_args()

    os.environ["FLEC_E2E_OFFSET_MS"] = str(float(getattr(args, "flec_e2e_offset_ms", 0.0) or 0.0))

    runs_csv = Path(args.runs_csv)
    if not runs_csv.exists():
        raise FileNotFoundError(str(runs_csv))

    out_dir = Path(args.out_dir) if str(args.out_dir).strip() else runs_csv.parent
    out_dir.mkdir(parents=True, exist_ok=True)

    runs = _load_runs(runs_csv)

    flec_path = Path(str(args.flec_jsonl)).expanduser() if str(args.flec_jsonl).strip() else None
    if flec_path is not None:
        if not flec_path.exists():
            raise FileNotFoundError(str(flec_path))
        runs.extend(_load_flec_runs(flec_path))

    # Filter rows and compute goodput.
    filtered: List[Run] = []
    dropped_hi = 0
    dropped_fail = 0
    dropped_bad = 0
    for rr in runs:
        if rr.file_bytes <= 0 or rr.dur_ms <= 0 or not math.isfinite(rr.overhead_ratio):
            dropped_bad += 1
            continue
        if not args.include_failures and int(rr.success) != 1:
            dropped_fail += 1
            continue
        gp = rr.goodput_mbps
        if not math.isfinite(gp) or gp <= 0:
            dropped_bad += 1
            continue
        if gp > float(args.max_goodput_mbps):
            dropped_hi += 1
            continue
        filtered.append(rr)

    # Build points.
    # Each point = (overhead, goodput, method, sender_id?, n)
    pts: List[Dict[str, Any]] = []
    if str(args.aggregate) == "none":
        for rr in filtered:
            pts.append(
                {
                    "sender_id": int(rr.sender_id),
                    "method": str(rr.method),
                    "n": 1,
                    "overhead": float(rr.overhead_ratio),
                    "goodput_mbps": float(rr.goodput_mbps),
                }
            )
    else:
        by: Dict[Tuple[int, str], List[Run]] = defaultdict(list)
        for rr in filtered:
            by[(int(rr.sender_id), str(rr.method))].append(rr)
        for (sid, method), rs in sorted(by.items(), key=lambda x: (x[0][1], x[0][0])):
            overheads = [float(x.overhead_ratio) for x in rs]
            gps = [float(x.goodput_mbps) for x in rs]
            pts.append(
                {
                    "sender_id": int(sid),
                    "method": str(method),
                    "n": int(len(rs)),
                    "overhead": float(_mean(overheads)),
                    "goodput_mbps": float(_mean(gps)),
                    "overhead_median": float(_median(overheads)),
                    "goodput_median_mbps": float(_median(gps)),
                }
            )

    out_pts = out_dir / "goodput_overhead_points.csv"
    fieldnames = sorted({k for p in pts for k in p.keys()})
    with out_pts.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for p in pts:
            w.writerow(p)

    # Styling
    method_labels = {
        "bandit": "QUIC-FEC-Bandit",
        "quic_bbrv2": "QUIC",
        "flec": "FLEC",
    }
    method_colors = {
        "bandit": "#1f77b4",
        "quic_bbrv2": "#ff7f0e",
        "flec": "#9467bd",
    }
    method_markers = {
        "bandit": "o",
        "quic_bbrv2": "^",
        "flec": "x",
    }

    # Add any fec_* methods with stable colors/markers.
    fec_methods = sorted({p["method"] for p in pts if str(p["method"]).startswith("fec_")})
    fec_palette = ["#2ca02c", "#d62728", "#9467bd", "#8c564b", "#e377c2"]
    fec_markers = ["s", "D", "P", "X", "v"]
    for i, m in enumerate(fec_methods):
        if m not in method_labels:
            method_labels[m] = _method_label(str(m))
        if m not in method_colors:
            method_colors[m] = fec_palette[i % len(fec_palette)]
        if m not in method_markers:
            method_markers[m] = fec_markers[i % len(fec_markers)]

    methods = sorted({str(p["method"]) for p in pts})

    _configure_matplotlib()
    fig, ax = plt.subplots()
    for m in methods:
        xs = [float(p["overhead"]) for p in pts if str(p["method"]) == m]
        ys = [float(p["goodput_mbps"]) for p in pts if str(p["method"]) == m]
        ax.scatter(
            xs,
            ys,
            s=26 if str(args.aggregate) != "none" else 12,
            alpha=0.85 if str(args.aggregate) != "none" else 0.25,
            marker=method_markers.get(m, "o"),
            color=method_colors.get(m, None),
            label=method_labels.get(m, m),
        )

    ax.set_xlabel("overhead")
    ax.set_ylabel("Goodput (Mbps)")
    # ax.set_title(f"Goodput vs overhead (goodput <= {float(args.max_goodput_mbps):g} Mbps)")
    ax.legend(loc="best", frameon=True)
    fig.tight_layout()

    out_fig = out_dir / "fig_goodput_vs_overhead_scatter.pdf"
    fig.savefig(out_fig)
    fig.savefig(out_fig.with_suffix(".png"))
    plt.close(fig)

    meta = {
        "runs_csv": str(runs_csv),
        "out_dir": str(out_dir),
        "aggregate": str(args.aggregate),
        "include_failures": bool(args.include_failures),
        "max_goodput_mbps": float(args.max_goodput_mbps),
        "rows_in": int(len(runs)),
        "rows_after_filter": int(len(filtered)),
        "dropped": {"bad": int(dropped_bad), "failures": int(dropped_fail), "goodput_gt_max": int(dropped_hi)},
    }
    (out_dir / "goodput_overhead_meta.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print("OUT:", out_dir)
    print("- points:", out_pts)
    print("- fig:", out_fig)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
