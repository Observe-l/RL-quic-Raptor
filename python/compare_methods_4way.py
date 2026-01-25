#!/usr/bin/env python3
from __future__ import annotations

import csv
import math
from dataclasses import dataclass
from pathlib import Path
from statistics import median
from typing import Dict, Iterable, List, Optional, Tuple


@dataclass(frozen=True)
class Row:
    method: str
    loss_pct: float
    rep: int
    goodput_mbps: float
    md5_ok: int
    residual_erasures: int


def _read_csv(path: Path) -> List[dict]:
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def _as_float(x: Optional[str]) -> Optional[float]:
    if x is None:
        return None
    x = str(x).strip()
    if x == "":
        return None
    return float(x)


def _as_int(x: Optional[str]) -> int:
    try:
        return int(float(x or 0))
    except Exception:
        return 0


def _load_baseline(paths: Iterable[Path]) -> List[Row]:
    rows: List[Row] = []
    for path in paths:
        for r in _read_csv(path):
            proto = str(r["proto"]).strip()
            if proto == "quic_raw":
                method = "quic_raw_cubic"
            elif proto in {"quic_bbrv2", "quic_raw_bbrv2", "quicraw_bbrv2"}:
                method = "quic_bbrv2"
            elif proto == "tcp":
                method = "tcp"
            else:
                continue
            rows.append(
                Row(
                    method=method,
                    loss_pct=float(r["loss_pct"]),
                    rep=int(r["rep"]),
                    goodput_mbps=float(r["goodput_mbps"]),
                    md5_ok=_as_int(r.get("md5_ok")),
                    residual_erasures=0,
                )
            )
    return rows


def _load_fec(paths: Iterable[Path], method: str) -> List[Row]:
    rows: List[Row] = []
    for path in paths:
        for r in _read_csv(path):
            # only CC runs
            if str(r.get("cc_bypass", "0")) != "0":
                continue
            gp = _as_float(r.get("goodput_arrival_mbps"))
            if gp is None:
                gp = _as_float(r.get("goodput_mbps"))
            if gp is None:
                continue
            rows.append(
                Row(
                    method=method,
                    loss_pct=float(r["loss_pct"]),
                    rep=int(r["rep"]),
                    goodput_mbps=float(gp),
                    md5_ok=_as_int(r.get("md5_ok")),
                    residual_erasures=_as_int(r.get("residual_erasures")),
                )
            )
    return rows


def _median_per_loss(rows: List[Row], losses: List[float]) -> Dict[float, float]:
    out: Dict[float, float] = {}
    for loss in losses:
        vals = [
            r.goodput_mbps
            for r in rows
            if math.isclose(r.loss_pct, loss) and r.md5_ok == 1 and r.residual_erasures == 0
        ]
        out[loss] = median(vals) if vals else float("nan")
    return out


def _plot(medians: Dict[str, Dict[float, float]], losses: List[float], out_png: Path, title: str) -> None:
    import matplotlib.pyplot as plt

    out_png.parent.mkdir(parents=True, exist_ok=True)
    plt.figure(figsize=(7.2, 4.2), dpi=170)

    styles = {
        "quic_raw_cubic": ("C0", "o", "Raw QUIC (CUBIC)"),
        "quic_bbrv2": ("C4", "x", "Raw QUIC (BBRv2)"),
        "tcp": ("C2", "s", "TCP"),
        "quic_fec_cubic": ("C3", "^", "QUIC-FEC (CUBIC)"),
        "quic_fec_bbrv2": ("C1", "D", "QUIC-FEC (BBRv2)"),
    }

    for method, series in medians.items():
        xs = losses
        ys = [series.get(x, float("nan")) for x in xs]
        color, marker, label = styles.get(method, (None, "o", method))
        plt.semilogx(xs, ys, marker=marker, linewidth=2.0, label=label, color=color)

    plt.xlabel("i.i.d. loss rate (%)")
    plt.ylabel("Arrival Goodput (Mbps) (median over reps)")
    plt.title(title)
    plt.grid(True, which="both", linestyle="--", alpha=0.35)
    plt.legend(frameon=False)
    plt.tight_layout()
    plt.savefig(out_png)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    results_dir = root / "python" / "results"

    losses = [0.1, 0.2, 0.3, 0.4, 0.5, 1.0, 5.0, 10.0]

    baseline_low = results_dir / "baseline_quicraw_tcp_bw50_loss_0p1_0p5_reps3.csv"
    baseline_high = results_dir / "baseline_quicraw_tcp_bw50_loss_1_5_10_reps3.csv"

    # Optional: QUIC raw with BBRv2 baseline (if you produced it).
    baseline_bbrv2_low = results_dir / "baseline_quicraw_bbrv2_tcp_bw50_loss_0p1_0p5_reps3.csv"
    baseline_bbrv2_high = results_dir / "baseline_quicraw_bbrv2_tcp_bw50_loss_1_5_10_reps3.csv"

    fec_cubic_low = results_dir / "quicfec_cc_cubic_bw50_loss_0p1_0p5_reps3.csv"
    fec_cubic_high = results_dir / "quicfec_cc_cubic_bw50_loss_1_5_10_reps3.csv"

    fec_bbrv2_low = results_dir / "quicfec_cc_bbrv2_bw50_loss_0p1_0p5_reps3.csv"
    fec_bbrv2_high = results_dir / "quicfec_cc_bbrv2_bw50_loss_1_5_10_reps3.csv"

    required = [
        baseline_low,
        baseline_high,
        fec_cubic_low,
        fec_cubic_high,
        fec_bbrv2_low,
        fec_bbrv2_high,
    ]
    missing = [p for p in required if not p.exists()]
    if missing:
        raise SystemExit("Missing required input CSVs:\n" + "\n".join(str(p) for p in missing))

    rows: List[Row] = []
    rows += _load_baseline([baseline_low, baseline_high])
    if baseline_bbrv2_low.exists() and baseline_bbrv2_high.exists():
        rows += _load_baseline([baseline_bbrv2_low, baseline_bbrv2_high])
    else:
        print(
            "[warn] QUIC-BBRv2 baseline CSVs not found; skipping. Expected both:\n"
            f"  - {baseline_bbrv2_low}\n  - {baseline_bbrv2_high}"
        )
    rows += _load_fec([fec_cubic_low, fec_cubic_high], method="quic_fec_cubic")
    rows += _load_fec([fec_bbrv2_low, fec_bbrv2_high], method="quic_fec_bbrv2")

    out_csv = results_dir / "compare_5methods_bw50_loss_0p1_10_reps3.csv"
    with out_csv.open("w", newline="") as f:
        w = csv.DictWriter(
            f,
            fieldnames=["method", "loss_pct", "rep", "goodput_mbps", "md5_ok", "residual_erasures"],
        )
        w.writeheader()
        for r in rows:
            w.writerow(
                {
                    "method": r.method,
                    "loss_pct": r.loss_pct,
                    "rep": r.rep,
                    "goodput_mbps": f"{r.goodput_mbps:.6f}",
                    "md5_ok": r.md5_ok,
                    "residual_erasures": r.residual_erasures,
                }
            )

    methods = ["quic_raw_cubic", "quic_bbrv2", "tcp", "quic_fec_cubic", "quic_fec_bbrv2"]
    per_method: Dict[str, Dict[float, float]] = {}
    for m in methods:
        per_method[m] = _median_per_loss([r for r in rows if r.method == m], losses)

    out_png = results_dir / "compare_5methods_bw50_loss_0p1_10_reps3.png"
    _plot(per_method, losses, out_png, title="Goodput vs loss @50Mbps (median over reps)")

    # Print a compact table.
    print("loss_pct," + ",".join(methods))
    for loss in losses:
        vals = [per_method[m].get(loss, float('nan')) for m in methods]
        print(
            f"{loss:.1f}," + ",".join("" if math.isnan(v) else f"{v:.3f}" for v in vals)
        )

    print("\nCSV:", out_csv)
    print("PNG:", out_png)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
