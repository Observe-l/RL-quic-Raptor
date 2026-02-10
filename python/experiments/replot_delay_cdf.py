#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

import numpy as np

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402


_METHOD_ORDER = [
    "bandit",
    "quic_bbrv2",
    "fec_k30_r0_2_rstep_6",
    "fec_k30_r0_10_rstep_6",
]

_METHOD_LABELS = {
    "bandit": "QUIC-FEC-Bandit",
    "quic_bbrv2": "QUIC",
    "fec_k30_r0_2_rstep_6": "IR-FEC1",
    "fec_k30_r0_10_rstep_6": "IR-FEC2",
}

_METHOD_COLORS = {
    "bandit": "#1f77b4",
    "quic_bbrv2": "#ff7f0e",
    "fec_k30_r0_2_rstep_6": "#2ca02c",
    "fec_k30_r0_10_rstep_6": "#d62728",
}


def _configure_matplotlib() -> None:
    plt.rcParams.update(
        {
            "figure.figsize": (8.2, 3.6),
            "font.size": 10,
            "axes.labelsize": 10,
            "axes.titlesize": 10,
            "legend.fontsize": 7,
            "xtick.labelsize": 9,
            "ytick.labelsize": 9,
            "axes.grid": True,
            "grid.alpha": 0.25,
            "lines.linewidth": 1.1,
            "savefig.dpi": 300,
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


def _load_delay_samples(*, csv_path: Path) -> Dict[str, List[float]]:
    out: Dict[str, List[float]] = {m: [] for m in _METHOD_ORDER}
    with csv_path.open("r", encoding="utf-8") as f:
        r = csv.DictReader(f)
        for row in r:
            if (row.get("task") or "").strip() != "delay_128kb":
                continue
            method = (row.get("method") or "").strip()
            if method not in out:
                continue
            # Exclude warmup and failures.
            try:
                if int(float(row.get("is_warmup") or 0)) != 0:
                    continue
                if int(float(row.get("success") or 0)) != 1:
                    continue
                dur_ms = float(row.get("dur_ms") or 0)
            except Exception:
                continue
            if dur_ms <= 0:
                continue
            out[method].append(dur_ms)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Replot E2E delay CDF from an existing paper-delay results folder")
    ap.add_argument(
        "--in-dir",
        type=str,
        required=True,
        help="Directory containing results.csv (e.g., python/results/paper-delay)",
    )
    ap.add_argument(
        "--xmin-ms",
        type=float,
        default=100.0,
        help="Lower x-axis limit for the CDF plot (ms)",
    )
    ap.add_argument(
        "--xmax-ms",
        type=float,
        default=300.0,
        help="Upper x-axis limit for the CDF plot (ms)",
    )
    ap.add_argument(
        "--out",
        type=str,
        default="fig_delay_cdf.pdf",
        help="Output filename (written under --in-dir unless absolute)",
    )
    args = ap.parse_args()

    in_dir = Path(args.in_dir)
    csv_path = in_dir / "results.csv"
    if not csv_path.exists():
        raise SystemExit(f"results.csv not found: {csv_path}")

    samples_by_method = _load_delay_samples(csv_path=csv_path)

    _configure_matplotlib()
    fig, ax = plt.subplots()

    for method in _METHOD_ORDER:
        values = samples_by_method.get(method, [])
        x, y = _ecdf(values)
        if x.size == 0:
            continue
        ax.plot(
            x,
            y,
            label=_METHOD_LABELS.get(method, method),
            color=_METHOD_COLORS.get(method, None),
        )

    # No title (paper figure style)
    ax.set_xlabel("E2E delay per message (ms)")
    ax.set_ylabel("CDF")
    ax.set_ylim(0.0, 1.02)
    # if args.xmax_ms is not None and float(args.xmax_ms) > 0:
    ax.set_xlim(float(args.xmin_ms), float(args.xmax_ms))

    ax.legend(loc="lower right", frameon=True)
    fig.tight_layout()

    out_path = Path(args.out)
    if not out_path.is_absolute():
        out_path = in_dir / out_path
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path)
    if out_path.suffix.lower() != ".png":
        fig.savefig(out_path.with_suffix(".png"))
    plt.close(fig)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
