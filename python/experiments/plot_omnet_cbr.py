#!/usr/bin/env python3
"""Plot vehicle-average OMNeT++ channelBusy:timeavg by traffic intensity."""
from __future__ import annotations

import argparse
import csv
import math
import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.ticker import MultipleLocator  # noqa: E402

EXPERIMENTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = EXPERIMENTS_DIR.parents[1]
if str(EXPERIMENTS_DIR) not in sys.path:
    sys.path.insert(0, str(EXPERIMENTS_DIR))

from paper10_plot_common import (  # noqa: E402
    configure_matplotlib_like_paper,
    method_color,
    method_label,
    method_marker,
    save_current_figure,
)


METHOD_DIRS = {
    "bandit": "BC-DIR_CBR",
    "flec": "flec_CBR",
    "flec_raptorq": "flec-rq_CBR",
    "quic_bbrv2": "quic_CBR",
}
METHOD_ORDER = ("bandit", "flec", "flec_raptorq", "quic_bbrv2")
TRAFFIC_INTENSITIES = (300, 600, 900, 1200)
SCALAR_RE = re.compile(
    r"^scalar\s+(\S+)\s+channelBusy:timeavg\s+([-+0-9.eE]+)(?:\s|$)"
)


def read_sca(path: Path) -> Tuple[List[float], List[float]]:
    vehicle_values: List[float] = []
    rsu_values: List[float] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = SCALAR_RE.match(line)
        if not match:
            continue
        module, raw_value = match.groups()
        value = float(raw_value)
        if not math.isfinite(value) or not 0.0 <= value <= 1.0:
            raise ValueError(f"invalid channelBusy:timeavg value {raw_value!r} in {path}")
        if ".node[" in module:
            vehicle_values.append(value)
        elif ".rsu[" in module:
            rsu_values.append(value)

    if not vehicle_values:
        raise ValueError(f"no vehicle node channelBusy:timeavg values in {path}")
    if len(rsu_values) != 1:
        raise ValueError(f"expected one RSU CBR value in {path}, found {len(rsu_values)}")
    return vehicle_values, rsu_values


def collect_rows(data_dir: Path) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    for method in METHOD_ORDER:
        method_dir = data_dir / METHOD_DIRS[method]
        if not method_dir.is_dir():
            raise FileNotFoundError(f"missing method directory: {method_dir}")
        for intensity in TRAFFIC_INTENSITIES:
            run_dir = method_dir / str(intensity)
            sca_files = sorted(run_dir.glob("*.sca"))
            if len(sca_files) != 1:
                raise ValueError(
                    f"expected one .sca file in {run_dir}, found {len(sca_files)}"
                )
            vehicle_values, rsu_values = read_sca(sca_files[0])
            rows.append(
                {
                    "method": method,
                    "method_label": method_label(method),
                    "traffic_intensity": intensity,
                    "vehicle_count": len(vehicle_values),
                    "vehicle_mean_cbr": sum(vehicle_values) / len(vehicle_values),
                    "rsu_cbr": rsu_values[0],
                    "source_sca": str(sca_files[0].relative_to(REPO_ROOT)),
                }
            )
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--data-dir", type=Path, default=REPO_ROOT / "python/results/CBR"
    )
    parser.add_argument(
        "--out", type=Path, default=REPO_ROOT / "figures/vary_density/v2x-cbr.png"
    )
    parser.add_argument(
        "--summary-csv", type=Path, default=REPO_ROOT / "python/results/CBR/cbr_summary.csv"
    )
    args = parser.parse_args()

    rows = collect_rows(args.data_dir.resolve())
    if len(rows) != len(METHOD_ORDER) * len(TRAFFIC_INTENSITIES):
        raise RuntimeError(f"expected 16 method/intensity rows, found {len(rows)}")

    configure_matplotlib_like_paper()
    # Match the 3.8 x 2.4 inch canvas used by iid-100k-overhead.png.
    fig, ax = plt.subplots(figsize=(3.8, 2.4))
    for method in METHOD_ORDER:
        method_rows = [row for row in rows if row["method"] == method]
        xs = [int(row["traffic_intensity"]) for row in method_rows]
        ys = [float(row["vehicle_mean_cbr"]) for row in method_rows]
        color = method_color(method)
        ax.plot(
            xs,
            ys,
            color=color,
            linewidth=1.6,
            marker=method_marker(method),
            markersize=5.2,
            markerfacecolor=color,
            markeredgecolor=color,
            markeredgewidth=0.0,
            label=method_label(method),
        )

    ax.set_xticks(TRAFFIC_INTENSITIES)
    ax.set_xlabel("Traffic Intensity")
    ax.set_ylabel("Channel Busy Ratio")
    ax.set_ylim(0, 1)
    ax.yaxis.set_major_locator(MultipleLocator(0.2))
    ax.grid(True, axis="y")
    ax.legend(loc="upper left", frameon=True)
    fig.tight_layout()

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.summary_csv.parent.mkdir(parents=True, exist_ok=True)
    save_current_figure(args.out)
    with args.summary_csv.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print(f"wrote {args.out}")
    print(f"wrote {args.summary_csv}")
    for row in rows:
        print(
            f"{row['method_label']:7} intensity={row['traffic_intensity']:4} "
            f"vehicle_mean_CBR={float(row['vehicle_mean_cbr']):.3f} "
            f"(n={row['vehicle_count']}) RSU_CBR={float(row['rsu_cbr']):.3f}"
        )


if __name__ == "__main__":
    main()
