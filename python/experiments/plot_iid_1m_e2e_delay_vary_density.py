#!/usr/bin/env python3
"""Replot 1 MB IID E2E delay for BC-DIR, FLEC, FLEC-RQ, and QUIC."""
from __future__ import annotations

import argparse
import math
import sys
from collections import defaultdict
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
from plot_iid_loss_boxplots import (  # noqa: E402
    Point,
    _load_bandit_eval_points,
    _load_baseline_points,
    _load_flec_points,
    _mean_ci95,
)


FILE_BYTES = 1024 * 1024
LOSS_PCTS = (0.1, 0.2, 0.3, 0.4, 0.5)
METHOD_ORDER = ("bandit", "flec", "flec_raptorq", "quic_bbrv2")


def load_selected_points(
    baseline_csv: Path,
    bandit_log: Path,
    flec_jsonl: Path,
    flec_rq_jsonl: Path,
) -> Dict[str, List[Point]]:
    rq_source_points = _load_flec_points(
        flec_jsonl=flec_rq_jsonl, methods={"flec"}, sender_ids=None
    )
    methods: Dict[str, List[Point]] = {
        "bandit": _load_bandit_eval_points(
            eval_jsonl=bandit_log, methods={"bandit"}, sender_ids=None
        ),
        "flec": _load_flec_points(
            flec_jsonl=flec_jsonl, methods={"flec"}, sender_ids=None
        ),
        # Reuse FLEC's success filtering and corrected E2E-delay calculation;
        # only relabel the rows so the RaptorQ variant stays a separate series.
        "flec_raptorq": [
            Point(
                method="flec_raptorq",
                loss_pct=point.loss_pct,
                overhead=point.overhead,
                e2e_delay_ms=point.e2e_delay_ms,
            )
            for point in rq_source_points
        ],
        "quic_bbrv2": _load_baseline_points(
            results_csv=baseline_csv,
            file_bytes=FILE_BYTES,
            methods={"quic_bbrv2"},
            sender_ids=None,
        ),
    }
    for method, points in methods.items():
        if not points:
            raise ValueError(f"no usable observations for {method}")
    return methods


def render(points_by_method: Dict[str, List[Point]], out_path: Path) -> None:
    values: Dict[Tuple[str, float], List[float]] = defaultdict(list)
    for method, points in points_by_method.items():
        for point in points:
            if point.loss_pct in LOSS_PCTS and math.isfinite(point.e2e_delay_ms):
                values[(method, point.loss_pct)].append(float(point.e2e_delay_ms))

    configure_matplotlib_like_paper()
    fig, ax = plt.subplots(figsize=(3.8, 2.4))
    for method in METHOD_ORDER:
        means: List[float] = []
        ci95: List[float] = []
        counts: List[int] = []
        for loss_pct in LOSS_PCTS:
            observations = values.get((method, loss_pct), [])
            if not observations:
                raise ValueError(f"missing {method} observations at {loss_pct:g}% IID loss")
            avg, ci = _mean_ci95(observations)
            means.append(avg)
            ci95.append(ci)
            counts.append(len(observations))

        color = method_color(method)
        ax.errorbar(
            LOSS_PCTS,
            means,
            yerr=ci95,
            color=color,
            ecolor=color,
            linewidth=1.6,
            elinewidth=0.8,
            capsize=2.0,
            capthick=0.8,
            marker=method_marker(method),
            markersize=5.2,
            markerfacecolor=color,
            markeredgecolor=color,
            markeredgewidth=0.0,
            linestyle="-",
            label=method_label(method),
        )
        print(
            f"{method_label(method)}: n={counts}; "
            f"mean delay (ms)={[round(value, 2) for value in means]}"
        )

    ax.set_xticks(LOSS_PCTS)
    ax.set_xticklabels([f"{loss:g}" for loss in LOSS_PCTS])
    ax.set_xlabel("IID loss rate (%)")
    ax.set_ylabel("E2E delay (ms)")
    # Retain the source figure's full delay scale so removing the IR-FEC
    # series changes only the requested method set, not the vertical frame.
    ax.set_ylim(850, 1200)
    ax.yaxis.set_major_locator(MultipleLocator(50))
    ax.grid(True)
    ax.legend(loc="upper right", frameon=True)
    fig.tight_layout()

    out_path.parent.mkdir(parents=True, exist_ok=True)
    save_current_figure(out_path)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--baseline-csv",
        type=Path,
        default=REPO_ROOT / "python/results/iid-1m-baseline-data/results.csv",
    )
    parser.add_argument(
        "--bandit-log",
        type=Path,
        default=REPO_ROOT
        / "python/results/iid-1m-bandit-data-49365/bandit_eval_metrics.jsonl",
    )
    parser.add_argument(
        "--flec-jsonl",
        type=Path,
        default=Path(
            "/home/lwh/Documents/Code/flec/baseline_exp/results/plugin_version/flec_iid_1m.jsonl"
        ),
    )
    parser.add_argument(
        "--flec-rq-jsonl",
        type=Path,
        default=REPO_ROOT / "python/results/flec_data/flec_raptorq_iid_1m.jsonl",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO_ROOT / "figures/vary_density/iid-1m-e2e-delay.png",
    )
    args = parser.parse_args()

    points = load_selected_points(
        args.baseline_csv.resolve(),
        args.bandit_log.resolve(),
        args.flec_jsonl.resolve(),
        args.flec_rq_jsonl.resolve(),
    )
    render(points, args.out.resolve())
    print(f"wrote {args.out.resolve()}")


if __name__ == "__main__":
    main()
