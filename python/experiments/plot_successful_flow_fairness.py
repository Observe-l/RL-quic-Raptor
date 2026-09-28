#!/usr/bin/env python3
"""Plot per-repetition Jain fairness using successfully completed flows only."""
from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from pathlib import Path
from statistics import mean, stdev
from typing import Dict, Iterable, List, Tuple

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


FLOW_COUNTS = (6, 12, 18, 24)
METHOD_ORDER = ("bandit", "flec", "flec_raptorq", "quic_bbrv2")
EXPECTED_REPETITIONS = 20


def result_path(data_dir: Path, method: str, flow_count: int) -> Tuple[Path, str]:
    if method == "bandit":
        return data_dir / f"bcdir-{flow_count}flow-fairness/flow_results.csv", "csv"
    if method == "flec":
        return data_dir / f"flec_{flow_count}flow_fairness_ge316/flow_results.jsonl", "jsonl"
    if method == "flec_raptorq":
        return (
            data_dir
            / f"flec_raptorq_{flow_count}flow_fairness_ge316/flow_results.jsonl",
            "jsonl",
        )
    if method == "quic_bbrv2":
        return (
            data_dir
            / "quicraw-ge316-20260927-retry5"
            / f"{flow_count}flow/flow_results.csv",
            "csv",
        )
    raise ValueError(f"unknown method: {method}")


def read_records(path: Path, kind: str) -> List[Dict[str, object]]:
    if not path.is_file():
        raise FileNotFoundError(f"missing flow-level results: {path}")
    if kind == "csv":
        with path.open("r", newline="", encoding="utf-8") as handle:
            return [dict(row) for row in csv.DictReader(handle)]
    if kind == "jsonl":
        records: List[Dict[str, object]] = []
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if line.strip():
                    row = json.loads(line)
                    if not isinstance(row, dict):
                        raise ValueError(f"expected JSON object at {path}:{line_number}")
                    records.append(row)
        return records
    raise ValueError(f"unsupported file type {kind!r} for {path}")


def is_success(value: object) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes"}


def successful_only_per_repetition(
    rows: Iterable[Dict[str, object]], *, path: Path, expected_flows: int
) -> Tuple[Dict[int, float], int, int]:
    goodputs_by_rep: Dict[int, List[float]] = {}
    flow_ids_by_rep: Dict[int, List[str]] = {}
    for row in rows:
        try:
            rep = int(row["rep"])
            flow_id = str(row["flow_id"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"missing/invalid rep or flow_id in {path}: {row}") from exc
        goodputs_by_rep.setdefault(rep, [])
        flow_ids_by_rep.setdefault(rep, [])
        flow_ids_by_rep[rep].append(flow_id)

        if not is_success(row.get("success")):
            continue
        try:
            goodput = float(row["goodput_mbps"])
        except (KeyError, TypeError, ValueError):
            continue
        if math.isfinite(goodput) and goodput > 0:
            goodputs_by_rep[rep].append(goodput)

    expected_reps = set(range(1, EXPECTED_REPETITIONS + 1))
    if set(goodputs_by_rep) != expected_reps:
        raise ValueError(
            f"expected repetitions 1..{EXPECTED_REPETITIONS} in {path}; "
            f"found {sorted(goodputs_by_rep)}"
        )
    for rep, flow_ids in flow_ids_by_rep.items():
        if len(flow_ids) != expected_flows or len(set(flow_ids)) != expected_flows:
            raise ValueError(
                f"rep {rep} in {path} has {len(flow_ids)} rows and "
                f"{len(set(flow_ids))} distinct flow IDs; expected {expected_flows}"
            )

    per_rep: Dict[int, float] = {}
    successful_flows = 0
    for rep, goodputs in goodputs_by_rep.items():
        successful_flows += len(goodputs)
        if not goodputs:
            # A repetition with no successful transfer has undefined fairness;
            # do not turn it into zero or include it in the mean.
            continue
        sum_goodput = sum(goodputs)
        sum_squares = sum(value * value for value in goodputs)
        per_rep[rep] = (sum_goodput * sum_goodput) / (len(goodputs) * sum_squares)
    return per_rep, successful_flows, len(goodputs_by_rep) * expected_flows


def collect_summary(data_dir: Path) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    for method in METHOD_ORDER:
        for flow_count in FLOW_COUNTS:
            source, kind = result_path(data_dir, method, flow_count)
            records = read_records(source, kind)
            per_rep, successful_flows, flow_trials = successful_only_per_repetition(
                records, path=source, expected_flows=flow_count
            )
            values = list(per_rep.values())
            rows.append(
                {
                    "aggregation": "per_flow_count",
                    "method": method,
                    "method_label": method_label(method),
                    "flow_count": flow_count,
                    "successful_only_jain_mean": mean(values) if values else None,
                    "successful_only_jain_sample_std": stdev(values) if len(values) > 1 else None,
                    "repetitions_with_success": len(values),
                    "repetitions_total": EXPECTED_REPETITIONS,
                    "successful_flows": successful_flows,
                    "flow_trials": flow_trials,
                    "flow_success_rate": successful_flows / flow_trials,
                    "source_file": str(source.relative_to(REPO_ROOT)),
                }
            )
    return rows


def add_method_average_rows(rows: List[Dict[str, object]]) -> List[Dict[str, object]]:
    """Append one equal-weight average across flow-count means per method."""
    averages: List[Dict[str, object]] = []
    for method in METHOD_ORDER:
        method_rows = [row for row in rows if row["method"] == method]
        if len(method_rows) != len(FLOW_COUNTS) or any(
            row["successful_only_jain_mean"] is None for row in method_rows
        ):
            raise ValueError(f"cannot average incomplete flow-count results for {method}")
        avg = mean(float(row["successful_only_jain_mean"]) for row in method_rows)
        averages.append(
            {
                "aggregation": "equal_weight_mean_across_flow_counts",
                "method": method,
                "method_label": method_label(method),
                "flow_count": "mean of 6, 12, 18, 24",
                "successful_only_jain_mean": avg,
                "successful_only_jain_sample_std": None,
                "repetitions_with_success": None,
                "repetitions_total": None,
                "successful_flows": None,
                "flow_trials": None,
                "flow_success_rate": None,
                "source_file": "",
            }
        )
    return rows + averages


def plot(rows: List[Dict[str, object]], out_path: Path) -> None:
    configure_matplotlib_like_paper()
    fig, ax = plt.subplots(figsize=(3.8, 2.4))
    for method in METHOD_ORDER:
        method_rows = [row for row in rows if row["method"] == method]
        xs = [int(row["flow_count"]) for row in method_rows]
        ys = [row["successful_only_jain_mean"] for row in method_rows]
        color = method_color(method)
        ax.plot(
            xs,
            ys,
            color=color,
            linewidth=1.5,
            marker=method_marker(method),
            markersize=5.2,
            markerfacecolor=color,
            markeredgecolor=color,
            markeredgewidth=0.0,
            label=method_label(method),
        )

    ax.set_xticks(FLOW_COUNTS)
    ax.set_xlabel("Number of Concurrent Flows")
    ax.set_ylabel("Jain Fairness Index\n(successes only)")
    ax.set_ylim(0.8, 1.0)
    ax.yaxis.set_major_locator(MultipleLocator(0.05))
    ax.grid(True, axis="y")
    # The measurements are concentrated in the upper part of [0, 1], so keep
    # the legend in the otherwise-empty lower corner instead of covering points.
    ax.legend(loc="lower left", frameon=True)
    fig.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    save_current_figure(out_path)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--data-dir", type=Path, default=REPO_ROOT / "python/results/fairness"
    )
    parser.add_argument(
        "--out", type=Path, default=REPO_ROOT / "figures/vary_density/v2x-fairness.png"
    )
    parser.add_argument(
        "--summary-csv",
        type=Path,
        default=REPO_ROOT / "python/results/fairness/fairness_successful_only_summary.csv",
    )
    args = parser.parse_args()

    flow_count_rows = collect_summary(args.data_dir.resolve())
    if len(flow_count_rows) != len(METHOD_ORDER) * len(FLOW_COUNTS):
        raise RuntimeError(
            f"expected 16 method/flow-count groups, found {len(flow_count_rows)}"
        )
    plot(flow_count_rows, args.out.resolve())
    rows = add_method_average_rows(flow_count_rows)

    args.summary_csv.parent.mkdir(parents=True, exist_ok=True)
    with args.summary_csv.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print(f"wrote {args.out}")
    print(f"wrote {args.summary_csv}")
    for row in flow_count_rows:
        avg = row["successful_only_jain_mean"]
        sd = row["successful_only_jain_sample_std"]
        avg_text = "NA" if avg is None else f"{float(avg):.4f}"
        sd_text = "NA" if sd is None else f"{float(sd):.4f}"
        print(
            f"{row['method_label']:7} flows={int(row['flow_count']):2} "
            f"Jain={avg_text} +/- {sd_text}; "
            f"valid_reps={row['repetitions_with_success']}/"
            f"{row['repetitions_total']}, successful_flows="
            f"{row['successful_flows']}/{row['flow_trials']}"
        )
    for row in rows[len(flow_count_rows) :]:
        print(
            f"{row['method_label']:7} equal-weight mean across flow counts: "
            f"{float(row['successful_only_jain_mean']):.4f}"
        )


if __name__ == "__main__":
    main()
