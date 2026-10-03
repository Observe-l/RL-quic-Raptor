#!/usr/bin/env python3
"""Summarize fixed-action GE runs into the project's overlapping D1-D4 bins."""

from __future__ import annotations

import argparse
import csv
import math
from collections import Counter
from pathlib import Path
from typing import Dict, Iterable, List, Tuple


BINS: Tuple[Tuple[str, float, float], ...] = (
    ("d1", 0.0, 10.0),
    ("d2", 1.0, 30.0),
    ("d3", 2.0, 50.0),
    ("d4", 3.0, 100.0),
)
DEADLINES_MS = (200, 300, 400, 500)
EXPECTED_SENDERS_PER_BIN = {"d1": 45, "d2": 57, "d3": 36, "d4": 29}


def _pi_bad_pct(row: Dict[str, str]) -> float:
    loss_mode = str(row.get("loss_mode", ""))
    if not loss_mode.startswith("gemodel:"):
        raise ValueError(f"not a GE loss mode: {loss_mode!r}")
    try:
        return float(loss_mode.split(":", 1)[1].split(",", 1)[0])
    except (ValueError, IndexError) as exc:
        raise ValueError(f"cannot parse p_bad from loss_mode={loss_mode!r}") from exc


def _read_rows(path: Path) -> List[Dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8") as source:
        rows = list(csv.DictReader(source))
    if not rows:
        raise ValueError(f"no result rows in {path}")
    return rows


def _summarize(label: str, rows: Iterable[Dict[str, str]]) -> List[Dict[str, object]]:
    records = list(rows)
    sender_counts = Counter(int(row["sender_id"]) for row in records)
    if len(sender_counts) != 61:
        raise ValueError(f"{label}: expected 61 senders, found {len(sender_counts)}")
    if any(count != 30 for count in sender_counts.values()):
        raise ValueError(f"{label}: not every sender has exactly 30 repetitions")
    trial_keys = [(int(row["sender_id"]), int(row["rep"])) for row in records]
    if len(set(trial_keys)) != len(records):
        raise ValueError(f"{label}: duplicate sender/repetition rows found")
    for sender_id in sender_counts:
        reps = sorted(int(row["rep"]) for row in records if int(row["sender_id"]) == sender_id)
        if reps != list(range(30)):
            raise ValueError(f"{label}: sender {sender_id} does not have repetitions 0..29")

    parsed = [(row, _pi_bad_pct(row)) for row in records]
    output: List[Dict[str, object]] = []
    for group, lower, upper in BINS:
        group_rows = [row for row, p in parsed if lower <= p <= upper]
        group_senders = {int(row["sender_id"]) for row in group_rows}
        expected_senders = EXPECTED_SENDERS_PER_BIN[group]
        if len(group_senders) != expected_senders:
            raise ValueError(
                f"{label}/{group}: expected {expected_senders} senders, found {len(group_senders)}"
            )
        expected_trials = expected_senders * 30
        if len(group_rows) != expected_trials:
            raise ValueError(
                f"{label}/{group}: expected {expected_trials} rows, found {len(group_rows)}"
            )
        for deadline in DEADLINES_MS:
            completed = 0
            for row in group_rows:
                try:
                    valid = int(float(row.get("success", "0") or 0)) == 1
                    delay = float(row.get("e2e_delay_ms", "0") or 0)
                except ValueError:
                    valid, delay = False, math.nan
                if valid and math.isfinite(delay) and 0 < delay <= deadline:
                    completed += 1
            output.append(
                {
                    "configuration": label,
                    "group": group,
                    "pi_bad_min_pct": lower,
                    "pi_bad_max_pct": upper,
                    "sender_count": len(group_senders),
                    "trial_count": len(group_rows),
                    "deadline_ms": deadline,
                    "completed_trials": completed,
                    "completion_ratio": completed / len(group_rows),
                }
            )
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        action="append",
        nargs=2,
        metavar=("LABEL", "RESULTS_DIR"),
        required=True,
        help="Repeat for each completed experiment; reads bandit_eval_results.csv",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    result_rows: List[Dict[str, object]] = []
    for label, result_dir in args.input:
        rows = _read_rows(Path(result_dir) / "bandit_eval_results.csv")
        result_rows.extend(_summarize(label, rows))

    args.output.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "configuration",
        "group",
        "pi_bad_min_pct",
        "pi_bad_max_pct",
        "sender_count",
        "trial_count",
        "deadline_ms",
        "completed_trials",
        "completion_ratio",
    ]
    with args.output.open("w", newline="", encoding="utf-8") as target:
        writer = csv.DictWriter(target, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(result_rows)
    print(f"wrote {len(result_rows)} summaries to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
