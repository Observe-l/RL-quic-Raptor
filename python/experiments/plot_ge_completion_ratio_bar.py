#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import math
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402


_METHOD_ORDER_DEFAULT = [
    "bandit",
    "fec_k60_r0_2_rstep_2",
    "fec_k40_r0_10_rstep_8",
    "quic_bbrv2",
    "flec",
]

_METHOD_LABELS = {
    "bandit": "BCIR",
    "quic_bbrv2": "QUIC",
    "fec_k60_r0_2_rstep_2": "IR-FEC1",
    "fec_k40_r0_10_rstep_8": "IR-FEC2",
    "flec": "FLEC",
}

_METHOD_COLORS = {
    "bandit": "#1f77b4",
    "quic_bbrv2": "#ff7f0e",
    "fec_k60_r0_2_rstep_2": "#2ca02c",
    "fec_k40_r0_10_rstep_8": "#d62728",
    "flec": "#9467bd",
}


_UNIFORM_BLUE = "#1f77b4"


def _configure_matplotlib() -> None:
    plt.style.use("default")
    plt.rcParams.update(
        {
            "figure.figsize": (4.6, 2.3),
            "font.size": 8,
            "axes.labelsize": 8,
            "axes.titlesize": 8,
            "legend.fontsize": 7,
            "xtick.labelsize": 7,
            "ytick.labelsize": 7,
            "figure.facecolor": "white",
            "axes.facecolor": "white",
            "savefig.facecolor": "white",
            "axes.axisbelow": True,
            "axes.grid": True,
            "grid.color": "#c7c7c7",
            "grid.alpha": 0.3,
            "grid.linewidth": 0.5,
            "grid.linestyle": "--",
            "xtick.direction": "in",
            "ytick.direction": "in",
            "xtick.major.size": 3.0,
            "ytick.major.size": 3.0,
            "savefig.dpi": 400,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
            "font.family": "serif",
            "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
        }
    )


def _desired_task(file_bytes: int) -> str:
    return "delay_128kb" if int(file_bytes) == 128 * 1024 else f"file_{int(file_bytes)}B"


def _default_ddl_ms(file_bytes: int) -> int:
    if int(file_bytes) == 128 * 1024:
        return 350
    if int(file_bytes) == 1024 * 1024:
        return 1350
    # Fallback (user can override).
    return 1350


def _to_int(row: Dict[str, str], k: str, default: int = 0) -> int:
    try:
        return int(float(row.get(k, str(default)) or str(default)))
    except Exception:
        return default


def _to_float(row: Dict[str, str], k: str, default: float = 0.0) -> float:
    try:
        return float(row.get(k, str(default)) or str(default))
    except Exception:
        return default


def _format_ge_loss_mode(*, p_pct: float, r_pct: float, rtt_ms: float) -> str:
    # Match baseline formatting: gemodel:1.905626,10.377358,0.000000,99.000000
    return f"gemodel:{p_pct:.6f},{r_pct:.6f},0.000000,{float(rtt_ms):.6f}"


@dataclass(frozen=True)
class Trial:
    method: str
    sender_id: int
    success: int
    dur_ms: float


def _load_baseline_trials(
    *,
    results_csv: Path,
    file_bytes: int,
    methods: set[str],
    sender_ids: Optional[set[int]],
    loss_modes: Optional[set[str]],
) -> List[Trial]:
    task_wanted = _desired_task(int(file_bytes))
    out: List[Trial] = []

    with results_csv.open("r", encoding="utf-8", newline="") as f:
        r = csv.DictReader(f)
        for row in r:
            method = (row.get("method") or "").strip()
            if method not in methods:
                continue

            task = (row.get("task") or "").strip() or task_wanted
            if task != task_wanted:
                continue

            sender = _to_int(row, "sender_id", 0)
            if sender_ids is not None and sender not in sender_ids:
                continue

            loss_mode = (row.get("loss_mode") or "").strip()
            if not loss_mode.startswith("gemodel:"):
                continue
            if loss_modes is not None and loss_mode not in loss_modes:
                continue

            success = _to_int(row, "success", 0)
            dur_ms = _to_float(row, "e2e_delay_ms", 0.0)
            if not math.isfinite(dur_ms):
                dur_ms = 0.0

            out.append(Trial(method=str(method), sender_id=int(sender), success=int(success), dur_ms=float(dur_ms)))

    return out


def _load_bandit_eval_trials(
    *,
    eval_jsonl: Path,
    sender_ids: Optional[set[int]],
    loss_modes: Optional[set[str]],
) -> List[Trial]:
    out: List[Trial] = []
    with eval_jsonl.open("r", encoding="utf-8") as f:
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

            sender = int(d.get("sender_id", 0) or 0)
            if sender_ids is not None and sender not in sender_ids:
                continue

            loss_mode = (d.get("loss_mode") or "").strip()
            if not loss_mode.startswith("gemodel:"):
                continue
            if loss_modes is not None and loss_mode not in loss_modes:
                continue

            env_info = d.get("env_info")
            if not isinstance(env_info, dict):
                continue

            step_valid = int(env_info.get("step_valid", 0) or 0)
            try:
                dur_ms = float(env_info.get("e2e_delay_ms", 0.0) or 0.0)
            except Exception:
                dur_ms = 0.0
            if not math.isfinite(dur_ms):
                dur_ms = 0.0

            out.append(Trial(method="bandit", sender_id=int(sender), success=int(step_valid), dur_ms=float(dur_ms)))

    return out


def _load_flec_ge_trials(
    *,
    flec_jsonl: Path,
    sender_ids: Optional[set[int]],
    loss_modes: Optional[set[str]],
) -> List[Trial]:
    from flec_metrics import flec_corrected_e2e_delay_s

    out: List[Trial] = []
    if not flec_jsonl.exists():
        return out

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

            sender = int(d.get("sender", 0) or 0)
            if sender_ids is not None and sender not in sender_ids:
                continue

            ok = int(d.get("ok", 0) or 0)
            if loss_modes is not None:
                try:
                    p_pct = float(d.get("p_pct", float("nan")))
                    r_pct = float(d.get("r_pct", float("nan")))
                    rtt_ms = float(d.get("rtt_ms", float("nan")))
                except Exception:
                    continue
                if not (math.isfinite(p_pct) and math.isfinite(r_pct) and math.isfinite(rtt_ms)):
                    continue
                loss_mode = _format_ge_loss_mode(p_pct=p_pct, r_pct=r_pct, rtt_ms=rtt_ms)
                if loss_mode not in loss_modes:
                    continue
            delay_s = flec_corrected_e2e_delay_s(d)
            dur_ms = float(delay_s) * 1000.0 if delay_s is not None else 0.0
            if not math.isfinite(dur_ms):
                dur_ms = 0.0

            out.append(Trial(method="flec", sender_id=int(sender), success=int(ok), dur_ms=float(dur_ms)))

    return out


def _completion_ratio_per_sender(trials: Sequence[Trial], *, ddl_ms: int) -> Dict[Tuple[str, int], float]:
    by: Dict[Tuple[str, int], List[Trial]] = {}
    for t in trials:
        by.setdefault((str(t.method), int(t.sender_id)), []).append(t)

    out: Dict[Tuple[str, int], float] = {}
    for k, rs in by.items():
        if not rs:
            continue
        complete_n = 0
        for r in rs:
            if int(r.success) == 1 and float(r.dur_ms) > 0.0 and float(r.dur_ms) <= float(ddl_ms):
                complete_n += 1
        out[k] = float(complete_n) / float(len(rs))
    return out


def _plot_bar(
    *,
    out_path: Path,
    method_to_ratios: Dict[str, List[float]],
    methods_order: List[str],
    ddl_ms: int,
    title: str,
) -> None:
    _configure_matplotlib()
    fig, ax = plt.subplots(figsize=(4.6, 2.3))

    labels: List[str] = []
    ys: List[float] = []
    colors: List[str] = []

    for m in methods_order:
        rs = method_to_ratios.get(m, [])
        if not rs:
            continue
        labels.append(_METHOD_LABELS.get(m, m))
        ys.append(float(np.mean(np.asarray(rs, dtype=float))) * 100.0)
        colors.append(_UNIFORM_BLUE)

    x = np.arange(len(labels), dtype=float)
    ax.bar(x, ys, color=colors, width=0.75, edgecolor="black", linewidth=0.6)

    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylim(0.0, 100.0)
    ax.set_ylabel("Completion ratio (%)")
    # Intentionally no title (paper-style).

    ax.grid(True, axis="y", linestyle="--", alpha=0.3)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, bbox_inches="tight")
    if out_path.suffix.lower() != ".png":
        fig.savefig(out_path.with_suffix(".png"), bbox_inches="tight")
    plt.close(fig)


def main() -> int:
    ap = argparse.ArgumentParser(
        description=(
            "GE completion ratio bar chart. Completion := success==1 and e2e_delay_ms<=DDL; "
            "ratio computed per sender, then averaged across senders per method."
        )
    )
    ap.add_argument("--baseline-in-dir", type=str, required=True, help="Directory containing results.csv")
    ap.add_argument("--bandit-eval-log", type=str, default="", help="bandit_eval_metrics.jsonl for BCIR")
    ap.add_argument("--flec-jsonl", type=str, default="", help="Optional explicit FLEC GE jsonl")
    ap.add_argument("--flec-dir", type=str, default="", help="Directory containing flec_GE_128k.jsonl / flec_GE_1m.jsonl")
    ap.add_argument(
        "--flec-e2e-offset-ms",
        type=float,
        default=0.0,
        help="FLEC-only: add this offset (ms) to e2e delay (default 0).",
    )
    ap.add_argument("--out", type=str, required=True, help="Output PDF path")
    ap.add_argument("--file-bytes", type=int, default=128 * 1024)
    ap.add_argument("--ddl-ms", type=int, default=0, help="Override DDL in ms")
    ap.add_argument("--sender-ids", type=str, default="", help="Comma-separated sender ids to include")
    ap.add_argument(
        "--loss-modes",
        type=str,
        default="",
        help="Semicolon-separated GE loss_mode strings to include (exact match).",
    )
    ap.add_argument(
        "--loss-mode",
        action="append",
        default=[],
        help="Repeatable: GE loss_mode string to include (exact match).",
    )
    ap.add_argument("--methods", type=str, default=",".join(_METHOD_ORDER_DEFAULT))
    ap.add_argument("--title", type=str, default="")

    args = ap.parse_args()

    os.environ["FLEC_E2E_OFFSET_MS"] = str(float(getattr(args, "flec_e2e_offset_ms", 0.0) or 0.0))

    baseline_in_dir = Path(str(args.baseline_in_dir))
    results_csv = baseline_in_dir / "results.csv"
    if not results_csv.exists():
        raise SystemExit(f"missing baseline results.csv: {results_csv}")

    out_path = Path(str(args.out))

    sender_ids: Optional[set[int]] = None
    if str(args.sender_ids or "").strip():
        sender_ids = {int(x.strip()) for x in str(args.sender_ids).split(",") if x.strip()}

    loss_modes: Optional[set[str]] = None
    loss_modes_list: List[str] = []
    loss_modes_list.extend([str(x).strip() for x in (args.loss_mode or []) if str(x).strip()])
    if str(args.loss_modes or "").strip():
        loss_modes_list.extend([x.strip() for x in str(args.loss_modes).split(";") if x.strip()])
    if loss_modes_list:
        loss_modes = set(loss_modes_list)

    methods = [m.strip() for m in str(args.methods).split(",") if m.strip()]
    methods_set = set(methods)
    methods_ordered = [m for m in _METHOD_ORDER_DEFAULT if m in methods_set]
    methods_ordered.extend([m for m in methods if m not in methods_ordered])

    file_bytes = int(args.file_bytes)
    ddl_ms = int(args.ddl_ms) if int(args.ddl_ms) > 0 else int(_default_ddl_ms(file_bytes))

    trials: List[Trial] = []

    # Baseline (non-bandit methods)
    trials.extend(
        _load_baseline_trials(
            results_csv=results_csv,
            file_bytes=file_bytes,
            methods=methods_set,
            sender_ids=sender_ids,
            loss_modes=loss_modes,
        )
    )

    # Bandit eval
    if str(args.bandit_eval_log or "").strip() and "bandit" in methods_set:
        trials.extend(
            _load_bandit_eval_trials(
                eval_jsonl=Path(str(args.bandit_eval_log)),
                sender_ids=sender_ids,
                loss_modes=loss_modes,
            )
        )

    # FLEC
    if "flec" in methods_set:
        flec_path = Path(str(args.flec_jsonl)) if str(args.flec_jsonl or "").strip() else None
        if flec_path is None:
            flec_dir = str(args.flec_dir or "").strip()
            if flec_dir:
                flec_path = Path(flec_dir) / ("flec_GE_1m.jsonl" if file_bytes >= 1024 * 1024 else "flec_GE_128k.jsonl")
        if flec_path is not None and flec_path.exists():
            trials.extend(_load_flec_ge_trials(flec_jsonl=flec_path, sender_ids=sender_ids, loss_modes=loss_modes))

    if not trials:
        raise SystemExit("no trials")

    cr_by_sender = _completion_ratio_per_sender(trials, ddl_ms=ddl_ms)

    method_to_ratios: Dict[str, List[float]] = {}
    for (method, _sender), cr in cr_by_sender.items():
        if method not in methods_set:
            continue
        method_to_ratios.setdefault(method, []).append(float(cr))

    # Print summary
    for m in methods_ordered:
        rs = method_to_ratios.get(m, [])
        if not rs:
            continue
        print(f"{m}: vehicles={len(rs)} mean_completion_ratio={float(np.mean(rs)):.6f}")

    _plot_bar(
        out_path=out_path,
        method_to_ratios=method_to_ratios,
        methods_order=methods_ordered,
        ddl_ms=ddl_ms,
        title=str(args.title or ""),
    )

    print(f"OUT: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
