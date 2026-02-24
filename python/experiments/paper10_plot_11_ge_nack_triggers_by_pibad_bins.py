#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import numpy as np

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402


EXPERIMENTS_DIR = Path(__file__).resolve().parent
if str(EXPERIMENTS_DIR) not in sys.path:
    sys.path.insert(0, str(EXPERIMENTS_DIR))

from paper10_plot_common import (  # noqa: E402
    configure_matplotlib_like_paper,
    desired_task_from_file_bytes,
    method_color,
    method_label,
    parse_ge_pibad_pct,
    parse_methods_csv,
    save_current_figure,
    set_flec_offset_env,
)


@dataclass(frozen=True)
class _Point:
    method: str
    loss_mode: str
    success: int
    nack_triggers: float


_RAW_QUIC_METRIC_RETX_PKTS = "retx_1rtt_pkts"
_RAW_QUIC_METRIC_TRIGGERS = "triggers"  # loss_detection_events + pto_events


def _bin_index(x: float, bins: List[float]) -> int:
    for i in range(len(bins) - 1):
        if float(bins[i]) <= x < float(bins[i + 1]):
            return i
    return len(bins) - 2


def _to_int(v: object, default: int = 0) -> int:
    try:
        return int(float(v))
    except Exception:
        return int(default)


def _load_jsonl_points_from_results(
    *,
    results_jsonl: Path,
    tasks_ok: Tuple[str, ...],
    allow_methods_prefixes: Tuple[str, ...],
    raw_quic_metric: str,
) -> List[_Point]:
    if not results_jsonl.exists():
        return []

    out: List[_Point] = []
    with results_jsonl.open("r", encoding="utf-8") as f:
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

            if str(d.get("task", "") or "") not in {str(t) for t in tasks_ok}:
                continue

            method = str(d.get("method", "") or "")
            if not any(method.startswith(p) for p in allow_methods_prefixes):
                continue
            loss_mode = str(d.get("loss_mode", "") or "")
            success = _to_int(d.get("success", 0), 0)

            extra = d.get("extra", {})
            run = {}
            if isinstance(extra, dict):
                run0 = extra.get("run", {})
                if isinstance(run0, dict):
                    run = run0

            nack: Optional[float] = None

            # QUIC-FEC: use ARQ attempts (already a "requests/rounds"-style metric).
            if method.startswith("fec_") or method.startswith("ir_fec"):
                if "arq_attempts" in run:
                    nack = float(_to_int(run.get("arq_attempts", 0), 0))

            # QUIC raw: metric depends on --raw-quic-metric.
            if method.startswith("quic_"):
                if str(raw_quic_metric) == _RAW_QUIC_METRIC_TRIGGERS:
                    # Trigger-style metric: loss detection events + PTO events.
                    if "raw_quic_loss_detection_events" in run or "raw_quic_pto_events" in run:
                        nack = float(
                            _to_int(run.get("raw_quic_loss_detection_events", 0), 0)
                            + _to_int(run.get("raw_quic_pto_events", 0), 0)
                        )
                    elif "loss_detection_events" in run or "pto_events" in run:
                        nack = float(_to_int(run.get("loss_detection_events", 0), 0) + _to_int(run.get("pto_events", 0), 0))
                    else:
                        if "loss_detection_events" in d or "pto_events" in d:
                            nack = float(_to_int(d.get("loss_detection_events", 0), 0) + _to_int(d.get("pto_events", 0), 0))
                else:
                    # Retx-style metric: retransmitted 1-RTT packets (STREAM overlap inference).
                    if "raw_quic_retx_1rtt_pkts" in run:
                        nack = float(_to_int(run.get("raw_quic_retx_1rtt_pkts", 0), 0))
                    elif "retx_1rtt_pkts" in run:
                        nack = float(_to_int(run.get("retx_1rtt_pkts", 0), 0))
                    else:
                        # Some rerun outputs also store parsed fields at the top-level.
                        if "retx_1rtt_pkts" in d:
                            nack = float(_to_int(d.get("retx_1rtt_pkts", 0), 0))

            if nack is None:
                continue

            out.append(_Point(method=method, loss_mode=loss_mode, success=success, nack_triggers=float(nack)))

    return out


def _load_flec_points(*, flec_jsonl: Path, tasks_ok: Tuple[str, ...]) -> List[_Point]:
    if not flec_jsonl.exists():
        return []

    out: List[_Point] = []
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

            ok = _to_int(d.get("ok", 0), 0)

            # Task inference matches paper10_plot_common.load_trials_from_flec_jsonl.
            data_bytes = d.get("tx_data_bytes", None)
            data_i = _to_int(data_bytes, 0) if data_bytes is not None else 0
            if data_i == 128 * 1024:
                task0 = "delay_128kb"
            elif data_i > 0:
                task0 = f"file_{data_i}B"
            else:
                task0 = ""

            if str(task0) not in {str(t) for t in tasks_ok}:
                continue

            # loss_mode compatible with parse_ge_pibad_pct.
            loss_model = str(d.get("loss_model", "") or "").strip().lower()
            p_pct = d.get("p_pct", None)
            r_pct = d.get("r_pct", None)
            rtt_ms = d.get("rtt_ms", None)
            loss_mode = ""
            if loss_model == "ge" or (p_pct is not None and r_pct is not None):
                try:
                    loss_mode = f"gemodel:{float(p_pct):.6f},{float(r_pct):.6f},0.000000,{float(rtt_ms or 0.0):.6f}"
                except Exception:
                    loss_mode = "gemodel:"
            else:
                # Not expected for this plot.
                continue

            if "flec_repair_count" not in d:
                continue

            out.append(
                _Point(
                    method="flec",
                    loss_mode=str(loss_mode),
                    success=int(ok),
                    nack_triggers=float(_to_int(d.get("flec_repair_count", 0), 0)),
                )
            )

    return out


def _load_bandit_points(*, bandit_jsonl: Path, tasks_ok: Tuple[str, ...]) -> List[_Point]:
    if not bandit_jsonl.exists():
        return []

    out: List[_Point] = []
    with bandit_jsonl.open("r", encoding="utf-8") as f:
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

            env_info = d.get("env_info")
            if not isinstance(env_info, dict):
                continue

            # Task determination (same logic as paper10_plot_common loader).
            task_d = str(d.get("task", "") or "").strip()
            if not task_d:
                fb = d.get("file_bytes", None)
                fb_i = _to_int(fb, 0) if fb is not None else 0
                if fb_i > 0:
                    task_d = desired_task_from_file_bytes(int(fb_i))
            if not task_d or str(task_d) not in {str(t) for t in tasks_ok}:
                continue

            loss_mode = str(d.get("loss_mode", "") or "").strip()
            if not loss_mode:
                net_params = env_info.get("net_params")
                if isinstance(net_params, dict):
                    loss_mode = str(net_params.get("loss_mode", "") or "").strip()

            success = _to_int(env_info.get("step_valid", 0), 0)

            raw_obs = env_info.get("raw_obs") if isinstance(env_info.get("raw_obs"), dict) else {}
            extra = env_info.get("extra") if isinstance(env_info.get("extra"), dict) else {}
            run = extra.get("run") if isinstance(extra.get("run"), dict) else {}

            # BCIR: use number of NACK messages transmitted as the "request/trigger" count.
            nack = None
            if isinstance(raw_obs, dict) and "ctrl_tx_nack_msgs" in raw_obs:
                try:
                    nack = float(raw_obs.get("ctrl_tx_nack_msgs", 0.0) or 0.0)
                except Exception:
                    nack = None
            if nack is None and isinstance(run, dict):
                # Fallback if the field is plumbed through run kv.
                if "ctrl_tx_nack_msgs" in run:
                    try:
                        nack = float(run.get("ctrl_tx_nack_msgs", 0.0) or 0.0)
                    except Exception:
                        nack = None

            if nack is None:
                continue

            out.append(_Point(method="bandit", loss_mode=str(loss_mode), success=int(success), nack_triggers=float(nack)))

    return out


def _mean_or_nan(xs: Iterable[float]) -> float:
    arr = np.array([float(x) for x in xs if math.isfinite(float(x))], dtype=float)
    if arr.size == 0:
        return float("nan")
    return float(np.mean(arr))


def main() -> None:
    ap = argparse.ArgumentParser(description="(Paper10 extra) GE NACK triggers by pi_bad bins")

    ap.add_argument("--file-bytes", type=int, default=128 * 1024)
    ap.add_argument("--methods", type=str, default="fec_k60_r0_2_rstep_2,fec_k40_r0_10_rstep_8,quic_bbrv2,flec")

    ap.add_argument("--bins", type=str, default="0,1,3,6,100")
    ap.add_argument("--bin-labels", type=str, default="<1%,1-3%,3-6%,>6%")

    ap.add_argument("--flec-jsonl", type=str, default="python/results/flec_data/*.jsonl")

    ap.add_argument("--bandit-jsonl-glob", type=str, default="python/results/*-bandit-*/bandit_eval_metrics.jsonl")
    ap.add_argument("--bandit-eval-log", action="append", default=[], help="Explicit bandit_eval_metrics.jsonl path. Repeatable.")

    ap.add_argument("--fec-jsonl-glob", type=str, default="python/results/*-baseline-data/results.jsonl")
    ap.add_argument(
        "--baseline-jsonl-glob",
        type=str,
        default=None,
        help="Alias for --fec-jsonl-glob (backwards compatibility).",
    )
    ap.add_argument("--raw-jsonl-glob", type=str, default="python/results/*-baseline-raw-data/results.jsonl")

    ap.add_argument(
        "--raw-quic-metric",
        type=str,
        default=_RAW_QUIC_METRIC_RETX_PKTS,
        choices=[_RAW_QUIC_METRIC_RETX_PKTS, _RAW_QUIC_METRIC_TRIGGERS],
        help="Metric for quic-raw: retx_1rtt_pkts (default) or triggers (loss_detection_events+pto_events).",
    )

    ap.add_argument("--fec-in-dir", action="append", default=[], help="Explicit QUIC-FEC baseline input dir (expects results.jsonl). Repeatable.")
    ap.add_argument(
        "--baseline-in-dir",
        action="append",
        dest="fec_in_dir",
        default=argparse.SUPPRESS,
        help="Alias for --fec-in-dir (backwards compatibility).",
    )
    ap.add_argument("--fec-results-jsonl", action="append", default=[], help="Explicit QUIC-FEC baseline results.jsonl path. Repeatable.")
    ap.add_argument(
        "--baseline-results-jsonl",
        action="append",
        dest="fec_results_jsonl",
        default=argparse.SUPPRESS,
        help="Alias for --fec-results-jsonl (backwards compatibility).",
    )

    ap.add_argument("--raw-in-dir", action="append", default=[], help="Explicit raw-quic input dir (expects results.jsonl). Repeatable.")
    ap.add_argument("--raw-results-jsonl", action="append", default=[], help="Explicit raw-quic results.jsonl path. Repeatable.")

    ap.add_argument(
        "--only-inputs-specified",
        action="store_true",
        help="If set, ignore glob inputs and only load explicit inputs.",
    )

    ap.add_argument("--flec-e2e-offset-ms", type=float, default=0.0)

    ap.add_argument("--xmin", type=float, default=None, help="Optional x-axis min")
    ap.add_argument("--xmax", type=float, default=None, help="Optional x-axis max")
    ap.add_argument("--ymin", type=float, default=None, help="Optional y-axis min")
    ap.add_argument("--ymax", type=float, default=None, help="Optional y-axis max")

    ap.add_argument("--out", type=str, default="python/results/paper10_figs/11_ge_nack_triggers_by_pibad_bins.pdf")

    args = ap.parse_args()

    if args.baseline_jsonl_glob:
        args.fec_jsonl_glob = args.baseline_jsonl_glob

    configure_matplotlib_like_paper()

    bins: List[float] = [float(x.strip()) for x in str(args.bins).split(",") if str(x).strip()]
    if len(bins) < 2:
        raise SystemExit("bins must have at least 2 edges")

    labels = [x.strip() for x in str(args.bin_labels).split(",") if str(x).strip()]
    if len(labels) != (len(bins) - 1):
        labels = [f"[{bins[i]}, {bins[i+1]})" for i in range(len(bins) - 1)]

    set_flec_offset_env(args.flec_e2e_offset_ms)

    task = desired_task_from_file_bytes(args.file_bytes)
    # Some experiment runners store 128KB as "file_131072B" while others use "delay_128kb".
    # Accept both for robustness.
    tasks_ok: Tuple[str, ...]
    if str(task) == "delay_128kb":
        tasks_ok = ("delay_128kb", f"file_{int(args.file_bytes)}B")
    else:
        tasks_ok = (str(task),)

    # Inputs.
    fec_jsonls: List[Path] = []
    raw_jsonls: List[Path] = []
    bandit_jsonls: List[Path] = []

    if not bool(args.only_inputs_specified):
        fec_jsonls.extend(sorted(Path().glob(str(args.fec_jsonl_glob))))
        raw_jsonls.extend(sorted(Path().glob(str(args.raw_jsonl_glob))))
        bandit_jsonls.extend(sorted(Path().glob(str(args.bandit_jsonl_glob))))

    for d in args.fec_in_dir:
        fec_jsonls.append(Path(str(d)) / "results.jsonl")
    for p in args.fec_results_jsonl:
        fec_jsonls.append(Path(str(p)))

    for d in args.raw_in_dir:
        raw_jsonls.append(Path(str(d)) / "results.jsonl")
    for p in args.raw_results_jsonl:
        raw_jsonls.append(Path(str(p)))

    for p_s in args.bandit_eval_log:
        bandit_jsonls.append(Path(str(p_s)).expanduser())

    flec_paths: List[Path] = []
    flec_pat = str(args.flec_jsonl or "").strip()
    if flec_pat:
        if any(ch in flec_pat for ch in "*?[]"):
            flec_paths.extend(sorted(Path().glob(flec_pat)))
        else:
            flec_paths.append(Path(flec_pat))

    # Load points.
    pts: List[_Point] = []
    # Important: QUIC-raw is re-run and lives in a separate data source (e.g., ge-128k-baseline-raw-data).
    # Load QUIC-FEC metrics only from the FEC baseline JSONLs, and QUIC raw metrics only from the raw JSONLs.
    for p in fec_jsonls:
        pts.extend(
            _load_jsonl_points_from_results(
                results_jsonl=p,
                tasks_ok=tasks_ok,
                allow_methods_prefixes=("fec_", "ir_fec"),
                raw_quic_metric=str(args.raw_quic_metric),
            )
        )
    for p in raw_jsonls:
        pts.extend(
            _load_jsonl_points_from_results(
                results_jsonl=p,
                tasks_ok=tasks_ok,
                allow_methods_prefixes=("quic_",),
                raw_quic_metric=str(args.raw_quic_metric),
            )
        )
    for p in bandit_jsonls:
        pts.extend(_load_bandit_points(bandit_jsonl=p, tasks_ok=tasks_ok))
    for p in flec_paths:
        pts.extend(_load_flec_points(flec_jsonl=p, tasks_ok=tasks_ok))

    # GE only.
    pts_ge: List[Tuple[int, float, _Point]] = []
    for t in pts:
        p = parse_ge_pibad_pct(t.loss_mode)
        if p is None or not math.isfinite(float(p)):
            continue
        bi = _bin_index(float(p), bins)
        pts_ge.append((bi, float(p), t))

    methods = parse_methods_csv(args.methods)
    if not methods:
        methods = sorted({t.method for (_bi, _p, t) in pts_ge})

    means: Dict[Tuple[int, str], float] = {}
    for bi in range(len(bins) - 1):
        for m in methods:
            xs = [t.nack_triggers for (_bi, _p, t) in pts_ge if _bi == bi and t.method == m and t.success == 1]
            means[(bi, m)] = _mean_or_nan(xs)

    x = np.arange(len(labels), dtype=float)
    w = 0.8 / max(1, len(methods))

    plt.figure()
    for i, m in enumerate(methods):
        ys = [means.get((bi, m), float("nan")) for bi in range(len(labels))]
        offsets = (i - (len(methods) - 1) / 2.0) * w
        plt.bar(x + offsets, ys, width=w, label=method_label(m), color=(method_color(m) or f"C{i}"))

    plt.xticks(x, labels)
    plt.xlabel("Average loss rate")
    if str(args.raw_quic_metric) == _RAW_QUIC_METRIC_TRIGGERS:
        plt.ylabel("Retransmission triggers (mean)")
    else:
        plt.ylabel("Retransmissions (pkts, mean)")
    plt.grid(True, axis="y")
    plt.legend()

    ax = plt.gca()
    xmin0, xmax0 = ax.get_xlim()
    ymin0, ymax0 = ax.get_ylim()
    if args.xmin is not None or args.xmax is not None:
        ax.set_xlim(left=(args.xmin if args.xmin is not None else xmin0), right=(args.xmax if args.xmax is not None else xmax0))
    if args.ymin is not None or args.ymax is not None:
        ax.set_ylim(bottom=(args.ymin if args.ymin is not None else ymin0), top=(args.ymax if args.ymax is not None else ymax0))

    plt.tight_layout()

    save_current_figure(Path(args.out))


if __name__ == "__main__":
    main()
