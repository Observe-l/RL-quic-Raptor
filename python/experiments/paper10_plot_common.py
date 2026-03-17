#!/usr/bin/env python3
from __future__ import annotations

import csv
import glob
import json
import math
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


_METHOD_LABELS_DEFAULT: Dict[str, str] = {
    "bandit": "BC-DIR",
    "quic_bbrv2": "QUIC",
    "flec": "FLEC",
    # Current DIR-FEC baselines.
    "fec_k40_r0_0_rstep_4": "DIR-only",
    "fec_k40_r0_4_rstep_0": "FEC-only",
    "fec_k40_r0_0_rstep_10": "DIR-only",
    "fec_k40_r0_10_rstep_0": "FEC-only",
    # Old aliases kept for backward-compatible plotting of existing results.
    "fec_k60_r0_2_rstep_2": "DIR-FEC1",
    "fec_k40_r0_10_rstep_8": "DIR-FEC2",
    "fec_k30_r0_2_rstep_6": "DIR-FEC1",
    "fec_k30_r0_10_rstep_6": "DIR-FEC2",
}


# Keep colors consistent with plot_overhead_and_delay_from_trainlog.py.
_METHOD_COLORS_DEFAULT: Dict[str, str] = {
    # Opaque paper-style colors close to the reference screenshot.
    "bandit": "#E7B05D",
    "quic_bbrv2": "#D1B98C",
    "fec_k40_r0_0_rstep_4": "#A6C97A",
    "fec_k40_r0_4_rstep_0": "#B8A3C7",
    "fec_k40_r0_0_rstep_10": "#A6C97A",
    "fec_k40_r0_10_rstep_0": "#B8A3C7",
    "fec_k60_r0_2_rstep_2": "#A6C97A",
    "fec_k40_r0_10_rstep_8": "#B8A3C7",
    "fec_k30_r0_2_rstep_6": "#A6C97A",
    "fec_k30_r0_10_rstep_6": "#B8A3C7",
    "flec": "#86AFC1",
}


_METHOD_MARKERS_DEFAULT: Dict[str, str] = {
    # Filled, distinct shapes for scatter plots.
    "bandit": "^",  # triangle
    "fec_k40_r0_0_rstep_4": "o",  # circle
    "fec_k40_r0_4_rstep_0": "s",  # square
    "fec_k40_r0_0_rstep_10": "o",  # circle
    "fec_k40_r0_10_rstep_0": "s",  # square
    "fec_k60_r0_2_rstep_2": "o",  # circle
    "fec_k40_r0_10_rstep_8": "s",  # square
    "quic_bbrv2": "D",  # diamond
    "flec": "X",  # filled cross
}


def method_label(method: str, *, labels: Optional[Dict[str, str]] = None) -> str:
    lab = (labels or _METHOD_LABELS_DEFAULT).get(str(method))
    return str(lab) if lab is not None else str(method)


def method_color(method: str, *, colors: Optional[Dict[str, str]] = None) -> Optional[str]:
    c = (colors or _METHOD_COLORS_DEFAULT).get(str(method))
    return str(c) if c is not None else None


def method_marker(method: str, *, markers: Optional[Dict[str, str]] = None) -> Optional[str]:
    m = (markers or _METHOD_MARKERS_DEFAULT).get(str(method))
    return str(m) if m is not None else None


def configure_matplotlib_like_paper() -> None:
    # Match plot_overhead_and_delay_from_trainlog.py defaults.
    import matplotlib.pyplot as plt

    plt.style.use("default")
    plt.rcParams.update(
        {
            "figure.figsize": (3.8, 2.40),
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
            "axes.edgecolor": "black",
            "axes.spines.top": True,
            "axes.spines.right": True,
            "axes.grid": True,
            "axes.linewidth": 0.55,
            "grid.color": "#8F8F8F",
            "grid.alpha": 1.0,
            "grid.linewidth": 0.5,
            "grid.linestyle": (0, (1.5, 2.5)),
            "lines.linewidth": 0.9,
            "patch.edgecolor": "black",
            "patch.force_edgecolor": True,
            "patch.linewidth": 0.45,
            "xtick.direction": "in",
            "ytick.direction": "in",
            "xtick.major.size": 3.0,
            "ytick.major.size": 3.0,
            "legend.frameon": True,
            "legend.framealpha": 1.0,
            "legend.fancybox": False,
            "legend.facecolor": "white",
            "legend.edgecolor": "#A8A8A8",
            "savefig.dpi": 400,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
            "font.family": "serif",
            "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
        }
    )


def save_current_figure(out_path: Path) -> None:
    """Save current matplotlib figure.

    Behavior matches the repo's plot_overhead_and_delay_from_* scripts:
    - If out_path has a suffix (e.g., .pdf), save it.
    - Also save a .png alongside (unless the requested format is already .png).
    - If out_path has no suffix, treat it as a base name and write both .pdf and .png.
    """

    import matplotlib.pyplot as plt

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    suf = out_path.suffix.lower()
    if suf == "":
        plt.savefig(out_path.with_suffix(".pdf"))
        plt.savefig(out_path.with_suffix(".png"))
        plt.close()
        return

    plt.savefig(out_path)
    if suf != ".png":
        plt.savefig(out_path.with_suffix(".png"))
    plt.close()


def parse_methods_csv(s: str) -> List[str]:
    s = str(s or "").strip()
    if not s:
        return []
    out: List[str] = []
    for part in s.split(","):
        p = str(part).strip()
        if p:
            out.append(p)
    return out


def desired_task_from_file_bytes(file_bytes: int) -> str:
    return "delay_128kb" if int(file_bytes) == 128 * 1024 else f"file_{int(file_bytes)}B"


def scenario_from_loss_mode(loss_mode: str) -> str:
    s = str(loss_mode or "").strip()
    if s.startswith("gemodel:"):
        return "ge"
    if s.startswith("iid:"):
        return "iid"
    return ""


def parse_iid_loss_pct(loss_mode: str) -> Optional[float]:
    s = str(loss_mode or "").strip()
    if not s.startswith("iid:"):
        return None
    try:
        return float(s.split(":", 1)[1])
    except Exception:
        return None


def parse_ge_pibad_pct(loss_mode: str) -> Optional[float]:
    s = str(loss_mode or "").strip()
    if not s.startswith("gemodel:"):
        return None
    # gemodel:p,r,h,k ; we only need p
    try:
        rest = s.split(":", 1)[1]
        p_s = rest.split(",", 1)[0]
        return float(p_s)
    except Exception:
        return None


def in_ge_pibad_range(loss_mode: str, *, pibad_min_pct: Optional[float], pibad_max_pct: Optional[float]) -> bool:
    if pibad_min_pct is None and pibad_max_pct is None:
        return True
    p = parse_ge_pibad_pct(loss_mode)
    if p is None or not math.isfinite(float(p)):
        return False
    if pibad_min_pct is not None and float(p) < float(pibad_min_pct):
        return False
    if pibad_max_pct is not None and float(p) > float(pibad_max_pct):
        return False
    return True


def format_ge_loss_mode(*, p_pct: float, r_pct: float, rtt_ms: float) -> str:
    return f"gemodel:{float(p_pct):.6f},{float(r_pct):.6f},0.000000,{float(rtt_ms):.6f}"


@dataclass(frozen=True)
class TrialRow:
    task: str
    method: str
    sender_id: int
    loss_mode: str
    rep: int
    success: int
    e2e_delay_ms: float
    overhead_ratio: float
    goodput_mbps: float
    timed_out: int


def _to_int(v: Any, default: int = 0) -> int:
    try:
        return int(float(v))
    except Exception:
        return int(default)


def _to_float(v: Any, default: float = 0.0) -> float:
    try:
        return float(v)
    except Exception:
        return float(default)


def load_trials_from_results_csv(results_csv: Path) -> List[TrialRow]:
    out: List[TrialRow] = []
    if not results_csv.exists():
        return out

    with results_csv.open("r", encoding="utf-8", newline="") as f:
        r = csv.DictReader(f)
        for row in r:
            method = str(row.get("method", "") or "").strip()
            task = str(row.get("task", "") or "").strip()
            if not method or not task:
                continue

            out.append(
                TrialRow(
                    task=task,
                    method=method,
                    sender_id=_to_int(row.get("sender_id", 0), 0),
                    loss_mode=str(row.get("loss_mode", "") or "").strip(),
                    rep=_to_int(row.get("rep", 0), 0),
                    success=_to_int(row.get("success", 0), 0),
                    timed_out=_to_int(row.get("timed_out", 0), 0),
                    e2e_delay_ms=_to_float(row.get("e2e_delay_ms", row.get("dur_ms", 0.0)), 0.0),
                    overhead_ratio=_to_float(row.get("overhead_ratio", 0.0), 0.0),
                    goodput_mbps=_to_float(row.get("goodput_mbps", 0.0), 0.0),
                )
            )

    return out


def load_trials_from_results_csv_glob(glob_s: str) -> List[TrialRow]:
    out: List[TrialRow] = []
    for p in sorted(Path().glob(str(glob_s))):
        out.extend(load_trials_from_results_csv(Path(p)))
    return out


def load_trials_from_bandit_eval_results_csv(bandit_csv: Path) -> List[TrialRow]:
    out: List[TrialRow] = []
    if not bandit_csv.exists():
        return out

    with bandit_csv.open("r", encoding="utf-8", newline="") as f:
        r = csv.DictReader(f)
        for row in r:
            task = str(row.get("task", "") or "").strip()
            if not task:
                continue
            out.append(
                TrialRow(
                    task=task,
                    method="bandit",
                    sender_id=_to_int(row.get("sender_id", 0), 0),
                    loss_mode=str(row.get("loss_mode", "") or "").strip(),
                    rep=_to_int(row.get("rep", 0), 0),
                    success=_to_int(row.get("success", 0), 0),
                    timed_out=0,
                    e2e_delay_ms=_to_float(row.get("e2e_delay_ms", row.get("dur_ms", 0.0)), 0.0),
                    overhead_ratio=_to_float(row.get("overhead_ratio", 0.0), 0.0),
                    goodput_mbps=_to_float(row.get("goodput_mbps", 0.0), 0.0),
                )
            )

    return out


def load_trials_from_bandit_eval_results_csv_glob(glob_s: str) -> List[TrialRow]:
    out: List[TrialRow] = []
    for p in sorted(Path().glob(str(glob_s))):
        out.extend(load_trials_from_bandit_eval_results_csv(Path(p)))
    return out


def load_trials_from_bandit_eval_metrics_jsonl(bandit_jsonl: Path) -> List[TrialRow]:
    out: List[TrialRow] = []
    if not bandit_jsonl.exists():
        return out

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

            # Task determination.
            task = str(d.get("task", "") or "").strip()
            if not task:
                fb = d.get("file_bytes", None)
                fb_i = _to_int(fb, 0) if fb is not None else 0
                if fb_i > 0:
                    task = desired_task_from_file_bytes(int(fb_i))
            if not task:
                continue

            loss_mode = str(d.get("loss_mode", "") or "").strip()
            if not loss_mode:
                net_params = env_info.get("net_params")
                if isinstance(net_params, dict):
                    loss_mode = str(net_params.get("loss_mode", "") or "").strip()

            sender_id = _to_int(d.get("sender_id", 0), 0)
            rep = _to_int(d.get("t", d.get("rep", 0)), 0)

            success = _to_int(env_info.get("step_valid", 0), 0)
            timed_out = _to_int(env_info.get("is_timeout", 0), 0)

            e2e_delay_ms = _to_float(env_info.get("e2e_delay_ms", env_info.get("dur_ms", 0.0)), 0.0)
            goodput_mbps = _to_float(env_info.get("goodput_mbps", 0.0), 0.0)

            # Prefer QUIC overhead ratio.
            overhead_ratio = _to_float(env_info.get("quic_overhead_ratio", float("nan")), float("nan"))
            if not math.isfinite(float(overhead_ratio)) or float(overhead_ratio) < 0:
                raw_obs = env_info.get("raw_obs") if isinstance(env_info.get("raw_obs"), dict) else {}
                overhead_ratio = _to_float(raw_obs.get("fec_overhead", 0.0), 0.0)

            out.append(
                TrialRow(
                    task=str(task),
                    method="bandit",
                    sender_id=int(sender_id),
                    loss_mode=str(loss_mode),
                    rep=int(rep),
                    success=int(success),
                    timed_out=int(timed_out),
                    e2e_delay_ms=float(e2e_delay_ms),
                    overhead_ratio=float(overhead_ratio),
                    goodput_mbps=float(goodput_mbps),
                )
            )

    return out


def load_trials_from_bandit_eval_metrics_jsonl_glob(glob_s: str) -> List[TrialRow]:
    out: List[TrialRow] = []
    pat = str(glob_s or "").strip()
    if not pat:
        return out
    for p in sorted(glob.glob(pat)):
        out.extend(load_trials_from_bandit_eval_metrics_jsonl(Path(p)))
    return out


def load_trials_from_flec_jsonl(flec_jsonl: Path) -> List[TrialRow]:
    if not flec_jsonl.exists():
        return []

    from flec_metrics import (
        flec_corrected_e2e_delay_s,
        flec_corrected_goodput_mbps,
        flec_corrected_overhead_ratio,
    )

    out: List[TrialRow] = []
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
            delay_s = flec_corrected_e2e_delay_s(d)
            overhead = flec_corrected_overhead_ratio(d)
            goodput = flec_corrected_goodput_mbps(d)

            # Sender can be None in IID logs.
            sender_raw = d.get("sender", 0)
            sender_id = 0
            if sender_raw is not None:
                sender_id = _to_int(sender_raw, 0)

            rep = _to_int(d.get("trial", 0), 0)

            # Task: infer from tx_data_bytes when available.
            data_bytes = d.get("tx_data_bytes", None)
            data_i = _to_int(data_bytes, 0) if data_bytes is not None else 0
            if data_i == 128 * 1024:
                task = "delay_128kb"
            elif data_i > 0:
                task = f"file_{data_i}B"
            else:
                task = ""

            # Loss mode.
            loss_model = str(d.get("loss_model", "") or "").strip().lower()
            p_pct = d.get("p_pct", None)
            r_pct = d.get("r_pct", None)
            loss_pct = d.get("loss_pct", None)
            rtt_ms = d.get("rtt_ms", None)
            rtt_ms_f = _to_float(rtt_ms, 0.0) if rtt_ms is not None else 0.0

            loss_mode = ""
            if loss_model == "ge" or (p_pct is not None and r_pct is not None):
                try:
                    loss_mode = format_ge_loss_mode(p_pct=float(p_pct), r_pct=float(r_pct), rtt_ms=float(rtt_ms_f))
                except Exception:
                    loss_mode = "gemodel:"
            else:
                try:
                    lp = float(loss_pct) if loss_pct is not None else float(p_pct)
                    loss_mode = f"iid:{lp:g}"
                except Exception:
                    loss_mode = "iid:"

            out.append(
                TrialRow(
                    task=str(task),
                    method="flec",
                    sender_id=int(sender_id),
                    loss_mode=str(loss_mode),
                    rep=int(rep),
                    success=int(ok),
                    timed_out=0 if ok == 1 else 1,
                    e2e_delay_ms=float(delay_s) * 1000.0 if delay_s is not None else float("nan"),
                    overhead_ratio=float(overhead) if overhead is not None else float("nan"),
                    goodput_mbps=float(goodput) if goodput is not None else float("nan"),
                )
            )

    return out


def load_trials_from_flec_jsonl_glob(flec_jsonl_glob: str) -> List[TrialRow]:
    out: List[TrialRow] = []
    pat = str(flec_jsonl_glob or "").strip()
    if not pat:
        return out
    for p in sorted(glob.glob(pat)):
        out.extend(load_trials_from_flec_jsonl(Path(p)))
    return out


def load_all_trials(
    *,
    baseline_glob: str,
    bandit_glob: str,
    flec_jsonl: str,
    baseline_in_dirs: Optional[Sequence[str]] = None,
    baseline_csvs: Optional[Sequence[str]] = None,
    bandit_eval_results_csvs: Optional[Sequence[str]] = None,
    bandit_eval_logs: Optional[Sequence[str]] = None,
    only_inputs_specified: bool = False,
) -> List[TrialRow]:
    trials: List[TrialRow] = []

    if not bool(only_inputs_specified):
        bg = str(baseline_glob or "").strip()
        if bg:
            trials.extend(load_trials_from_results_csv_glob(bg))
        bbg = str(bandit_glob or "").strip()
        if bbg:
            trials.extend(load_trials_from_bandit_eval_results_csv_glob(bbg))

    # Explicit baseline sources.
    for d in (baseline_in_dirs or []):
        p = Path(str(d)).expanduser().resolve()
        trials.extend(load_trials_from_results_csv(p / "results.csv"))
    for p_s in (baseline_csvs or []):
        trials.extend(load_trials_from_results_csv(Path(str(p_s)).expanduser()))

    # Explicit bandit sources (CSV or JSONL).
    for p_s in (bandit_eval_results_csvs or []):
        trials.extend(load_trials_from_bandit_eval_results_csv(Path(str(p_s)).expanduser()))
    for p_s in (bandit_eval_logs or []):
        trials.extend(load_trials_from_bandit_eval_metrics_jsonl(Path(str(p_s)).expanduser()))

    # Accept either a direct JSONL path or a glob pattern.
    flec_pat = str(flec_jsonl or "").strip()
    if flec_pat:
        if any(ch in flec_pat for ch in "*?[]"):
            trials.extend(load_trials_from_flec_jsonl_glob(flec_pat))
        else:
            trials.extend(load_trials_from_flec_jsonl(Path(flec_pat).expanduser()))
    return trials


def filter_trials(
    trials: Iterable[TrialRow],
    *,
    scenario: str,
    task: str,
    methods: Optional[Sequence[str]] = None,
) -> List[TrialRow]:
    scen = str(scenario or "").strip()
    t = str(task or "").strip()
    allow = set(str(m) for m in (methods or []) if str(m).strip()) if methods else None

    out: List[TrialRow] = []
    for rr in trials:
        if t and str(rr.task) != t:
            continue
        if scen and scenario_from_loss_mode(rr.loss_mode) != scen:
            continue
        if allow is not None and str(rr.method) not in allow:
            continue
        out.append(rr)
    return out


def auto_methods_in_trials(trials: Sequence[TrialRow]) -> List[str]:
    seen: set[str] = set()
    for rr in trials:
        seen.add(str(rr.method))

    default_order = [
        "bandit",
        "fec_k40_r0_0_rstep_4",
        "fec_k40_r0_4_rstep_0",
        "fec_k40_r0_0_rstep_10",
        "fec_k40_r0_10_rstep_0",
        "fec_k60_r0_2_rstep_2",
        "fec_k40_r0_10_rstep_8",
        "fec_k30_r0_2_rstep_6",
        "fec_k30_r0_10_rstep_6",
        "quic_bbrv2",
        "flec",
    ]

    ordered = [m for m in default_order if m in seen]
    ordered.extend(sorted([m for m in seen if m not in ordered]))
    return ordered


def set_flec_offset_env(offset_ms: float) -> None:
    os.environ["FLEC_E2E_OFFSET_MS"] = str(float(offset_ms))


def is_finite_nonneg(x: float) -> bool:
    return math.isfinite(float(x)) and float(x) >= 0.0


def is_finite_pos(x: float) -> bool:
    return math.isfinite(float(x)) and float(x) > 0.0
