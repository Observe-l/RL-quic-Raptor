#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import matplotlib.patches as mpatches  # noqa: E402
from matplotlib.transforms import Bbox  # noqa: E402
from mpl_toolkits.axes_grid1.inset_locator import BboxConnector, BboxPatch, inset_axes, mark_inset  # noqa: E402


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

# Color mapping as requested.
_METHOD_COLORS = {
    "bandit": "#1f77b4",  # deep-ish blue
    "quic_bbrv2": "#ff7f0e",  # orange
    "fec_k60_r0_2_rstep_2": "#2ca02c",  # green
    "fec_k40_r0_10_rstep_8": "#d62728",  # red
    "flec": "#9467bd",  # purple
}

# Marker mapping consistent with plot_overhead_and_delay_from_bandit_evallog.py
_METHOD_MARKERS = {
    "bandit": "+",
    "fec_k60_r0_2_rstep_2": "x",
    "fec_k40_r0_10_rstep_8": "1",
    "quic_bbrv2": "2",
    "flec": ".",
}


def _configure_matplotlib() -> None:
    # IEEE-ish: default style, white background, light dashed grid.
    plt.style.use("default")
    plt.rcParams.update(
        {
            "figure.figsize": (5.0, 2.6),
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
            "grid.color": "#c7c7c7",
            "grid.alpha": 0.3,
            "grid.linewidth": 0.5,
            "grid.linestyle": "--",
            "lines.linewidth": 0.9,
            # Ticks point inward (paper style).
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


def _add_zoom_inset(
    *,
    ax: plt.Axes,
    width: str,
    height: str,
    xlim: Tuple[float, float],
    ylim: Tuple[float, float],
    inset_loc: str,
    bbox_axes: Optional[Tuple[float, float, float, float]] = None,
    loc1: int,
    loc2: int,
) -> Tuple[plt.Axes, object]:
    """Create an inset placed inside the main axes, with a zoom rectangle + connectors."""

    # Place the inset INSIDE the main axes (prefer a blank region).
    if bbox_axes is not None:
        iax = inset_axes(
            ax,
            width=width,
            height=height,
            loc="upper left",
            bbox_to_anchor=bbox_axes,
            bbox_transform=ax.transAxes,
            borderpad=0.0,
        )
    else:
        iax = inset_axes(ax, width=width, height=height, loc=inset_loc, borderpad=0.8)
    # Ensure the inset itself draws above connector lines / masks.
    try:
        iax.set_zorder(10)
    except Exception:
        pass
    iax.set_xlim(float(xlim[0]), float(xlim[1]))
    iax.set_ylim(float(ylim[0]), float(ylim[1]))
    iax.grid(True, linestyle="--", alpha=0.3)
    iax.tick_params(direction="in")
    iax.set_facecolor("white")

    # Draw a zoom rectangle on the main axes and connector lines to the inset.
    artists = mark_inset(ax, iax, loc1=loc1, loc2=loc2, fc="none", ec="0.25", lw=0.8)
    # Keep the zoom rectangle on top; force connector lines to the very bottom.
    # (We can't rely on the return ordering across matplotlib versions.)
    try:
        arts = list(artists)
    except TypeError:
        arts = [artists]

    for a in arts:
        if not hasattr(a, "set_zorder"):
            continue
        if isinstance(a, BboxPatch):
            a.set_zorder(30)
        elif isinstance(a, BboxConnector):
            a.set_zorder(-30)
        else:
            # Fallback: treat unknown as connector-like.
            a.set_zorder(-30)
    return iax, artists


def _hide_connectors_under_inset(
    *,
    ax: plt.Axes,
    inset_ax: plt.Axes,
    pad_px: float = 2.0,
) -> None:
    """Hide connector-line segments that overlap the inset axes (incl. tick labels).

    We add a small white cover patch over the inset tight-bbox area. Because the
    inset axes is drawn above this patch, only the connector lines underneath are
    hidden; the zoom rectangle remains visible (it has a much higher zorder).
    """

    fig = ax.figure
    try:
        fig.canvas.draw()
        renderer = fig.canvas.get_renderer()
    except Exception:
        return

    tb = inset_ax.get_tightbbox(renderer)
    if tb is None:
        return

    tb2 = Bbox.from_extents(tb.x0 - pad_px, tb.y0 - pad_px, tb.x1 + pad_px, tb.y1 + pad_px)
    fb = fig.transFigure.inverted().transform_bbox(tb2)

    cover = mpatches.Rectangle(
        (float(fb.x0), float(fb.y0)),
        float(fb.width),
        float(fb.height),
        transform=fig.transFigure,
        facecolor="white",
        edgecolor="none",
        # Above connectors (-30) but below any data lines/markers (>=0).
        zorder=-25,
        clip_on=False,
    )
    ax.add_artist(cover)


def _legend_outside(ax: plt.Axes, *, methods_order: List[str]) -> None:
    handles, labels = ax.get_legend_handles_labels()
    desired_labels = [_METHOD_LABELS.get(m, m) for m in methods_order]
    by_label = {lab: h for h, lab in zip(handles, labels)}
    new_handles = []
    new_labels = []
    for lab in desired_labels:
        if lab in by_label:
            new_handles.append(by_label[lab])
            new_labels.append(lab)
    for h, lab in zip(handles, labels):
        if lab not in set(new_labels):
            new_handles.append(h)
            new_labels.append(lab)

    ax.legend(
        new_handles,
        new_labels,
        loc="upper left",
        bbox_to_anchor=(1.02, 1.0),
        borderaxespad=0.0,
        frameon=True,
    )


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


def _parse_iid_loss_pct(loss_mode: str) -> Optional[float]:
    s = str(loss_mode or "").strip()
    if not s.startswith("iid:"):
        return None
    try:
        return float(s.split(":", 1)[1])
    except Exception:
        return None


def _mean_ci95(values: Sequence[float]) -> Tuple[float, float]:
    xs = [float(v) for v in values if isinstance(v, (int, float)) and math.isfinite(float(v))]
    if not xs:
        return float("nan"), float("nan")
    mu = float(np.mean(xs))
    if len(xs) < 2:
        return mu, 0.0
    sd = float(np.std(xs, ddof=1))
    se = sd / math.sqrt(float(len(xs)))
    return mu, 1.96 * se


@dataclass
class Point:
    method: str
    loss_pct: float
    overhead_ratio: float  # fraction (e.g., 0.05)
    e2e_delay_ms: float


def _desired_task(file_bytes: int) -> str:
    return "delay_128kb" if int(file_bytes) == 128 * 1024 else f"file_{int(file_bytes)}B"


def _load_baseline_points(*, results_csv: Path, file_bytes: int, methods: set[str], sender_ids: Optional[set[int]]) -> List[Point]:
    pts: List[Point] = []
    task_wanted = _desired_task(int(file_bytes))

    with results_csv.open("r", encoding="utf-8", newline="") as f:
        r = csv.DictReader(f)
        for row in r:
            method = (row.get("method") or "").strip()
            if method not in methods:
                continue

            task = (row.get("task") or "").strip() or task_wanted
            if task != task_wanted:
                continue

            if _to_int(row, "success", 0) != 1:
                continue

            sid = _to_int(row, "sender_id", 0)
            if sender_ids is not None and sid not in sender_ids:
                continue

            loss_pct = _parse_iid_loss_pct(row.get("loss_mode") or "")
            if loss_pct is None:
                continue

            overhead = _to_float(row, "overhead_ratio", 0.0)
            delay_ms = _to_float(row, "e2e_delay_ms", 0.0)
            if not math.isfinite(overhead) or overhead < 0:
                continue
            if not math.isfinite(delay_ms) or delay_ms <= 0:
                continue

            pts.append(Point(method=method, loss_pct=float(loss_pct), overhead_ratio=float(overhead), e2e_delay_ms=float(delay_ms)))

    return pts


def _load_bandit_eval_points(*, eval_jsonl: Path, methods: set[str], sender_ids: Optional[set[int]]) -> List[Point]:
    pts: List[Point] = []
    if "bandit" not in methods:
        return pts

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

            loss_pct = _parse_iid_loss_pct(d.get("loss_mode") or "")
            if loss_pct is None:
                continue

            try:
                sid = int(d.get("sender_id", 0) or 0)
            except Exception:
                sid = 0
            if sender_ids is not None and sid not in sender_ids:
                continue

            env_info = d.get("env_info")
            if not isinstance(env_info, dict):
                continue
            step_valid = int(env_info.get("step_valid", 0) or 0)
            if step_valid != 1:
                continue

            qov = env_info.get("quic_overhead_ratio", None)
            try:
                overhead = float(qov) if qov is not None else float("nan")
            except Exception:
                overhead = float("nan")
            if not math.isfinite(overhead) or overhead < 0:
                continue

            try:
                delay_ms = float(env_info.get("e2e_delay_ms", 0.0) or 0.0)
            except Exception:
                delay_ms = 0.0
            if not math.isfinite(delay_ms) or delay_ms <= 0:
                continue

            pts.append(Point(method="bandit", loss_pct=float(loss_pct), overhead_ratio=float(overhead), e2e_delay_ms=float(delay_ms)))

    return pts


def _load_flec_points(*, flec_jsonl: Path, methods: set[str], sender_ids: Optional[set[int]]) -> List[Point]:
    pts: List[Point] = []
    if "flec" not in methods:
        return pts
    if not flec_jsonl.exists():
        return pts

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
                sid = int(d.get("sender", 0) or 0)
            except Exception:
                sid = 0
            if sender_ids is not None and sid not in sender_ids:
                continue

            ok = int(d.get("ok", 0) or 0)
            if ok != 1:
                continue

            try:
                loss_pct = float(d.get("loss_pct", d.get("p_pct", float("nan"))))
            except Exception:
                loss_pct = float("nan")
            if not math.isfinite(loss_pct):
                continue

            try:
                overhead = float(d.get("overhead", 0.0) or 0.0)
            except Exception:
                overhead = 0.0
            if not math.isfinite(overhead) or overhead < 0:
                continue

            try:
                delay_ms = float(d.get("e2e_s", 0.0) or 0.0) * 1000.0
            except Exception:
                delay_ms = 0.0
            if not math.isfinite(delay_ms) or delay_ms <= 0:
                continue

            pts.append(Point(method="flec", loss_pct=float(loss_pct), overhead_ratio=float(overhead), e2e_delay_ms=float(delay_ms)))

    return pts


def _infer_flec_jsonl_iid(*, flec_dir: Path, file_bytes: int) -> Path:
    size_tag = "1m" if int(file_bytes) >= 1024 * 1024 else "128k"
    return flec_dir / f"flec_iid_{size_tag}.jsonl"


def _is_ours(method: str) -> bool:
    m = str(method or "")
    return m == "bandit" or m.startswith("fec_")


def _draw_series_errorbar(
    *,
    ax: plt.Axes,
    loss_pcts: List[float],
    methods: List[str],
    values_by: Dict[Tuple[str, float], List[float]],
    y_scale: float,
    draw_bcir_last: bool,
    with_legend: bool,
) -> None:
    draw_methods = methods
    if draw_bcir_last and "bandit" in methods:
        draw_methods = [m for m in methods if m != "bandit"] + ["bandit"]

    for method in draw_methods:
        color = _METHOD_COLORS.get(method, None)
        label = _METHOD_LABELS.get(method, method)
        linestyle = "-" if _is_ours(method) else "--"
        marker = _METHOD_MARKERS.get(method, ".")

        xs: List[float] = []
        ys: List[float] = []
        yerr: List[float] = []
        for lp in loss_pcts:
            vals = values_by.get((method, float(lp)), [])
            mu, ci = _mean_ci95(vals)
            if not math.isfinite(float(mu)):
                continue
            xs.append(float(lp))
            ys.append(float(mu) * float(y_scale))
            yerr.append((float(ci) * float(y_scale)) if math.isfinite(float(ci)) else 0.0)

        if not xs:
            continue

        is_ir_fec1 = method == "fec_k60_r0_2_rstep_2"
        is_bcir = method == "bandit"
        markersize = 3.2 if is_ir_fec1 else 2.0
        markeredgewidth = 1.0 if is_ir_fec1 else 0.6
        linewidth = 1.6 if is_ir_fec1 else (0.9 if is_bcir else 1.0)
        elinewidth = 1.1 if is_ir_fec1 else 0.9
        capthick = 1.1 if is_ir_fec1 else 0.9

        ax.errorbar(
            xs,
            ys,
            yerr=yerr,
            fmt=marker,
            markersize=markersize,
            markeredgewidth=markeredgewidth,
            color=color,
            ecolor=color,
            elinewidth=elinewidth,
            capsize=2.0,
            capthick=capthick,
            linestyle=linestyle,
            linewidth=linewidth,
            alpha=0.95,
            label=label if with_legend else None,
            barsabove=True,
            zorder=5 if method == "bandit" else (3 if _is_ours(method) else 2),
        )


def _plot_delay_with_inset(
    *,
    out_path: Path,
    loss_pcts: List[float],
    methods: List[str],
    delay_by: Dict[Tuple[str, float], List[float]],
) -> None:
    _configure_matplotlib()
    fig, ax = plt.subplots(figsize=(5.0, 2.6))

    _draw_series_errorbar(
        ax=ax,
        loss_pcts=loss_pcts,
        methods=methods,
        values_by=delay_by,
        y_scale=1.0,
        draw_bcir_last=True,
        with_legend=True,
    )

    ax.set_xticks([float(lp) for lp in loss_pcts])
    ax.set_xticklabels([f"{lp:g}%" for lp in loss_pcts])
    ax.set_xlabel("IID loss rate")
    ax.set_ylabel("E2E delay (ms)")
    ax.grid(True, linestyle="--", alpha=0.3)

    # Inset: zoom region.
    # Spec (updated): x 0.09% - 0.11%, y 100 - 107 (ms)
    inset, inset_artists = _add_zoom_inset(
        ax=ax,
        width="45%",
        height="45%",
        xlim=(0.09, 0.11),
        ylim=(100.0, 107.0),
        # Place inset into the visually empty band (roughly y=125-250).
        bbox_axes=(0.15, 0.12, 0.6, 0.6),
        inset_loc="upper left",
        # Connectors at top-left and bottom-right of the zoom rectangle.
        loc1=2,
        loc2=4,
    )
    _draw_series_errorbar(
        ax=inset,
        loss_pcts=loss_pcts,
        methods=methods,
        values_by=delay_by,
        y_scale=1.0,
        draw_bcir_last=True,
        with_legend=False,
    )
    inset.set_xticks([0.09, 0.10, 0.11])
    inset.set_xticklabels(["0.09%", "0.10%", "0.11%"], fontsize=6)
    inset.tick_params(labelsize=6)
    _hide_connectors_under_inset(ax=ax, inset_ax=inset)

    _legend_outside(ax, methods_order=methods)
    # Make room for the outside legend.
    fig.subplots_adjust(right=0.78)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, bbox_inches="tight")
    if out_path.suffix.lower() != ".png":
        fig.savefig(out_path.with_suffix(".png"), bbox_inches="tight")
    plt.close(fig)


def _plot_overhead_with_inset(
    *,
    out_path: Path,
    loss_pcts: List[float],
    methods: List[str],
    overhead_by: Dict[Tuple[str, float], List[float]],
) -> None:
    _configure_matplotlib()

    fig, ax = plt.subplots(figsize=(5.0, 2.6))

    _draw_series_errorbar(
        ax=ax,
        loss_pcts=loss_pcts,
        methods=methods,
        values_by=overhead_by,
        y_scale=100.0,
        draw_bcir_last=True,
        with_legend=True,
    )
    ax.set_xticks([float(lp) for lp in loss_pcts])
    ax.set_xticklabels([f"{lp:g}%" for lp in loss_pcts])
    ax.set_xlabel("IID loss rate")
    ax.set_ylabel("Overhead Ratio (%)")
    ax.grid(True, linestyle="--", alpha=0.3)

    # Inset: zoom region.
    # Spec (updated): x 0.09% - 0.11%, y 5 - 12 (%).
    inset, inset_artists = _add_zoom_inset(
        ax=ax,
        width="45%",
        height="45%",
        xlim=(0.09, 0.11),
        ylim=(5.0, 12.0),
        # Place inset into the visually empty band (roughly y=40-120).
        bbox_axes=(0.15, 0.12, 0.6, 0.6),
        inset_loc="upper left",
        # Connectors at top-left and bottom-right of the zoom rectangle.
        loc1=2,
        loc2=4,
    )
    _draw_series_errorbar(
        ax=inset,
        loss_pcts=loss_pcts,
        methods=methods,
        values_by=overhead_by,
        y_scale=100.0,
        draw_bcir_last=True,
        with_legend=False,
    )
    inset.set_xticks([0.09, 0.10, 0.11])
    inset.set_xticklabels(["0.09%", "0.10%", "0.11%"], fontsize=6)
    inset.tick_params(labelsize=6)
    _hide_connectors_under_inset(ax=ax, inset_ax=inset)

    _legend_outside(ax, methods_order=methods)
    fig.subplots_adjust(right=0.78)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, bbox_inches="tight")
    if out_path.suffix.lower() != ".png":
        fig.savefig(out_path.with_suffix(".png"), bbox_inches="tight")
    plt.close(fig)


def _tradeoff_points_per_loss(
    *,
    pts: List[Point],
    methods: List[str],
    loss_pcts: List[float],
    overhead_scale: float = 100.0,
) -> Dict[str, Tuple[List[float], List[float]]]:
    out: Dict[str, Tuple[List[float], List[float]]] = {}
    for method in methods:
        xs: List[float] = []
        ys: List[float] = []
        for lp in loss_pcts:
            ovs = [p.overhead_ratio for p in pts if p.method == method and float(p.loss_pct) == float(lp) and math.isfinite(float(p.overhead_ratio))]
            ds = [p.e2e_delay_ms for p in pts if p.method == method and float(p.loss_pct) == float(lp) and math.isfinite(float(p.e2e_delay_ms))]
            if not ovs or not ds:
                continue
            xs.append(float(np.mean(ovs)) * float(overhead_scale))
            ys.append(float(np.mean(ds)))
        out[method] = (xs, ys)
    return out


def _plot_tradeoff_with_inset(
    *,
    out_path: Path,
    pts: List[Point],
    methods: List[str],
    loss_pcts: List[float],
) -> None:
    _configure_matplotlib()
    fig, ax = plt.subplots(figsize=(5.0, 2.6))

    series = _tradeoff_points_per_loss(pts=pts, methods=methods, loss_pcts=loss_pcts, overhead_scale=100.0)

    # Main: full range x 0-140%.
    draw_methods = [m for m in methods if m != "bandit"] + (["bandit"] if "bandit" in methods else [])
    for method in draw_methods:
        xs, ys = series.get(method, ([], []))
        if not xs:
            continue
        is_ir_fec1 = method == "fec_k60_r0_2_rstep_2"
        marker = _METHOD_MARKERS.get(method, ".")
        ax.scatter(
            xs,
            ys,
            marker=marker,
            s=22 if is_ir_fec1 else 14,
            linewidths=1.0 if is_ir_fec1 else 0.6,
            alpha=0.85,
            color=_METHOD_COLORS.get(method, None),
            label=_METHOD_LABELS.get(method, method),
            zorder=5 if method == "bandit" else 3,
            rasterized=True,
        )

    ax.set_xlabel("Overhead Ratio (%)")
    ax.set_ylabel("E2E delay (ms)")
    ax.set_xlim(0.0, 140.0)
    ax.grid(True, linestyle="--", alpha=0.3)

    # Inset: zoom bottom-left region.
    # Spec: x 5-12 (%), y 100-110 (ms)
    inset, inset_artists = _add_zoom_inset(
        ax=ax,
        width="45%",
        height="45%",
        xlim=(5.0, 12.0),
        ylim=(100.0, 110.0),
        # Upper-left is empty in the main tradeoff plot.
        bbox_axes=(0.15, 0.12, 0.6, 0.6),
        inset_loc="upper left",
        loc1=2,
        loc2=4,
    )
    # Keep all methods in the inset (only points in the zoom box will appear).
    draw_focus = [m for m in methods if m != "bandit"] + (["bandit"] if "bandit" in methods else [])
    for method in draw_focus:
        xs, ys = series.get(method, ([], []))
        if not xs:
            continue
        is_ir_fec1 = method == "fec_k60_r0_2_rstep_2"
        inset.scatter(
            xs,
            ys,
            marker=_METHOD_MARKERS.get(method, "."),
            s=22 if is_ir_fec1 else 14,
            linewidths=1.0 if is_ir_fec1 else 0.6,
            alpha=0.9,
            color=_METHOD_COLORS.get(method, None),
            rasterized=True,
            zorder=5 if method == "bandit" else 3,
        )
    inset.set_xticks([5, 8, 10, 12])
    inset.tick_params(labelsize=6)
    _hide_connectors_under_inset(ax=ax, inset_ax=inset)

    _legend_outside(ax, methods_order=methods)
    # Make room for the outside legend.
    fig.subplots_adjust(right=0.78)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, bbox_inches="tight")
    if out_path.suffix.lower() != ".png":
        fig.savefig(out_path.with_suffix(".png"), bbox_inches="tight")
    plt.close(fig)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="IID-128k plots with insets (delay/overhead/tradeoff)."
    )
    ap.add_argument("--baseline-in-dir", type=str, required=True)
    ap.add_argument("--bandit-eval-log", type=str, default="")
    ap.add_argument("--out-dir", type=str, required=True)
    ap.add_argument("--file-bytes", type=int, default=128 * 1024)
    ap.add_argument("--sender-ids", type=str, default="")
    ap.add_argument("--loss-pcts", type=str, default="0.1,0.2,0.3,0.4,0.5")
    ap.add_argument("--methods", type=str, default=",".join(_METHOD_ORDER_DEFAULT))
    ap.add_argument("--flec-jsonl", type=str, default="")
    ap.add_argument("--flec-dir", type=str, default="")

    args = ap.parse_args()

    baseline_in_dir = Path(str(args.baseline_in_dir))
    results_csv = baseline_in_dir / "results.csv"
    if not results_csv.exists():
        raise SystemExit(f"missing baseline results.csv: {results_csv}")

    out_dir = Path(str(args.out_dir))
    out_dir.mkdir(parents=True, exist_ok=True)

    sender_ids: Optional[set[int]] = None
    if str(args.sender_ids or "").strip():
        sender_ids = {int(x.strip()) for x in str(args.sender_ids).split(",") if x.strip()}

    methods = [m.strip() for m in str(args.methods).split(",") if m.strip()]
    methods_set = set(methods)

    loss_pcts: List[float] = []
    for part in str(args.loss_pcts).split(","):
        part = (part or "").strip().rstrip("%")
        if not part:
            continue
        try:
            loss_pcts.append(float(part))
        except Exception:
            continue

    pts: List[Point] = []
    pts.extend(_load_baseline_points(results_csv=results_csv, file_bytes=int(args.file_bytes), methods=methods_set, sender_ids=sender_ids))

    if str(args.bandit_eval_log or "").strip() and "bandit" in methods_set:
        pts.extend(_load_bandit_eval_points(eval_jsonl=Path(str(args.bandit_eval_log)), methods=methods_set, sender_ids=sender_ids))

    if str(args.flec_jsonl or "").strip() and "flec" in methods_set:
        pts.extend(_load_flec_points(flec_jsonl=Path(str(args.flec_jsonl)), methods=methods_set, sender_ids=sender_ids))
    else:
        flec_dir_s = str(args.flec_dir or "").strip()
        if flec_dir_s:
            flec_path = _infer_flec_jsonl_iid(flec_dir=Path(flec_dir_s), file_bytes=int(args.file_bytes))
            if flec_path.exists():
                if "flec" not in methods_set:
                    methods.append("flec")
                    methods_set.add("flec")
                pts.extend(_load_flec_points(flec_jsonl=flec_path, methods=methods_set, sender_ids=sender_ids))

    if not pts:
        raise SystemExit("no points loaded")

    overhead_by: Dict[Tuple[str, float], List[float]] = {}
    delay_by: Dict[Tuple[str, float], List[float]] = {}
    loss_set = {float(x) for x in loss_pcts}
    for p in pts:
        if float(p.loss_pct) not in loss_set:
            continue
        overhead_by.setdefault((p.method, float(p.loss_pct)), []).append(float(p.overhead_ratio))
        delay_by.setdefault((p.method, float(p.loss_pct)), []).append(float(p.e2e_delay_ms))

    methods_ordered = [m for m in _METHOD_ORDER_DEFAULT if m in methods]
    methods_ordered.extend([m for m in methods if m not in methods_ordered])

    _plot_delay_with_inset(
        out_path=out_dir / "iid128k_delay_inset.pdf",
        loss_pcts=loss_pcts,
        methods=methods_ordered,
        delay_by=delay_by,
    )

    _plot_overhead_with_inset(
        out_path=out_dir / "iid128k_overhead_inset.pdf",
        loss_pcts=loss_pcts,
        methods=methods_ordered,
        overhead_by=overhead_by,
    )

    _plot_tradeoff_with_inset(
        out_path=out_dir / "iid128k_tradeoff_inset.pdf",
        pts=pts,
        methods=methods_ordered,
        loss_pcts=loss_pcts,
    )

    print(f"OUT: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
