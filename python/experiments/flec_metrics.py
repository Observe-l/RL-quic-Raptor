from __future__ import annotations

import os

from typing import Any, Mapping, Optional


# FLEC metrics v2 logs include plugin-adjusted fields. We prefer these.
# Some environments may still require an E2E time offset due to different QUIC
# implementations; this is configurable via env var.
FLEC_E2E_OFFSET_MS_ENV = "FLEC_E2E_OFFSET_MS"


def _get_int(d: Mapping[str, Any], key: str) -> Optional[int]:
    v = d.get(key)
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _get_float(d: Mapping[str, Any], key: str) -> Optional[float]:
    v = d.get(key)
    if v is None:
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _flec_e2e_offset_s(offset_ms: Optional[float] = None) -> float:
    if offset_ms is None:
        s = str(os.environ.get(FLEC_E2E_OFFSET_MS_ENV, "") or "").strip()
        if s:
            try:
                offset_ms = float(s)
            except Exception:
                offset_ms = 0.0
        else:
            offset_ms = 0.0
    if offset_ms is None:
        offset_ms = 0.0
    return float(offset_ms) / 1000.0


def flec_corrected_attempted_bytes(d: Mapping[str, Any]) -> Optional[int]:
    """Return attempted bytes suitable for overhead comparisons.

    For flec_metrics_v2, prefer `tx_total_bytes_attempted_minus_plugin_payload`.
    Otherwise fall back to `tx_total_bytes_attempted`.
    """

    v2 = _get_int(d, "tx_total_bytes_attempted_minus_plugin_payload")
    if v2 is not None:
        return max(0, int(v2))
    attempted = _get_int(d, "tx_total_bytes_attempted")
    if attempted is None:
        return None
    return max(0, int(attempted))


def flec_corrected_e2e_delay_s(d: Mapping[str, Any], *, offset_ms: Optional[float] = None) -> Optional[float]:
    """Compute corrected end-to-end delay seconds.

    Requirement (current):
      1) Use `e2e_s_minus_plugin_time_est` as base E2E delay.
      2) Add an optional per-scenario offset (ms), default 0.

    Falls back to `e2e_s` if v2 field is missing.
    """

    base = _get_float(d, "e2e_s_minus_plugin_time_est")
    if base is None:
        base = _get_float(d, "e2e_s")
    if base is None:
        return None

    e2e = float(base) + _flec_e2e_offset_s(offset_ms)
    # Guard: never return negative delay.
    if not (e2e > 0):
        return 0.0
    return e2e


def flec_corrected_overhead_ratio(d: Mapping[str, Any]) -> Optional[float]:
    """Compute corrected overhead ratio (extra bytes / data bytes).

    Requirement (current): use `overhead_attempted_minus_plugin_payload`.

    Fallbacks:
      - `overhead_attempted`
      - `overhead`
      - compute from bytes: (attempted_minus_plugin_payload - tx_data_bytes) / tx_data_bytes
    """

    for k in ("overhead_attempted_minus_plugin_payload", "overhead_attempted", "overhead"):
        v = _get_float(d, k)
        if v is not None:
            return float(max(0.0, v))

    data_bytes = _get_int(d, "tx_data_bytes")
    attempted = flec_corrected_attempted_bytes(d)
    if data_bytes is None or data_bytes <= 0 or attempted is None or attempted <= 0:
        return None
    if attempted < data_bytes:
        return 0.0
    return float(attempted - data_bytes) / float(data_bytes)


def flec_corrected_goodput_mbps(d: Mapping[str, Any]) -> Optional[float]:
    """Compute corrected goodput (Mbps).

    Requirement:
      goodput = tx_data_bytes / (e2e_delay - RTT/2)

    We return Mbps: bytes/s -> bits/s -> Mbit/s.
    """

    data_bytes = _get_int(d, "tx_data_bytes")
    if data_bytes is None or data_bytes <= 0:
        return None

    e2e_delay_s = flec_corrected_e2e_delay_s(d)
    if e2e_delay_s is None:
        return None

    rtt_ms = _get_float(d, "rtt_ms") or 0.0
    denom_s = e2e_delay_s - (rtt_ms / 2000.0)
    if denom_s <= 0:
        return None

    bps = (float(data_bytes) * 8.0) / denom_s
    return bps / 1e6
