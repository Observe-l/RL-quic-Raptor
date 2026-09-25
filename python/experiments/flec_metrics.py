from __future__ import annotations

import os

from typing import Any, Mapping, Optional


# New FlEC metrics logs expose the same canonical fields as the RL runner:
#   e2e_delay_s = dur_s + RTT/2
#   overhead_ratio = max(0, (quic_sent_bytes - file_bytes) / file_bytes)
# `overhead_if` is additionally available for the lower-layer veth accounting.
# The legacy fields remain supported for reading old JSONL files.
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

    Prefer the whole-transfer QUIC attempted-byte field used by the RL runner.
    Keep the pre-v4 fields as fallbacks for older FlEC logs.
    """

    quic = _get_int(d, "quic_sent_bytes")
    if quic is not None:
        return max(0, int(quic))
    quic_alias = _get_int(d, "tx_total_bytes_quic_attempted")
    if quic_alias is not None:
        return max(0, int(quic_alias))

    v2 = _get_int(d, "tx_total_bytes_attempted_minus_plugin_payload")
    if v2 is not None:
        return max(0, int(v2))
    attempted = _get_int(d, "tx_total_bytes_attempted")
    if attempted is None:
        return None
    return max(0, int(attempted))


def flec_corrected_e2e_delay_s(d: Mapping[str, Any], *, offset_ms: Optional[float] = None) -> Optional[float]:
    """Compute corrected end-to-end delay seconds.

    Prefer the RL-compatible `e2e_delay_s` / `e2e_delay_ms` fields. For old
    records, fall back to the historical plugin-adjusted fields and then raw
    `e2e_s`.
    """

    base = _get_float(d, "e2e_delay_s")
    if base is None:
        delay_ms = _get_float(d, "e2e_delay_ms")
        if delay_ms is not None:
            base = delay_ms / 1000.0
    if base is None:
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

    Prefer whole-transfer QUIC attempted bytes, matching the RL runner's
    `quic_overhead_ratio`. The veth-layer metric is deliberately not selected
    here; it is available as `overhead_if`.
    """

    for k in ("quic_overhead_ratio", "overhead_ratio", "overhead_total", "overhead"):
        v = _get_float(d, k)
        if v is not None:
            return float(max(0.0, v))

    file_bytes = _get_int(d, "file_bytes")
    quic_sent_bytes = _get_int(d, "quic_sent_bytes")
    if file_bytes is not None and file_bytes > 0 and quic_sent_bytes is not None and quic_sent_bytes >= 0:
        return float(max(0, quic_sent_bytes - file_bytes)) / float(file_bytes)

    # Legacy fallback for pre-v3 records.
    for k in ("overhead_attempted_minus_plugin_payload", "overhead_attempted"):
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
