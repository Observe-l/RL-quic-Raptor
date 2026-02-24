#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import subprocess
import time
import zlib
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

_REPO_ROOT = Path(__file__).resolve().parents[2]
_PY_ROOT = Path(__file__).resolve().parents[1]

import sys

if str(_PY_ROOT) not in sys.path:
	sys.path.insert(0, str(_PY_ROOT))

from bandit.run_lints_ge_schedule import _ge_to_tc_gemodel_loss_mode  # noqa: E402


def _now_ts() -> str:
	return time.strftime("%Y%m%d-%H%M%S")


def _default_run_tag() -> str:
	pid = os.getpid()
	t = int(time.time() * 1000)
	raw = f"{pid:x}{t:x}"
	raw = re.sub(r"[^0-9a-zA-Z]+", "", raw)
	return raw[:8] or "run"


def _used_10_10_subnets() -> set[int]:
	used: set[int] = set()
	try:
		p = subprocess.run(
			["ip", "-4", "-o", "addr", "show"],
			stdout=subprocess.PIPE,
			stderr=subprocess.DEVNULL,
			text=True,
			check=False,
		)
		for line in (p.stdout or "").splitlines():
			m = re.search(r"\binet\s+10\.10\.(\d+)\.(\d+)/(\d+)", line)
			if not m:
				continue
			used.add(int(m.group(1)))
	except Exception:
		pass
	return used


def _netns_env_for_tag(tag: str) -> Dict[str, str]:
	tag = re.sub(r"[^0-9a-zA-Z]+", "", str(tag or ""))
	tag = tag[:8] if tag else _default_run_tag()

	veth_host = ("vh" + tag)[:15]
	veth_ns = ("vn" + tag)[:15]

	base = 20 + (zlib.crc32(tag.encode("utf-8")) % 200)
	used = _used_10_10_subnets()
	subnet = base
	for off in range(0, 200):
		cand = 20 + ((base - 20 + off) % 200)
		if cand not in used:
			subnet = cand
			break

	host_ip = f"10.10.{subnet}.1/24"
	ns_ip = f"10.10.{subnet}.2/24"

	return {
		"NS": f"qns_{tag}",
		"VETH_HOST": veth_host,
		"VETH_NS": veth_ns,
		"HOST_IP": host_ip,
		"NS_IP": ns_ip,
	}


def _extract_last_run_record(s: str) -> str:
	"""Extract the last [run] record, handling CRs and line wraps."""

	text = (s or "").replace("\r", "\n")
	lines = text.split("\n")
	start_idx = -1
	for i, line in enumerate(lines):
		if line.startswith("[run]"):
			start_idx = i
	if start_idx < 0:
		return ""
	parts: List[str] = []
	for j in range(start_idx, len(lines)):
		line = (lines[j] or "").strip()
		if not line:
			continue
		if j != start_idx and line.startswith("["):
			break
		parts.append(line)
	return " ".join(parts).strip()


def _parse_kv_from_run_line(line: str) -> Dict[str, str]:
	out: Dict[str, str] = {}
	for tok in (line or "").strip().split():
		if "=" not in tok:
			continue
		k, v = tok.split("=", 1)
		if k.startswith("["):
			continue
		out[k.strip()] = v.strip()
	return out


def _to_int(d: Dict[str, str], k: str, default: int = 0) -> int:
	try:
		return int(float(d.get(k, str(default))))
	except Exception:
		return default


def _to_float(d: Dict[str, str], k: str, default: float = 0.0) -> float:
	try:
		return float(d.get(k, str(default)))
	except Exception:
		return default


def _goodput_mbps_from_file_and_dur(*, file_bytes: int, dur_ms: float) -> float:
	if file_bytes <= 0:
		return 0.0
	if not np.isfinite(float(dur_ms)) or float(dur_ms) <= 0:
		return 0.0
	sec = float(dur_ms) / 1000.0
	return float(file_bytes) * 8.0 / 1e6 / sec


def _overhead_quic_ratio_from_kv(*, kv: Dict[str, str]) -> float:
	for key in (
		"raw_quic_overhead_ratio",
		"quic_overhead_ratio",
		"overhead_ratio",
	):
		if key in kv:
			try:
				v = float(kv.get(key, "0") or "0")
				if np.isfinite(v) and v >= 0:
					return float(v)
			except Exception:
				pass

	file_bytes = _to_int(kv, "file_bytes", 0)
	sent_bytes = _to_int(kv, "raw_quic_sent_bytes", 0)
	if file_bytes > 0 and sent_bytes > 0:
		return float(max(0.0, (float(sent_bytes) - float(file_bytes)) / float(file_bytes)))

	tx_bytes = _to_int(kv, "tx_bytes", 0)
	if file_bytes > 0 and tx_bytes > 0:
		return float(max(0.0, (float(tx_bytes) - float(file_bytes)) / float(file_bytes)))
	return 0.0


def _run_script(*, script: Path, env: Dict[str, str], timeout_s: int) -> str:
	p = subprocess.run(
		["bash", str(script)],
		cwd=str(_REPO_ROOT),
		env={**os.environ, **env},
		stdout=subprocess.DEVNULL,
		stderr=subprocess.PIPE,
		text=True,
		timeout=int(timeout_s),
	)
	return str(p.stderr or "")


def _ensure_file_of_size(*, file_path: Path, file_bytes: int) -> None:
	file_path.parent.mkdir(parents=True, exist_ok=True)
	if not file_path.exists() or int(file_path.stat().st_size) != int(file_bytes):
		with open("/dev/urandom", "rb") as src, open(file_path, "wb") as dst:
			remaining = int(file_bytes)
			while remaining > 0:
				chunk = src.read(min(1024 * 1024, remaining))
				if not chunk:
					break
				dst.write(chunk)
				remaining -= len(chunk)


def _parse_int_list(s: str) -> List[int]:
	s = (s or "").strip()
	if not s:
		return []
	if s.lower() == "all":
		return [-1]

	out: List[int] = []
	for part in s.split(","):
		part = part.strip()
		if not part:
			continue
		if "-" in part:
			lo_s, hi_s = part.split("-", 1)
			lo = int(lo_s)
			hi = int(hi_s)
			if hi < lo:
				lo, hi = hi, lo
			out.extend(list(range(lo, hi + 1)))
		else:
			out.append(int(part))

	seen = set()
	dedup: List[int] = []
	for x in out:
		if x in seen:
			continue
		seen.add(x)
		dedup.append(x)
	return dedup


def _parse_float_list(s: str) -> List[float]:
	s = (s or "").strip()
	if not s:
		return []
	out: List[float] = []
	for part in s.split(","):
		part = (part or "").strip()
		if not part:
			continue
		if part.endswith("%"):
			part = part[:-1]
		try:
			out.append(float(part))
		except Exception:
			continue
	return out


def _load_ge_params(params_path: Path) -> Dict[str, Any]:
	with params_path.open("r", encoding="utf-8") as f:
		data = json.load(f)
	if not isinstance(data, dict):
		raise ValueError(f"invalid GE params json: {params_path}")
	senders = data.get("senders")
	if not isinstance(senders, dict) or not senders:
		raise ValueError(f"invalid GE params json (no senders): {params_path}")
	return data


def _ge_sender_ids(params: Dict[str, Any]) -> List[int]:
	senders = params.get("senders")
	out: List[int] = []
	if isinstance(senders, dict):
		for k in senders.keys():
			try:
				out.append(int(k))
			except Exception:
				continue
	out.sort()
	return out


def _get_sender_entry(params: Dict[str, Any], sender_id: int) -> Dict[str, Any]:
	senders = params.get("senders")
	if not isinstance(senders, dict):
		raise KeyError("senders missing")
	e = senders.get(str(int(sender_id)))
	if not isinstance(e, dict):
		raise KeyError(f"sender_id not found in GE params: {sender_id}")
	return e


@dataclass
class Rec:
	task: str
	method: str
	sender_id: int
	loss_mode: str
	rep: int
	success: int
	timed_out: int
	md5_ok: int
	client_ok: int
	dur_ms: float
	e2e_delay_ms: float
	goodput_mbps: float
	overhead_ratio: float
	recovery_triggers: int
	loss_detection_events: int
	pto_events: int
	retx_1rtt_pkts: int
	retx_1rtt_bytes: int
	extra: Dict[str, Any]


def main() -> int:
	ap = argparse.ArgumentParser(
		description=(
			"Re-run quic-raw only (no FEC/ARQ), collect QUIC recovery/retransmission trigger metrics, and write results."
		)
	)
	ap.add_argument("--out-dir", type=str, required=True, help="Output directory")
	ap.add_argument("--run-tag", type=str, default="", help="Tag for netns/veth isolation")

	ap.add_argument("--loss-profile", type=str, default="ge", choices=["ge", "iid"], help="Loss profile")
	ap.add_argument("--iid-loss-pcts", type=str, default="0.1,0.2,0.3,0.4,0.5", help="IID loss percents list")
	ap.add_argument(
		"--rtt-ms",
		type=int,
		default=30,
		help="RTT (ms) for IID mode. In GE mode RTT is read per-sender from quic_fec_params.json.",
	)

	ap.add_argument("--ge-params", type=str, default=str(_PY_ROOT / "bandit" / "quic_fec_params.json"))
	ap.add_argument("--ge-key", type=str, default="GE_steady_rp")
	ap.add_argument("--ge-h-pct", type=float, default=0.0)
	ap.add_argument("--ge-k-pct", type=float, default=99.0)
	ap.add_argument("--sender-ids", type=str, default="all", help="Comma list / ranges, or 'all'")

	ap.add_argument("--bitrate-mbps", type=int, default=10)
	ap.add_argument("--timeout-transfer-s", type=int, default=10)
	ap.add_argument("--timeout-s", type=int, default=60, help="Python-side subprocess timeout")
	ap.add_argument("--reps", type=int, default=30)
	ap.add_argument(
		"--cc",
		type=str,
		default="bbrv2",
		choices=["bbrv2", "bbr", "bbrv1", "bbr1", "cubic", "reno"],
		help="Congestion control algorithm (QUIC_FEC_CC_ALGO passed to quicraw script)",
	)

	ap.add_argument("--file-bytes", type=int, default=128 * 1024)
	ap.add_argument(
		"--enable-quic-stats",
		type=int,
		default=1,
		choices=[0, 1],
		help="Enable QUIC tracer stats in quicraw-client (required for recovery/retx metrics)",
	)

	args = ap.parse_args()

	out_dir = Path(str(args.out_dir))
	out_dir.mkdir(parents=True, exist_ok=True)

	run_tag = str(args.run_tag or "").strip() or _default_run_tag()
	net_env = _netns_env_for_tag(run_tag)

	tmp_out_dir = Path("/tmp") / f"rl-quic-out-{net_env['NS']}"
	tmp_out_dir.mkdir(parents=True, exist_ok=True)

	file_path = _REPO_ROOT / "go" / "test_data" / f"raw_payload_{int(args.file_bytes)}B_{run_tag}.bin"
	_ensure_file_of_size(file_path=file_path, file_bytes=int(args.file_bytes))

	# Setup netns and build binaries once.
	setup_env = {
		**net_env,
		"OUT_DIR": str(tmp_out_dir),
		"SETUP_ONLY": "1",
		"SKIP_NETNS_RESET": "0",
		"SKIP_TC_CONFIG": "0",
		"SKIP_BUILD": "0",
		"BITRATE_MBPS": str(int(args.bitrate_mbps)),
		"RTT_MS": str(int(args.rtt_ms)),
		"LOSS_MODE": "none",
		"TIMEOUT_S": str(int(args.timeout_transfer_s)),
	}
	_run_script(script=_REPO_ROOT / "scripts" / "quicraw_run_once.sh", env=setup_env, timeout_s=60)

	common_env = {
		**net_env,
		"OUT_DIR": str(tmp_out_dir),
		"SKIP_NETNS_RESET": "1",
		"SKIP_TC_CONFIG": "0",
		"SKIP_BUILD": "0",
		"BITRATE_MBPS": str(int(args.bitrate_mbps)),
		"TIMEOUT_S": str(int(args.timeout_transfer_s)),
		"QUIC_FEC_CC_BYPASS": "0",
		"QUIC_FEC_CC_ALGO": str(args.cc),
		"FILE": str(file_path),
	}

	task = f"file_{int(args.file_bytes)}B"
	recs: List[Rec] = []

	loss_profile = str(args.loss_profile)
	sender_ids = _parse_int_list(str(args.sender_ids))

	ge_params: Optional[Dict[str, Any]] = None
	if loss_profile == "ge":
		ge_params = _load_ge_params(Path(str(args.ge_params)))
		if sender_ids == [-1]:
			sender_ids = _ge_sender_ids(ge_params)

	iid_loss_pcts = _parse_float_list(str(args.iid_loss_pcts))
	if loss_profile == "iid" and not iid_loss_pcts:
		iid_loss_pcts = [0.5]

	scenarios: List[Tuple[int, int, str]] = []
	if loss_profile == "ge":
		assert ge_params is not None
		for sid in sender_ids:
			e = _get_sender_entry(ge_params, int(sid))
			rtt_ms = int(e.get("rtt_ms", int(args.rtt_ms)) or int(args.rtt_ms))
			ge_rp = e.get(str(args.ge_key))
			if not isinstance(ge_rp, dict):
				raise ValueError(f"sender {sid} missing ge key {args.ge_key}")
			loss_mode = _ge_to_tc_gemodel_loss_mode(
				ge_rp,
				h_loss_pct=float(args.ge_h_pct),
				k_loss_pct=float(args.ge_k_pct),
			)
			scenarios.append((int(sid), int(rtt_ms), str(loss_mode)))
	else:
		base_sids = sender_ids if sender_ids and sender_ids != [-1] else [0]
		for sid in base_sids:
			for pct in iid_loss_pcts:
				scenarios.append((int(sid), int(args.rtt_ms), f"iid:{float(pct):g}"))

	def _run_one(*, env: Dict[str, str], sender_id: int, loss_mode: str, rtt_ms: int, rep: int) -> None:
		stderr = _run_script(script=_REPO_ROOT / "scripts" / "quicraw_run_once.sh", env=env, timeout_s=int(args.timeout_s))
		run_line = _extract_last_run_record(stderr)
		kv = _parse_kv_from_run_line(run_line)

		timed_out = _to_int(kv, "timed_out", 0)
		md5_ok = _to_int(kv, "md5_ok", 0)
		client_ok = _to_int(kv, "client_ok", 1)
		success = 1 if (timed_out == 0 and md5_ok == 1 and client_ok == 1) else 0

		dur_ms = float(_to_float(kv, "dur_ms", 0.0))
		e2e_delay_ms = float(dur_ms) + float(rtt_ms) / 2.0 if dur_ms > 0 else 0.0
		goodput_mbps = _goodput_mbps_from_file_and_dur(file_bytes=int(args.file_bytes), dur_ms=dur_ms)
		overhead_ratio = _overhead_quic_ratio_from_kv(kv=kv)

		recovery_triggers = _to_int(kv, "raw_quic_recovery_triggers", 0)
		loss_detection_events = _to_int(kv, "raw_quic_loss_detection_events", 0)
		pto_events = _to_int(kv, "raw_quic_pto_events", 0)
		retx_pkts = _to_int(kv, "raw_quic_retx_1rtt_pkts", 0)
		retx_bytes = _to_int(kv, "raw_quic_retx_1rtt_bytes", 0)

		recs.append(
			Rec(
				task=str(task),
				method=f"quic_{str(args.cc)}",
				sender_id=int(sender_id),
				loss_mode=str(loss_mode),
				rep=int(rep),
				success=int(success),
				timed_out=int(timed_out),
				md5_ok=int(md5_ok),
				client_ok=int(client_ok),
				dur_ms=float(dur_ms),
				e2e_delay_ms=float(e2e_delay_ms),
				goodput_mbps=float(goodput_mbps),
				overhead_ratio=float(overhead_ratio),
				recovery_triggers=int(recovery_triggers),
				loss_detection_events=int(loss_detection_events),
				pto_events=int(pto_events),
				retx_1rtt_pkts=int(retx_pkts),
				retx_1rtt_bytes=int(retx_bytes),
				extra={"run": kv},
			)
		)

	for sender_id, rtt_ms, loss_mode in scenarios:
		for rep in range(int(args.reps)):
			env_raw = {
				**common_env,
				"RTT_MS": str(int(rtt_ms)),
				"LOSS_MODE": str(loss_mode),
			}
			if int(args.enable_quic_stats) == 1:
				env_raw["RAW_STATS"] = "1"
			_run_one(env=env_raw, sender_id=int(sender_id), loss_mode=str(loss_mode), rtt_ms=int(rtt_ms), rep=int(rep))

			r = recs[-1]
			print(
				f"rep={rep:02d} sender={sender_id} rtt_ms={rtt_ms} loss={loss_mode} "
				f"ok={r.success} dur_ms={int(r.dur_ms)} recovery_triggers={r.recovery_triggers} "
				f"loss_detection_events={r.loss_detection_events} pto_events={r.pto_events} retx_pkts={r.retx_1rtt_pkts}"
			)

	out_csv = out_dir / "results.csv"
	with out_csv.open("w", encoding="utf-8", newline="") as f:
		w = csv.DictWriter(
			f,
			fieldnames=[
				"task",
				"method",
				"sender_id",
				"loss_mode",
				"rep",
				"success",
				"timed_out",
				"md5_ok",
				"client_ok",
				"dur_ms",
				"e2e_delay_ms",
				"goodput_mbps",
				"overhead_ratio",
				"recovery_triggers",
				"loss_detection_events",
				"pto_events",
				"retx_1rtt_pkts",
				"retx_1rtt_bytes",
			],
		)
		w.writeheader()
		for r in recs:
			d = asdict(r)
			d.pop("extra", None)
			w.writerow(d)

	out_jsonl = out_dir / "results.jsonl"
	with out_jsonl.open("w", encoding="utf-8") as f:
		for r in recs:
			f.write(json.dumps(asdict(r), ensure_ascii=False) + "\n")

	meta = {
		"created": _now_ts(),
		"out_dir": str(out_dir),
		"task": str(task),
		"file_bytes": int(args.file_bytes),
		"net": net_env,
		"tmp_out_dir": str(tmp_out_dir),
		"args": vars(args),
	}
	(out_dir / "meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

	print(f"OUT: {out_dir}")
	print(f"- results.csv: {out_csv}")
	print(f"- results.jsonl: {out_jsonl}")

	return 0


if __name__ == "__main__":
	raise SystemExit(main())
