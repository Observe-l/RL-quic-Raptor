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


def _extract_last_timing_record(s: str) -> str:
	"""Extract the last [timing] record (single-line)."""
	text = (s or "").replace("\r", "\n")
	last = ""
	for line in text.split("\n"):
		line = (line or "").strip()
		if line.startswith("[timing]"):
			last = line
	return last


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
		"fec_quic_overhead_ratio",
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

	for sent_key in ("raw_quic_sent_bytes", "fec_quic_sent_bytes"):
		if sent_key in kv:
			file_bytes = _to_int(kv, "file_bytes", 0)
			sent_bytes = _to_int(kv, sent_key, 0)
			if file_bytes > 0 and sent_bytes > 0:
				return float(max(0.0, (float(sent_bytes) - float(file_bytes)) / float(file_bytes)))

	tx_bytes = _to_int(kv, "tx_bytes", 0)
	file_bytes = _to_int(kv, "file_bytes", 0)
	if file_bytes > 0 and tx_bytes > 0:
		return float(max(0.0, (float(tx_bytes) - float(file_bytes)) / float(file_bytes)))
	return 0.0


def _run_script(*, script: Path, env: Dict[str, str], timeout_s: int) -> Tuple[str, str, int, float, int]:
	"""Run a bash script and capture output.

	Returns: (stdout, stderr, returncode, wall_ms, timed_out)
	"""
	start = time.perf_counter()
	try:
		p = subprocess.run(
			["bash", str(script)],
			cwd=str(_REPO_ROOT),
			env={**os.environ, **env},
			stdout=subprocess.PIPE,
			stderr=subprocess.PIPE,
			text=True,
			timeout=int(timeout_s),
		)
		wall_ms = (time.perf_counter() - start) * 1000.0
		return str(p.stdout or ""), str(p.stderr or ""), int(p.returncode), float(wall_ms), 0
	except subprocess.TimeoutExpired as e:
		wall_ms = (time.perf_counter() - start) * 1000.0
		stdout = ""
		stderr = ""
		try:
			stdout = str(e.stdout or "")
		except Exception:
			stdout = ""
		try:
			stderr = str(e.stderr or "")
		except Exception:
			stderr = ""
		return stdout, stderr, -1, float(wall_ms), 1


def _tail_text(s: str, *, max_chars: int = 4000) -> str:
	s = str(s or "")
	if len(s) <= max_chars:
		return s
	return s[-max_chars:]


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
	trial_wall_ms: float
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
			"Run baselines only (quic-raw, IR-FEC1, IR-FEC2) under IID or GE loss, and write results (no plotting)."
		)
	)
	ap.add_argument("--out-dir", type=str, required=True, help="Output directory")
	ap.add_argument("--run-tag", type=str, default="", help="Tag for netns/veth isolation")

	ap.add_argument("--loss-profile", type=str, default="ge", choices=["ge", "iid"], help="Loss profile")
	ap.add_argument("--iid-loss-pcts", type=str, default="0.1,0.2,0.3,0.4,0.5", help="IID loss percents list, e.g. '0.1,0.5,1.0'")
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
	ap.add_argument("--timeout-transfer-s", type=int, default=5)
	ap.add_argument("--timeout-s", type=int, default=60, help="Python-side subprocess timeout")
	ap.add_argument("--reps", type=int, default=30)
	ap.add_argument(
		"--cc",
		type=str,
		default="bbrv2",
		choices=["bbrv2", "bbr", "bbrv1", "bbr1", "cubic", "reno"],
		help="Congestion control algorithm (passed as QUIC_FEC_CC_ALGO to quicfec/quicraw scripts)",
	)

	ap.add_argument("--file-bytes", type=int, default=128 * 1024)
	ap.add_argument("--symbol-bytes", type=int, default=1200)
	ap.add_argument(
		"--ddl-ms",
		type=int,
		default=55,
		help="Receiver ARQ soft deadline in ms (passed as DDL_MS to quicfec_run_once.sh)",
	)
	ap.add_argument(
		"--decode-ddl-ms",
		type=int,
		default=25,
		help="Receiver decode/check pacing in ms (passed as DECODE_DDL_MS to quicfec_run_once.sh)",
	)

	ap.add_argument("--enable-quic-overhead", type=int, default=1, choices=[0, 1])

	args = ap.parse_args()

	out_dir = Path(str(args.out_dir))
	out_dir.mkdir(parents=True, exist_ok=True)

	run_tag = str(args.run_tag or "").strip() or _default_run_tag()
	net_env = _netns_env_for_tag(run_tag)

	tmp_out_dir = Path("/tmp") / f"rl-quic-out-{net_env['NS']}"
	tmp_out_dir.mkdir(parents=True, exist_ok=True)

	file_path = _REPO_ROOT / "go" / "test_data" / f"baseline_payload_{int(args.file_bytes)}B_{run_tag}.bin"
	_ensure_file_of_size(file_path=file_path, file_bytes=int(args.file_bytes))

	# Setup netns once using quicfec script (has SETUP_ONLY) to build QUIC-FEC binaries.
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
	setup_out, setup_err, setup_rc, _, setup_timed_out = _run_script(
		script=_REPO_ROOT / "scripts" / "quicfec_run_once.sh", env=setup_env, timeout_s=60
	)
	if setup_timed_out == 1 or setup_rc != 0:
		sys.stderr.write("[error] setup failed (quicfec_run_once.sh).\n")
		sys.stderr.write("- If this is the first run: run `sudo -v` once, then retry.\n")
		sys.stderr.write(f"- rc={setup_rc} timed_out={setup_timed_out}\n")
		if setup_out.strip():
			sys.stderr.write("--- setup stdout (tail) ---\n" + _tail_text(setup_out).rstrip() + "\n")
		if setup_err.strip():
			sys.stderr.write("--- setup stderr (tail) ---\n" + _tail_text(setup_err).rstrip() + "\n")
		return 2

	# Build quic-raw binaries once as well.
	raw_setup_env = {
		**net_env,
		"OUT_DIR": str(tmp_out_dir),
		"SETUP_ONLY": "1",
		"SKIP_NETNS_RESET": "1",
		"SKIP_TC_CONFIG": "1",
		"SKIP_BUILD": "0",
		"BITRATE_MBPS": str(int(args.bitrate_mbps)),
		"RTT_MS": str(int(args.rtt_ms)),
		"LOSS_MODE": "none",
		"TIMEOUT_S": str(int(args.timeout_transfer_s)),
	}
	raw_setup_out, raw_setup_err, raw_setup_rc, _, raw_setup_timed_out = _run_script(
		script=_REPO_ROOT / "scripts" / "quicraw_run_once.sh", env=raw_setup_env, timeout_s=60
	)
	if raw_setup_timed_out == 1 or raw_setup_rc != 0:
		sys.stderr.write("[error] setup failed (quicraw_run_once.sh).\n")
		sys.stderr.write("- If this is the first run: run `sudo -v` once, then retry.\n")
		sys.stderr.write(f"- rc={raw_setup_rc} timed_out={raw_setup_timed_out}\n")
		if raw_setup_out.strip():
			sys.stderr.write("--- setup stdout (tail) ---\n" + _tail_text(raw_setup_out).rstrip() + "\n")
		if raw_setup_err.strip():
			sys.stderr.write("--- setup stderr (tail) ---\n" + _tail_text(raw_setup_err).rstrip() + "\n")
		return 2

	common_env = {
		**net_env,
		"OUT_DIR": str(tmp_out_dir),
		"SKIP_NETNS_RESET": "1",
		"SKIP_TC_CONFIG": "0",
		"SKIP_SYSCTL": "1",
		"SKIP_BUILD": "1",
		"BITRATE_MBPS": str(int(args.bitrate_mbps)),
		"TIMEOUT_S": str(int(args.timeout_transfer_s)),
		"QUIC_FEC_CC_BYPASS": "0",
		"QUIC_FEC_CC_ALGO": str(args.cc),
		"FILE": str(file_path),
	}

	task = f"file_{int(args.file_bytes)}B"
	if int(args.file_bytes) == 128 * 1024:
		task = "delay_128kb"

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

	def _run_one(*, method: str, script: Path, env: Dict[str, str], sender_id: int, loss_mode: str, rtt_ms: int, rep: int) -> None:
		stdout, stderr, rc, trial_wall_ms, timed_out_flag = _run_script(
			script=script, env=env, timeout_s=int(args.timeout_s)
		)
		run_line = _extract_last_run_record(stderr)
		kv = _parse_kv_from_run_line(run_line)
		timing_line = _extract_last_timing_record(stderr)
		timing_kv = _parse_kv_from_run_line(timing_line) if timing_line else {}

		timed_out = 1 if timed_out_flag == 1 else _to_int(kv, "timed_out", 0)
		md5_ok = _to_int(kv, "md5_ok", 0)
		client_ok = _to_int(kv, "client_ok", 0) if not kv else _to_int(kv, "client_ok", 1)
		if rc != 0 and "client_ok" not in kv:
			client_ok = 0
		success = 1 if (timed_out == 0 and md5_ok == 1 and client_ok == 1) else 0
		if str(method).startswith("fec_"):
			# QUIC-FEC provides an explicit receiver DONE ACK. When baselines run
			# with SKIP_MD5=1 to reduce wall-time jitter, this is our correctness guard.
			done_ok = _to_int(kv, "fec_done_ok", 1)
			done_written = _to_int(kv, "fec_done_written", 0)
			if "fec_done_ok" in kv and done_ok != 1:
				success = 0
			if "fec_done_written" in kv and done_written < int(args.file_bytes):
				success = 0

		dur_ms = float(_to_float(kv, "dur_ms", 0.0))
		e2e_delay_ms = float(dur_ms) + float(rtt_ms) / 2.0 if dur_ms > 0 else 0.0
		goodput_mbps = _goodput_mbps_from_file_and_dur(file_bytes=int(args.file_bytes), dur_ms=dur_ms)
		overhead_ratio = _overhead_quic_ratio_from_kv(kv=kv) if int(args.enable_quic_overhead) == 1 else 0.0

		recovery_triggers = _to_int(kv, "raw_quic_recovery_triggers", 0)
		loss_detection_events = _to_int(kv, "raw_quic_loss_detection_events", 0)
		pto_events = _to_int(kv, "raw_quic_pto_events", 0)
		retx_1rtt_pkts = _to_int(kv, "raw_quic_retx_1rtt_pkts", 0)
		retx_1rtt_bytes = _to_int(kv, "raw_quic_retx_1rtt_bytes", 0)

		extra: Dict[str, Any] = {"run": kv, "timing": timing_kv, "script_rc": int(rc)}
		if not kv:
			# Store tails to make early failures diagnosable (e.g., missing sudo cache, missing netns).
			if stdout.strip():
				extra["stdout_tail"] = _tail_text(stdout)
			if stderr.strip():
				extra["stderr_tail"] = _tail_text(stderr)
		recs.append(
			Rec(
				task=str(task),
				method=str(method),
				sender_id=int(sender_id),
				loss_mode=str(loss_mode),
				rep=int(rep),
				trial_wall_ms=float(trial_wall_ms),
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
				retx_1rtt_pkts=int(retx_1rtt_pkts),
				retx_1rtt_bytes=int(retx_1rtt_bytes),
				extra=extra,
			)
		)

	for sender_id, rtt_ms, loss_mode in scenarios:
		for rep in range(int(args.reps)):
			env_raw = {
				**common_env,
				"RTT_MS": str(int(rtt_ms)),
				"LOSS_MODE": str(loss_mode),
			}
			if int(args.enable_quic_overhead) == 1:
				env_raw["RAW_STATS"] = "1"
			_run_one(
				method=f"quic_{str(args.cc)}",
				script=_REPO_ROOT / "scripts" / "quicraw_run_once.sh",
				env=env_raw,
				sender_id=int(sender_id),
				loss_mode=str(loss_mode),
				rtt_ms=int(rtt_ms),
				rep=int(rep),
			)

			for method, k, r0, rstep in (
				("fec_k40_r0_0_rstep_4", 40, 0, 4),
				("fec_k40_r0_4_rstep_0", 40, 4, 0),
			):
				env_fec = {
					**common_env,
					"RTT_MS": str(int(rtt_ms)),
					"LOSS_MODE": str(loss_mode),
					# Baseline runner doesn't consume RL observations, and uses client-side
					# DONE ACK (fec_done_ok) instead of server-side md5.
					# Disable post-transfer polling/flush to avoid ~0.5s wall-time jitter.
					"OBS_JSON": "/dev/null",
					"OBS_WAIT_SECS": "0",
					"WAIT_RECV_SECS": "0",
					"SKIP_MD5": "1",
					"K": str(int(k)),
					"R0": str(int(r0)),
					"RSTEP": str(int(rstep)),
					"DDL_MS": str(int(args.ddl_ms)),
					"DECODE_DDL_MS": str(int(args.decode_ddl_ms)),
					"SYMBOL_BYTES": str(int(args.symbol_bytes)),
					"USE_ARQ": "1",
				}
				if int(args.enable_quic_overhead) == 1:
					env_fec["FEC_STATS"] = "1"
				_run_one(
					method=str(method),
					script=_REPO_ROOT / "scripts" / "quicfec_run_once.sh",
					env=env_fec,
					sender_id=int(sender_id),
					loss_mode=str(loss_mode),
					rtt_ms=int(rtt_ms),
					rep=int(rep),
				)

			last = recs[-3:]
			parts: List[str] = []
			for r in last:
				part = f"{r.method}(ok={r.success} dur_ms={int(r.dur_ms)} wall_ms={int(r.trial_wall_ms)}"
				if r.method.startswith("quic_"):
					part += (
						f" loss_detection_events={r.loss_detection_events}"
						f" pto_events={r.pto_events}"
						f" retx_pkts={r.retx_1rtt_pkts}"
					)
				part += ")"
				parts.append(part)
			ok_str = " ".join(parts)
			print(f"rep={rep:02d} sender={sender_id} rtt_ms={rtt_ms} loss={loss_mode} {ok_str}")

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
				"trial_wall_ms",
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
