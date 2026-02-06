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
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import numpy as np

_REPO_ROOT = Path(__file__).resolve().parents[2]


def _now_ts() -> str:
	return time.strftime("%Y%m%d-%H%M%S")


def _default_run_tag() -> str:
	pid = os.getpid()
	t = int(time.time() * 1000)
	raw = f"{pid:x}{t:x}"
	raw = re.sub(r"[^0-9a-zA-Z]+", "", raw)
	return raw[:8] or "run"


def _used_10_10_subnets() -> set[int]:
	"""Return 3rd-octet values (X) for any 10.10.X.* IPv4 addresses on host."""
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
			# Example: "2: eth0    inet 10.10.78.1/24 brd ..."
			m = re.search(r"\binet\s+10\.10\.(\d+)\.(\d+)/(\d+)", line)
			if not m:
				continue
			x = int(m.group(1))
			used.add(x)
	except Exception:
		# Best-effort: if we can't inspect, fall back to deterministic subnet.
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
	# Avoid collisions with any existing 10.10.X.* addresses on host.
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


def _extract_last_line(prefix: str, s: str) -> Optional[str]:
	last = None
	for line in (s or "").splitlines():
		if line.startswith(prefix):
			last = line
	return last


def _extract_last_run_record(s: str) -> str:
	"""Extract the last [run] record.

	Some runs can contain carriage returns (e.g. live tracers) or terminal-wrapped
	output that splits the [run] line across multiple physical lines.

	We take the last line starting with '[run]' and append immediate continuation
	lines that don't start with '['.
	"""
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
	return p.stderr


def _overhead_ratio_from_kv(*, kv: Dict[str, str]) -> float:
	# Prefer explicit overhead_ratio emitted by the scripts.
	if "overhead_ratio" in kv:
		try:
			v = float(kv.get("overhead_ratio", "0") or "0")
			if np.isfinite(v) and v >= 0:
				return float(v)
		except Exception:
			pass

	tx_bytes = _to_int(kv, "tx_bytes", 0)
	file_bytes = _to_int(kv, "file_bytes", 0)
	if file_bytes > 0 and tx_bytes > 0:
		return float(max(0.0, (float(tx_bytes) - float(file_bytes)) / float(file_bytes)))
	return 0.0


def _overhead_quic_ratio_from_kv(*, kv: Dict[str, str]) -> float:
	"""Overhead ratio computed from QUIC attempted send bytes (pre-qdisc).

	This matches the quic-raw / quic-fec QUIC-layer stats when enabled:
	- raw_quic_overhead_ratio (from quicraw-client tracer)
	- fec_quic_overhead_ratio (from fecquic.ClientSendFile tracer)

	Falls back to veth tx_bytes overhead when QUIC stats are unavailable.
	"""
	for key in ("raw_quic_overhead_ratio", "fec_quic_overhead_ratio"):
		if key in kv:
			try:
				v = float(kv.get(key, "0") or "0")
				if np.isfinite(v) and v >= 0:
					return float(v)
			except Exception:
				pass

	# If scripts emitted only sent_bytes, compute locally.
	for sent_key in ("raw_quic_sent_bytes", "fec_quic_sent_bytes"):
		if sent_key in kv:
			file_bytes = _to_int(kv, "file_bytes", 0)
			sent_bytes = _to_int(kv, sent_key, 0)
			if file_bytes > 0 and sent_bytes > 0:
				return float(max(0.0, (float(sent_bytes) - float(file_bytes)) / float(file_bytes)))

	return _overhead_ratio_from_kv(kv=kv)


def _parse_loss_modes(s: str) -> List[str]:
	"""Parse loss modes from CLI.

	`gemodel:p,r,h,k` contains commas, so we cannot blindly split on ','.
	We accept:
	  - ';' separated list (recommended)
	  - ',' separated list when no 'gemodel:' token is present
	"""

	s = str(s or "").strip()
	if not s:
		return []
	if ";" in s:
		parts = s.split(";")
	else:
		parts = [s] if "gemodel:" in s else s.split(",")
	return [p.strip() for p in parts if p.strip()]


@dataclass
class Rec:
	file_label: str
	loss_mode: str
	proto: str
	rep: int
	ok: int
	goodput_mbps: float
	dur_ms: int
	overhead_ratio: float
	overhead_quic_ratio: float
	extra: Dict[str, Any]


def _summarize(recs: List[Rec]) -> Dict[str, Any]:
	ok = [r for r in recs if int(r.ok) == 1]
	out: Dict[str, Any] = {
		"n": int(len(recs)),
		"n_ok": int(len(ok)),
		"ok_rate": float(len(ok) / len(recs)) if recs else 0.0,
	}

	def s_float(vals: List[float]) -> Dict[str, Any]:
		if not vals:
			return {"mean": None, "p50": None, "p95": None}
		arr = np.asarray(vals, dtype=np.float64)
		return {
			"mean": float(np.mean(arr)),
			"p50": float(np.percentile(arr, 50)),
			"p95": float(np.percentile(arr, 95)),
		}

	out["goodput_mbps"] = s_float([float(r.goodput_mbps) for r in ok])
	out["dur_ms"] = s_float([float(r.dur_ms) for r in ok])
	out["overhead_pct"] = s_float([float(r.overhead_ratio) * 100.0 for r in ok])
	out["overhead_quic_pct"] = s_float([float(r.overhead_quic_ratio) * 100.0 for r in ok])
	return out


def main() -> int:
	ap = argparse.ArgumentParser(description="Compare QUIC-FEC vs QUIC-raw under fixed bw/rtt and loss modes")
	ap.add_argument("--reps", type=int, default=20)
	ap.add_argument("--bitrate-mbps", type=int, default=10)
	ap.add_argument("--rtt-ms", type=int, default=100)
	ap.add_argument(
		"--loss-modes",
		type=str,
		default="none;gemodel:15.384615,70.000000,0.000000,99.000000",
		help="Loss modes list. Use ';' separated values. Example: 'none;gemodel:p,r,h,k'.",
	)
	ap.add_argument(
		"--files",
		type=str,
		default="128k,1m",
		help="Which file sizes to run: '128k', '1m' (comma list).",
	)
	ap.add_argument("--timeout-s", type=int, default=180)
	ap.add_argument("--timeout-transfer-s", type=int, default=60)
	ap.add_argument(
		"--enable-quic-overhead",
		action="store_true",
		default=True,
		help="Enable QUIC-layer stats (RAW_STATS/FEC_STATS). Default: enabled. Overhead is computed from QUIC attempted send bytes when available.",
	)

	# QUIC-FEC knobs (passed to scripts/quicfec_run_once.sh)
	ap.add_argument("--k", type=int, default=30)
	ap.add_argument("--r0", type=int, default=12)
	ap.add_argument("--rstep", type=int, default=6)
	ap.add_argument("--symbol-bytes", type=int, default=1200)

	ap.add_argument("--run-tag", type=str, default="")
	ap.add_argument("--out-dir", type=str, default="")

	args = ap.parse_args()

	run_tag = str(args.run_tag).strip() or _default_run_tag()
	net_env = _netns_env_for_tag(run_tag)
	run_tag_effective = str(net_env.get("NS", "qns")).replace("qns_", "", 1) or "run"

	data_dir = _REPO_ROOT / "go" / "test_data"
	data_dir.mkdir(parents=True, exist_ok=True)

	file_map: Dict[str, Path] = {
		"128k": data_dir / f"cmp_128k_{run_tag_effective}.bin",
		"1m": data_dir / f"cmp_1m_{run_tag_effective}.bin",
	}
	sizes = {"128k": 128 * 1024, "1m": 1024 * 1024}

	wanted_files = [x.strip().lower() for x in str(args.files).split(",") if x.strip()]
	for k in wanted_files:
		if k not in file_map:
			raise SystemExit(f"unknown --files entry: {k}")
		p = file_map[k]
		sz = int(sizes[k])
		if not p.exists() or p.stat().st_size != sz:
			with open("/dev/urandom", "rb") as src, open(p, "wb") as dst:
				dst.write(src.read(sz))

	if str(args.out_dir).strip():
		out_dir = Path(str(args.out_dir)).expanduser()
	else:
		out_dir = _REPO_ROOT / "python" / "results" / f"fec-vs-raw-bbrv2-{_now_ts()}-{run_tag_effective}"
	out_dir.mkdir(parents=True, exist_ok=True)

	# Setup netns once using quicfec script (has SETUP_ONLY).
	setup_env = {
		**net_env,
		"SETUP_ONLY": "1",
		"BITRATE_MBPS": str(int(args.bitrate_mbps)),
		"RTT_MS": str(int(args.rtt_ms)),
		"LOSS_MODE": "none",
		"SKIP_BUILD": "0",
	}
	_run_script(script=_REPO_ROOT / "scripts" / "quicfec_run_once.sh", env=setup_env, timeout_s=60)

	# Build quic-raw binaries once as well.
	# Later reps run with SKIP_BUILD=1 for speed, so without this step a stale
	# quicraw-client (missing newer flags like -connect-timeout) could fail every rep.
	raw_setup_env = {
		**net_env,
		"SETUP_ONLY": "1",
		"SKIP_NETNS_RESET": "1",
		"SKIP_TC_CONFIG": "1",
		"BITRATE_MBPS": str(int(args.bitrate_mbps)),
		"RTT_MS": str(int(args.rtt_ms)),
		"LOSS_MODE": "none",
		"SKIP_BUILD": "0",
	}
	_run_script(script=_REPO_ROOT / "scripts" / "quicraw_run_once.sh", env=raw_setup_env, timeout_s=60)

	common_env = {
		**net_env,
		"SKIP_NETNS_RESET": "1",
		"SKIP_SYSCTL": "1",
		"SKIP_BUILD": "1",
		"BITRATE_MBPS": str(int(args.bitrate_mbps)),
		"RTT_MS": str(int(args.rtt_ms)),
		"TIMEOUT_S": str(int(args.timeout_transfer_s)),
		"QUIC_FEC_CC_BYPASS": "0",
		"QUIC_FEC_CC_ALGO": "bbrv2",
	}

	loss_modes = _parse_loss_modes(str(args.loss_modes))
	recs: List[Rec] = []

	for file_label in wanted_files:
		file_path = file_map[file_label]
		for loss_mode in loss_modes:
			for rep in range(int(args.reps)):
				env_raw = {**common_env, "LOSS_MODE": str(loss_mode), "FILE": str(file_path)}
				if args.enable_quic_overhead:
					env_raw["RAW_STATS"] = "1"
				raw_stderr = _run_script(
					script=_REPO_ROOT / "scripts" / "quicraw_run_once.sh",
					env=env_raw,
					timeout_s=int(args.timeout_s),
				)
				raw_line = _extract_last_run_record(raw_stderr)
				raw_kv = _parse_kv_from_run_line(raw_line)
				raw_ok = 1 if (
					_to_int(raw_kv, "timed_out", 0) == 0
					and _to_int(raw_kv, "md5_ok", 0) == 1
					and _to_int(raw_kv, "client_ok", 1) == 1
				) else 0
				recs.append(
					Rec(
						file_label=file_label,
						loss_mode=str(loss_mode),
						proto="quic_raw_bbrv2",
						rep=int(rep),
						ok=int(raw_ok),
						goodput_mbps=float(_to_float(raw_kv, "s_mbps", 0.0)),
						dur_ms=int(_to_int(raw_kv, "dur_ms", 0)),
						overhead_ratio=float(_overhead_quic_ratio_from_kv(kv=raw_kv)),
						overhead_quic_ratio=float(_overhead_quic_ratio_from_kv(kv=raw_kv)),
						extra={"run": raw_kv},
					)
				)

				env_fec = {
					**common_env,
					"LOSS_MODE": str(loss_mode),
					"FILE": str(file_path),
					"K": str(int(args.k)),
					"R0": str(int(args.r0)),
					"RSTEP": str(int(args.rstep)),
					"SYMBOL_BYTES": str(int(args.symbol_bytes)),
					"USE_ARQ": "1",
				}
				if args.enable_quic_overhead:
					env_fec["FEC_STATS"] = "1"
				fec_stderr = _run_script(
					script=_REPO_ROOT / "scripts" / "quicfec_run_once.sh",
					env=env_fec,
					timeout_s=int(args.timeout_s),
				)
				fec_line = _extract_last_run_record(fec_stderr)
				fec_kv = _parse_kv_from_run_line(fec_line)
				fec_ok = 1 if (
					_to_int(fec_kv, "timed_out", 0) == 0
					and _to_int(fec_kv, "md5_ok", 0) == 1
					and _to_int(fec_kv, "client_ok", 1) == 1
				) else 0
				recs.append(
					Rec(
						file_label=file_label,
						loss_mode=str(loss_mode),
						proto="quic_fec_bbrv2",
						rep=int(rep),
						ok=int(fec_ok),
						goodput_mbps=float(_to_float(fec_kv, "s_mbps", 0.0)),
						dur_ms=int(_to_int(fec_kv, "dur_ms", 0)),
						overhead_ratio=float(_overhead_quic_ratio_from_kv(kv=fec_kv)),
						overhead_quic_ratio=float(_overhead_quic_ratio_from_kv(kv=fec_kv)),
						extra={"run": fec_kv},
					)
				)

				print(
					f"rep={rep:02d} file={file_label} loss={loss_mode} "
					f"raw(ok={raw_ok} dur_ms={_to_int(raw_kv,'dur_ms',0)} ov={_overhead_quic_ratio_from_kv(kv=raw_kv)*100:.2f}%) "
					f"fec(ok={fec_ok} dur_ms={_to_int(fec_kv,'dur_ms',0)} ov={_overhead_quic_ratio_from_kv(kv=fec_kv)*100:.2f}%)"
				)

	out_jsonl = out_dir / "results.jsonl"
	with out_jsonl.open("w", encoding="utf-8") as f:
		for r in recs:
			f.write(
				json.dumps(
					{
						"file": r.file_label,
						"loss_mode": r.loss_mode,
						"proto": r.proto,
						"rep": r.rep,
						"ok": r.ok,
						"goodput_mbps": r.goodput_mbps,
						"dur_ms": r.dur_ms,
						"overhead_ratio": r.overhead_ratio,
						"overhead_quic_ratio": r.overhead_quic_ratio,
						"extra": r.extra,
					},
					ensure_ascii=False,
				)
				+ "\n"
			)

	out_csv = out_dir / "results.csv"
	with out_csv.open("w", newline="", encoding="utf-8") as f:
		w = csv.DictWriter(
			f,
			fieldnames=["file", "loss_mode", "proto", "rep", "ok", "goodput_mbps", "dur_ms", "overhead_pct", "overhead_quic_pct"],
		)
		w.writeheader()
		for r in recs:
			w.writerow(
				{
					"file": r.file_label,
					"loss_mode": r.loss_mode,
					"proto": r.proto,
					"rep": r.rep,
					"ok": r.ok,
					"goodput_mbps": f"{r.goodput_mbps:.6f}",
					"dur_ms": r.dur_ms,
					"overhead_pct": f"{r.overhead_ratio*100.0:.6f}",
					"overhead_quic_pct": f"{r.overhead_quic_ratio*100.0:.6f}",
				}
			)

	summary: Dict[str, Any] = {}
	for file_label in wanted_files:
		for loss_mode in loss_modes:
			for proto in ["quic_raw_bbrv2", "quic_fec_bbrv2"]:
				key = f"{file_label}::{loss_mode}::{proto}"
				rs = [r for r in recs if r.file_label == file_label and r.loss_mode == loss_mode and r.proto == proto]
				summary[key] = _summarize(rs)

	(out_dir / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
	(out_dir / "meta.json").write_text(
		json.dumps(
			{
				"bitrate_mbps": int(args.bitrate_mbps),
				"rtt_ms": int(args.rtt_ms),
				"loss_modes": loss_modes,
				"reps": int(args.reps),
				"files": wanted_files,
				"run_tag": run_tag,
				"run_tag_effective": run_tag_effective,
				"net_env": net_env,
				"fec": {"K": int(args.k), "R0": int(args.r0), "RSTEP": int(args.rstep), "SYMBOL_BYTES": int(args.symbol_bytes)},
				"overhead_definition": "overhead_ratio = max(0, (quic_sent_bytes - file_bytes)/file_bytes), quic_sent_bytes from QUIC tracer (attempted send bytes, pre-qdisc)",
				"overhead_quic_definition": "overhead_quic_ratio = max(0, (quic_sent_bytes - file_bytes)/file_bytes), quic_sent_bytes from QUIC tracer (attempted send bytes, pre-qdisc)",
			},
			indent=2,
			ensure_ascii=False,
		)
		+ "\n",
		encoding="utf-8",
	)

	print("OUT:", out_dir)
	print("- results:", out_jsonl)
	print("- summary:", out_dir / "summary.json")

	for file_label in wanted_files:
		for loss_mode in loss_modes:
			print(f"\n[file={file_label} loss={loss_mode}]")
			for proto in ["quic_raw_bbrv2", "quic_fec_bbrv2"]:
				key = f"{file_label}::{loss_mode}::{proto}"
				s = summary.get(key, {})
				g = s.get("goodput_mbps", {})
				d = s.get("dur_ms", {})
				o = s.get("overhead_pct", {})
				oq = s.get("overhead_quic_pct", {})
				print(
					f"  {proto:14s} ok_rate={s.get('ok_rate',0):.2f} "
					f"goodput(mean/p50/p95)={g.get('mean')}/{g.get('p50')}/{g.get('p95')} "
					f"dur_ms(mean/p50/p95)={d.get('mean')}/{d.get('p50')}/{d.get('p95')} "
					f"overhead%(mean/p50/p95)={o.get('mean')}/{o.get('p50')}/{o.get('p95')} "
					f"overhead_quic%(mean/p50/p95)={oq.get('mean')}/{oq.get('p50')}/{oq.get('p95')}"
				)

	return 0


if __name__ == "__main__":
	raise SystemExit(main())

