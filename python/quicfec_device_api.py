from __future__ import annotations

import re
import subprocess

from quicfec_device_common import (
	CLIENT_BIN,
	DEFAULT_BUILD_TAG,
	SERVER_BIN,
	build_binary,
	ensure_binary,
)


_CLIENT_BYTES_PATTERNS = (
	re.compile(r"\[live-client\]\s+tx_bytes=(\d+)"),
	re.compile(r"\[client-stats\].*?\bbytes=(\d+)"),
)

_SERVER_BYTES_PATTERNS = (
	re.compile(r"\[server-progress\]\s+written=(\d+)/(\d+)"),
	re.compile(r"\[server-e2e\].*?\bwritten=(\d+)/(\d+)"),
)


def build_device_binaries(build_tag: str = DEFAULT_BUILD_TAG) -> None:
	build_binary(CLIENT_BIN, "./cmd/quicfec-device-client", build_tag or None)
	build_binary(SERVER_BIN, "./cmd/quicfec-device-server", build_tag or None)


def _run_and_collect_bytes(cmd: list[str], patterns: tuple[re.Pattern[str], ...]) -> int:
	proc = subprocess.Popen(
		cmd,
		stdout=subprocess.PIPE,
		stderr=subprocess.STDOUT,
		text=True,
		bufsize=1,
	)
	assert proc.stdout is not None
	max_bytes = 0
	log_lines: list[str] = []
	for line in proc.stdout:
		log_lines.append(line)
		for pattern in patterns:
			match = pattern.search(line)
			if not match:
				continue
			value = int(match.group(1))
			if value > max_bytes:
				max_bytes = value
			break
	returncode = proc.wait()
	if returncode != 0:
		joined = "".join(log_lines[-40:]).strip()
		raise RuntimeError(f"command failed with exit code {returncode}:\n{joined}")
	return max_bytes


def dir_client(
	timeout: str = "60s",
	server: str = "127.0.0.1",
	port: int = 25569,
	alpn: str = "quic-fec",
	in_path: str = "data/send.bin",
	connect_timeout: str = "3s",
	insecure: bool = True,
	K: int = 60,
	R0: int = 6,
	Rstep: int = 4,
	ddl_ms: int = 25,
	L: int = 1200,
	W: int = 8,
	max_attempts: int = 0,
	ack_every: int = 8,
	post_wait: str = "0s",
	transport: str = "dgram",
	dgram_warn: int = 1400,
	dev_retx: bool = True,
	quic_stats: bool = False,
	build: bool = False,
	build_tag: str = DEFAULT_BUILD_TAG,
) -> int:
	if build:
		build_binary(CLIENT_BIN, "./cmd/quicfec-device-client", build_tag or None)
	else:
		ensure_binary(CLIENT_BIN)
	cmd = [
		str(CLIENT_BIN),
		"-server",
		server,
		"-port",
		str(port),
		"-alpn",
		alpn,
		"-in",
		in_path,
		"-timeout",
		timeout,
		"-connect-timeout",
		connect_timeout,
		f"-insecure={str(insecure).lower()}",
		"-K",
		str(K),
		"-R0",
		str(R0),
		"-Rstep",
		str(Rstep),
		"-ddl-ms",
		str(ddl_ms),
		"-L",
		str(L),
		"-W",
		str(W),
		"-max-attempts",
		str(max_attempts),
		"-ack-every",
		str(ack_every),
		"-post-wait",
		post_wait,
		"-transport",
		transport,
		"-dgram-warn",
		str(dgram_warn),
		f"-dev-retx={str(dev_retx).lower()}",
		f"-quic-stats={str(quic_stats).lower()}",
	]
	return _run_and_collect_bytes(cmd, _CLIENT_BYTES_PATTERNS)


def dir_server(
	timeout: str = "0",
	addr: str = "0.0.0.0:25569",
	alpn: str = "quic-fec",
	out_path: str = "data/receive.bin",
	rtt_ms: int = 350,
	rx_budget_bytes: int = 64 * 1024 * 1024,
	decode_ddl: str = "25ms",
	rx_workers: int = 2,
	enable_obs: bool = False,
	dev_retx: bool = True,
	quic_stats: bool = False,
	build: bool = False,
	build_tag: str = DEFAULT_BUILD_TAG,
) -> int:
	if build:
		build_binary(SERVER_BIN, "./cmd/quicfec-device-server", build_tag or None)
	else:
		ensure_binary(SERVER_BIN)
	cmd = [
		str(SERVER_BIN),
		"-addr",
		addr,
		"-alpn",
		alpn,
		"-out",
		out_path,
		"-timeout",
		timeout,
		"-rtt-ms",
		str(rtt_ms),
		"-rx-budget-bytes",
		str(rx_budget_bytes),
		"-decode-ddl",
		decode_ddl,
		"-rx-workers",
		str(rx_workers),
		f"-enable-obs={str(enable_obs).lower()}",
		f"-dev-retx={str(dev_retx).lower()}",
		f"-quic-stats={str(quic_stats).lower()}",
	]
	return _run_and_collect_bytes(cmd, _SERVER_BYTES_PATTERNS)