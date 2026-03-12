from __future__ import annotations

import argparse
import sys

from quicfec_device_common import (
	CLIENT_BIN,
	DEFAULT_BUILD_TAG,
	build_binary,
	ensure_binary,
	fail,
	run_command,
)


def parse_args() -> argparse.Namespace:
	ap = argparse.ArgumentParser(description="Run QUIC-FEC device client on a sender machine")
	ap.add_argument("--build", action="store_true", help="build the Go binary before running")
	ap.add_argument(
		"--build-tag",
		default=DEFAULT_BUILD_TAG,
		help="Go build tag for device instrumentation; use empty string to disable",
	)
	ap.add_argument("--print-cmd", action="store_true", help="print the final command and exit")

	ap.add_argument("--server", default="127.0.0.1", help="server IP or hostname")
	ap.add_argument("--port", type=int, default=25569, help="server UDP port")
	ap.add_argument("--alpn", default="quic-fec", help="ALPN protocol")
	ap.add_argument("--in", dest="in_path", default="data/send.bin", help="input file path")
	ap.add_argument("--timeout", default="60s", help="overall client timeout")
	ap.add_argument(
		"--connect-timeout",
		default="3s",
		help="timeout for dialing and QUIC handshake",
	)
	ap.add_argument("--insecure", action=argparse.BooleanOptionalAction, default=True)

	ap.add_argument("--K", type=int, default=60, help="source symbols K")
	ap.add_argument("--R0", type=int, default=6, help="initial repair symbols R0")
	ap.add_argument("--Rstep", type=int, default=4, help="minimum repairs appended per NACK")
	ap.add_argument("--ddl-ms", type=int, default=25, help="receiver soft deadline in milliseconds")
	ap.add_argument("--L", type=int, default=1200, help="symbol bytes L")
	ap.add_argument("--W", type=int, default=8, help="ARQ unfinished-cluster window")
	ap.add_argument("--max-attempts", type=int, default=0, help="ARQ max attempts per cluster (0=unlimited)")
	ap.add_argument("--ack-every", type=int, default=8, help="write 1B on a stream every N datagrams (0=disable)")
	ap.add_argument("--post-wait", default="0s", help="linger after sending; bare numbers mean seconds")
	ap.add_argument("--transport", default="dgram", choices=["dgram", "stream"], help="symbol transport")
	ap.add_argument("--dgram-warn", type=int, default=1400, help="warn if datagram exceeds bytes (0=off)")

	ap.add_argument(
		"--dev-retx",
		action=argparse.BooleanOptionalAction,
		default=True,
		help="enable QUIC retransmission reason logging",
	)
	ap.add_argument(
		"--quic-stats",
		action=argparse.BooleanOptionalAction,
		default=False,
		help="enable aggregate QUIC stats line",
	)
	return ap.parse_args()


def build_cmd(args: argparse.Namespace) -> list[str]:
	return [
		str(CLIENT_BIN),
		"-server",
		args.server,
		"-port",
		str(args.port),
		"-alpn",
		args.alpn,
		"-in",
		args.in_path,
		"-timeout",
		args.timeout,
		"-connect-timeout",
		args.connect_timeout,
		f"-insecure={str(args.insecure).lower()}",
		"-K",
		str(args.K),
		"-R0",
		str(args.R0),
		"-Rstep",
		str(args.Rstep),
		"-ddl-ms",
		str(args.ddl_ms),
		"-L",
		str(args.L),
		"-W",
		str(args.W),
		"-max-attempts",
		str(args.max_attempts),
		"-ack-every",
		str(args.ack_every),
		"-post-wait",
		args.post_wait,
		"-transport",
		args.transport,
		"-dgram-warn",
		str(args.dgram_warn),
		f"-dev-retx={str(args.dev_retx).lower()}",
		f"-quic-stats={str(args.quic_stats).lower()}",
	]


def main() -> int:
	args = parse_args()
	if args.port <= 0 or args.port > 65535:
		return fail("bad --port: must be in 1..65535")
	if args.K <= 0 or args.R0 < 0 or args.L <= 0 or args.ddl_ms < 0:
		return fail("bad FEC arguments: require K>0, R0>=0, L>0, ddl-ms>=0")
	if args.ack_every < 0:
		return fail("bad --ack-every: must be >= 0")
	if args.max_attempts < 0:
		return fail("bad --max-attempts: must be >= 0")
	if args.dgram_warn < 0:
		return fail("bad --dgram-warn: must be >= 0")
	if args.build:
		build_binary(CLIENT_BIN, "./cmd/quicfec-device-client", args.build_tag or None)
	try:
		ensure_binary(CLIENT_BIN)
	except FileNotFoundError as exc:
		return fail(str(exc))
	return run_command(build_cmd(args), print_only=args.print_cmd)


if __name__ == "__main__":
	sys.exit(main())