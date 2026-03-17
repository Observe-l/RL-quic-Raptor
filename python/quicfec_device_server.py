from __future__ import annotations

import argparse
import sys

from quicfec_device_common import (
	DEFAULT_BUILD_TAG,
	SERVER_BIN,
	build_binary,
	ensure_binary,
	fail,
	run_command,
)


def parse_args() -> argparse.Namespace:
	ap = argparse.ArgumentParser(description="Run QUIC-FEC device server on a receiver machine")
	ap.add_argument("--build", action="store_true", help="build the Go binary before running")
	ap.add_argument(
		"--build-tag",
		default=DEFAULT_BUILD_TAG,
		help="Go build tag for device instrumentation; use empty string to disable",
	)
	ap.add_argument("--print-cmd", action="store_true", help="print the final command and exit")

	ap.add_argument("--addr", default="0.0.0.0:25569", help="listen address")
	ap.add_argument("--alpn", default="quic-fec", help="ALPN protocol")
	ap.add_argument(
		"--out",
		dest="out_path",
		default="data/receive.bin",
		help="output file path or base path; concurrent sessions get unique per-connection suffixes",
	)
	ap.add_argument("--timeout", default="0", help="server timeout, 0 means no timeout")
	ap.add_argument("--rtt-ms", type=int, default=350, help="manual RTT override in ms for ARQ waiting (0=use measured SRTT)")
	ap.add_argument("--rx-budget-bytes", type=int, default=64 * 1024 * 1024)
	ap.add_argument("--decode-ddl", default="25ms", help="receiver decode/check pacing")
	ap.add_argument("--rx-workers", type=int, default=2, help="receiver decode workers")
	ap.add_argument(
		"--enable-obs",
		action=argparse.BooleanOptionalAction,
		default=False,
		help="emit final [rl-observation] JSON line",
	)
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
		str(SERVER_BIN),
		"-addr",
		args.addr,
		"-alpn",
		args.alpn,
		"-out",
		args.out_path,
		"-timeout",
		args.timeout,
		"-rtt-ms",
		str(args.rtt_ms),
		"-rx-budget-bytes",
		str(args.rx_budget_bytes),
		"-decode-ddl",
		args.decode_ddl,
		"-rx-workers",
		str(args.rx_workers),
		f"-enable-obs={str(args.enable_obs).lower()}",
		f"-dev-retx={str(args.dev_retx).lower()}",
		f"-quic-stats={str(args.quic_stats).lower()}",
	]


def main() -> int:
	args = parse_args()
	if args.rx_budget_bytes <= 0 or args.rx_workers <= 0:
		return fail("bad receiver arguments: require rx-budget-bytes>0 and rx-workers>0")
	if args.rtt_ms < 0:
		return fail("bad --rtt-ms: must be >= 0")
	if not args.out_path:
		return fail("bad --out: empty path")
	if args.build:
		build_binary(SERVER_BIN, "./cmd/quicfec-device-server", args.build_tag or None)
	try:
		ensure_binary(SERVER_BIN)
	except FileNotFoundError as exc:
		return fail(str(exc))
	return run_command(build_cmd(args), print_only=args.print_cmd)


if __name__ == "__main__":
	sys.exit(main())
