from __future__ import annotations

import argparse
import sys

from quicfec_device_api import build_device_binaries
from quicfec_device_common import DEFAULT_BUILD_TAG


def parse_args() -> argparse.Namespace:
	ap = argparse.ArgumentParser(description="Build QUIC-FEC device client and server binaries")
	ap.add_argument(
		"--build-tag",
		default=DEFAULT_BUILD_TAG,
		help="Go build tag for device instrumentation; use empty string to disable",
	)
	return ap.parse_args()


def main() -> int:
	args = parse_args()
	build_device_binaries(args.build_tag)
	print("built: quicfec-device-client, quicfec-device-server")
	return 0


if __name__ == "__main__":
	sys.exit(main())