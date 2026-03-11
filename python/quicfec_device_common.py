from __future__ import annotations

import shlex
import subprocess
import sys
from pathlib import Path
from typing import Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]
GO_DIR = REPO_ROOT / "go"
BIN_DIR = GO_DIR / "bin"
SERVER_BIN = BIN_DIR / "quicfec-device-server"
CLIENT_BIN = BIN_DIR / "quicfec-device-client"
DEFAULT_BUILD_TAG = "quicfecdev"


def build_binary(binary_path: Path, package_path: str, build_tag: str | None) -> None:
	BIN_DIR.mkdir(parents=True, exist_ok=True)
	cmd = ["go", "build"]
	if build_tag:
		cmd.extend(["-tags", build_tag])
	cmd.extend(["-o", str(binary_path), package_path])
	subprocess.run(cmd, cwd=GO_DIR, check=True)


def ensure_binary(binary_path: Path) -> None:
	if binary_path.exists():
		return
	raise FileNotFoundError(
		f"missing binary: {binary_path}. Run with --build first, or build it manually."
	)


def print_command(cmd: Iterable[str]) -> None:
	print(shlex.join(list(cmd)))


def run_command(cmd: list[str], print_only: bool) -> int:
	if print_only:
		print_command(cmd)
		return 0
	proc = subprocess.run(cmd)
	return int(proc.returncode)


def fail(message: str) -> int:
	print(message, file=sys.stderr)
	return 2