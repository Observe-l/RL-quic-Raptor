#!/usr/bin/env python3
"""Run a 300-second, period-3, 100-KiB QUIC-RaptorQ/Veins experiment."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time


PROJECT = Path(__file__).resolve().parent
VEINS = Path("/opt/omnetpp-6.1/samples/veins")
RESULTS = PROJECT / "results/period3_100KiB_K40_R0_0_dR5"
FILE_BYTES = 102400
VEHICLE_COUNT = 100
N = 40
K = 40
R0 = 0
RSTEP = 5
L = 1200
BRIDGE_PORT_BASE = 20000
RSU_BRIDGE_PORT = 19999


def prepare_inputs() -> str:
    input_dir = RESULTS / "input"
    input_dir.mkdir(parents=True, exist_ok=True)
    payload = bytes((i * 73 + (i >> 3) * 19 + 41) & 0xFF for i in range(FILE_BYTES))
    digest = hashlib.sha256(payload).hexdigest()
    for node_id in range(VEHICLE_COUNT):
        path = input_dir / f"flow_{node_id:04d}.bin"
        if path.exists():
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            if path.stat().st_size != FILE_BYTES or actual != digest:
                raise RuntimeError(f"refusing to overwrite unexpected input file: {path}")
        else:
            path.write_bytes(payload)
    return digest


def channel_busy_scalars(path: Path) -> dict[str, float]:
    values: dict[str, float] = {}
    if not path.exists():
        return values
    for line in path.read_text(errors="replace").splitlines():
        parts = line.split()
        if len(parts) == 4 and parts[0] == "scalar" and parts[2] == "channelBusy:timeavg":
            values[parts[1]] = float(parts[3])
    return values


def terminate_group(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait()


def wait_for_launchd(proc: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"veins_launchd exited with status {proc.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", 9999), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("veins_launchd did not open TCP port 9999")


def main() -> int:
    input_dir = RESULTS / "input"
    output_files = [p for p in RESULTS.rglob("*") if p.is_file() and input_dir not in p.parents]
    if output_files:
        raise RuntimeError(f"results already exist (e.g. {output_files[0]}); move them before rerunning")

    input_sha256 = prepare_inputs()
    (RESULTS / "received").mkdir(parents=True, exist_ok=True)
    (RESULTS / "logs").mkdir(parents=True, exist_ok=True)
    shared_lib = PROJECT / "out/gcc-release/libveins_quicfec_cosim.so"
    for binary in (PROJECT / "bin/quicfec-veins-client", PROJECT / "bin/quicfec-veins-server", shared_lib):
        if not binary.exists():
            raise RuntimeError(f"missing build artifact {binary}; run ./build.sh first")

    ned_path = ":".join((str(PROJECT / "src"), str(VEINS / "examples/veins"), str(VEINS / "src/veins")))
    command = [
        "opp_run", "-u", "Cmdenv", "-f", str(PROJECT / "config/omnetpp.ini"),
        "-c", "Period3K40R0dR5", "-n", ned_path,
        "-l", str(VEINS / "src/libveins.so"), "-l", str(shared_lib),
    ]
    env = os.environ.copy()
    lib_path = f"{PROJECT / 'out/gcc-release'}:{VEINS / 'src'}"
    if env.get("LD_LIBRARY_PATH"):
        lib_path += ":" + env["LD_LIBRARY_PATH"]
    env["LD_LIBRARY_PATH"] = lib_path
    log_path = RESULTS / "simulation.log"
    launchd_path = RESULTS / "logs/launchd.log"
    print("Starting real-time OMNeT++/SUMO QUIC-RaptorQ co-simulation (300 simulated seconds).", flush=True)
    print(f"Vehicle period: 3 seconds; expected vehicles: {VEHICLE_COUNT}", flush=True)
    print(f"FEC parameters: K={K}, R0={R0}, deltaR={RSTEP}, L={L}", flush=True)
    print(f"Bridge ports: RSU={RSU_BRIDGE_PORT}, vehicle base={BRIDGE_PORT_BASE}", flush=True)
    print(f"Results directory: {RESULTS}", flush=True)
    started = time.time()
    return_code = 2
    launchd = subprocess.Popen([str(VEINS / "bin/veins_launchd"), "-p", "9999", "-L", str(launchd_path)],
                               cwd=PROJECT / "config", env=env,
                               stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, start_new_session=True)
    try:
        wait_for_launchd(launchd)
        with log_path.open("w") as log:
            proc = subprocess.Popen(command, cwd=PROJECT / "config", env=env,
                                    stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                return_code = proc.wait()
            except KeyboardInterrupt:
                terminate_group(proc)
                return 130
    finally:
        terminate_group(launchd)

    cbr = channel_busy_scalars(RESULTS / "veins.sca")
    rsu_values = [v for k, v in cbr.items() if ".rsu[" in k]
    received_files = sorted((RESULTS / "received").glob("*.recv"))
    verified = []
    for path in received_files:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        verified.append({"file": path.name, "bytes": path.stat().st_size,
                         "sha256": digest,
                         "matches_input": path.stat().st_size == FILE_BYTES and digest == input_sha256})

    all_values = list(cbr.values())
    summary = {
        "sim_time_limit_s": 300,
        "vehicle_generation_period_s": 3,
        "expected_vehicle_count": VEHICLE_COUNT,
        "file_bytes": FILE_BYTES,
        "transport": {"protocol": "Go quic-go QUIC + TLS + quic-fec RaptorQ/ARQ",
                      "cc": "bbrv2", "N": N, "K": K, "R0_initial_repairs": R0,
                      "deltaR_repairs_per_nack": RSTEP, "L": L,
                      "arq_window": 8, "max_attempts": 5},
        "bridge_ports": {"rsu": RSU_BRIDGE_PORT, "vehicle_base": BRIDGE_PORT_BASE},
        "input_sha256": input_sha256,
        "simulator_exit_code": return_code,
        "elapsed_wall_seconds": round(time.time() - started, 3),
        "files_received": len(received_files),
        "files_verified": sum(x["matches_input"] for x in verified),
        "received": verified,
        "rsu_channel_busy_ratio": sum(rsu_values) / len(rsu_values) if rsu_values else None,
        "mean_channel_busy_ratio_all_interfaces": sum(all_values) / len(all_values) if all_values else None,
        "channel_busy_scalar_count": len(cbr),
    }
    (RESULTS / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({k: summary[k] for k in (
        "simulator_exit_code", "files_received", "files_verified", "rsu_channel_busy_ratio",
        "mean_channel_busy_ratio_all_interfaces", "channel_busy_scalar_count",
        "elapsed_wall_seconds")}, indent=2))
    if return_code:
        print(f"Simulation failed; inspect {log_path}", file=sys.stderr)
    return return_code


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)
