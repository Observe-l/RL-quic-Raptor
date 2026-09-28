#!/usr/bin/env python3
"""Measure Jain fairness for concurrent original quic-go raw-stream transfers."""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import hashlib
import json
import math
import os
import re
import statistics
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PARAMS = ROOT / "python" / "bandit" / "quic_fec_params.json"
DEFAULT_HELPER = Path("/usr/local/libexec/quicfec-net-helper")
SERVER_BIN = ROOT / "go" / "bin" / "quicraw-server"
CLIENT_BIN = ROOT / "go" / "bin" / "quicraw-client"
RAW_SERVER_RE = re.compile(r"\[raw-server\].*?bytes=(\d+).*?dur_ms=(\d+).*?goodput_mbps=([0-9.]+)")
CLIENT_STATS_RE = re.compile(r"\[raw-client\].*?bytes=(\d+).*?dur_ms=(\d+).*?goodput_mbps=([0-9.]+)")


def run_checked(args: list[str], *, timeout: float = 30.0, cwd: Path = ROOT) -> str:
    proc = subprocess.run(
        args,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"command failed ({proc.returncode}): {' '.join(args)}\n{proc.stdout}")
    return proc.stdout


def helper_call(helper: Path, *args: str, timeout: float = 30.0) -> str:
    return run_checked(["sudo", "-n", str(helper), *args], timeout=timeout)


def md5_file(path: Path) -> str:
    digest = hashlib.md5()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def jain(values: list[float]) -> float | None:
    if not values:
        return None
    total = sum(values)
    squares = sum(value * value for value in values)
    if squares <= 0:
        return None
    return total * total / (len(values) * squares)


def load_sender(params_path: Path, sender_id: int, ge_key: str) -> tuple[dict[str, Any], dict[str, float], str]:
    payload = json.loads(params_path.read_text(encoding="utf-8"))
    sender = payload.get("senders", {}).get(str(sender_id))
    if not isinstance(sender, dict):
        raise ValueError(f"sender {sender_id} not found in {params_path}")
    ge = sender.get(ge_key)
    if not isinstance(ge, dict):
        raise ValueError(f"sender {sender_id} does not contain {ge_key}")
    p = float(ge["p_g2b"])
    r = float(ge["r_b2g"])
    if not (math.isfinite(p) and math.isfinite(r) and 0 <= p <= 1 and 0 <= r <= 1):
        raise ValueError(f"invalid GE transition probabilities: p={p}, r={r}")
    h_pct, k_pct = 0.0, 99.0
    loss_mode = f"gemodel:{p * 100:.6f},{r * 100:.6f},{h_pct:.6f},{k_pct:.6f}"
    return sender, {"p_g2b": p, "r_b2g": r, "h_loss_pct": h_pct, "k_loss_pct": k_pct}, loss_mode


def parse_server_stats(path: Path) -> list[dict[str, float | int]]:
    rows: list[dict[str, float | int]] = []
    if not path.is_file():
        return rows
    for line in path.read_text(errors="replace").splitlines():
        match = RAW_SERVER_RE.search(line)
        if match:
            rows.append({"bytes": int(match.group(1)), "dur_ms": int(match.group(2)), "goodput_mbps": float(match.group(3))})
    return rows


def parse_tc_stats(output: str) -> dict[str, int | None]:
    in_netem = False
    for line in output.splitlines():
        if "qdisc netem 10:" in line:
            in_netem = True
            continue
        if in_netem:
            match = re.search(r"Sent\s+(\d+)\s+bytes\s+(\d+)\s+pkt\s+\(dropped\s+(\d+)", line)
            if match:
                return {
                    "netem_sent_bytes": int(match.group(1)),
                    "netem_sent_pkts": int(match.group(2)),
                    "netem_dropped_pkts": int(match.group(3)),
                }
    return {"netem_sent_bytes": None, "netem_sent_pkts": None, "netem_dropped_pkts": None}


def write_rows(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def reserve_topologies(flow_counts: list[int]) -> dict[int, dict[str, str]]:
    """Allocate four unique namespace, veth, and /24 tuples before workers start."""
    ns_output = run_checked(["ip", "netns", "list"])
    existing_ns = {line.split()[0] for line in ns_output.splitlines() if line.split()}
    link_output = run_checked(["ip", "-o", "link", "show"])
    existing_links = {match.group(1).split("@", 1)[0] for line in link_output.splitlines() if (match := re.match(r"\d+:\s+([^:]+):", line))}
    addr_output = run_checked(["ip", "-4", "-o", "addr", "show"])
    used_subnets = {int(match.group(1)) for line in addr_output.splitlines() if (match := re.search(r"\binet\s+10\.238\.(\d+)\.", line))}

    pid_tag = os.getpid() % 1_000_000
    reserved: dict[int, dict[str, str]] = {}
    local_subnets: set[int] = set()
    for index, flows in enumerate(flow_counts):
        token = f"{pid_tag:06d}{flows:02d}"
        ns, vh, vn = f"qraw{token}", f"qrh{token}", f"qrn{token}"
        if ns in existing_ns or vh in existing_links or vn in existing_links:
            raise RuntimeError(f"refusing to reuse an existing namespace/interface: {ns}, {vh}, {vn}")
        subnet = next((n for n in range(1, 255) if n not in used_subnets and n not in local_subnets), None)
        if subnet is None:
            raise RuntimeError("no unused 10.238.X.0/24 subnet is available for the isolated experiments")
        local_subnets.add(subnet)
        reserved[flows] = {
            "ns": ns,
            "veth_host": vh,
            "veth_ns": vn,
            "host_cidr": f"10.238.{subnet}.1/24",
            "ns_cidr": f"10.238.{subnet}.2/24",
        }
    return reserved


def run_client(
    *,
    barrier: threading.Barrier,
    client_env: dict[str, str],
    payload: Path,
    recv_path: Path,
    expected_md5: str,
    address: str,
    timeout_s: int,
    log_path: Path,
    rep: int,
    flow_id: int,
    sender_id: int,
    loss_mode: str,
) -> dict[str, Any]:
    try:
        barrier.wait(timeout=20)
    except threading.BrokenBarrierError as exc:
        raise RuntimeError("could not synchronize raw QUIC client starts") from exc

    started_ns = time.monotonic_ns()
    command = [
        str(CLIENT_BIN), "-addr", address, "-file", str(payload),
        "-timeout", f"{timeout_s}s", "-connect-timeout", "2s",
        "-measure-delay=true", "-packet-bytes", "1200",
    ]
    rc: int | None = None
    output = ""
    final_output = ""
    error = ""
    connection_attempts = 0
    attempt_logs: list[str] = []
    for attempt in range(1, 6):
        connection_attempts = attempt
        try:
            proc = subprocess.run(
                command,
                cwd=ROOT,
                env=client_env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=timeout_s + 10,
                check=False,
            )
            rc, final_output = proc.returncode, proc.stdout
        except subprocess.TimeoutExpired as exc:
            final_output = exc.stdout or ""
            if isinstance(final_output, bytes):
                final_output = final_output.decode(errors="replace")
            error = f"client exceeded {timeout_s + 10}s wall timeout"
            attempt_logs.append(f"[connection-attempt={attempt}]\n{final_output}")
            break
        except Exception as exc:  # retain evidence for an individual failed flow
            error = f"{type(exc).__name__}: {exc}"
            break

        attempt_logs.append(f"[connection-attempt={attempt}]\n{final_output}")
        dial_failed = any(
            line.startswith(("dial timeout:", "dial error:"))
            for line in final_output.splitlines()
        )
        if rc == 0 or not dial_failed or attempt == 5:
            break
        time.sleep(0.05)
    output = "\n".join(attempt_logs)

    ended_ns = time.monotonic_ns()
    log_path.write_text(output + (f"\n[runner-error] {error}\n" if error else ""), encoding="utf-8")
    client_match = CLIENT_STATS_RE.search(final_output)
    client_bytes = int(client_match.group(1)) if client_match else None
    client_dur_ms = int(client_match.group(2)) if client_match else None
    client_mbps = float(client_match.group(3)) if client_match else None
    client_error = next((line.strip() for line in final_output.splitlines() if line.strip().startswith(("dial error:", "dial timeout:", "error:"))), "")

    checksum_ok = recv_path.is_file() and recv_path.stat().st_size == payload.stat().st_size
    if checksum_ok:
        checksum_ok = md5_file(recv_path) == expected_md5
    elapsed_s = (ended_ns - started_ns) / 1e9
    return {
        "rep": rep,
        "flow_id": flow_id,
        "sender_id": sender_id,
        "loss_mode": loss_mode,
        "file_bytes": payload.stat().st_size,
        "client_elapsed_s": elapsed_s,
        "client_bytes": client_bytes,
        "client_dur_ms": client_dur_ms,
        "client_reported_mbps": client_mbps,
        "connection_attempts": connection_attempts,
        "receiver_dur_ms": None,
        "receiver_reported_mbps": None,
        "goodput_mbps": 0.0,
        "client_rc": rc,
        "client_clean_exit": int(rc == 0),
        "client_error": client_error,
        "md5_ok": int(checksum_ok),
        "success": 0,
        "error": error,
        "client_log": str(log_path.relative_to(ROOT)),
        "recv_file": str(recv_path.relative_to(ROOT)) if recv_path.exists() else "",
    }


def run_condition(
    *,
    flows: int,
    reps: int,
    file_bytes: int,
    bitrate_mbps: int,
    timeout_s: int,
    sender_id: int,
    ge_key: str,
    rtt_ms: int,
    loss_mode: str,
    ge: dict[str, float],
    topology: dict[str, str],
    root_out: Path,
    payload: Path,
    expected_md5: str,
    helper: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    out_dir = root_out / f"{flows}flow"
    logs_dir, recv_dir = out_dir / "logs", out_dir / "recv"
    logs_dir.mkdir(parents=True)
    recv_dir.mkdir()
    ns = topology["ns"]
    host_ip, ns_ip = topology["host_cidr"].split("/")[0], topology["ns_cidr"].split("/")[0]
    port_base = 30000 + ((os.getpid() * 97 + flows * 131) % 20000)
    ports = [port_base + index for index in range(flows)]
    server_logs: list[Path] = []
    server_procs: list[subprocess.Popen[str]] = []
    topology_attempted = False
    flow_rows: list[dict[str, Any]] = []
    round_rows: list[dict[str, Any]] = []
    metadata: dict[str, Any] = {
        "status": "starting",
        "flow_count": flows,
        "sender_id": sender_id,
        "ge_key": ge_key,
        "ge": ge,
        "loss_mode": loss_mode,
        "rtt_ms": rtt_ms,
        "bitrate_mbps": bitrate_mbps,
        "repetitions": reps,
        "file_bytes_each_flow": file_bytes,
        "transport": "original quic-go QUIC stream (quicraw-client/server)",
        "fec": False,
        "connection_retry_policy": "retry dial timeout/error up to 5 total attempts, matching run_quicraw_baselines.py",
        "concurrent_flows_share_one_tbf_and_ge_netem_qdisc": True,
        "cc": "bbrv2",
        "namespace": ns,
        "veth_host": topology["veth_host"],
        "veth_ns": topology["veth_ns"],
        "host_ip": topology["host_cidr"],
        "namespace_ip": topology["ns_cidr"],
        "ports": ports,
        "measurement": "receiver useful-payload goodput = verified file bytes * 8 / raw-server receive duration; failed or missing checksum/stat contributes 0; client exit status is reported separately",
        "jain_formula": "(sum(flow_goodput_mbps)^2) / (flow_count * sum(flow_goodput_mbps^2))",
    }
    (out_dir / "meta.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")

    flow_fields = [
        "rep", "flow_id", "sender_id", "loss_mode", "file_bytes", "client_elapsed_s", "client_bytes",
        "client_dur_ms", "client_reported_mbps", "connection_attempts", "receiver_dur_ms", "receiver_reported_mbps", "goodput_mbps",
        "client_rc", "client_clean_exit", "client_error", "md5_ok", "success", "error", "client_log", "recv_file",
    ]
    round_fields = [
        "rep", "jain_fairness", "success_flows", "client_clean_flows", "total_flows", "sum_goodput_mbps",
        "mean_flow_goodput_mbps", "min_flow_goodput_mbps", "max_flow_goodput_mbps",
        "netem_sent_bytes", "netem_sent_pkts", "netem_dropped_pkts",
    ]

    try:
        topology_attempted = True
        helper_call(helper, "reset", ns, topology["veth_host"], topology["veth_ns"], topology["host_cidr"], topology["ns_cidr"])
        helper_call(helper, "tc-config", topology["veth_host"], topology["veth_ns"], ns, str(bitrate_mbps), str(rtt_ms), loss_mode, "0")

        for flow_id, port in enumerate(ports):
            flow_recv = recv_dir / f"flow_{flow_id:02d}"
            flow_recv.mkdir()
            log_path = logs_dir / f"server_flow_{flow_id:02d}.log"
            log_handle = log_path.open("w", encoding="utf-8")
            proc = subprocess.Popen(
                [
                    "sudo", "-n", str(helper), "raw-server-start", ns, str(SERVER_BIN),
                    f"{ns_ip}:{port}", str(flow_recv), "1800s",
                ],
                cwd=ROOT,
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                text=True,
            )
            log_handle.close()
            server_procs.append(proc)
            server_logs.append(log_path)

        for flow_id, port in enumerate(ports):
            ready = False
            for _ in range(40):
                if server_procs[flow_id].poll() is not None:
                    break
                probe = subprocess.run(
                    ["sudo", "-n", str(helper), "wait-port", ns, str(port)],
                    cwd=ROOT,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                    check=False,
                )
                if probe.returncode == 0:
                    ready = True
                    break
                time.sleep(0.05)
            if not ready:
                raise RuntimeError(f"raw server for flow {flow_id} failed to listen on {ns_ip}:{port}; see {server_logs[flow_id]}")

        metadata["status"] = "running"
        (out_dir / "meta.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
        client_env = os.environ.copy()
        client_env["QUIC_FEC_CC_ALGO"] = "bbrv2"
        client_env["QUIC_FEC_CC_BYPASS"] = "0"
        client_env.pop("QUIC_RAW_STATS", None)

        with (out_dir / "flow_results.csv").open("w", newline="", encoding="utf-8") as flow_csv:
            flow_writer = csv.DictWriter(flow_csv, fieldnames=flow_fields)
            flow_writer.writeheader()
            flow_csv.flush()
            with (out_dir / "round_summary.csv").open("w", newline="", encoding="utf-8") as round_csv:
                round_writer = csv.DictWriter(round_csv, fieldnames=round_fields)
                round_writer.writeheader()
                round_csv.flush()

                for rep in range(1, reps + 1):
                    helper_call(helper, "tc-config", topology["veth_host"], topology["veth_ns"], ns, str(bitrate_mbps), str(rtt_ms), loss_mode, "0")
                    stats_before = [len(parse_server_stats(path)) for path in server_logs]
                    barrier = threading.Barrier(flows)
                    with concurrent.futures.ThreadPoolExecutor(max_workers=flows) as pool:
                        futures = []
                        for flow_id, port in enumerate(ports):
                            recv_path = recv_dir / f"flow_{flow_id:02d}" / f"{payload.name}.recv"
                            recv_path.unlink(missing_ok=True)
                            Path(str(recv_path) + ".part").unlink(missing_ok=True)
                            futures.append(
                                pool.submit(
                                    run_client,
                                    barrier=barrier,
                                    client_env=client_env,
                                    payload=payload,
                                    recv_path=recv_path,
                                    expected_md5=expected_md5,
                                    address=f"{ns_ip}:{port}",
                                    timeout_s=timeout_s,
                                    log_path=logs_dir / f"rep_{rep:02d}_flow_{flow_id:02d}.log",
                                    rep=rep,
                                    flow_id=flow_id,
                                    sender_id=sender_id,
                                    loss_mode=loss_mode,
                                )
                            )
                        batch = [future.result() for future in futures]

                    stats_by_flow: list[list[dict[str, float | int]]] = [[] for _ in range(flows)]
                    stats_deadline = time.monotonic() + 15.0
                    while time.monotonic() < stats_deadline:
                        stats_by_flow = [parse_server_stats(path) for path in server_logs]
                        if all(len(stats_by_flow[index]) > stats_before[index] for index in range(flows)):
                            break
                        time.sleep(0.05)

                    for flow_id, row in enumerate(batch):
                        record_index = stats_before[flow_id]
                        if len(stats_by_flow[flow_id]) > record_index:
                            stat = stats_by_flow[flow_id][record_index]
                            row["receiver_dur_ms"] = stat["dur_ms"]
                            row["receiver_reported_mbps"] = stat["goodput_mbps"]
                            if row["md5_ok"] == 1 and int(stat["bytes"]) == file_bytes and int(stat["dur_ms"]) > 0:
                                row["goodput_mbps"] = file_bytes * 8.0 / 1e6 / (int(stat["dur_ms"]) / 1000.0)
                        row["success"] = int(row["md5_ok"] == 1 and row["receiver_dur_ms"] is not None and row["goodput_mbps"] > 0)

                    flow_rows.extend(batch)
                    flow_writer.writerows(batch)
                    flow_csv.flush()
                    goodputs = [float(row["goodput_mbps"]) for row in batch]
                    try:
                        tc_stats = parse_tc_stats(helper_call(helper, "tc-stats", topology["veth_host"]))
                    except Exception:
                        tc_stats = {"netem_sent_bytes": None, "netem_sent_pkts": None, "netem_dropped_pkts": None}
                    summary = {
                        "rep": rep,
                        "jain_fairness": jain(goodputs),
                        "success_flows": sum(int(row["success"]) for row in batch),
                        "client_clean_flows": sum(int(row["client_clean_exit"]) for row in batch),
                        "total_flows": flows,
                        "sum_goodput_mbps": sum(goodputs),
                        "mean_flow_goodput_mbps": statistics.mean(goodputs),
                        "min_flow_goodput_mbps": min(goodputs),
                        "max_flow_goodput_mbps": max(goodputs),
                        **tc_stats,
                    }
                    round_rows.append(summary)
                    round_writer.writerow(summary)
                    round_csv.flush()
                    print(
                        f"[{flows} flows, {rep}/{reps}] JFI={summary['jain_fairness'] if summary['jain_fairness'] is not None else float('nan'):.4f} "
                        f"success={summary['success_flows']}/{flows} mean_goodput={summary['mean_flow_goodput_mbps']:.3f} Mbps",
                        flush=True,
                    )

        valid_jfi = [float(row["jain_fairness"]) for row in round_rows if row["jain_fairness"] is not None]
        all_goodputs = [float(row["goodput_mbps"]) for row in flow_rows]
        summary_json = {
            "repetitions_completed": len(round_rows),
            "flow_trials": len(flow_rows),
            "successful_flows": sum(int(row["success"]) for row in flow_rows),
            "failed_or_invalid_flows": len(flow_rows) - sum(int(row["success"]) for row in flow_rows),
            "client_nonzero_exit_flows": sum(int(not row["client_clean_exit"]) for row in flow_rows),
            "jain_fairness_mean": statistics.mean(valid_jfi) if valid_jfi else None,
            "jain_fairness_sample_std": statistics.stdev(valid_jfi) if len(valid_jfi) > 1 else 0.0 if valid_jfi else None,
            "jain_fairness_min": min(valid_jfi) if valid_jfi else None,
            "jain_fairness_max": max(valid_jfi) if valid_jfi else None,
            "flow_goodput_mean_mbps_including_failures_as_zero": statistics.mean(all_goodputs) if all_goodputs else None,
            "flow_goodput_sample_std_mbps": statistics.stdev(all_goodputs) if len(all_goodputs) > 1 else 0.0 if all_goodputs else None,
            "per_rep_jain": valid_jfi,
        }
        (out_dir / "summary.json").write_text(json.dumps(summary_json, indent=2) + "\n", encoding="utf-8")
        metadata["status"] = "complete" if len(round_rows) == reps else "incomplete"
        (out_dir / "meta.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
        return flow_rows, round_rows, {"meta": metadata, "summary": summary_json}
    except Exception as exc:
        metadata["status"] = "failed"
        metadata["error"] = f"{type(exc).__name__}: {exc}"
        (out_dir / "meta.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
        raise
    finally:
        if topology_attempted:
            try:
                helper_call(helper, "server-stop-ns", ns, timeout=20)
            except Exception as exc:
                print(f"[{flows} flows cleanup] server-stop-ns: {exc}", flush=True)
            for proc in server_procs:
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.terminate()
                    try:
                        proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        proc.kill()
            try:
                helper_call(helper, "cleanup", ns, topology["veth_host"], timeout=20)
            except Exception as exc:
                print(f"[{flows} flows cleanup] cleanup: {exc}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sender-id", type=int, default=316)
    parser.add_argument("--ge-key", default="GE_steady_rp")
    parser.add_argument("--ge-params", type=Path, default=DEFAULT_PARAMS)
    parser.add_argument("--flow-counts", default="6,12,18,24")
    parser.add_argument("--reps", type=int, default=20)
    parser.add_argument("--file-bytes", type=int, default=128 * 1024)
    parser.add_argument("--bitrate-mbps", type=int, default=10)
    parser.add_argument("--timeout-s", type=int, default=90)
    parser.add_argument(
        "--reuse-existing-binaries",
        action="store_true",
        help="Reuse already-built quicraw binaries instead of rebuilding the shared Go packages",
    )
    parser.add_argument("--out-dir", type=Path, default=None)
    parser.add_argument("--helper", type=Path, default=Path(os.environ.get("QUIC_FEC_PRIV_HELPER", str(DEFAULT_HELPER))))
    args = parser.parse_args()

    flow_counts = [int(value.strip()) for value in args.flow_counts.split(",") if value.strip()]
    if len(flow_counts) != len(set(flow_counts)) or any(value < 2 for value in flow_counts):
        parser.error("flow-counts must contain distinct integers >= 2")
    if args.reps < 1 or args.file_bytes < 1 or args.bitrate_mbps < 1 or args.timeout_s < 1:
        parser.error("reps, file-bytes, bitrate-mbps and timeout-s must be positive")
    if not args.helper.is_file():
        raise RuntimeError(f"privileged helper not found: {args.helper}")
    if not args.ge_params.is_file():
        raise RuntimeError(f"GE parameter file not found: {args.ge_params}")

    sender, ge, loss_mode = load_sender(args.ge_params, args.sender_id, args.ge_key)
    rtt_ms = int(sender.get("rtt_ms", 84))
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir = args.out_dir or (ROOT / "python" / "results" / "fairness" / f"quicraw-ge{args.sender_id}-{stamp}")
    if not out_dir.is_absolute():
        out_dir = ROOT / out_dir
    if out_dir.exists() and any(out_dir.iterdir()):
        raise RuntimeError(f"output directory is not empty: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)

    topology_by_flows = reserve_topologies(flow_counts)
    helper_call(args.helper, "self-test")
    if args.reuse_existing_binaries:
        for binary in (SERVER_BIN, CLIENT_BIN):
            if not binary.is_file() or not os.access(binary, os.X_OK):
                raise RuntimeError(f"cannot reuse missing or non-executable binary: {binary}")
    else:
        run_checked(["go", "build", "-o", str(SERVER_BIN), "./cmd/quicraw-server"], timeout=180, cwd=ROOT / "go")
        run_checked(["go", "build", "-o", str(CLIENT_BIN), "./cmd/quicraw-client"], timeout=180, cwd=ROOT / "go")

    payload = out_dir / "payload.bin"
    payload.write_bytes(os.urandom(args.file_bytes))
    expected_md5 = md5_file(payload)
    metadata = {
        "created": datetime.now().astimezone().isoformat(),
        "status": "running",
        "sender_id": args.sender_id,
        "ge_key": args.ge_key,
        "ge_params_file": str(args.ge_params),
        "ge": ge,
        "loss_mode": loss_mode,
        "rtt_ms": rtt_ms,
        "bitrate_mbps_per_experiment": args.bitrate_mbps,
        "flow_counts": flow_counts,
        "repetitions_per_flow_count": args.reps,
        "file_bytes_each_flow": args.file_bytes,
        "transport": "quicraw original quic-go stream protocol, no FEC/ARQ",
        "cc": "bbrv2",
        "client_packetization": "run_quicraw_baselines.py-compatible framed 1200-byte payload records with delay measurement enabled",
        "connection_retry_policy": "retry dial timeout/error up to 5 total attempts, matching run_quicraw_baselines.py",
        "binary_policy": "reused existing binaries" if args.reuse_existing_binaries else "built immediately before experiment",
        "binary_sha256": {"quicraw-server": sha256_file(SERVER_BIN), "quicraw-client": sha256_file(CLIENT_BIN)},
        "parallelism": "one worker thread and dedicated namespace/qdisc per flow-count experiment; all flows within each group start concurrently",
        "jain_formula": "per-repetition Jain index over receiver goodputs; mean and sample std across repetitions",
        "host_cpu_shared_between_workers": True,
    }
    (out_dir / "meta.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")

    flow_fields = [
        "flow_count", "rep", "flow_id", "sender_id", "loss_mode", "file_bytes", "client_elapsed_s", "client_bytes",
        "client_dur_ms", "client_reported_mbps", "connection_attempts", "receiver_dur_ms", "receiver_reported_mbps", "goodput_mbps",
        "client_rc", "client_clean_exit", "client_error", "md5_ok", "success", "error", "client_log", "recv_file",
    ]
    round_fields = [
        "flow_count", "rep", "jain_fairness", "success_flows", "client_clean_flows", "total_flows", "sum_goodput_mbps",
        "mean_flow_goodput_mbps", "min_flow_goodput_mbps", "max_flow_goodput_mbps",
        "netem_sent_bytes", "netem_sent_pkts", "netem_dropped_pkts",
    ]

    failures: list[str] = []
    all_flows: list[dict[str, Any]] = []
    all_rounds: list[dict[str, Any]] = []
    condition_results: dict[int, Any] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(flow_counts)) as pool:
        future_map = {
            pool.submit(
                run_condition,
                flows=flows,
                reps=args.reps,
                file_bytes=args.file_bytes,
                bitrate_mbps=args.bitrate_mbps,
                timeout_s=args.timeout_s,
                sender_id=args.sender_id,
                ge_key=args.ge_key,
                rtt_ms=rtt_ms,
                loss_mode=loss_mode,
                ge=ge,
                topology=topology_by_flows[flows],
                root_out=out_dir,
                payload=payload,
                expected_md5=expected_md5,
                helper=args.helper,
            ): flows
            for flows in flow_counts
        }
        for future in concurrent.futures.as_completed(future_map):
            flows = future_map[future]
            try:
                flow_rows, round_rows, result = future.result()
                all_flows.extend([{**row, "flow_count": flows} for row in flow_rows])
                all_rounds.extend([{**row, "flow_count": flows} for row in round_rows])
                condition_results[flows] = result
            except Exception as exc:
                failures.append(f"{flows} flows: {type(exc).__name__}: {exc}")
                print(f"[{flows} flows failed] {exc}", flush=True)

    write_rows(out_dir / "flow_results.csv", all_flows, flow_fields)
    write_rows(out_dir / "round_summary.csv", all_rounds, round_fields)
    metadata["status"] = "complete" if not failures and len(condition_results) == len(flow_counts) else "incomplete"
    metadata["condition_results"] = condition_results
    metadata["errors"] = failures
    (out_dir / "meta.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"results_dir": str(out_dir), "status": metadata["status"], "conditions": condition_results, "errors": failures}, indent=2))
    return 0 if not failures else 2


if __name__ == "__main__":
    raise SystemExit(main())
