#!/usr/bin/env python3
"""Measure finite-file goodput fairness for concurrent QUIC-RaptorQ flows."""

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
CLIENT_BIN = ROOT / "go" / "bin" / "quicfec-client"
SERVER_BIN = ROOT / "go" / "bin" / "quicfec-server"
CLIENT_STATS_RE = re.compile(
    r"\[client-stats\].*?bytes=(\d+).*?dur_s=([0-9.]+).*?mbps=([0-9.]+)"
)


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


def choose_topology() -> tuple[str, str, str, str, str]:
    existing_ns = {line.split()[0] for line in run_checked(["ip", "netns", "list"]).splitlines() if line.split()}
    pid_seed = os.getpid() % 90000
    for offset in range(1000):
        token = (pid_seed + offset) % 90000
        ns = f"qff{token}"
        veth_host = f"qfh{token}"
        veth_ns = f"qfn{token}"
        if ns in existing_ns:
            continue
        if subprocess.run(["ip", "link", "show", "dev", veth_host], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            continue
        if subprocess.run(["ip", "link", "show", "dev", veth_ns], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            continue
        octet = token % 250 + 1
        return ns, veth_host, veth_ns, f"10.239.{octet}.1/24", f"10.239.{octet}.2/24"
    raise RuntimeError("could not find collision-free names for a private test namespace")


def load_sender(params_path: Path, sender_id: int, ge_key: str) -> tuple[dict[str, Any], dict[str, float], str]:
    payload = json.loads(params_path.read_text())
    sender = payload.get("senders", {}).get(str(sender_id))
    if not isinstance(sender, dict):
        raise ValueError(f"sender {sender_id} not found in {params_path}")
    ge = sender.get(ge_key)
    if not isinstance(ge, dict):
        raise ValueError(f"sender {sender_id} does not contain {ge_key}")
    p = float(ge["p_g2b"])
    r = float(ge["r_b2g"])
    if not (math.isfinite(p) and math.isfinite(r) and 0 <= p <= 1 and 0 <= r <= 1):
        raise ValueError(f"invalid GE transition probabilities for sender {sender_id}: p={p}, r={r}")
    rtt_ms = int(sender.get("rtt_ms", 84))
    h_pct, k_pct = 0.0, 99.0
    loss_mode = f"gemodel:{p * 100:.6f},{r * 100:.6f},{h_pct:.6f},{k_pct:.6f}"
    return sender, {"p_g2b": p, "r_b2g": r, "h_loss_pct": h_pct, "k_loss_pct": k_pct}, loss_mode


def jain(values: list[float]) -> float | None:
    if not values:
        return None
    total = sum(values)
    squares = sum(value * value for value in values)
    if squares <= 0:
        return None
    return total * total / (len(values) * squares)


def md5_file(path: Path) -> str:
    digest = hashlib.md5()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_client_stats(output: str) -> tuple[int | None, float | None, float | None]:
    match = CLIENT_STATS_RE.search(output)
    if not match:
        return None, None, None
    return int(match.group(1)), float(match.group(2)), float(match.group(3))


def parse_tc_stats(output: str) -> dict[str, int | None]:
    in_netem = False
    for line in output.splitlines():
        if "qdisc netem 10:" in line:
            in_netem = True
            continue
        if not in_netem:
            continue
        match = re.search(r"Sent\s+(\d+)\s+bytes\s+(\d+)\s+pkt\s+\(dropped\s+(\d+)", line)
        if match:
            return {
                "netem_sent_bytes": int(match.group(1)),
                "netem_sent_pkts": int(match.group(2)),
                "netem_dropped_pkts": int(match.group(3)),
            }
    return {"netem_sent_bytes": None, "netem_sent_pkts": None, "netem_dropped_pkts": None}


def parse_server_stats(path: Path) -> list[tuple[float, float]]:
    stats: list[tuple[float, float]] = []
    if not path.is_file():
        return stats
    pattern = re.compile(r"\[server-stats\].*?dur_s=([0-9.]+).*?mbps=([0-9.]+)")
    for line in path.read_text(errors="replace").splitlines():
        match = pattern.search(line)
        if match:
            stats.append((float(match.group(1)), float(match.group(2))))
    return stats


def write_rows(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def run_flow(
    *,
    barrier: threading.Barrier,
    client_args: list[str],
    client_env: dict[str, str],
    timeout_s: int,
    output_log: Path,
    recv_path: Path,
    expected_md5: str,
    file_bytes: int,
    rep: int,
    flow_id: int,
    sender_id: int,
    loss_mode: str,
) -> dict[str, Any]:
    try:
        barrier.wait(timeout=10)
    except threading.BrokenBarrierError as exc:
        raise RuntimeError("could not synchronize concurrent client starts") from exc

    started = time.monotonic_ns()
    rc: int | None = None
    output = ""
    error = ""
    try:
        proc = subprocess.run(
            client_args,
            cwd=ROOT,
            env=client_env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout_s + 10,
            check=False,
        )
        rc = proc.returncode
        output = proc.stdout
    except subprocess.TimeoutExpired as exc:
        output = (exc.stdout or "")
        if isinstance(output, bytes):
            output = output.decode(errors="replace")
        error = f"client subprocess exceeded {timeout_s + 10}s wall timeout"
    except Exception as exc:  # retain per-flow failure evidence
        error = f"{type(exc).__name__}: {exc}"

    client_finished_ns = time.monotonic_ns()
    # The client can receive DONE just before the receiver's final file rename.
    # Wait for a checksum-valid output, so filesystem timing cannot create a
    # false transfer failure. End-to-end completion includes this short delay.
    deadline = time.monotonic() + 8.0
    md5_ok = False
    verified_ns: int | None = None
    while time.monotonic() < deadline:
        if recv_path.is_file() and md5_file(recv_path) == expected_md5:
            md5_ok = True
            verified_ns = time.monotonic_ns()
            break
        time.sleep(0.02)
    elapsed_end_ns = verified_ns if verified_ns is not None else client_finished_ns
    elapsed_s = max((elapsed_end_ns - started) / 1e9, 1e-9)
    recv_finalize_delay_s = (
        max((verified_ns - client_finished_ns) / 1e9, 0.0) if verified_ns is not None else None
    )
    output_log.write_text(output + (f"\n[runner-error] {error}\n" if error else ""))
    sent_bytes, client_dur_s, client_tx_mbps = parse_client_stats(output)
    client_error = next((line.strip() for line in output.splitlines() if line.strip().startswith("error:")), "")
    client_process_goodput = (file_bytes * 8 / 1e6 / elapsed_s) if md5_ok else 0.0

    return {
        "rep": rep,
        "flow_id": flow_id,
        "sender_id": sender_id,
        "loss_mode": loss_mode,
        "file_bytes": file_bytes,
        "elapsed_s": elapsed_s,
        "client_dur_s": client_dur_s,
        "recv_finalize_delay_s": recv_finalize_delay_s,
        "receiver_duration_s": None,
        "receiver_reported_mbps": None,
        "client_process_goodput_mbps": client_process_goodput,
        "client_sent_bytes": sent_bytes,
        "client_tx_mbps": client_tx_mbps,
        "goodput_mbps": 0.0,
        "client_rc": rc,
        "client_clean_exit": int(rc == 0),
        "client_error": client_error,
        "md5_ok": int(md5_ok),
        "success": 0,
        "error": error,
        "client_log": str(output_log.relative_to(ROOT)),
        "recv_file": str(recv_path.relative_to(ROOT)) if recv_path.exists() else "",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sender-id", type=int, default=316)
    parser.add_argument("--ge-key", default="GE_steady_rp")
    parser.add_argument("--ge-params", type=Path, default=DEFAULT_PARAMS)
    parser.add_argument("--flows", type=int, default=12)
    parser.add_argument("--reps", type=int, default=20)
    parser.add_argument("--file-bytes", type=int, default=128 * 1024)
    parser.add_argument("--bitrate-mbps", type=int, default=10)
    parser.add_argument("--symbol-bytes", type=int, default=1200)
    parser.add_argument("--timeout-s", type=int, default=45)
    parser.add_argument("--out-dir", type=Path, default=None)
    parser.add_argument("--helper", type=Path, default=Path(os.environ.get("QUIC_FEC_PRIV_HELPER", str(DEFAULT_HELPER))))
    args = parser.parse_args()

    if args.flows < 2 or args.reps < 1 or args.file_bytes < 1 or args.bitrate_mbps < 1:
        parser.error("flows >= 2, reps >= 1, file-bytes >= 1, and bitrate-mbps >= 1 are required")
    if not args.helper.is_file():
        raise RuntimeError(f"privileged helper not found: {args.helper}")
    if not args.ge_params.is_file():
        raise RuntimeError(f"GE parameter file not found: {args.ge_params}")

    sender, ge, loss_mode = load_sender(args.ge_params, args.sender_id, args.ge_key)
    rtt_ms = int(sender.get("rtt_ms", 84))
    K, R0, RSTEP = 60, 15, 10
    file_bytes = int(args.file_bytes)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir = args.out_dir or (ROOT / "python" / "results" / f"quicfec-flow-fairness-ge{args.sender_id}-{stamp}")
    if not out_dir.is_absolute():
        out_dir = ROOT / out_dir
    if out_dir.exists() and any(out_dir.iterdir()):
        raise RuntimeError(f"output directory is not empty: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    for sub in ("logs", "recv"):
        (out_dir / sub).mkdir(exist_ok=True)

    # Rebuild stale binaries before measuring, but do not touch experiment source files.
    run_checked(["go", "build", "-o", str(SERVER_BIN), "./cmd/quicfec-server"], timeout=180, cwd=ROOT / "go")
    run_checked(["go", "build", "-o", str(CLIENT_BIN), "./cmd/quicfec-client"], timeout=180, cwd=ROOT / "go")

    payload = out_dir / "payload.bin"
    payload.write_bytes(os.urandom(file_bytes))
    expected_md5 = md5_file(payload)

    ns, veth_host, veth_ns, host_cidr, ns_cidr = choose_topology()
    host_ip, ns_ip = host_cidr.split("/")[0], ns_cidr.split("/")[0]
    port_base = 40000 + (os.getpid() % 15000)
    ports = [port_base + i for i in range(args.flows)]
    server_logs: list[Path] = []
    server_procs: list[subprocess.Popen[str]] = []
    topology_attempted = False
    flow_rows: list[dict[str, Any]] = []
    round_rows: list[dict[str, Any]] = []

    metadata = {
        "created": datetime.now().astimezone().isoformat(),
        "sender_id": args.sender_id,
        "ge_key": args.ge_key,
        "ge_params_file": str(args.ge_params),
        "ge": ge,
        "loss_mode": loss_mode,
        "rtt_ms": rtt_ms,
        "bitrate_mbps": args.bitrate_mbps,
        "flows": args.flows,
        "repetitions": args.reps,
        "file_bytes_each_flow": file_bytes,
        "fec": {"K": K, "R0": R0, "RSTEP": RSTEP, "N": K + R0, "symbol_bytes": args.symbol_bytes},
        "cc": "bbrv2",
        "transport": "dgram",
        "arq": True,
        "measurement": "receiver goodput = file payload bits / that flow's server-reported receive duration; checksum-invalid or missing receiver measurements contribute 0. Client exit status is recorded separately.",
        "jain_formula": "(sum(flow_goodput_mbps)^2) / (flows * sum(flow_goodput_mbps^2))",
        "namespace": ns,
        "veth_host": veth_host,
        "veth_ns": veth_ns,
        "host_ip": host_cidr,
        "namespace_ip": ns_cidr,
        "ports": ports,
        "status": "starting",
    }
    (out_dir / "meta.json").write_text(json.dumps(metadata, indent=2) + "\n")

    flow_fields = [
        "rep", "flow_id", "sender_id", "loss_mode", "file_bytes", "elapsed_s", "client_dur_s",
        "recv_finalize_delay_s", "receiver_duration_s", "receiver_reported_mbps", "server_stat_record_index",
        "client_process_goodput_mbps",
        "client_sent_bytes", "client_tx_mbps", "goodput_mbps", "client_rc", "client_clean_exit",
        "client_error", "md5_ok", "success", "error", "client_log", "recv_file",
    ]
    round_fields = [
        "rep", "jain_fairness", "success_flows", "client_clean_flows", "total_flows", "sum_goodput_mbps",
        "mean_flow_goodput_mbps", "min_flow_goodput_mbps", "max_flow_goodput_mbps",
        "netem_sent_bytes", "netem_sent_pkts", "netem_dropped_pkts",
    ]

    try:
        helper_call(args.helper, "self-test")
        topology_attempted = True
        helper_call(args.helper, "reset", ns, veth_host, veth_ns, host_cidr, ns_cidr)

        # All flows share one sender-side qdisc: the configured bottleneck and
        # Gilbert-Elliott state are common to the concurrent flows in each rep.
        helper_call(args.helper, "tc-config", veth_host, veth_ns, ns, str(args.bitrate_mbps), str(rtt_ms), loss_mode, "0")

        for flow_id, port in enumerate(ports):
            recv_dir = out_dir / "recv" / f"flow_{flow_id:02d}"
            recv_dir.mkdir(parents=True, exist_ok=True)
            log_path = out_dir / "logs" / f"server_flow_{flow_id:02d}.log"
            log_handle = log_path.open("w")
            proc = subprocess.Popen(
                [
                    "sudo", "-n", str(args.helper), "server-start", ns, str(SERVER_BIN),
                    f"{ns_ip}:{port}", str(recv_dir), "900s", "25",
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
            for _ in range(30):
                if server_procs[flow_id].poll() is not None:
                    break
                probe = subprocess.run(
                    ["sudo", "-n", str(args.helper), "wait-port", ns, str(port)],
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
                raise RuntimeError(f"server for flow {flow_id} did not open port {port}; see {server_logs[flow_id]}")

        metadata["status"] = "running"
        (out_dir / "meta.json").write_text(json.dumps(metadata, indent=2) + "\n")

        with (out_dir / "flow_results.csv").open("w", newline="") as flow_csv:
            flow_writer = csv.DictWriter(flow_csv, fieldnames=flow_fields)
            flow_writer.writeheader()
            flow_csv.flush()
            with (out_dir / "round_summary.csv").open("w", newline="") as round_csv:
                round_writer = csv.DictWriter(round_csv, fieldnames=round_fields)
                round_writer.writeheader()
                round_csv.flush()

                for rep in range(1, args.reps + 1):
                    helper_call(args.helper, "tc-config", veth_host, veth_ns, ns, str(args.bitrate_mbps), str(rtt_ms), loss_mode, "0")
                    # Record each server log's current length so missing stats
                    # in one round cannot shift every later round's attribution.
                    stats_count_before = [len(parse_server_stats(path)) for path in server_logs]
                    barrier = threading.Barrier(args.flows)
                    futures: list[concurrent.futures.Future[dict[str, Any]]] = []
                    client_env = os.environ.copy()
                    client_env["QUIC_FEC_CC_ALGO"] = "bbrv2"
                    client_env["QUIC_FEC_CC_BYPASS"] = "0"
                    client_env.pop("QUIC_FEC_STATS", None)
                    with concurrent.futures.ThreadPoolExecutor(max_workers=args.flows) as pool:
                        for flow_id, port in enumerate(ports):
                            recv_path = out_dir / "recv" / f"flow_{flow_id:02d}" / f"{payload.name}.recv"
                            part_path = Path(str(recv_path) + ".part")
                            recv_path.unlink(missing_ok=True)
                            part_path.unlink(missing_ok=True)
                            client_path = out_dir / "logs" / f"rep_{rep:02d}_flow_{flow_id:02d}.log"
                            client_args = [
                                str(CLIENT_BIN), "-addr", f"{ns_ip}:{port}", "-file", str(payload),
                                "-timeout", f"{args.timeout_s}s", "-connect-timeout", "2s",
                                "-N", str(K + R0), "-K", str(K), "-L", str(args.symbol_bytes),
                                "-post-wait", "0s", "-ack-every", "8", "-dgram-warn", "1400",
                                "-transport", "dgram", "-arq", "-R0", str(R0), "-W", "8",
                                "-Rstep", str(RSTEP), "-max-attempts", "0", "-loss", "0",
                            ]
                            futures.append(
                                pool.submit(
                                    run_flow,
                                    barrier=barrier,
                                    client_args=client_args,
                                    client_env=client_env,
                                    timeout_s=args.timeout_s,
                                    output_log=client_path,
                                    recv_path=recv_path,
                                    expected_md5=expected_md5,
                                    file_bytes=file_bytes,
                                    rep=rep,
                                    flow_id=flow_id,
                                    sender_id=args.sender_id,
                                    loss_mode=loss_mode,
                                )
                            )
                        batch = [future.result() for future in futures]

                    # Use only server records appended during this round. Do
                    # not assume record N always belongs to round N: a failed
                    # transfer may produce no server-stats line.
                    stats_by_flow: list[list[tuple[float, float]]] = [[] for _ in range(args.flows)]
                    stats_deadline = time.monotonic() + 15.0
                    while time.monotonic() < stats_deadline:
                        stats_by_flow = [parse_server_stats(path) for path in server_logs]
                        if all(len(stats) > stats_count_before[i] for i, stats in enumerate(stats_by_flow)):
                            break
                        time.sleep(0.05)
                    for flow_id, row in enumerate(batch):
                        record_index = stats_count_before[flow_id]
                        if len(stats_by_flow[flow_id]) > record_index:
                            rx_duration_s, reported_mbps = stats_by_flow[flow_id][record_index]
                            row["receiver_duration_s"] = rx_duration_s
                            row["receiver_reported_mbps"] = reported_mbps
                            row["server_stat_record_index"] = record_index + 1
                            if row["md5_ok"] == 1 and rx_duration_s > 0:
                                row["goodput_mbps"] = file_bytes * 8 / 1e6 / rx_duration_s
                        row["success"] = int(row["md5_ok"] == 1 and row["receiver_duration_s"] is not None)

                    flow_rows.extend(batch)
                    flow_writer.writerows(batch)
                    flow_csv.flush()

                    goodputs = [float(row["goodput_mbps"]) for row in batch]
                    jfi = jain(goodputs)
                    try:
                        tc_output = helper_call(args.helper, "tc-stats", veth_host)
                        tc_stats = parse_tc_stats(tc_output)
                    except Exception:
                        tc_stats = {"netem_sent_bytes": None, "netem_sent_pkts": None, "netem_dropped_pkts": None}
                    summary = {
                        "rep": rep,
                        "jain_fairness": jfi,
                        "success_flows": sum(int(row["success"]) for row in batch),
                        "client_clean_flows": sum(int(row["client_clean_exit"]) for row in batch),
                        "total_flows": args.flows,
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
                        f"[{rep}/{args.reps}] JFI={jfi if jfi is not None else float('nan'):.4f} "
                        f"success={summary['success_flows']}/{args.flows} "
                        f"mean_goodput={summary['mean_flow_goodput_mbps']:.3f} Mbps",
                        flush=True,
                    )

        valid_jfi = [float(row["jain_fairness"]) for row in round_rows if row["jain_fairness"] is not None]
        all_goodputs = [float(row["goodput_mbps"]) for row in flow_rows]
        successful = sum(int(row["success"]) for row in flow_rows)
        summary_json = {
            "repetitions_completed": len(round_rows),
            "flow_trials": len(flow_rows),
            "successful_flows": successful,
            "failed_or_md5_invalid_flows": len(flow_rows) - successful,
            "client_nonzero_exit_flows": sum(1 for row in flow_rows if int(row["client_clean_exit"]) == 0),
            "jain_fairness_mean": statistics.mean(valid_jfi) if valid_jfi else None,
            "jain_fairness_sample_std": statistics.stdev(valid_jfi) if len(valid_jfi) > 1 else 0.0 if valid_jfi else None,
            "jain_fairness_min": min(valid_jfi) if valid_jfi else None,
            "jain_fairness_max": max(valid_jfi) if valid_jfi else None,
            "flow_goodput_mean_mbps_including_failures_as_zero": statistics.mean(all_goodputs) if all_goodputs else None,
            "flow_goodput_sample_std_mbps": statistics.stdev(all_goodputs) if len(all_goodputs) > 1 else 0.0 if all_goodputs else None,
            "per_rep_jain": valid_jfi,
        }
        (out_dir / "summary.json").write_text(json.dumps(summary_json, indent=2) + "\n")
        metadata["status"] = "complete" if len(round_rows) == args.reps else "incomplete"
        (out_dir / "meta.json").write_text(json.dumps(metadata, indent=2) + "\n")
        print(json.dumps(summary_json, indent=2))
        print(f"results_dir={out_dir}")
        return 0 if successful == args.flows * args.reps else 2
    finally:
        if topology_attempted:
            try:
                helper_call(args.helper, "server-stop-ns", ns, timeout=15)
            except Exception as exc:
                print(f"[cleanup-warning] server-stop-ns: {exc}", flush=True)
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
                helper_call(args.helper, "cleanup", ns, veth_host, timeout=20)
            except Exception as exc:
                print(f"[cleanup-warning] cleanup: {exc}", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
