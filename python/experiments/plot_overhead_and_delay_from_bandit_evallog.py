#!/usr/bin/env python3
from __future__ import annotations

# Thin wrapper around plot_overhead_and_delay_from_trainlog.py:
# same plotting, but the bandit input is the *evaluation* JSONL produced by
# eval_bandit_model_on_testbed.py.

import argparse
import json
from pathlib import Path

from plot_overhead_and_delay_from_trainlog import main as _main_trainlog


def _infer_flec_jsonl(*, flec_dir: Path, baseline_in_dir: Path, file_bytes: int) -> Path:
    # flec_dir contains 4 fixed files:
    # - flec_GE_128k.jsonl, flec_GE_1m.jsonl, flec_iid_128k.jsonl, flec_iid_1m.jsonl
    loss_profile: str = ""
    meta = baseline_in_dir / "meta.json"
    if meta.exists():
        try:
            d = json.loads(meta.read_text(encoding="utf-8"))
            if isinstance(d, dict) and isinstance(d.get("args"), dict):
                loss_profile = str(d["args"].get("loss_profile", "") or "").strip().lower()
        except Exception:
            loss_profile = ""

    if not loss_profile:
        # Fallback: infer from directory name.
        s = str(baseline_in_dir).lower()
        if "ge" in s:
            loss_profile = "ge"
        elif "iid" in s:
            loss_profile = "iid"

    lp_tag = "GE" if loss_profile == "ge" else "iid"
    size_tag = "1m" if int(file_bytes) >= 1024 * 1024 else "128k"
    return flec_dir / f"flec_{lp_tag}_{size_tag}.jsonl"


def main() -> int:
    ap = argparse.ArgumentParser(
        description=(
            "Plot overhead+delay figures using baseline CSV (quic/raw + FEC1/2) and bandit QUIC-FEC from a local evaluation log JSONL."
        )
    )
    ap.add_argument("--baseline-in-dir", type=str, required=True, help="Directory containing results.csv from run_raw_fec1_fec2_baselines.py")
    ap.add_argument("--bandit-eval-log", type=str, required=True, help="Bandit evaluation JSONL (bandit_eval_metrics.jsonl)")
    ap.add_argument(
        "--flec-dir",
        type=str,
        default="",
        help="Optional directory containing flec_{GE,iid}_{128k,1m}.jsonl to add method 'flec'",
    )
    ap.add_argument("--out-dir", type=str, default="", help="Output directory (default: baseline-in-dir)")

    ap.add_argument("--file-bytes", type=int, default=128 * 1024)
    ap.add_argument("--duration-field", type=str, default="e2e_delay_ms", choices=["dur_ms", "e2e_delay_ms"])

    ap.add_argument("--t-min", type=int, default=None)
    ap.add_argument("--t-max", type=int, default=None)
    ap.add_argument("--sender-ids", type=str, default="")

    ap.add_argument(
        "--methods",
        type=str,
        default="bandit,quic_bbrv2,fec_k40_r0_0_rstep_4,fec_k40_r0_4_rstep_0",
    )

    ap.add_argument("--aggregate", type=str, default="none", choices=["none", "sender_method_mean"])
    ap.add_argument("--include-failures", action="store_true")
    ap.add_argument("--xmin-delay-ms", type=float, default=0.0)
    ap.add_argument("--xmax-delay-ms", type=float, default=500.0)

    args = ap.parse_args()

    # Delegate to the trainlog plotter by mapping arg name.
    # (Both formats share the same env_info/raw_obs schema.)
    argv = [
        "--baseline-in-dir",
        str(args.baseline_in_dir),
        "--bandit-train-log",
        str(args.bandit_eval_log),
        "--out-dir",
        str(args.out_dir),
        "--file-bytes",
        str(int(args.file_bytes)),
        "--duration-field",
        str(args.duration_field),
        "--methods",
        str(args.methods),
        "--aggregate",
        str(args.aggregate),
        "--xmin-delay-ms",
        str(float(args.xmin_delay_ms)),
        "--xmax-delay-ms",
        str(float(args.xmax_delay_ms)),
    ]
    if args.t_min is not None:
        argv += ["--t-min", str(int(args.t_min))]
    if args.t_max is not None:
        argv += ["--t-max", str(int(args.t_max))]
    if str(args.sender_ids or "").strip():
        argv += ["--sender-ids", str(args.sender_ids)]
    if bool(args.include_failures):
        argv += ["--include-failures"]

    flec_dir_s = str(args.flec_dir or "").strip()
    if flec_dir_s:
        flec_path = _infer_flec_jsonl(
            flec_dir=Path(flec_dir_s),
            baseline_in_dir=Path(str(args.baseline_in_dir)),
            file_bytes=int(args.file_bytes),
        )
        if flec_path.exists():
            argv += ["--flec-jsonl", str(flec_path)]
            # If user didn't include flec explicitly, add it.
            methods = [m.strip() for m in str(args.methods).split(",") if m.strip()]
            if "flec" not in methods:
                methods.append("flec")
                # Replace the earlier --methods value.
                for i in range(len(argv) - 1):
                    if argv[i] == "--methods":
                        argv[i + 1] = ",".join(methods)
                        break
        else:
            print(f"WARN: flec jsonl not found: {flec_path}")

    # Monkeypatch sys.argv for the delegated parser.
    import sys

    sys.argv = [sys.argv[0]] + argv

    # Ensure baseline dir exists early (nicer error).
    if not (Path(str(args.baseline_in_dir)) / "results.csv").exists():
        raise SystemExit("missing baseline results.csv under --baseline-in-dir")

    return int(_main_trainlog())


if __name__ == "__main__":
    raise SystemExit(main())
