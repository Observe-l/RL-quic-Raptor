from __future__ import annotations

import argparse
import csv
import gc
import json
import os
import sys
from typing import Any, Dict

import numpy as np

_THIS_DIR = os.path.dirname(__file__)
_PYTHON_DIR = os.path.abspath(os.path.join(_THIS_DIR, ".."))
if _PYTHON_DIR not in sys.path:
    sys.path.insert(0, _PYTHON_DIR)

from bandit.benchmark_lints_checkpoint import (  # noqa: E402
    _CudaLinTS,
    _fresh_cpu,
    _load_checkpoint,
    _load_fixed_context,
)


def _mib(n_bytes: int) -> float:
    return float(n_bytes) / (1024.0 * 1024.0)


def _measure(
    *,
    workload: str,
    checkpoint_prefix: str,
    context: np.ndarray,
    reward: float,
    iterations: int,
    warmups: int,
    seed: int,
) -> Dict[str, Any]:
    import torch

    cpu_agent, _, action_set, _, checkpoint_step = _fresh_cpu(checkpoint_prefix)
    agent = _CudaLinTS(cpu_agent, action_set, "cuda:0", seed)
    agent.set_context(context)
    torch.cuda.synchronize(agent.device)

    baseline_allocated = int(torch.cuda.memory_allocated(agent.device))
    baseline_reserved = int(torch.cuda.memory_reserved(agent.device))
    torch.cuda.reset_peak_memory_stats(agent.device)

    def run_once() -> None:
        action_idx, _ = agent.select_action_features()
        if workload == "fixed_context_select_feature_update":
            phi = agent.make_phi(action_idx)
            agent.update(phi, reward)

    for _ in range(warmups):
        run_once()
    torch.cuda.synchronize(agent.device)
    warmup_peak_allocated = int(torch.cuda.max_memory_allocated(agent.device))
    warmup_peak_reserved = int(torch.cuda.max_memory_reserved(agent.device))

    torch.cuda.reset_peak_memory_stats(agent.device)
    for i in range(iterations):
        run_once()
        if (i + 1) % 250 == 0:
            print(f"[{workload}] {i + 1}/{iterations}", flush=True)
    torch.cuda.synchronize(agent.device)
    measured_peak_allocated = int(torch.cuda.max_memory_allocated(agent.device))
    measured_peak_reserved = int(torch.cuda.max_memory_reserved(agent.device))

    if workload == "fixed_context_select_feature_update":
        agent.assert_finite()

    # Warmup and measured execution can have different transient peaks. Keep the
    # larger high-water mark for the reported compute requirement.
    peak_allocated = max(warmup_peak_allocated, measured_peak_allocated)
    peak_reserved = max(warmup_peak_reserved, measured_peak_reserved)
    final_allocated = int(torch.cuda.memory_allocated(agent.device))
    final_reserved = int(torch.cuda.memory_reserved(agent.device))

    result = {
        "backend": "CUDA/PyTorch FP64",
        "workload": workload,
        "iterations": iterations,
        "warmup_calls": warmups,
        "checkpoint_step_t": checkpoint_step,
        "lin_ts_dim": agent.dim,
        "action_count": len(action_set),
        "action_feature_dim": int(agent.features64.shape[1]),
        "persistent_allocated_mib": _mib(baseline_allocated),
        "persistent_reserved_mib": _mib(baseline_reserved),
        "peak_allocated_mib": _mib(peak_allocated),
        "peak_allocated_increment_mib": _mib(max(0, peak_allocated - baseline_allocated)),
        "peak_reserved_mib": _mib(peak_reserved),
        "peak_reserved_increment_mib": _mib(max(0, peak_reserved - baseline_reserved)),
        "final_allocated_mib": _mib(final_allocated),
        "final_reserved_mib": _mib(final_reserved),
        "warmup_peak_allocated_mib": _mib(warmup_peak_allocated),
        "warmup_peak_reserved_mib": _mib(warmup_peak_reserved),
        "device": torch.cuda.get_device_name(agent.device),
    }

    del agent, cpu_agent
    gc.collect()
    torch.cuda.empty_cache()
    torch.cuda.synchronize()
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="GPU-only LinTS memory profile")
    parser.add_argument(
        "--checkpoint-prefix",
        default="python/results/lints-ge-timing-2000-20260927/checkpoints/model_t500",
    )
    parser.add_argument(
        "--metrics-jsonl",
        default="python/results/lints-ge-timing-2000-20260927/bandit_metrics.json",
    )
    parser.add_argument(
        "--result-dir",
        default="python/results/lints-checkpoint500-fixed-context-20260927",
    )
    parser.add_argument("--iterations", type=int, default=2000)
    parser.add_argument("--warmup", type=int, default=10)
    parser.add_argument("--context-seed", type=int, default=20260927)
    parser.add_argument("--gpu-seed", type=int, default=20260927)
    args = parser.parse_args()

    if args.iterations <= 0 or args.warmup < 0:
        raise ValueError("iterations must be positive and warmup nonnegative")
    output_dir = os.path.abspath(args.result_dir)
    os.makedirs(output_dir, exist_ok=True)
    json_path = os.path.join(output_dir, "gpu_memory.json")
    csv_path = os.path.join(output_dir, "gpu_memory.csv")
    if os.path.exists(json_path) or os.path.exists(csv_path):
        raise FileExistsError("GPU memory result already exists; refusing to overwrite")

    checkpoint_prefix = os.path.abspath(args.checkpoint_prefix)
    metrics_path = os.path.abspath(args.metrics_jsonl)
    cpu_agent, cfg, _, _, action_set, checkpoint_step = _load_checkpoint(checkpoint_prefix)
    selected, pool = _load_fixed_context(metrics_path, checkpoint_step, args.context_seed)
    context = np.asarray(selected["context"], dtype=np.float32)
    reward = float(selected["reward"])

    import torch

    if not torch.cuda.is_available():
        raise RuntimeError("CUDA is not available")
    print(
        f"GPU={torch.cuda.get_device_name(0)}, checkpoint_t={checkpoint_step}, "
        f"context_t={selected['t']}, context_pool={len(pool)}, "
        f"LinTS_dim={cpu_agent.dim}, actions={len(action_set)}, "
        f"sigma={cfg.sigma}, rho={cfg.rho}, exact_inverse_every={cfg.recompute_inv_every}",
        flush=True,
    )

    workloads = (
        "fixed_context_action_only",
        "fixed_context_select_feature_update",
    )
    results = []
    for index, workload in enumerate(workloads):
        results.append(
            _measure(
                workload=workload,
                checkpoint_prefix=checkpoint_prefix,
                context=context,
                reward=reward,
                iterations=args.iterations,
                warmups=args.warmup,
                seed=args.gpu_seed + index,
            )
        )

    summary = {
        "benchmark": "fixed_context_checkpoint_gpu_memory",
        "checkpoint_prefix": checkpoint_prefix,
        "checkpoint_step_t": checkpoint_step,
        "checkpoint_agent_update_count": cpu_agent.t,
        "context_source_metrics": metrics_path,
        "context_seed": args.context_seed,
        "selected_context_t": int(selected["t"]),
        "context": [float(value) for value in context.tolist()],
        "fixed_reward_for_update_test": reward,
        "iterations_per_workload": args.iterations,
        "warmup_calls_excluded": args.warmup,
        "gpu_runtime": {
            "torch": torch.__version__,
            "cuda_runtime": torch.version.cuda,
            "device": torch.cuda.get_device_name(0),
            "device_capability": list(torch.cuda.get_device_capability(0)),
            "dtype": "float64",
        },
        "memory_metric_note": (
            "PyTorch per-process CUDA allocator memory. allocated is live tensor memory; "
            "reserved includes allocator caching. CUDA context and other processes are excluded. "
            "Peak includes both warmup and measured execution; incremental peak is relative to "
            "the persistent model/context allocation before warmup."
        ),
        "results": results,
    }
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    with open(csv_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(results[0].keys()))
        writer.writeheader()
        writer.writerows(results)
    print(f"wrote {json_path}")
    print(f"wrote {csv_path}")
    print(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
