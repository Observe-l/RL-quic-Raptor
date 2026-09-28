from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from statistics import mean, stdev
from typing import Any, Dict, List, Tuple

import numpy as np

_THIS_DIR = os.path.dirname(__file__)
_PYTHON_DIR = os.path.abspath(os.path.join(_THIS_DIR, ".."))
if _PYTHON_DIR not in sys.path:
    sys.path.insert(0, _PYTHON_DIR)

from bandit.features import phi as phi_fn  # noqa: E402
from bandit.lints import LinTS  # noqa: E402
from bandit.model_io import load_checkpoint  # noqa: E402


def _stats(values_ns: List[int]) -> Dict[str, float | int]:
    vals = [float(v) / 1e6 for v in values_ns]
    return {
        "n": len(vals),
        "mean_ms": mean(vals),
        "std_ms": stdev(vals) if len(vals) > 1 else 0.0,
        "total_ms": sum(vals),
    }


def _load_checkpoint(prefix: str):
    return load_checkpoint(path_prefix=prefix)


def _load_fixed_context(metrics_path: str, before_step: int, seed: int) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    rows: List[Dict[str, Any]] = []
    with open(metrics_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rec = json.loads(line)
                if int(rec.get("t", before_step)) < int(before_step):
                    context = np.asarray(rec.get("context", []), dtype=np.float64)
                    reward = float(rec.get("reward", float("nan")))
                    if context.ndim == 1 and context.size == 6 and np.isfinite(context).all() and np.isfinite(reward):
                        rows.append(rec)
    if not rows:
        raise ValueError(f"no usable 6-D contexts with t < {before_step} in {metrics_path}")
    rng = np.random.RandomState(int(seed))
    selected = rows[int(rng.randint(len(rows)))]
    return selected, rows


def _fresh_cpu(prefix: str):
    agent, agent_cfg, ctx, ctx_cfg, action_set, step_t = _load_checkpoint(prefix)
    features = np.asarray(
        [action_set.get_onehot(i) for i in range(len(action_set))], dtype=np.float64
    )
    if agent.dim != 1925 or features.shape != (2541, 274):
        raise ValueError(f"unexpected model/action dimensions: dim={agent.dim}, features={features.shape}")
    return agent, agent_cfg, action_set, features, step_t


def _run_cpu_selection(prefix: str, context: np.ndarray, n: int, warmups: int) -> Dict[str, Any]:
    agent, _, action_set, features, step_t = _fresh_cpu(prefix)
    for _ in range(warmups):
        agent.select_action_features(x=context, action_features=features)
    agent, _, action_set, features, step_t = _fresh_cpu(prefix)

    wall_samples: List[int] = []
    cpu_samples: List[int] = []
    action_indices: List[int] = []
    total_wall_start = time.perf_counter_ns()
    total_cpu_start = time.process_time_ns()
    for i in range(n):
        wall_start = time.perf_counter_ns()
        cpu_start = time.process_time_ns()
        action_idx, _theta = agent.select_action_features(x=context, action_features=features)
        wall_samples.append(time.perf_counter_ns() - wall_start)
        cpu_samples.append(time.process_time_ns() - cpu_start)
        action_indices.append(int(action_idx))
        if (i + 1) % 250 == 0:
            elapsed = (time.perf_counter_ns() - total_wall_start) / 1e9
            print(f"[CPU select] {i + 1}/{n}, elapsed={elapsed:.1f}s", flush=True)
    total_wall_ns = time.perf_counter_ns() - total_wall_start
    total_cpu_ns = time.process_time_ns() - total_cpu_start
    return {
        "backend": "CPU/NumPy",
        "workload": "fixed_context_action_only",
        "n": n,
        "warmup_calls_excluded": warmups,
        "checkpoint_step_t": step_t,
        "lin_ts_t_start": agent.t,
        "wall_per_call": _stats(wall_samples),
        "process_cpu_per_call": _stats(cpu_samples),
        "total_wall_ms": total_wall_ns / 1e6,
        "total_process_cpu_ms": total_cpu_ns / 1e6,
        "action_idx_min": min(action_indices),
        "action_idx_max": max(action_indices),
    }


def _run_cpu_select_update(
    prefix: str,
    context: np.ndarray,
    reward: float,
    n: int,
    warmups: int,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    agent, _, action_set, features, step_t = _fresh_cpu(prefix)
    for _ in range(warmups):
        action_idx, _theta = agent.select_action_features(x=context, action_features=features)
        ph = phi_fn(x=context, a_onehot=action_set.get_onehot(action_idx))
        agent.update(phi=ph, reward=reward)
    agent, _, action_set, features, step_t = _fresh_cpu(prefix)

    score_wall: List[int] = []
    score_cpu: List[int] = []
    feature_wall: List[int] = []
    feature_cpu: List[int] = []
    update_wall: List[int] = []
    update_cpu: List[int] = []
    cycle_wall: List[int] = []
    cycle_cpu: List[int] = []
    records: List[Dict[str, Any]] = []
    total_wall_start = time.perf_counter_ns()
    total_cpu_start = time.process_time_ns()

    for i in range(n):
        cycle_wall_start = time.perf_counter_ns()
        cycle_cpu_start = time.process_time_ns()

        t0 = time.perf_counter_ns()
        c0 = time.process_time_ns()
        action_idx, _theta = agent.select_action_features(x=context, action_features=features)
        sw = time.perf_counter_ns() - t0
        sc = time.process_time_ns() - c0

        t0 = time.perf_counter_ns()
        c0 = time.process_time_ns()
        ph = phi_fn(x=context, a_onehot=action_set.get_onehot(action_idx))
        fw = time.perf_counter_ns() - t0
        fc = time.process_time_ns() - c0

        exact_due = ((agent.t + 1) % int(agent.cfg.recompute_inv_every)) == 0
        t0 = time.perf_counter_ns()
        c0 = time.process_time_ns()
        agent.update(phi=ph, reward=reward)
        uw = time.perf_counter_ns() - t0
        uc = time.process_time_ns() - c0

        cw = time.perf_counter_ns() - cycle_wall_start
        cc = time.process_time_ns() - cycle_cpu_start
        score_wall.append(sw)
        score_cpu.append(sc)
        feature_wall.append(fw)
        feature_cpu.append(fc)
        update_wall.append(uw)
        update_cpu.append(uc)
        cycle_wall.append(cw)
        cycle_cpu.append(cc)
        records.append({
            "backend": "CPU/NumPy",
            "workload": "fixed_context_select_feature_update",
            "i": i,
            "action_idx": int(action_idx),
            "exact_inverse_due": bool(exact_due),
            "action_scoring_wall_ns": sw,
            "action_scoring_cpu_ns": sc,
            "feature_map_wall_ns": fw,
            "feature_map_cpu_ns": fc,
            "posterior_update_wall_ns": uw,
            "posterior_update_cpu_ns": uc,
            "cycle_wall_ns": cw,
            "cycle_cpu_ns": cc,
        })
        if (i + 1) % 250 == 0:
            elapsed = (time.perf_counter_ns() - total_wall_start) / 1e9
            print(f"[CPU select+update] {i + 1}/{n}, elapsed={elapsed:.1f}s", flush=True)

    total_wall_ns = time.perf_counter_ns() - total_wall_start
    total_cpu_ns = time.process_time_ns() - total_cpu_start
    return ({
        "backend": "CPU/NumPy",
        "workload": "fixed_context_select_feature_update",
        "n": n,
        "warmup_calls_excluded": warmups,
        "checkpoint_step_t": step_t,
        "lin_ts_t_start": 480,
        "lin_ts_t_end": agent.t,
        "periodic_exact_inverse_count": sum(r["exact_inverse_due"] for r in records),
        "action_scoring_wall_per_call": _stats(score_wall),
        "action_scoring_process_cpu_per_call": _stats(score_cpu),
        "feature_map_wall_per_call": _stats(feature_wall),
        "feature_map_process_cpu_per_call": _stats(feature_cpu),
        "posterior_update_wall_per_call": _stats(update_wall),
        "posterior_update_process_cpu_per_call": _stats(update_cpu),
        "full_cycle_wall_per_call": _stats(cycle_wall),
        "full_cycle_process_cpu_per_call": _stats(cycle_cpu),
        "total_wall_ms": total_wall_ns / 1e6,
        "total_process_cpu_ms": total_cpu_ns / 1e6,
    }, records)


class _CudaLinTS:
    """FP64 CUDA implementation matching the repository's LinTS operations."""

    def __init__(self, cpu_agent: LinTS, action_set, device: str, seed: int):
        import torch

        self.torch = torch
        self.device = torch.device(device)
        self.dim = int(cpu_agent.dim)
        self.cfg = cpu_agent.cfg
        self.t = int(cpu_agent.t)
        self.A = torch.as_tensor(cpu_agent.A.copy(), dtype=torch.float64, device=self.device)
        self.b = torch.as_tensor(cpu_agent.b.copy(), dtype=torch.float64, device=self.device)
        self.A_inv = torch.as_tensor(cpu_agent.A_inv.copy(), dtype=torch.float64, device=self.device)
        self.theta_hat = torch.as_tensor(cpu_agent.theta_hat.copy(), dtype=torch.float64, device=self.device)
        self.eye = torch.eye(self.dim, dtype=torch.float64, device=self.device)
        self.features64 = torch.as_tensor(
            np.asarray([action_set.get_onehot(i) for i in range(len(action_set))]),
            dtype=torch.float64,
            device=self.device,
        )
        self.features32 = self.features64.to(dtype=torch.float32)
        self.x64 = None
        self.x32 = None
        self.one32 = torch.ones((1,), dtype=torch.float32, device=self.device)
        self.generator = torch.Generator(device=self.device)
        self.generator.manual_seed(int(seed))
        self.torch.cuda.synchronize(self.device)

    def set_context(self, context: np.ndarray) -> None:
        self.x64 = self.torch.as_tensor(context, dtype=self.torch.float64, device=self.device)
        self.x32 = self.torch.as_tensor(context, dtype=self.torch.float32, device=self.device)

    def select_action_features(self) -> Tuple[int, np.ndarray]:
        torch = self.torch
        sigma2 = float(self.cfg.sigma) ** 2
        cov = sigma2 * (0.5 * (self.A_inv + self.A_inv.T))
        factor = torch.linalg.cholesky(cov)
        noise = torch.randn(
            (self.dim,), dtype=torch.float64, device=self.device, generator=self.generator
        )
        theta = self.theta_hat + factor @ noise
        d = int(self.x64.numel())
        m = int(self.features64.shape[1])
        off = 1 + d
        theta_a = theta[off : off + m]
        theta_xa = theta[off + m :].reshape(d, m)
        action_weights = theta_a + theta_xa.T @ self.x64
        scores = self.features64 @ action_weights
        action_idx = int(torch.argmax(scores).item())
        # Mirror LinTS.select_action_features' returned sampled theta API.
        theta_cpu = theta.detach().cpu().numpy()
        return action_idx, theta_cpu

    def make_phi(self, action_idx: int):
        torch = self.torch
        a = self.features32[int(action_idx)]
        cross = (self.x32[:, None] * a[None, :]).reshape(-1)
        phi32 = torch.cat((self.one32, self.x32, a, cross), dim=0)
        return phi32.to(dtype=torch.float64)

    def update(self, phi, reward: float) -> None:
        torch = self.torch
        rho = float(self.cfg.rho)
        lam = float(self.cfg.lam)
        self.A.mul_(rho)
        self.b.mul_(rho)
        self.A.add_(self.eye, alpha=(1.0 - rho) * lam)
        self.A.add_(torch.outer(phi, phi))
        self.b.add_(phi, alpha=float(reward))
        self.t += 1
        if self.t % int(self.cfg.recompute_inv_every) == 0:
            self.A_inv = torch.linalg.inv(self.A)
            self.theta_hat = self.A_inv @ self.b
            return

        B = self.A_inv / rho
        u = B @ phi
        denominator = 1.0 + torch.dot(phi, u)
        denominator_value = float(denominator.item())
        if not np.isfinite(denominator_value) or denominator_value <= 1e-12:
            self.A_inv = torch.linalg.inv(self.A)
            self.theta_hat = self.A_inv @ self.b
            return
        self.A_inv = B - torch.outer(u, u) / denominator
        self.A_inv = 0.5 * (self.A_inv + self.A_inv.T)
        self.theta_hat = self.A_inv @ self.b

    def assert_finite(self) -> None:
        torch = self.torch
        for name in ("A", "b", "A_inv", "theta_hat"):
            if not bool(torch.isfinite(getattr(self, name)).all().item()):
                raise FloatingPointError(f"non-finite CUDA model state in {name}")


def _run_cuda_selection(prefix: str, context: np.ndarray, n: int, warmups: int, seed: int) -> Dict[str, Any]:
    import torch

    cpu_agent, _, action_set, _, step_t = _fresh_cpu(prefix)
    gpu_agent = _CudaLinTS(cpu_agent, action_set, "cuda:0", seed)
    gpu_agent.set_context(context)
    for _ in range(warmups):
        torch.cuda.synchronize()
        gpu_agent.select_action_features()
        torch.cuda.synchronize()

    cpu_agent, _, action_set, _, step_t = _fresh_cpu(prefix)
    gpu_agent = _CudaLinTS(cpu_agent, action_set, "cuda:0", seed)
    gpu_agent.set_context(context)
    walls: List[int] = []
    actions: List[int] = []
    torch.cuda.synchronize()
    total_wall_start = time.perf_counter_ns()
    for i in range(n):
        torch.cuda.synchronize()
        t0 = time.perf_counter_ns()
        action_idx, _theta = gpu_agent.select_action_features()
        torch.cuda.synchronize()
        walls.append(time.perf_counter_ns() - t0)
        actions.append(action_idx)
        if (i + 1) % 250 == 0:
            elapsed = (time.perf_counter_ns() - total_wall_start) / 1e9
            print(f"[CUDA select] {i + 1}/{n}, elapsed={elapsed:.1f}s", flush=True)
    total_wall_ns = time.perf_counter_ns() - total_wall_start
    return {
        "backend": "CUDA/PyTorch FP64",
        "workload": "fixed_context_action_only",
        "n": n,
        "warmup_calls_excluded": warmups,
        "checkpoint_step_t": step_t,
        "lin_ts_t_start": cpu_agent.t,
        "wall_per_call": _stats(walls),
        "total_wall_ms": total_wall_ns / 1e6,
        "action_idx_min": min(actions),
        "action_idx_max": max(actions),
        "device": torch.cuda.get_device_name(0),
    }


def _run_cuda_select_update(
    prefix: str,
    context: np.ndarray,
    reward: float,
    n: int,
    warmups: int,
    seed: int,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    import torch

    cpu_agent, _, action_set, _, step_t = _fresh_cpu(prefix)
    gpu_agent = _CudaLinTS(cpu_agent, action_set, "cuda:0", seed)
    gpu_agent.set_context(context)
    for _ in range(warmups):
        torch.cuda.synchronize()
        action_idx, _theta = gpu_agent.select_action_features()
        phi = gpu_agent.make_phi(action_idx)
        gpu_agent.update(phi, reward)
        torch.cuda.synchronize()

    cpu_agent, _, action_set, _, step_t = _fresh_cpu(prefix)
    gpu_agent = _CudaLinTS(cpu_agent, action_set, "cuda:0", seed)
    gpu_agent.set_context(context)
    score_wall: List[int] = []
    feature_wall: List[int] = []
    update_wall: List[int] = []
    cycle_wall: List[int] = []
    records: List[Dict[str, Any]] = []
    torch.cuda.synchronize()
    total_wall_start = time.perf_counter_ns()

    for i in range(n):
        torch.cuda.synchronize()
        cycle_start = time.perf_counter_ns()

        t0 = time.perf_counter_ns()
        action_idx, _theta = gpu_agent.select_action_features()
        torch.cuda.synchronize()
        sw = time.perf_counter_ns() - t0

        t0 = time.perf_counter_ns()
        phi = gpu_agent.make_phi(action_idx)
        torch.cuda.synchronize()
        fw = time.perf_counter_ns() - t0

        exact_due = ((gpu_agent.t + 1) % int(gpu_agent.cfg.recompute_inv_every)) == 0
        t0 = time.perf_counter_ns()
        gpu_agent.update(phi, reward)
        torch.cuda.synchronize()
        uw = time.perf_counter_ns() - t0

        cw = time.perf_counter_ns() - cycle_start
        score_wall.append(sw)
        feature_wall.append(fw)
        update_wall.append(uw)
        cycle_wall.append(cw)
        records.append({
            "backend": "CUDA/PyTorch FP64",
            "workload": "fixed_context_select_feature_update",
            "i": i,
            "action_idx": int(action_idx),
            "exact_inverse_due": bool(exact_due),
            "action_scoring_wall_ns": sw,
            "feature_map_wall_ns": fw,
            "posterior_update_wall_ns": uw,
            "cycle_wall_ns": cw,
        })
        if (i + 1) % 250 == 0:
            elapsed = (time.perf_counter_ns() - total_wall_start) / 1e9
            print(f"[CUDA select+update] {i + 1}/{n}, elapsed={elapsed:.1f}s", flush=True)

    total_wall_ns = time.perf_counter_ns() - total_wall_start
    gpu_agent.assert_finite()
    return ({
        "backend": "CUDA/PyTorch FP64",
        "workload": "fixed_context_select_feature_update",
        "n": n,
        "warmup_calls_excluded": warmups,
        "checkpoint_step_t": step_t,
        "lin_ts_t_start": 480,
        "lin_ts_t_end": gpu_agent.t,
        "periodic_exact_inverse_count": sum(r["exact_inverse_due"] for r in records),
        "action_scoring_wall_per_call": _stats(score_wall),
        "feature_map_wall_per_call": _stats(feature_wall),
        "posterior_update_wall_per_call": _stats(update_wall),
        "full_cycle_wall_per_call": _stats(cycle_wall),
        "total_wall_ms": total_wall_ns / 1e6,
        "device": torch.cuda.get_device_name(0),
    }, records)


def main() -> int:
    ap = argparse.ArgumentParser(description="Benchmark fixed-context LinTS latency from a saved checkpoint")
    ap.add_argument(
        "--checkpoint-prefix",
        default="python/results/lints-ge-timing-2000-20260927/checkpoints/model_t500",
    )
    ap.add_argument(
        "--metrics-jsonl",
        default="python/results/lints-ge-timing-2000-20260927/bandit_metrics.json",
    )
    ap.add_argument("--iterations", type=int, default=2000)
    ap.add_argument("--warmup", type=int, default=10)
    ap.add_argument("--context-seed", type=int, default=20260927)
    ap.add_argument("--gpu-seed", type=int, default=20260927)
    ap.add_argument("--result-dir", required=True)
    args = ap.parse_args()

    n = int(args.iterations)
    warmups = int(args.warmup)
    if n <= 0 or warmups < 0:
        raise ValueError("iterations must be positive and warmup nonnegative")
    prefix = os.path.abspath(args.checkpoint_prefix)
    metrics_path = os.path.abspath(args.metrics_jsonl)
    output_dir = os.path.abspath(args.result_dir)
    if os.path.exists(output_dir):
        raise FileExistsError(f"result directory already exists: {output_dir}")
    os.makedirs(output_dir)

    initial, cfg, ctx, ctx_cfg, action_set, checkpoint_step = _load_checkpoint(prefix)
    selected, context_pool = _load_fixed_context(metrics_path, checkpoint_step, args.context_seed)
    context = np.asarray(selected["context"], dtype=np.float32)
    reward = float(selected["reward"])

    print(
        f"checkpoint_step={checkpoint_step}, checkpoint_update_count={initial.t}, "
        f"selected_context_t={selected['t']}, context={context.tolist()}, reward={reward}",
        flush=True,
    )
    print(
        f"LinTS dim={initial.dim}, actions={len(action_set)}, action_feature_dim={action_set.onehot_dim}, "
        f"context_pool={len(context_pool)} (t < {checkpoint_step})",
        flush=True,
    )

    cpu_selection = _run_cpu_selection(prefix, context, n, warmups)
    cpu_combined, cpu_rows = _run_cpu_select_update(prefix, context, reward, n, warmups)
    cuda_selection = _run_cuda_selection(prefix, context, n, warmups, args.gpu_seed)
    cuda_combined, cuda_rows = _run_cuda_select_update(
        prefix, context, reward, n, warmups, args.gpu_seed
    )

    import torch
    from threadpoolctl import threadpool_info

    result: Dict[str, Any] = {
        "benchmark": "fixed_context_checkpoint_latency",
        "iterations_per_workload": n,
        "warmup_calls_excluded": warmups,
        "checkpoint_prefix": prefix,
        "checkpoint_step_t": checkpoint_step,
        "checkpoint_agent_update_count": initial.t,
        "context_source_metrics": metrics_path,
        "context_sampling": "uniform random over recorded contexts with t < checkpoint step, reproducible seed",
        "context_seed": int(args.context_seed),
        "selected_context_t": int(selected["t"]),
        "context": [float(v) for v in context.tolist()],
        "fixed_reward_for_update_test": reward,
        "action_count": len(action_set),
        "action_feature_dim": int(action_set.onehot_dim),
        "context_dim": int(context.size),
        "lin_ts_dim": int(initial.dim),
        "lints_config": {
            "lam": float(cfg.lam),
            "sigma": float(cfg.sigma),
            "rho": float(cfg.rho),
            "recompute_inv_every": int(cfg.recompute_inv_every),
        },
        "cpu_runtime": {
            "numpy": np.__version__,
            "threadpools": threadpool_info(),
        },
        "gpu_runtime": {
            "torch": torch.__version__,
            "cuda_runtime": torch.version.cuda,
            "device": torch.cuda.get_device_name(0),
            "device_capability": list(torch.cuda.get_device_capability(0)),
            "dtype": "float64",
            "checkpoint_matrices_copied_to_device_before_timing": True,
            "cuda_synchronized_at_each_measurement_boundary": True,
        },
        "results": [cpu_selection, cpu_combined, cuda_selection, cuda_combined],
        "interpretation_note": (
            "Timing only; in the select+update workload the same historical reward is replayed for each update. "
            "This is not a policy-performance evaluation. CPU and CUDA use the same feature layout and FP64 "
            "LinTS equations, but independent random streams mean their sampled actions need not match."
        ),
    }
    with open(os.path.join(output_dir, "benchmark_summary.json"), "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
        f.write("\n")

    csv_rows: List[Dict[str, Any]] = []
    for res in (cpu_selection, cpu_combined, cuda_selection, cuda_combined):
        if res["workload"] == "fixed_context_action_only":
            wall_stats = res["wall_per_call"]
            csv_rows.append({
                "backend": res["backend"],
                "workload": res["workload"],
                "component": "action_scoring_or_full_call",
                "n": res["n"],
                "mean_ms": wall_stats["mean_ms"],
                "std_ms": wall_stats["std_ms"],
                "total_wall_s": res["total_wall_ms"] / 1000.0,
            })
        else:
            for component in (
                "action_scoring_wall_per_call",
                "feature_map_wall_per_call",
                "posterior_update_wall_per_call",
                "full_cycle_wall_per_call",
            ):
                stats = res[component]
                csv_rows.append({
                    "backend": res["backend"],
                    "workload": res["workload"],
                    "component": component.removesuffix("_wall_per_call"),
                    "n": stats["n"],
                    "mean_ms": stats["mean_ms"],
                    "std_ms": stats["std_ms"],
                    "total_wall_s": res["total_wall_ms"] / 1000.0 if component == "full_cycle_wall_per_call" else None,
                })
    with open(os.path.join(output_dir, "benchmark_summary.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=("backend", "workload", "component", "n", "mean_ms", "std_ms", "total_wall_s"),
        )
        writer.writeheader()
        writer.writerows(csv_rows)

    timing_path = os.path.join(output_dir, "per_call_timings.jsonl")
    with open(timing_path, "w", encoding="utf-8") as f:
        for row in cpu_rows + cuda_rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"wrote {os.path.join(output_dir, 'benchmark_summary.csv')}")
    print(f"wrote {os.path.join(output_dir, 'benchmark_summary.json')}")
    print(f"wrote {timing_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
