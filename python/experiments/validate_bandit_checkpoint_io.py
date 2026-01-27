from __future__ import annotations

import argparse
import os
import sys
import tempfile
from dataclasses import asdict
from typing import Any, Dict, Tuple

import hashlib

import numpy as np

# Allow running as a script from repo root:
_THIS_DIR = os.path.dirname(__file__)
_PY_ROOT = os.path.abspath(os.path.join(_THIS_DIR, ".."))
if _PY_ROOT not in sys.path:
    sys.path.insert(0, _PY_ROOT)

_REPO_ROOT = os.path.abspath(os.path.join(_PY_ROOT, ".."))

from bandit.model_io import load_checkpoint, save_checkpoint  # noqa: E402


def _assert(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


def _summarize(action_set) -> Dict[str, Any]:
    ddl_vals = list(action_set.ddl_ms_values)

    return {
        "n_actions": int(len(action_set)),
        "onehot_dim": int(getattr(action_set, "onehot_dim", -1)),
        "ddl_ms_values": [int(x) for x in ddl_vals],
    }


def _check_agent_arrays(agent) -> Tuple[int, Dict[str, Any]]:
    dim = int(getattr(agent, "dim", 0))
    _assert(dim > 0, f"invalid agent.dim={dim}")

    A = np.asarray(getattr(agent, "A", None))
    b = np.asarray(getattr(agent, "b", None))
    A_inv = np.asarray(getattr(agent, "A_inv", None))
    theta_hat = np.asarray(getattr(agent, "theta_hat", None))

    _assert(A.shape == (dim, dim), f"A shape mismatch: {A.shape} vs {(dim, dim)}")
    _assert(A_inv.shape == (dim, dim), f"A_inv shape mismatch: {A_inv.shape} vs {(dim, dim)}")
    _assert(b.shape == (dim,), f"b shape mismatch: {b.shape} vs {(dim,)}")
    _assert(theta_hat.shape == (dim,), f"theta_hat shape mismatch: {theta_hat.shape} vs {(dim,)}")

    # Basic sanity
    _assert(np.all(np.isfinite(A)), "A has NaN/Inf")
    _assert(np.all(np.isfinite(A_inv)), "A_inv has NaN/Inf")
    _assert(np.all(np.isfinite(b)), "b has NaN/Inf")
    _assert(np.all(np.isfinite(theta_hat)), "theta_hat has NaN/Inf")

    # Symmetry sanity (A should stay symmetric in LinTS)
    sym_err = float(np.max(np.abs(A - A.T)))

    return dim, {"sym_err": sym_err}


def _check_dim_matches(agent, ctx, action_set) -> Dict[str, Any]:
    x0 = np.asarray(ctx.get_context()).reshape(-1)
    d = int(x0.size)
    m = int(getattr(action_set, "onehot_dim", 0))
    dim_expected = 1 + d + m + d * m
    dim_agent = int(getattr(agent, "dim", 0))
    _assert(
        dim_agent == dim_expected,
        f"feature dim mismatch: agent.dim={dim_agent} expected={dim_expected} (d={d}, m={m})",
    )
    return {"d": d, "m": m, "dim_expected": dim_expected}


def _check_actionset_indices(action_set) -> None:
    n = int(len(action_set))
    _assert(n > 0, "action_set empty")

    ddl_vals = list(action_set.ddl_ms_values)
    _assert(len(ddl_vals) > 0, "ddl_ms_values empty")

    # Spot-check a few actions (evenly spaced) for index validity.
    idxs = sorted({0, n - 1, n // 2, n // 3, (2 * n) // 3})
    for i in idxs:
        spec = action_set.get_action(int(i))
        env_action = spec.to_env_action().astype(int).reshape(-1)
        _assert(env_action.size == 4, f"env_action must have 4 dims; got {env_action}")
        k_idx, r0_idx, rstep_idx, ddl_idx = map(int, env_action.tolist())
        _assert(0 <= k_idx <= 54, f"k_idx out of range: {k_idx}")
        _assert(0 <= r0_idx <= 20, f"r0_idx out of range: {r0_idx}")
        _assert(0 <= rstep_idx <= 7, f"rstep_idx out of range: {rstep_idx}")
        _assert(0 <= ddl_idx < len(ddl_vals), f"ddl_idx out of range: {ddl_idx} (len={len(ddl_vals)})")


def _rng_fingerprint(agent) -> Dict[str, Any]:
    """Non-destructive RNG fingerprint.

    Uses RandomState.get_state() and hashes the key array so we can compare
    equality across save/load without consuming RNG samples.
    """

    rng = getattr(agent, "rng", None)
    _assert(rng is not None, "agent.rng missing")

    algo, keys, pos, has_gauss, cached_gauss = rng.get_state()
    keys_arr = np.asarray(keys, dtype=np.uint32)
    h = hashlib.sha1(keys_arr.tobytes()).hexdigest()
    return {
        "algo": str(algo),
        "pos": int(pos),
        "has_gauss": int(has_gauss),
        "cached_gauss": float(cached_gauss),
        "keys_sha1": str(h),
        "keys_len": int(keys_arr.size),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Validate LinTS bandit checkpoint save/load integrity")
    ap.add_argument(
        "--model-prefix",
        type=str,
        required=True,
        help="Checkpoint prefix (without .json/.npz), e.g. python/results/.../bandit_model",
    )
    ap.add_argument("--roundtrip", type=int, default=1, help="1: save+reload and compare; 0: load-only")
    ap.add_argument("--print-json", type=int, default=0, help="1: print a JSON-ish dict at end")
    args = ap.parse_args()

    prefix = str(args.model_prefix)
    if prefix.endswith(".json"):
        prefix = prefix[:-5]
    if prefix.endswith(".npz"):
        prefix = prefix[:-4]

    json_path = os.path.abspath(prefix) + ".json"
    npz_path = os.path.abspath(prefix) + ".npz"
    _assert(os.path.exists(json_path), f"missing {json_path}")
    _assert(os.path.exists(npz_path), f"missing {npz_path}")

    agent, agent_cfg, ctx, ctx_cfg, action_set, step_t = load_checkpoint(path_prefix=prefix)

    report: Dict[str, Any] = {
        "prefix": os.path.abspath(prefix),
        "step_t": int(step_t),
        "agent_cfg": asdict(agent_cfg),
        "ctx_cfg": asdict(ctx_cfg),
        "action_set": _summarize(action_set),
    }

    dim, agent_stats = _check_agent_arrays(agent)
    report["agent"] = {"dim": int(dim), **agent_stats}

    report["feature_dim"] = _check_dim_matches(agent, ctx, action_set)
    _check_actionset_indices(action_set)

    # RNG fingerprint on loaded model.
    fp0 = _rng_fingerprint(agent)
    report["rng_fp_loaded"] = fp0

    if int(args.roundtrip) != 0:
        tmp_dir = tempfile.mkdtemp(prefix="bandit-ckpt-io-", dir=None)
        tmp_prefix = os.path.join(tmp_dir, "roundtrip_model")
        save_checkpoint(
            path_prefix=tmp_prefix,
            agent=agent,
            agent_cfg=agent_cfg,
            ctx=ctx,
            ctx_cfg=ctx_cfg,
            action_set=action_set,
            step_t=int(step_t),
            extra_meta={"note": "roundtrip validate", "source": os.path.abspath(prefix)},
        )

        agent2, agent_cfg2, ctx2, ctx_cfg2, action_set2, step_t2 = load_checkpoint(path_prefix=tmp_prefix)
        report["roundtrip"] = {
            "tmp_prefix": tmp_prefix,
            "step_t": int(step_t2),
            "action_set": _summarize(action_set2),
        }

        # Compare configs
        _assert(asdict(agent_cfg2) == asdict(agent_cfg), "agent_cfg changed after roundtrip")
        _assert(asdict(ctx_cfg2) == asdict(ctx_cfg), "ctx_cfg changed after roundtrip")

        # Compare shapes & numeric arrays (exact equality is expected for npz save/load)
        _assert(int(getattr(agent2, "dim", 0)) == int(getattr(agent, "dim", 0)), "agent.dim changed after roundtrip")
        for name in ("A", "b", "A_inv", "theta_hat"):
            v1 = np.asarray(getattr(agent, name))
            v2 = np.asarray(getattr(agent2, name))
            _assert(v1.shape == v2.shape, f"{name} shape differs after roundtrip")
            _assert(np.array_equal(v1, v2), f"{name} differs after roundtrip")

        # Compare action set summary
        _assert(
            _summarize(action_set2) == _summarize(action_set),
            "action_set summary differs after roundtrip",
        )

        # Compare context-derived feature dim
        _check_dim_matches(agent2, ctx2, action_set2)

        # RNG state should be preserved: fingerprints must match.
        fp1 = _rng_fingerprint(agent2)
        report["rng_fp_roundtrip"] = fp1
        _assert(fp1 == fp0, "RNG fingerprint mismatch after roundtrip (rng_state not preserved)")

    print("[ok] checkpoint IO validated")
    print(f"[model] prefix={os.path.abspath(prefix)} step_t={int(step_t)}")
    print(f"[action_set] n={report['action_set']['n_actions']} ddl_ms_values={report['action_set']['ddl_ms_values']}")
    print(f"[agent] dim={report['agent']['dim']} sym_err={report['agent']['sym_err']:.3e}")

    if int(args.print_json) != 0:
        # Avoid importing json just for pretty-print; keep it simple.
        print(report)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
