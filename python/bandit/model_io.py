from __future__ import annotations

import json
import os
from dataclasses import asdict
from typing import Any, Dict, Tuple

import numpy as np

from bandit.action_set import ActionSet
from bandit.context import ContextBuilder, ContextConfig
from bandit.lints import LinTS, LinTSConfig


def _rng_state_to_dict(rng: np.random.RandomState) -> Dict[str, Any]:
    # RandomState.get_state(): (str, ndarray, int, int, float)
    algo, keys, pos, has_gauss, cached_gauss = rng.get_state()
    return {
        "algo": str(algo),
        "keys": np.asarray(keys, dtype=np.uint32).tolist(),
        "pos": int(pos),
        "has_gauss": int(has_gauss),
        "cached_gauss": float(cached_gauss),
    }


def _rng_state_from_dict(d: Dict[str, Any]) -> Tuple[str, np.ndarray, int, int, float]:
    algo = str(d.get("algo", "MT19937"))
    keys = np.asarray(d.get("keys", []), dtype=np.uint32)
    pos = int(d.get("pos", 0))
    has_gauss = int(d.get("has_gauss", 0))
    cached_gauss = float(d.get("cached_gauss", 0.0))
    return (algo, keys, pos, has_gauss, cached_gauss)


def save_checkpoint(
    *,
    path_prefix: str,
    agent: LinTS,
    agent_cfg: LinTSConfig,
    ctx: ContextBuilder,
    ctx_cfg: ContextConfig,
    action_set: ActionSet,
    step_t: int,
    extra_meta: Dict[str, Any] | None = None,
) -> Tuple[str, str]:
    """Save LinTS + context + action set.

    Writes:
      - <prefix>.npz : arrays (A, b, A_inv, theta_hat)
      - <prefix>.json: metadata (configs, rng state, action discretization, context state)

    Returns: (npz_path, json_path)
    """

    prefix = os.path.abspath(path_prefix)
    npz_path = prefix + ".npz"
    json_path = prefix + ".json"

    np.savez_compressed(
        npz_path,
        A=np.asarray(agent.A, dtype=np.float64),
        b=np.asarray(agent.b, dtype=np.float64),
        A_inv=np.asarray(agent.A_inv, dtype=np.float64),
        theta_hat=np.asarray(agent.theta_hat, dtype=np.float64),
        t=np.asarray([int(agent.t)], dtype=np.int64),
        dim=np.asarray([int(agent.dim)], dtype=np.int64),
    )

    # Minimal action set reconstruction data.
    action_meta = {
        "k_values": action_set.k_values,
        "r0_values": action_set.r0_values,
        "rstep_values": action_set.rstep_values,
    }

    # ContextBuilder internal state (kept as JSON-friendly types).
    ctx_state = {
        "t": int(getattr(ctx, "_t", 0)),
        "ewma": {
            "goodput": float(getattr(ctx, "_ewma_goodput", 0.0)),
            "overhead": float(getattr(ctx, "_ewma_overhead", 0.0)),
            "retx": float(getattr(ctx, "_ewma_retx", 0.0)),
            "residual": float(getattr(ctx, "_ewma_residual", 0.0)),
        },
        "last": {
            "fec_rate": float(getattr(ctx, "_last_fec_rate", 0.0)),
        },
        "hists": {
            "residual": list(getattr(ctx, "_residual_hist", [])),
        },
        "version": 2,
    }

    meta: Dict[str, Any] = {
        "step_t": int(step_t),
        "agent_cfg": asdict(agent_cfg),
        "ctx_cfg": asdict(ctx_cfg),
        "action_set": action_meta,
        "rng_state": _rng_state_to_dict(agent.rng),
        "context_state": ctx_state,
    }
    if extra_meta:
        meta["extra"] = extra_meta

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, sort_keys=True)

    return npz_path, json_path


def load_checkpoint(
    *,
    path_prefix: str,
) -> Tuple[LinTS, LinTSConfig, ContextBuilder, ContextConfig, ActionSet, int]:
    """Load checkpoint saved by save_checkpoint()."""

    prefix = os.path.abspath(path_prefix)
    npz_path = prefix + ".npz"
    json_path = prefix + ".json"

    with open(json_path, "r", encoding="utf-8") as f:
        meta = json.load(f)

    agent_cfg = LinTSConfig(**dict(meta.get("agent_cfg", {})))
    ctx_cfg = ContextConfig(**dict(meta.get("ctx_cfg", {})))

    action_set_meta = dict(meta.get("action_set", {}))
    action_set = ActionSet(
        k_values=action_set_meta.get("k_values"),
        r0_values=action_set_meta.get("r0_values"),
        rstep_values=action_set_meta.get("rstep_values"),
    )

    arr = np.load(npz_path)
    dim = int(np.asarray(arr["dim"]).reshape(-1)[0])
    agent = LinTS(dim=dim, cfg=agent_cfg)
    agent.A = np.asarray(arr["A"], dtype=np.float64)
    agent.b = np.asarray(arr["b"], dtype=np.float64)
    agent.A_inv = np.asarray(arr["A_inv"], dtype=np.float64)
    agent.theta_hat = np.asarray(arr["theta_hat"], dtype=np.float64)
    agent.t = int(np.asarray(arr["t"]).reshape(-1)[0])

    # Restore RNG state
    rng_state = meta.get("rng_state", {})
    if isinstance(rng_state, dict):
        agent.rng.set_state(_rng_state_from_dict(rng_state))

    ctx = ContextBuilder(ctx_cfg)
    ctx_state = meta.get("context_state", {})
    if isinstance(ctx_state, dict):
        try:
            setattr(ctx, "_t", int(ctx_state.get("t", 0)))
            ewma = ctx_state.get("ewma", {}) if isinstance(ctx_state.get("ewma"), dict) else {}
            setattr(ctx, "_ewma_goodput", float(ewma.get("goodput", 0.0)))
            setattr(ctx, "_ewma_overhead", float(ewma.get("overhead", 0.0)))
            # Backward-compat: older checkpoints may store "arq" or "nack".
            # Prefer explicit "retx" (new), otherwise fall back to "arq".
            setattr(ctx, "_ewma_retx", float(ewma.get("retx", ewma.get("arq", 0.0))))
            setattr(ctx, "_ewma_residual", float(ewma.get("residual", 0.0)))
            last = ctx_state.get("last", {}) if isinstance(ctx_state.get("last"), dict) else {}
            setattr(ctx, "_last_fec_rate", float(last.get("fec_rate", 0.0)))
            hists = ctx_state.get("hists", {}) if isinstance(ctx_state.get("hists"), dict) else {}
            setattr(ctx, "_residual_hist", list(hists.get("residual", [])))
        except Exception:
            pass

    step_t = int(meta.get("step_t", 0))
    return agent, agent_cfg, ctx, ctx_cfg, action_set, step_t
