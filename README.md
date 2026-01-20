# RL-QUIC-Raptor: Experiment Guide

This repo integrates a QUIC-FEC Go stack with an RLlib (IPPO) pipeline. Each RL step runs one QUIC-FEC file transfer under a shaped network namespace using Linux `tc`.

## Environment summary
- QUIC-FEC server/client (Go) with RaptorQ; server emits `[rl-observation]` JSON at run end.
- Linux netns + tc for rate/RTT/loss; supports two loss models:
  - iid:x (x%)
  - gemodel:p,r,h,k (Gilbert–Elliott in %)
- Python env `FecEnv` (Gym/Gymnasium) launches the harness and is registered in RLlib as `FECEnv-v0`.
- Files:
  - `python/fecenv_env.py` — environment + harness bridge
  - `python/fecenv_config.py` — PPO config builder
  - `python/fecenv_train.py` — training entrypoint
- Results & logs are written under `python/results/run-<timestamp>/`:
  - per-step metrics (JSONL): `step_metrics.jsonl`
  - RLlib summary for the iteration: `ray_result.json`

## RL interface (current)
The RL environment is tuned for **QUIC-FEC + BBRv2 congestion control** (CC enabled).

- Action space: 2-D continuous in [-1, 1]^2 (mapped internally)
  - `R0_pct`: initial repair ratio relative to `K` (e.g., 0.2 means `R0≈0.2*K`)
  - `ddl_ms`: receiver decode deadline (affects ARQ timing)
- Observations: derived from server `[rl-observation]` JSON, focusing on arrival goodput, overhead, residual erasures, ARQ stats, latency, and estimated bandwidth.
- Fixed knobs (by default): CC algorithm (`bbrv2`), `K`, and `symbol_bytes`. Adjust via `EnvConfig` in `python/fecenv_env.py` if needed.

## Episode design
- Default `episode_step=100` (configurable via env var `EPISODE_STEP`).
- Default per-step transfer: 1 MiB file, shaped to 50 Mbps, RTT=100 ms (override via `env_config` in `python/fecenv_env.py` / RLlib config).
- Network parameters are randomized on every `reset()` with a 40%/40%/20% mix of:
  - iid loss + RTT jitter + slow bandwidth drift
  - Gilbert–Elliott burst loss
  - Mixed events (bandwidth drops / RTT spikes)

## How to run
1) Prepare sudo (for tc/netns):
```bash
sudo -v
```

2) Train with RLlib IPPO (100-step episode by default):
```bash
cd python
# Shaped (tc) run — requires sudo (see step 1)
EPISODE_STEP=100 python3 fecenv_train.py
```

Notes:
- Each episode contains `EPISODE_STEP` QUIC-FEC transfers.
- Results live in `python/results/run-<timestamp>/` alongside `step_metrics.jsonl` and `ray_result.json`.
- Ensure `scripts/*` and Go binaries exist; the harness builds automatically if missing.

## Troubleshooting
- If permission errors, run `sudo -v` to cache credentials.
- First run after edits may rebuild binaries and take longer.
- To force rebuild: `FORCE_BUILD=1` in environment before runs.

## NS3 Simulator

```bash
sudo ./ns3 run "scratch/quic_tap_bridge_dual.cc --errorMode=random --randomLossRate=0.02 --dataRate=50Mbps --rtt=40ms --stopSeconds=100"

sudo ./ns3 run "scratch/quic_tap_bridge_dual.cc --errorMode=ge --geP=0.01 --geQ=0.1 --dataRate=50Mbps --rtt=40ms --stopSeconds=100"
```