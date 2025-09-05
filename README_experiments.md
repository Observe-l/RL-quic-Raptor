# RL-QUIC-Raptor: Experiment Guide

This repo integrates a QUIC-FEC Go stack with an EPyMARL-based RL pipeline. Each RL step runs one QUIC-FEC file transfer under a shaped network namespace using Linux `tc`.

## Environment summary
- QUIC-FEC server/client (Go) with RaptorQ; server emits `[rl-observation]` JSON at run end.
- Linux netns + tc for rate/RTT/loss; supports two loss models:
  - iid:x (x%)
  - gemodel:p,r,h,k (Gilbert–Elliott in %)
- Python env `QuicFecEnv` launches the harness; wrapper `QuicFecWrapper` exposes an EPyMARL-compatible single-agent env.
- EpisodeRunner logs step metrics and raw observations into Sacred run folders; W&B can be enabled.

## Experiment design mapping
- `quicfec_wrapper` now supports 100-step episodes and scenario planning per doc:
  - A: iid loss + stable link with jitter and slow BW drift.
  - B: Gilbert–Elliott bursts.
  - C: Non-stationary events (BW drop / RTT spike windows).
- Phase control: `phase` in env_args can be `train`, `val`, or `test`. Fixed sets for val/test are implemented; training does 40%/40%/20% sampling of A/B/C.

## How to run
1) Prepare sudo (for tc/netns):
```bash
sudo -v
```

2) Train (10 steps example) with online W&B:
```bash
sudo -v
cd python
python -u src/main.py --env-config=quicfec --config=ippo_quicfec \
  with name=readme_small use_cuda=False use_tensorboard=False use_wandb=True \
  wandb_mode="online" wandb_team="hitliuweihao-national-university-of-singapore" wandb_project="quic-raptor" \
  save_model=True wandb_save_model=True \
  t_max=2 env_args.prefer_local=True env_args.episode_steps=2 env_args.phase="train"
```

3) Validate (100 steps total, 1 episode of 100 steps) on fixed sets:
```bash
sudo -v
python -u src/main.py --env-config=quicfec --config=ippo_quicfec \
  with name=ippo_full_val use_wandb=True wandb_mode="online" wandb_team="hitliuweihao-national-university-of-singapore"  wandb_project="quic-raptor" \
  t_max=100 env_args.prefer_local=False env_args.episode_steps=100 env_args.phase=\"val\"
```

4) Test:
```bash
sudo -v
python -u src/main.py --env-config=quicfec --config=ippo_quicfec \
  with name=ippo_full_test use_wandb=True wandb_mode=\"online\" wandb_team="hitliuweihao-national-university-of-singapore"  wandb_project="quic-raptor" \
  t_max=100 env_args.prefer_local=False env_args.episode_steps=100 env_args.phase=\"test\"
```

Notes:
- Each outer episode contains 100 QUIC-FEC transfers; wrapper advances the per-step scenario.
- Sacred logs are under `python/results/sacred/<exp>/<env>/<runId>`; W&B mirrors metrics if enabled.
- Ensure `scripts/netns_reset.sh` and Go binaries exist; the harness builds automatically if missing.

## Troubleshooting
- If permission errors, run `sudo -v` to cache credentials.
- First run after edits may rebuild binaries and take longer.
- To force rebuild: `FORCE_BUILD=1` in environment before runs.
