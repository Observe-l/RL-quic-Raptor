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
  - per-step metrics (JSON): `step_metrics.json`
  - RLlib summary for the iteration: `ray_result.json`

## RL interface (current)
The RL environment is tuned for **QUIC-FEC + BBRv2 congestion control** (CC enabled).

- Action space: **MultiDiscrete(4)**
  - `K`: integer in [10, 64]
  - `R0_pct`: one of `[0, 0.1, ..., 1.0]`, and `R0 = floor(K * R0_pct)`
  - `R_step`: integer in [1, 9]
  - `ddl_ms`: integer in [300, 600] with 15ms granularity
- Observations: derived from server `[rl-observation]` JSON, focusing on arrival goodput, overhead, residual erasures, ARQ stats, and latency.
- Fixed knobs (by default): CC algorithm (`bbrv2`) and `symbol_bytes=1200`.

## Episode design
- Default `episode_step=1` (each episode is one transfer).
- Default per-step transfer: 1 MiB (generated under `/tmp`), shaped to 50 Mbps.
- Network parameters are randomized on every `reset()` with a 40%/40%/20% mix of:
  - iid loss + RTT jitter + slow bandwidth drift
  - Gilbert–Elliott burst loss
  - Mixed events (bandwidth drops / RTT spikes)

## How to run
1) Prepare sudo (for tc/netns):
```bash
sudo -v
```

2) Train with RLlib PPO (CLI arguments; env vars still supported):
```bash
cd python
# Shaped (tc) run — requires sudo (see step 1)
python3 fecenv_train.py \
  --train-episodes 200000 \
  --episode-step 1 \
  --rtt-ms 50 \
  --loss-mode iid:5 \
  --bitrate-mbps 50 \
  --train-file-bytes 1048576 \
  --timeout-sec 10 \
  --no-randomize-net-params \
  --curriculum-warmup-episodes 0 \
  --no-reward-delay-binary \
  --no-reward-residual-binary \
  --reward-w-arq 0.1
```

Notes:
- Each episode contains `episode_step` QUIC-FEC transfers (default 1).
- Results live in `python/results/run-<timestamp>/` alongside `step_metrics.json` and `ray_result.json`.
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

Command
```bash
python3 python/experiments/compare_ge_steady_rp_paper_figs.py --bandit-model-prefix python/results/bandit-ge-run-20260123-220614/best_models/block_0007/model_t7063_r0p877026 --ge-key GE_steady_rp --sender-ids all --bitrate-mbps 10 --rtt-ms 50 --reps 10 --out-dir python/results/paper-delay-rtt50-64kb --which delay --delay-file-bytes 65536

python3 python/experiments/replot_delay_cdf.py --in-dir python/results/paper-delay-rtt50 --xmax-ms 500 --out fig_delay_cdf.pdf && ls -l python/results/paper-delay-rtt50/fig_delay_cdf.pdf python/results/paper-delay-rtt50/fig_delay_cdf.png

python3 python/bandit/run_lints_ge_schedule.py --reward-w-goodput 1.0 --reward-w-overhead 0.8 --result-dir python/results/bandit-ge-rg1.0-ro0.8
```

## Plotting: paper-style “10 figures” (script version)

These scripts re-create the **10 plot types** that were previously produced by the notebook.
They load:
- Baseline CSVs: `python/results/*-baseline-data/results.csv`
- Bandit eval CSVs: `python/results/*-bandit-*/bandit_eval_results.csv` (matches both `*-bandit-data-*` and `*-bandit-date-*`)
- FLEC JSONL (schema `flec_metrics_v2`): default `python/results/flec_data/*.jsonl`

All scripts write figures to `python/results/paper10_figs/` by default.

### Shared options
- `--methods bandit,fec_k60_r0_2_rstep_2,fec_k40_r0_10_rstep_8,quic_bbrv2,flec`
  - Controls which methods appear in the plot (comma-separated).
- `--flec-e2e-offset-ms <float>`
  - Applies an offset (ms, can be negative) to FLEC E2E delay using v2 field `e2e_s_minus_plugin_time_est`.
  - Default is `0`.
- `--xmin/--xmax/--ymin/--ymax <float>`
  - Optional axis ranges for the plot. If omitted, the script keeps its default/auto limits.

#### Shared options: explicit data sources (recommended)
By default, paper10 scripts glob inputs from `python/results/`. To avoid mixing datasets, you can explicitly provide inputs:
- `--baseline-in-dir <dir>` (repeatable)
  - A baseline results directory containing `results.csv`.
- `--baseline-results-csv <path>` (repeatable)
  - A specific baseline `results.csv`.
- `--bandit-eval-results-csv <path>` (repeatable)
  - A specific `bandit_eval_results.csv`.
- `--bandit-eval-log <path>` (repeatable)
  - A specific `bandit_eval_metrics.jsonl`.
- `--only-inputs-specified`
  - If set, ignores `--baseline-glob/--bandit-glob` and loads only the explicit paths provided.

### (1) E2E delay CDF
```bash
python3 python/experiments/paper10_plot_01_delay_cdf.py \
  --scenario ge \
  --flec-e2e-offset-ms 0 \
  --out python/results/paper10_figs/01_delay_cdf.pdf
```

### (2) Overhead boxplot
```bash
python3 python/experiments/paper10_plot_02_overhead_boxplot.py \
  --scenario ge \
  --flec-e2e-offset-ms 0 \
  --out python/results/paper10_figs/02_overhead_boxplot.pdf
```

### (3) Completion ratio vs DDL
```bash
python3 python/experiments/paper10_plot_03_completion_ratio_vs_ddl.py \
  --scenario ge \
  --ddl-ms-list 200,300,400,500 \
  --flec-e2e-offset-ms 0 \
  --out python/results/paper10_figs/03_completion_ratio_vs_ddl.pdf
```

### (4) Overhead vs E2E delay scatter
```bash
python3 python/experiments/paper10_plot_04_overhead_vs_delay_scatter.py \
  --scenario ge \
  --agg sender_loss_method_mean \
  --flec-e2e-offset-ms 0 \
  --out python/results/paper10_figs/04_overhead_vs_delay_scatter.pdf
```

### (5) Delay percentile bar chart (p50/p99)
```bash
python3 python/experiments/paper10_plot_05_delay_percentiles_bar.py \
  --scenario ge \
  --pcts 50,99 \
  --flec-e2e-offset-ms 0 \
  --out python/results/paper10_figs/05_delay_percentiles_bar.pdf
```

### (6) Failure/timeout rate bar chart (timeout default 1s)
```bash
python3 python/experiments/paper10_plot_06_failure_timeout_rate_bar.py \
  --scenario ge \
  --timeout-s 1.0 \
  --flec-e2e-offset-ms 0 \
  --out python/results/paper10_figs/06_failure_timeout_rate_bar.pdf
```

### (7) GE: completion ratio by `pi_bad` bins (default DDL=350ms)
```bash
python3 python/experiments/paper10_plot_07_ge_completion_by_pibad_bins.py \
  --ge-ddl-ms 350 \
  --bins 0,3,6,10,100 \
  --bin-labels "<3%,3-6%,6-10%,>10%" \
  --flec-e2e-offset-ms 0 \
  --out python/results/paper10_figs/07_ge_completion_by_pibad_bins.pdf
```

### (8) IID: E2E delay vs loss rate boxplot
```bash
python3 python/experiments/paper10_plot_08_iid_delay_vs_loss_boxplot.py \
  --flec-e2e-offset-ms 0 \
  --out python/results/paper10_figs/08_iid_delay_vs_loss_boxplot.pdf
```

### (9) IID: overhead vs loss rate boxplot
```bash
python3 python/experiments/paper10_plot_09_iid_overhead_vs_loss_boxplot.py \
  --flec-e2e-offset-ms 0 \
  --out python/results/paper10_figs/09_iid_overhead_vs_loss_boxplot.pdf
```

### (10) Goodput vs overhead scatter
```bash
python3 python/experiments/paper10_plot_10_goodput_vs_overhead_scatter.py \
  --scenario ge \
  --agg sender_loss_method_mean \
  --flec-e2e-offset-ms 0 \
  --out python/results/paper10_figs/10_goodput_vs_overhead_scatter.pdf
```