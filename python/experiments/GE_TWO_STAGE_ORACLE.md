# Two-stage GE offline search

`run_ge_two_stage_oracle.py` uses the current `ActionSet`, `FecEnv`, QUIC-FEC
harness and Go binaries. Reward configuration is copied from
`ge-100kb-bandit-model-step500-100k/bandit_model.json`; network parameters come
from each sender's `GE_steady_rp` in `quic_fec_params.json` (good-state loss 0%,
bad-state loss 99%, sender-specific RTT, 10 Mbps).

For each of 61 scenes:

1. Run all 2541 `(K, R0, RSTEP)` actions five times in shuffled sweeps.
2. Rank by mean training reward and retain 20 actions.
3. Run each finalist 20 **new** times, with a freshly configured network.
4. Select the highest final-stage mean reward; ties use the lowest action index.

The final mean excludes screening observations. Failed transfers count as -1;
infrastructure errors stop the affected worker and remain visible in its log.
This is a two-stage empirical best, not a guaranteed exhaustive oracle: noisy
five-trial screening can discard the true optimum.

Total: `61 * (2541 * 5 + 20 * 20) = 799405` transfers, each 102400 bytes.
Client and server timeouts are 2 seconds; process/setup overhead is additional
(network setup has a separate 60-second allowance).

The coordinator runs up to 21 independent worker processes and assigns the
next scene when a worker finishes. Each slot has its own namespace, veth pair,
10.231.x.0/24 subnet and netem queue. Each scene has its own logs, observation
file, received files and SQLite database. CPUs, memory and kernel resources
are still shared. BLAS and Go parallelism are limited to one thread each;
initial worker count is capped by logical CPUs and available memory.

```bash
/home/lwh/.conda/envs/ray/bin/python -u python/experiments/run_ge_two_stage_oracle.py \
  --result-dir python/results/ge-100kb-oracle-5x-top20-20x-2s-par21-20260915 \
  --workers 21
```

Run under a persistent service for unattended execution. Re-run with the same
arguments and unchanged code to resume. Every transfer is committed to SQLite;
stage/action/repeat primary keys prevent duplicate observations. Resumption
does not reproduce the kernel's random GE sequence. Configuration/source hashes
reject accidentally mixing changed experiment definitions in one directory.

Outputs:

- `manifest.json`: experiment configuration and source fingerprint.
- `oracle.json`: progress, measured throughput/ETA, per-scene best and completion.
- `action_summary.csv`: combined per-scene/action/stage statistics.
- `sender_ID/trials.sqlite3`: individual rewards, metrics and raw observations.
- `sender_ID/shortlist.json`: screening top 20.
- `sender_ID/oracle.json`: final winner when that scene is complete.
- `sender_ID/network.json` and `run.log`: isolation parameters and worker log.

Summaries refresh every 25 local trials and at stage boundaries; coordinator
refreshes every 15 seconds. Early ETA includes startup and summary lag, so allow
several minutes before using it. Do not interpret incomplete-stage rankings as
final results.
