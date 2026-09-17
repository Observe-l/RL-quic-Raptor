# GE offline best / empirical oracle

Run `run_ge_offline_oracle.py` with the local conda `ray` Python. This uses
`FecEnv`, the same action mapping and reward implementation as
`run_lints_ge_schedule.py`. No LinTS model is trained or sampled.

Defaults: all 61 senders in `GE_steady_rp`, all 2541 `(K,R0,RSTEP)` actions,
20 transfers per action, 102400-byte files, 10 Mbps, per-sender RTT,
good-state loss 0%, bad-state loss 99%. Sender order is sorted; action order
is shuffled reproducibly per sender, with 20 consecutive trials per action.
GE netem randomness is not seeded; the seed only controls action order.

Client and server timeouts are 2 seconds; connection retries are disabled
(`CONNECT_RETRIES=1`). Network setup has a separate 60-second allowance;
wrapper cleanup can extend wall time beyond the transfer timeout.

Reward settings are copied from the previous training checkpoint metadata.
Successful transfers use the existing goodput, overhead, ARQ, and 500-ms
deadline reward. Failed transfers retain reward -1 and count toward the
20 repetitions. Infrastructure errors stop the run with a traceback rather
than silently becoming network measurements.

Outputs:

- `manifest.json`: configuration, commit and source/data fingerprints.
- `trials.sqlite3`: one committed row per `(sender,action,repeat)`, including
  reward, duration, success, observations, and retained failure logs in `details`.
- `action_summary.csv`: per-action sample means, reward standard deviation,
  success rate, duration, goodput, and overhead (updated periodically).
- `oracle.json`: best mean reward among actions with all 20 repetitions;
  `complete` becomes true only after all 2541 actions of that sender finish.
- `run.log`: stdout/stderr when launched with the systemd command below.

The best is empirical: selecting and reporting on the same 20 measurements
does not give an unbiased estimate of the selected action's performance.
Use independent evaluation trials when comparing its performance to bandit.
The previous 5-second training and this 2-second sweep have different budgets.

Start from the repository root (existing directory automatically resumes):

```bash
mkdir -p python/results/ge-100kb-offline-oracle-20x-2s-20260915
systemd-run --user --unit=quicfec-oracle-20260915 \
  --working-directory="$PWD" \
  --property="StandardOutput=append:$PWD/python/results/ge-100kb-offline-oracle-20x-2s-20260915/run.log" \
  --property="StandardError=append:$PWD/python/results/ge-100kb-offline-oracle-20x-2s-20260915/run.log" \
  --setenv=OMP_NUM_THREADS=1 --setenv=OPENBLAS_NUM_THREADS=1 \
  --setenv=MKL_NUM_THREADS=1 \
  --setenv=QUIC_FEC_PRIV_HELPER=/usr/local/libexec/quicfec-net-helper \
  /home/lwh/.conda/envs/ray/bin/python -u \
  python/experiments/run_ge_offline_oracle.py \
  --result-dir python/results/ge-100kb-offline-oracle-20x-2s-20260915
```

Inspect with `systemctl --user status quicfec-oracle-20260915` and `tail -f`
on `run.log`. User services survive closing the terminal, but surviving logout
requires user lingering; automatic restart after reboot is not configured.
Repeat the launch after a stopped transient unit is removed/reset, or use a
different unit name with the same result directory. A lock prevents duplicate
writers. Resume refuses changed configuration/source fingerprints.

The sweep has 3,100,020 transfers. At two seconds of wall time per transfer,
sequential execution takes about 72 days. The 2-second timeout does not imply
every transfer takes two seconds, nor that wrapper wall time is capped at two.

Git provenance: `f0676a4` removed the DDL action and added K/R0 interaction
features; `7b60aff` changed control fields; `95b6dc6` introduced the BBRv2
implementation and helper; `a1e9901` contains the subsequent training changes.
