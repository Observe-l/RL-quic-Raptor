#!/usr/bin/env bash
set -euo pipefail

# Fair comparison: QUIC-FEC (BBRv2) vs raw QUIC stream (BBRv2)
# - Same netns/tc shaping, same bw+rtt, no loss.
# - Default CWND (do not set QUIC_GO_INITIAL_CWND_PKTS).
# - Runs N trials for each proto and summarizes mean/p50/p95 for s_mbps, dur_ms, overhead.

ROOT=$(cd "$(dirname "$0")/.." && pwd)

N=${N:-30}
BITRATE_MBPS=${BITRATE_MBPS:-10}
RTT_MS=${RTT_MS:-30}
LOSS_MODE=${LOSS_MODE:-none}
LOSS_PCT=${LOSS_PCT:-0}
TIMEOUT_S=${TIMEOUT_S:-20}
SRV_TIMEOUT=${SRV_TIMEOUT:-${TIMEOUT_S}s}
CLI_TIMEOUT=${CLI_TIMEOUT:-${TIMEOUT_S}s}

# QUIC-FEC params
K=${K:-8}
R0=${R0:-0}
RSTEP=${RSTEP:-2}
W=${W:-8}
SYMBOL_BYTES=${SYMBOL_BYTES:-1200}

FILE_128K=${FILE_128K:-"$ROOT/go/test_data/file_128k.bin"}
FILE_1M=${FILE_1M:-"$ROOT/go/test_data/file_1m.bin"}

OUT_DIR=${OUT_DIR:-"$ROOT/tmp_compare"}
mkdir -p "$OUT_DIR"

# Ensure files exist.
if [[ ! -f "$FILE_128K" ]]; then truncate -s 131072 "$FILE_128K"; fi
if [[ ! -f "$FILE_1M" ]]; then truncate -s 1048576 "$FILE_1M"; fi

setup_net() {
  # One-time netns/tc setup via quicfec harness.
  env -u QUIC_GO_INITIAL_CWND_PKTS -u INITIAL_CWND_PKTS -u AUTO_CWND \
    QUIC_FEC_CC_BYPASS=0 QUIC_FEC_CC_ALGO=bbrv2 \
    SETUP_ONLY=1 BITRATE_MBPS="$BITRATE_MBPS" RTT_MS="$RTT_MS" LOSS_MODE="$LOSS_MODE" LOSS_PCT="$LOSS_PCT" \
    K="$K" R0="$R0" RSTEP="$RSTEP" W="$W" SYMBOL_BYTES="$SYMBOL_BYTES" \
    "$ROOT/scripts/quicfec_run_once.sh" >/dev/null 2>&1
}

run_trials() {
  local proto=$1
  local file=$2
  local tag=$3
  local out_file="$OUT_DIR/${proto}_${tag}.runs"
  : >"$out_file"

  for i in $(seq 1 "$N"); do
    if [[ "$proto" == "quic_fec" ]]; then
      cmd_out=$(env -u QUIC_GO_INITIAL_CWND_PKTS -u INITIAL_CWND_PKTS -u AUTO_CWND \
        QUIC_FEC_CC_BYPASS=0 QUIC_FEC_CC_ALGO=bbrv2 \
        SKIP_NETNS_RESET=1 SKIP_TC_CONFIG=1 \
        BITRATE_MBPS="$BITRATE_MBPS" RTT_MS="$RTT_MS" LOSS_MODE="$LOSS_MODE" LOSS_PCT="$LOSS_PCT" \
        K="$K" R0="$R0" RSTEP="$RSTEP" W="$W" SYMBOL_BYTES="$SYMBOL_BYTES" \
        FILE="$file" TIMEOUT_S="$TIMEOUT_S" SRV_TIMEOUT="$SRV_TIMEOUT" CLI_TIMEOUT="$CLI_TIMEOUT" \
        "$ROOT/scripts/quicfec_run_once.sh" 2>&1 || true)
      line=$(echo "$cmd_out" | grep -E '^\[run\] ' | tail -n1 || true)
      adj=$(echo "$cmd_out" | grep -E '^\[run-adj\] ' | tail -n1 || true)
    else
      cmd_out=$(env -u QUIC_GO_INITIAL_CWND_PKTS -u INITIAL_CWND_PKTS -u AUTO_CWND \
        QUIC_FEC_CC_BYPASS=0 QUIC_FEC_CC_ALGO=bbrv2 \
        SKIP_NETNS_RESET=1 SKIP_TC_CONFIG=1 \
        BITRATE_MBPS="$BITRATE_MBPS" RTT_MS="$RTT_MS" LOSS_MODE="$LOSS_MODE" LOSS_PCT="$LOSS_PCT" \
        FILE="$file" TIMEOUT_S="$TIMEOUT_S" \
        "$ROOT/scripts/quicraw_run_once.sh" 2>&1 || true)
      line=$(echo "$cmd_out" | grep -E '^\[run\] ' | tail -n1 || true)
      adj=$(echo "$cmd_out" | grep -E '^\[run-adj\] ' | tail -n1 || true)
    fi

    if [[ -z "$line" ]]; then
      echo "[warn] missing [run] line (proto=$proto trial=$i)" >&2
      continue
    fi
    echo "$line" >>"$out_file"
    if [[ -n "${adj:-}" ]]; then
      echo "$adj" >>"$out_file"
    fi
  done

  echo "$out_file"
}

summarize() {
  python3 - <<'PY'
import os, re, math

def parse_runs(path):
  rows = []
  with open(path, 'r', encoding='utf-8', errors='ignore') as f:
    last_row = None
    for line in f:
      line=line.strip()
      if line.startswith('[run-adj] '):
        kv = {}
        for part in line.split()[1:]:
          if '=' not in part:
            continue
          k,v = part.split('=',1)
          kv[k]=v
        def fnum(x):
          try:
            return float(x)
          except Exception:
            return None
        adj = {
          'overhead_adj': fnum(kv.get('overhead_adj','')),
          'tx_bytes_adj': fnum(kv.get('tx_bytes_adj','')),
          'drop_pkts': fnum(kv.get('drop_pkts','')),
        }
        if last_row is not None and adj.get('overhead_adj') is not None:
          last_row['overhead_adj'] = adj.get('overhead_adj')
        continue

      if not line.startswith('[run] '):
        continue
      kv = {}
      for part in line.split()[1:]:
        if '=' not in part:
          continue
        k,v = part.split('=',1)
        kv[k]=v
      # coerce
      def fnum(x):
        try:
          return float(x)
        except Exception:
          return None
      dur = fnum(kv.get('dur_ms',''))
      mbps = fnum(kv.get('s_mbps',''))
      fb = fnum(kv.get('file_bytes',''))
      tx = fnum(kv.get('tx_bytes',''))
      overhead_run = fnum(kv.get('overhead',''))
      overhead_sys_run = fnum(kv.get('overhead_sys',''))
      drop_pkts_run = fnum(kv.get('drop_pkts',''))
      tx_source_syms = fnum(kv.get('tx_source_symbols',''))
      tx_repairs = fnum(kv.get('tx_repairs',''))
      sym_over = fnum(kv.get('sym_overhead',''))
      fec_ovh = fnum(kv.get('fec_ovh',''))
      overhead = None
      # Prefer protocol-emitted overhead (drop-aware, adjusted).
      if overhead_run is not None:
        overhead = overhead_run
      elif fb and tx is not None and fb>0:
        overhead = (tx - fb)/fb
      row = {
        'dur_ms': dur,
        's_mbps': mbps,
        'overhead': overhead,
        'overhead_sys': overhead_sys_run,
        'drop_pkts': drop_pkts_run,
        'tx_source_symbols': tx_source_syms,
        'tx_repairs': tx_repairs,
        'overhead_adj': None,
        'sym_overhead': sym_over,
        'fec_ovh': fec_ovh,
        'md5_ok': kv.get('md5_ok',''),
        'client_ok': kv.get('client_ok',''),
        'timed_out': kv.get('timed_out',''),
      }
      rows.append(row)
      last_row = row
  return rows

def pct(values, p):
  vs = sorted([v for v in values if v is not None and not math.isnan(v)])
  if not vs:
    return None
  if len(vs)==1:
    return vs[0]
  k = (len(vs)-1)*p
  i = int(math.floor(k))
  j = int(math.ceil(k))
  if i==j:
    return vs[i]
  return vs[i]*(j-k) + vs[j]*(k-i)

def mean(values):
  vs = [v for v in values if v is not None and not math.isnan(v)]
  return sum(vs)/len(vs) if vs else None

def fmt(x, nd=3):
  if x is None:
    return 'NA'
  return f'{x:.{nd}f}'

paths = os.environ.get('RUN_PATHS','').split()
for path in paths:
  rows = parse_runs(path)
  ok = [r for r in rows if r['md5_ok']=='1' and r['client_ok']=='1' and r['timed_out']=='0']
  n = len(rows)
  nok = len(ok)
  durs = [r['dur_ms'] for r in ok]
  mbps = [r['s_mbps'] for r in ok]
  ovh = [r['overhead'] for r in ok]
  ovh_adj = [r['overhead_adj'] for r in ok]
  ovh_sys = [r.get('overhead_sys') for r in ok]
  drop_pkts = [r.get('drop_pkts') for r in ok]
  tx_source_syms = [r.get('tx_source_symbols') for r in ok]
  tx_repairs = [r.get('tx_repairs') for r in ok]
  sym = [r['sym_overhead'] for r in ok]
  fec = [r['fec_ovh'] for r in ok]

  print(f'== {os.path.basename(path)} ==')
  print(f'trials={n} ok={nok}')
  print('dur_ms   mean=%s p50=%s p95=%s' % (fmt(mean(durs),1), fmt(pct(durs,0.5),1), fmt(pct(durs,0.95),1)))
  print('s_mbps   mean=%s p50=%s p95=%s' % (fmt(mean(mbps),2), fmt(pct(mbps,0.5),2), fmt(pct(mbps,0.95),2)))
  print('overhead mean=%s p50=%s p95=%s' % (fmt(mean(ovh),3), fmt(pct(ovh,0.5),3), fmt(pct(ovh,0.95),3)))
  if any(v is not None for v in ovh_sys):
    print('ovh_sys  mean=%s p50=%s p95=%s' % (fmt(mean(ovh_sys),3), fmt(pct(ovh_sys,0.5),3), fmt(pct(ovh_sys,0.95),3)))
  if any(v is not None for v in ovh_adj):
    print('ovh_adj  mean=%s p50=%s p95=%s' % (fmt(mean(ovh_adj),3), fmt(pct(ovh_adj,0.5),3), fmt(pct(ovh_adj,0.95),3)))
  if any(v is not None for v in drop_pkts):
    print('drop_pkts mean=%s p50=%s p95=%s' % (fmt(mean(drop_pkts),1), fmt(pct(drop_pkts,0.5),1), fmt(pct(drop_pkts,0.95),1)))
  if any(v is not None for v in tx_source_syms):
    print('tx_src   mean=%s p50=%s p95=%s' % (fmt(mean(tx_source_syms),1), fmt(pct(tx_source_syms,0.5),1), fmt(pct(tx_source_syms,0.95),1)))
  if any(v is not None for v in tx_repairs):
    print('tx_rep   mean=%s p50=%s p95=%s' % (fmt(mean(tx_repairs),1), fmt(pct(tx_repairs,0.5),1), fmt(pct(tx_repairs,0.95),1)))
  if any(v is not None for v in sym):
    print('sym_ovh  mean=%s p50=%s p95=%s' % (fmt(mean(sym),3), fmt(pct(sym,0.5),3), fmt(pct(sym,0.95),3)))
  if any(v is not None for v in fec):
    print('fec_ovh  mean=%s p50=%s p95=%s' % (fmt(mean(fec),3), fmt(pct(fec,0.5),3), fmt(pct(fec,0.95),3)))
  print('')
PY
}

setup_net

paths=()
paths+=("$(run_trials quic_fec "$FILE_128K" 128k)")
paths+=("$(run_trials quic_raw "$FILE_128K" 128k)")
paths+=("$(run_trials quic_fec "$FILE_1M" 1m)")
paths+=("$(run_trials quic_raw "$FILE_1M" 1m)")

RUN_PATHS="${paths[*]}" summarize
