#!/usr/bin/env bash
set -euo pipefail

# Measures the gap between client-side and server-side transfer duration:
#   gap_ms = dur_ms_client - dur_ms
#
# Supports quic-fec and quic-raw. The script is modeled after verify_quicfec_md5_128k_50x.sh:
# - Generates a fresh random file every run
# - Reuses netns/tc for quic-fec runs (fast path)
# - Captures the [run] line and computes summary statistics
#
# Defaults:
#   proto = both
#   file_size = 128 KiB
#   reps = 50
#   bw = 10 Mbps
#   rtt = 50 ms
#   loss_mode = gemodel:1.905626,10.377358,0.000000,99.000000

ROOT=$(cd "$(dirname "$0")/.." && pwd)

PROTO=${PROTO:-both}           # quic_fec|quic_raw|both
REPS=${REPS:-50}
FILE_SIZE_BYTES=${FILE_SIZE_BYTES:-131072}

BITRATE_MBPS=${BITRATE_MBPS:-10}
RTT_MS=${RTT_MS:-50}
LOSS_MODE=${LOSS_MODE:-gemodel:1.905626,10.377358,0.000000,99.000000}
TIMEOUT_S=${TIMEOUT_S:-15}

RETRY_PER_RUN=${RETRY_PER_RUN:-2}
STOP_ON_FIRST_FAIL=${STOP_ON_FIRST_FAIL:-1}

# Where to write artifacts.
TS=$(date +%Y%m%d_%H%M%S)
OUT_DIR_BASE=${OUT_DIR_BASE:-/tmp/quic_gap_verify_${TS}}
mkdir -p "$OUT_DIR_BASE"
CSV="$OUT_DIR_BASE/gap_runs.csv"
LOG="$OUT_DIR_BASE/gap_runs.log"

usage() {
  cat >&2 <<EOF
Usage: $(basename "$0") [--proto quic_fec|quic_raw|both] [-n REPS] [-s BYTES]

Env vars:
  PROTO (default: both)
  REPS (default: 50)
  FILE_SIZE_BYTES (default: 131072)

  BITRATE_MBPS (default: 10)
  RTT_MS (default: 50)
  LOSS_MODE (default: gemodel:1.905626,10.377358,0.000000,99.000000)
  TIMEOUT_S (default: 15)

  RETRY_PER_RUN (default: 2)
  STOP_ON_FIRST_FAIL (default: 1)
  OUT_DIR_BASE (default: /tmp/quic_gap_verify_YYYYMMDD_HHMMSS)

Outputs:
  $OUT_DIR_BASE/gap_runs.csv
  $OUT_DIR_BASE/gap_runs.log
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --proto)
      PROTO="$2"; shift 2 ;;
    -n|--reps)
      REPS="$2"; shift 2 ;;
    -s|--size)
      FILE_SIZE_BYTES="$2"; shift 2 ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      echo "[error] unknown arg: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if ! sudo -n true 2>/dev/null; then
  echo "[error] sudo privileges are required. Run: sudo -v" >&2
  exit 2
fi

# Common send file (overwritten each run).
SEND_FILE="$OUT_DIR_BASE/send.bin"
: >"$SEND_FILE"

# CSV header
printf "%s\n" "proto,run_idx,attempt,bitrate_mbps,rtt_ms,loss_mode,file_bytes,md5_ok,client_ok,client_rc,timed_out,dur_ms,dur_ms_client,gap_ms" >"$CSV"
: >"$LOG"

do_setup_quic_fec() {
  # One-time netns/tc setup for quic-fec to reduce flakiness and speed up.
  RTT_MS="$RTT_MS" BITRATE_MBPS="$BITRATE_MBPS" LOSS_MODE="$LOSS_MODE" FILE="$SEND_FILE" OUT_DIR="$OUT_DIR_BASE/out_fec" TIMEOUT_S="$TIMEOUT_S" \
    SETUP_ONLY=1 \
    "$ROOT/scripts/quicfec_run_once.sh" >/dev/null
}

run_once_quic_fec() {
  local skip_netns="$1"
  local skip_tc="$2"
  RTT_MS="$RTT_MS" BITRATE_MBPS="$BITRATE_MBPS" LOSS_MODE="$LOSS_MODE" FILE="$SEND_FILE" OUT_DIR="$OUT_DIR_BASE/out_fec" TIMEOUT_S="$TIMEOUT_S" \
    SKIP_NETNS_RESET="$skip_netns" SKIP_TC_CONFIG="$skip_tc" \
    "$ROOT/scripts/quicfec_run_once.sh" 2>&1 || true
}

run_once_quic_raw() {
  BITRATE_MBPS="$BITRATE_MBPS" RTT_MS="$RTT_MS" LOSS_MODE="$LOSS_MODE" FILE="$SEND_FILE" OUT_DIR="$OUT_DIR_BASE/out_raw" TIMEOUT_S="$TIMEOUT_S" \
    "$ROOT/scripts/quicraw_run_once.sh" 2>&1 || true
}

emit_stats() {
  local proto="$1"
  local csv_in="$2"
  python3 - <<PY
import csv, math, sys
from pathlib import Path
proto = "$proto"
p=Path("$csv_in")
rows=[]
with p.open() as f:
  r=csv.DictReader(f)
  for row in r:
    if row.get('proto')!=proto: continue
    try:
      if row.get('md5_ok')!='1' or row.get('client_ok')!='1':
        continue
      rows.append(float(row['gap_ms']))
    except Exception:
      pass
rows.sort()
print(f"[stats] proto={proto} ok_samples={len(rows)}")
if not rows:
  sys.exit(0)

def pct(x, p):
  if not x: return math.nan
  k=(len(x)-1)*p/100.0
  f=int(math.floor(k)); c=min(f+1,len(x)-1)
  if f==c: return x[f]
  return x[f]*(c-k)+x[c]*(k-f)

mean=sum(rows)/len(rows)
print(f"[stats] gap_ms mean={mean:.3f} p50={pct(rows,50):.3f} p90={pct(rows,90):.3f} p95={pct(rows,95):.3f} min={rows[0]:.3f} max={rows[-1]:.3f}")
PY
}

case "$PROTO" in
  quic_fec|quic_raw|both)
    ;;
  *)
    echo "[error] invalid PROTO=$PROTO (expected quic_fec|quic_raw|both)" >&2
    exit 2
    ;;
esac

if [[ "$PROTO" == "quic_fec" || "$PROTO" == "both" ]]; then
  do_setup_quic_fec
fi

fails=0
for i in $(seq 1 "$REPS"); do
  head -c "$FILE_SIZE_BYTES" </dev/urandom >"$SEND_FILE"

  if [[ "$PROTO" == "quic_fec" || "$PROTO" == "both" ]]; then
    for attempt in $(seq 1 "$RETRY_PER_RUN"); do
      skip_netns=1
      skip_tc=1
      if [[ "$attempt" -eq "$RETRY_PER_RUN" && "$RETRY_PER_RUN" -gt 1 ]]; then
        skip_netns=0
        skip_tc=0
      fi
      out=$(run_once_quic_fec "$skip_netns" "$skip_tc")
      line=$(echo "$out" | grep -E '^\[run\] ' | tail -n1 || true)
      echo "[quic_fec $i/$REPS a=$attempt] $line" | tee -a "$LOG" >&2

      md5_ok=$(echo "$line" | sed -n 's/.*md5_ok=\([01]\).*/\1/p')
      client_ok=$(echo "$line" | sed -n 's/.*client_ok=\([01]\).*/\1/p')
      client_rc=$(echo "$line" | sed -n 's/.*client_rc=\([0-9]\+\).*/\1/p')
      timed_out=$(echo "$line" | sed -n 's/.*timed_out=\([01]\).*/\1/p')
      dur_ms=$(echo "$line" | sed -n 's/.*dur_ms=\([0-9]\+\).*/\1/p')
      dur_ms_client=$(echo "$line" | sed -n 's/.*dur_ms_client=\([0-9]\+\).*/\1/p')

      gap_ms=""
      if [[ -n "$dur_ms" && -n "$dur_ms_client" ]]; then
        gap_ms=$((dur_ms_client - dur_ms))
      fi

      printf "%s\n" "quic_fec,$i,$attempt,$BITRATE_MBPS,$RTT_MS,\"$LOSS_MODE\",$FILE_SIZE_BYTES,${md5_ok:-},${client_ok:-},${client_rc:-},${timed_out:-},${dur_ms:-},${dur_ms_client:-},${gap_ms:-}" >>"$CSV"

      if [[ "$md5_ok" == "1" && "$client_ok" == "1" ]]; then
        break
      fi
      if [[ "$attempt" -lt "$RETRY_PER_RUN" ]]; then
        echo "[diag] quic_fec retry i=$i attempt=$attempt/$RETRY_PER_RUN" | tee -a "$LOG" >&2
      fi
    done

    if [[ "${md5_ok:-0}" != "1" || "${client_ok:-0}" != "1" ]]; then
      fails=$((fails+1))
      if [[ "$STOP_ON_FIRST_FAIL" == "1" ]]; then
        break
      fi
    fi
  fi

  if [[ "$PROTO" == "quic_raw" || "$PROTO" == "both" ]]; then
    out=$(run_once_quic_raw)
    line=$(echo "$out" | grep -E '^\[run\] ' | tail -n1 || true)
    echo "[quic_raw $i/$REPS] $line" | tee -a "$LOG" >&2

    md5_ok=$(echo "$line" | sed -n 's/.*md5_ok=\([01]\).*/\1/p')
    client_ok=$(echo "$line" | sed -n 's/.*client_ok=\([01]\).*/\1/p')
    client_rc=$(echo "$line" | sed -n 's/.*client_rc=\([0-9]\+\).*/\1/p')
    timed_out=$(echo "$line" | sed -n 's/.*timed_out=\([01]\).*/\1/p')
    dur_ms=$(echo "$line" | sed -n 's/.*dur_ms=\([0-9]\+\).*/\1/p')
    dur_ms_client=$(echo "$line" | sed -n 's/.*dur_ms_client=\([0-9]\+\).*/\1/p')

    gap_ms=""
    if [[ -n "$dur_ms" && -n "$dur_ms_client" ]]; then
      gap_ms=$((dur_ms_client - dur_ms))
    fi

    printf "%s\n" "quic_raw,$i,1,$BITRATE_MBPS,$RTT_MS,\"$LOSS_MODE\",$FILE_SIZE_BYTES,${md5_ok:-},${client_ok:-},${client_rc:-},${timed_out:-},${dur_ms:-},${dur_ms_client:-},${gap_ms:-}" >>"$CSV"

    if [[ "${md5_ok:-0}" != "1" || "${client_ok:-0}" != "1" ]]; then
      fails=$((fails+1))
      if [[ "$STOP_ON_FIRST_FAIL" == "1" ]]; then
        break
      fi
    fi
  fi

done

if [[ "$PROTO" == "quic_fec" || "$PROTO" == "both" ]]; then
  emit_stats quic_fec "$CSV" | tee -a "$LOG" >&2
fi
if [[ "$PROTO" == "quic_raw" || "$PROTO" == "both" ]]; then
  emit_stats quic_raw "$CSV" | tee -a "$LOG" >&2
fi

echo "[done] fails=$fails csv=$CSV log=$LOG" >&2

if [[ "$fails" -ne 0 ]]; then
  exit 1
fi
