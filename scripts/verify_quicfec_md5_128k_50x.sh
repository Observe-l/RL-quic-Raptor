#!/usr/bin/env bash
set -euo pipefail

# Verifies QUIC-FEC correctness by running repeated transfers and requiring md5_ok=1.
#
# Defaults match the requested experiment:
#   file_size = 128 KiB
#   reps = 50
#   bw = 10 Mbps
#   rtt = 50 ms
#   loss_mode = gemodel:5.15463917,78.571428571,0.000000,99.000000

ROOT=$(cd "$(dirname "$0")/.." && pwd)

REPS=${REPS:-50}
FILE_SIZE_BYTES=${FILE_SIZE_BYTES:-131072}
FILE=${FILE:-/tmp/quicfec_verify_send.bin}
OUT_DIR=${OUT_DIR:-/tmp/quicfec_out_verify}

BITRATE_MBPS=${BITRATE_MBPS:-10}
RTT_MS=${RTT_MS:-50}
LOSS_MODE=${LOSS_MODE:-gemodel:5.15463917,78.571428571,0.000000,99.000000}

TIMEOUT_S=${TIMEOUT_S:-15}
RETRY_PER_RUN=${RETRY_PER_RUN:-2}
STOP_ON_FIRST_FAIL=${STOP_ON_FIRST_FAIL:-1}

usage() {
  cat >&2 <<EOF
Usage: $(basename "$0") [-n REPS] [-s BYTES]

Env vars:
  REPS (default: 50)
  FILE_SIZE_BYTES (default: 131072)
  FILE (default: /tmp/quicfec_verify_send.bin)
  OUT_DIR (default: /tmp/quicfec_out_verify)
  BITRATE_MBPS, RTT_MS, LOSS_MODE, TIMEOUT_S
  RETRY_PER_RUN (default: 2; per-run max attempts, last attempt refreshes netns/tc)
  STOP_ON_FIRST_FAIL (default: 1)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
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

mkdir -p "$OUT_DIR"

# Create a tiny placeholder file for SETUP_ONLY so quicfec_run_once.sh doesn't auto-generate a large one.
: >"$FILE"

# One-time netns/tc setup.
RTT_MS="$RTT_MS" BITRATE_MBPS="$BITRATE_MBPS" LOSS_MODE="$LOSS_MODE" FILE="$FILE" OUT_DIR="$OUT_DIR" TIMEOUT_S="$TIMEOUT_S" \
  SETUP_ONLY=1 \
  "$ROOT/scripts/quicfec_run_once.sh" >/dev/null

fails=0
for i in $(seq 1 "$REPS"); do
  # Fresh random file each run (no pre-generated file).
  head -c "$FILE_SIZE_BYTES" </dev/urandom >"$FILE"

  out=""
  line=""
  md5_ok=""
  client_ok=""
  client_rc=""
  dur_ms=""
  for attempt in $(seq 1 "$RETRY_PER_RUN"); do
    # Fast path: reuse netns/tc.
    skip_netns=1
    skip_tc=1
    # On the last attempt, refresh netns + tc to recover from stale state.
    if [[ "$attempt" -eq "$RETRY_PER_RUN" && "$RETRY_PER_RUN" -gt 1 ]]; then
      skip_netns=0
      skip_tc=0
    fi
    out=$(RTT_MS="$RTT_MS" BITRATE_MBPS="$BITRATE_MBPS" LOSS_MODE="$LOSS_MODE" FILE="$FILE" OUT_DIR="$OUT_DIR" TIMEOUT_S="$TIMEOUT_S" \
      SKIP_NETNS_RESET="$skip_netns" SKIP_TC_CONFIG="$skip_tc" \
      "$ROOT/scripts/quicfec_run_once.sh" 2>&1 || true)
    line=$(echo "$out" | grep -E '^\[run\] ' | tail -n1 || true)
    dur_ms=$(echo "$line" | sed -n 's/.*dur_ms=\([0-9]\+\).*/\1/p')
    md5_ok=$(echo "$line" | sed -n 's/.*md5_ok=\([01]\).*/\1/p')
    client_ok=$(echo "$line" | sed -n 's/.*client_ok=\([01]\).*/\1/p')
    client_rc=$(echo "$line" | sed -n 's/.*client_rc=\([0-9]\+\).*/\1/p')
    if [[ "$md5_ok" == "1" && "$client_ok" == "1" ]]; then
      break
    fi
    if [[ "$RETRY_PER_RUN" -gt 1 ]]; then
      echo "[diag] retry i=$i attempt=$attempt/$RETRY_PER_RUN md5_ok=${md5_ok:-?} client_ok=${client_ok:-?} client_rc=${client_rc:-?}" >&2
    fi
  done
  line=$(echo "$out" | grep -E '^\[run\] ' | tail -n1 || true)
  echo "[$i/$REPS] $line" >&2

  # Keep logs for slow or failing runs by printing the captured output.
  if [[ -n "$dur_ms" && "$dur_ms" -gt 500 ]]; then
    echo "[diag] slow_run i=$i dur_ms=$dur_ms (printing full output)" >&2
    echo "$out" >&2
  fi

  if [[ "$md5_ok" != "1" || "$client_ok" != "1" ]]; then
    fails=$((fails + 1))
    fail_log="/tmp/quicfec_verify_fail_${i}.log"
    echo "[diag] fail i=$i md5_ok=${md5_ok:-?} client_ok=${client_ok:-?} client_rc=${client_rc:-?} (printing full output)" >&2
    echo "$out" >&2
    printf "%s\n" "$out" >"$fail_log" || true
    echo "[diag] saved failing output to $fail_log" >&2
    if [[ "$STOP_ON_FIRST_FAIL" == "1" ]]; then
      break
    fi
  fi
done

if [[ "$fails" -ne 0 ]]; then
  echo "[fail] md5_ok failures: $fails / $REPS" >&2
  exit 1
fi

echo "[pass] md5_ok=1 for $REPS runs (${FILE_SIZE_BYTES}B, ${BITRATE_MBPS}Mbps, ${RTT_MS}ms, ${LOSS_MODE})" >&2
