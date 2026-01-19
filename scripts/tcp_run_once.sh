#!/usr/bin/env bash
set -euo pipefail

# Single trial TCP file transfer baseline using netcat.
# Reuses the same netns + tc shaping setup as quicfec_run_once.sh.

ROOT=$(cd "$(dirname "$0")/.." && pwd)

NS=${NS:-qns}
PORT=${PORT:-45302}

BITRATE_MBPS=${BITRATE_MBPS:-50}
RTT_MS=${RTT_MS:-20}
LOSS_PCT=${LOSS_PCT:-0}
RATE="${BITRATE_MBPS}mbit"

FILE=${FILE:-"$ROOT/go/test_data/train_FD001.txt"}
OUT_DIR=${OUT_DIR:-"$ROOT/go/test_data"}

if ! sudo -n true 2>/dev/null; then
  echo "[error] sudo privileges are required. Run 'sudo -v' once and rerun." >&2
  exit 1
fi

chmod +x "$ROOT/scripts"/*.sh || true
mkdir -p "$ROOT/go/test_data"
if [[ ! -f "$FILE" ]]; then
  head -c $((3*1024*1024)) </dev/urandom >"$FILE"
fi

"$ROOT/scripts/netns_reset.sh" "$NS"

# Configure qdiscs: same as quicfec_run_once.sh
half=$(( RTT_MS / 2 ))
sudo tc qdisc del dev veth0 root 2>/dev/null || true
NETEM_ARGS=(delay ${half}ms loss ${LOSS_PCT}%)
sudo tc qdisc replace dev veth0 root handle 1: tbf rate ${RATE} burst 32kb latency 400ms
sudo tc qdisc replace dev veth0 parent 1:1 handle 10: netem "${NETEM_ARGS[@]}"
sudo ip netns exec "$NS" tc qdisc del dev veth1 root 2>/dev/null || true
sudo ip netns exec "$NS" tc qdisc replace dev veth1 root netem delay ${half}ms

mkdir -p "$OUT_DIR"
OUT_FILE="$OUT_DIR/$(basename "$FILE").recv_tcp"
rm -f "$OUT_FILE" 2>/dev/null || true

# Start TCP receiver inside netns
SRV_LOG=$(mktemp -t tcp_srv.XXXXXX.log)
CLI_LOG=$(mktemp -t tcp_cli.XXXXXX.log)

sudo ip netns exec "$NS" bash -lc "nc -l -p $PORT > '$OUT_FILE'" >"$SRV_LOG" 2>&1 & SP=$!
sleep 0.05

START=$(date +%s%N)
# Send from host to netns
if nc -h 2>&1 | grep -q "\-N"; then
  nc -N 10.10.0.2 $PORT < "$FILE" >"$CLI_LOG" 2>&1 || true
elif nc -h 2>&1 | grep -q "\-q"; then
  nc -q 0 10.10.0.2 $PORT < "$FILE" >"$CLI_LOG" 2>&1 || true
else
  nc 10.10.0.2 $PORT < "$FILE" >"$CLI_LOG" 2>&1 || true
fi

# Wait for server to finish receiving (bounded).
IN_SIZE=$(stat -c%s "$FILE")
tries=0
max_tries=200  # ~20s
while [[ $tries -lt $max_tries ]]; do
  if ! kill -0 $SP 2>/dev/null; then
    break
  fi
  if [[ -f "$OUT_FILE" ]]; then
    OUT_SIZE=$(stat -c%s "$OUT_FILE" 2>/dev/null || echo 0)
    if [[ "$OUT_SIZE" -ge "$IN_SIZE" ]]; then
      break
    fi
  fi
  sleep 0.1
  tries=$((tries+1))
done
END=$(date +%s%N)

sleep 0.05; kill $SP 2>/dev/null || true
sleep 0.05; kill -9 $SP 2>/dev/null || true

IN_MD5=$(md5sum "$FILE" | awk '{print $1}')
OUT_MD5=$(md5sum "$OUT_FILE" | awk '{print $1}' || true)
MD5_OK=0; [[ "$IN_MD5" == "$OUT_MD5" ]] && MD5_OK=1

DUR_MS=$(( (END-START)/1000000 ))
FILE_SIZE=$(stat -c%s "$FILE")
if [[ "$DUR_MS" -gt 0 ]]; then
  S_MBPS=$(awk -v sz="$FILE_SIZE" -v ms="$DUR_MS" 'BEGIN{printf "%.3f", (sz*8.0/1000000.0)/(ms/1000.0)}')
else
  S_MBPS=0
fi

echo "[run] proto=tcp_nc bitrate=${BITRATE_MBPS}Mbps rtt=${RTT_MS}ms loss=${LOSS_PCT}% dur_ms=${DUR_MS} md5_ok=${MD5_OK} s_mbps=${S_MBPS}" >&2
if [[ "$MD5_OK" != "1" ]]; then
  echo "[diag] md5 mismatch; server log: $SRV_LOG" >&2
  echo "[diag] client log: $CLI_LOG" >&2
  tail -n 80 "$SRV_LOG" >&2 || true
  tail -n 80 "$CLI_LOG" >&2 || true
fi
