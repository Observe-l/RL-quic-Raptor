#!/usr/bin/env bash
set -euo pipefail
# FEC microbench at constant rate with CC bypass. Section 6 harness.
# Usage:
#   ./scripts/fec_bench.sh --rate 36mbit --K 40 --N 46 --payload 1200 --loss "iid:5"|"gemodel:0.5,20,80,0.1"

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN_DIR="$ROOT/go/bin"
NS=${NS:-qns}
PORT=${PORT:-45260}
RATE=${RATE:-36mbit}
K=40
N=46
L=1200
LOSS=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rate) RATE="$2"; shift 2;;
    --K) K="$2"; shift 2;;
    --N) N="$2"; shift 2;;
    --payload|--L) L="$2"; shift 2;;
    --loss) LOSS="$2"; shift 2;;
    *) echo "unknown arg: $1"; exit 2;;
  esac
done

chmod +x "$ROOT/scripts"/*.sh
"$ROOT/scripts/netns_reset.sh" "$NS"

# Build
if [[ ! -x "$BIN_DIR/quicfec-server" ]] || [[ ! -x "$BIN_DIR/quicfec-client" ]]; then
  (cd "$ROOT/go" && go build -o "$BIN_DIR/quicfec-server" ./cmd/quicfec-server && go build -o "$BIN_DIR/quicfec-client" ./cmd/quicfec-client)
fi

FILE="$ROOT/go/test_data/train_FD001.txt"

# Pacer interval for near-payload-sized datagrams at RATE.
# Approx: pps = rate(bps)/(8*L); us_per_pkt = 1e6/pps
bits=$(echo "$RATE" | sed -E 's/mbit/(1024*1024*8)/; s/kbit/(1024*8)/; s/bit//')
# Not evaluating math in sed; provide a couple presets
case "$RATE" in
  *mbit*) rate_bps=$(( ${RATE%mbit} * 1000 * 1000 ));;
  *kbit*) rate_bps=$(( ${RATE%kbit} * 1000 ));;
  *) rate_bps=${RATE%bit};;
esac
pps=$(( rate_bps / (8 * L) ))
if [[ $pps -le 0 ]]; then pps=1; fi
us_per_pkt=$(( 1000000 / pps ))

# Apply netem loss on veth0
sudo tc qdisc del dev veth0 root 2>/dev/null || true
if [[ -n "$LOSS" ]]; then
  if [[ "$LOSS" == iid:* ]]; then
    pct=${LOSS#iid:}
    sudo tc qdisc replace dev veth0 root netem loss ${pct}%
  elif [[ "$LOSS" == gemodel:* ]]; then
    params=${LOSS#gemodel:}
    IFS=',' read -r p r h k <<<"$params"
    sudo tc qdisc replace dev veth0 root netem loss gemodel ${p}% ${r}% ${h}% ${k}%
  fi
else
  sudo tc qdisc replace dev veth0 root netem loss 0%
fi

# Start server
SRV_LOG=$(mktemp)
sudo ip netns exec "$NS" bash -lc "ulimit -n 1048576; '$BIN_DIR/quicfec-server' -addr 10.10.0.2:$PORT -out '$ROOT/go/test_data' -timeout 25s" >"$SRV_LOG" 2>&1 & SP=$!
sleep 0.5

# Run client with CC bypass and pacing
CLI_LOG=$(mktemp)
export QUIC_FEC_CC_BYPASS=1
# pace per packet using --pace flag
PACING_ARG="--pace ${us_per_pkt}us"
ACK_EVERY=${ACK_EVERY:-0}
START=$(date +%s%N)
"$BIN_DIR/quicfec-client" -addr 10.10.0.2:$PORT -file "$FILE" -N "$N" -K "$K" -L "$L" -post-wait 1s -ack-every "$ACK_EVERY" -dgram-warn 1400 $PACING_ARG >"$CLI_LOG" 2>&1 || true
END=$(date +%s%N)
sleep 0.3; kill $SP 2>/dev/null || true

IN=$(md5sum "$FILE" | awk '{print $1}')
OUT=$(md5sum "$ROOT/go/test_data/$(basename "$FILE").recv" | awk '{print $1}' || true)
DUR_MS=$(( (END-START)/1000000 ))

echo "[fec-bench] cfg rate=$RATE L=$L K=$K N=$N pace_us=$us_per_pkt"
echo "[fec-bench] checksum md5_in=$IN md5_out=$OUT dur_ms=$DUR_MS"
echo "--- client log ---"; tail -n 50 "$CLI_LOG"
echo "--- server log ---"; tail -n 50 "$SRV_LOG"
