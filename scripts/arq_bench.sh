#!/usr/bin/env bash
set -euo pipefail
# ARQ test harness (Section 9 T1–T3). Uses CC bypass, DATAGRAMs, and prints metrics.

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN_DIR="$ROOT/go/bin"
NS=${NS:-qns}
PORT=${PORT:-45300}

K=${K:-40}
R0=${R0:-6}
W=${W:-8}
RSTEP=${RSTEP:-4}
LOSS_MODE=${LOSS_MODE:-none}  # none | iid:5 | gemodel:p,r,h,k (h=GOOD loss%, k=BAD loss%)

chmod +x "$ROOT/scripts"/*.sh
"$ROOT/scripts/netns_reset.sh" "$NS"

# Always rebuild to pick up latest flags/logic
(cd "$ROOT/go" && go build -o "$BIN_DIR/quicfec-server" ./cmd/quicfec-server && go build -o "$BIN_DIR/quicfec-client" ./cmd/quicfec-client)

FILE="$ROOT/go/test_data/train_FD001.txt"

# Apply loss
sudo tc qdisc del dev veth0 root 2>/dev/null || true
case "$LOSS_MODE" in
  none) sudo tc qdisc replace dev veth0 root netem loss 0%;;
  iid:*) pct=${LOSS_MODE#iid:}; sudo tc qdisc replace dev veth0 root netem loss ${pct}%;;
  gemodel:*) params=${LOSS_MODE#gemodel:}; IFS=',' read -r p r h k <<<"$params"; sudo tc qdisc replace dev veth0 root netem loss gemodel ${p}% ${r}% ${k}% ${h}%;;
esac

REPS=${REPS:-1}
for run in $(seq 1 $REPS); do
  # Start server with DDL
  SRV_LOG=$(mktemp)
  sudo ip netns exec "$NS" bash -lc "ulimit -n 1048576; '$BIN_DIR/quicfec-server' -addr 10.10.0.2:$PORT -out '$ROOT/go/test_data' -timeout 35s" >"$SRV_LOG" 2>&1 & SP=$!
  sleep 0.4

  # Run client with ARQ and CC bypass
  CLI_LOG=$(mktemp)
  export QUIC_FEC_CC_BYPASS=1
  ACK_EVERY=${ACK_EVERY:-0}
  START=$(date +%s%N)
  "$BIN_DIR/quicfec-client" -addr 10.10.0.2:$PORT -file "$FILE" -N $((K+R0)) -K "$K" -L 1200 -post-wait 1s -ack-every "$ACK_EVERY" -dgram-warn 1400 -arq -R0 "$R0" -W "$W" -Rstep "$RSTEP" -max-attempts 5 >"$CLI_LOG" 2>&1 || true
  END=$(date +%s%N)
  sleep 0.2; kill $SP 2>/dev/null || true

  IN=$(md5sum "$FILE" | awk '{print $1}')
  OUT=$(md5sum "$ROOT/go/test_data/$(basename "$FILE").recv" | awk '{print $1}' || true)
  DUR_MS=$(( (END-START)/1000000 ))
  ARQ=$(grep -E "^\[arq-stats\]" "$CLI_LOG" | tail -n1 || true)

  echo "[arq] run=$run loss=$LOSS_MODE K=$K R0=$R0 W=$W -> dur_ms=$DUR_MS md5_in=$IN md5_out=$OUT"
  echo "[arq] $ARQ"
  echo "--- client log (tail) ---"; tail -n 25 "$CLI_LOG"
  echo "--- server log (tail) ---"; tail -n 25 "$SRV_LOG"
done
