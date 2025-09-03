#!/usr/bin/env bash
set -euo pipefail
# Test 4: Combined AQM (ECN) + burst loss.
# - Apply RED ECN at the receiver side (ns veth1) with a moderate bottleneck
# - Apply netem gemodel on sender egress (host veth0)
# - Run transfer, print client ECN, checksum, and qdisc stats

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN_DIR="$ROOT/go/bin"
NS=${1:-qns}
PORT=${2:-45240}

chmod +x "$ROOT/scripts"/*.sh
"$ROOT/scripts/netns_reset.sh" "$NS"

# Build binaries if needed
if [[ ! -x "$BIN_DIR/quicfec-server" ]] || [[ ! -x "$BIN_DIR/quicfec-client" ]]; then
  (cd "$ROOT/go" && go build -o "$BIN_DIR/quicfec-server" ./cmd/quicfec-server && go build -o "$BIN_DIR/quicfec-client" ./cmd/quicfec-client)
fi

FILE="$ROOT/go/test_data/train_FD001.txt"

# AQM: RED ECN on ns veth1, 3mbit bottleneck, tuned to primarily mark, rarely drop
# Clean any existing qdisc quietly (avoid 'handle of zero' noise)
sudo ip netns exec "$NS" tc qdisc del dev veth1 root 2>/dev/null || true
sudo ip netns exec "$NS" tc qdisc replace dev veth1 root handle 1: htb default 1
sudo ip netns exec "$NS" tc class replace dev veth1 parent 1: classid 1:1 htb rate 3mbit burst 15k
sudo ip netns exec "$NS" tc qdisc replace dev veth1 parent 1:1 red limit 400000 min 5000 max 15000 avpkt 1000 burst 55 probability 0.2 ecn bandwidth 3mbit

# Burst loss: netem gemodel on host veth0 (sender egress)
sudo tc qdisc del dev veth0 root 2>/dev/null || true
sudo tc qdisc replace dev veth0 root handle 10: netem loss gemodel 0.02 0.5 0.1 0.1

# Start server inside namespace
SRV_LOG=$(mktemp)
sudo ip netns exec "$NS" bash -lc "ulimit -n 1048576; '$BIN_DIR/quicfec-server' -addr 10.10.0.2:$PORT -out '$ROOT/go/test_data' -timeout 35s" >"$SRV_LOG" 2>&1 & SP=$!
sleep 0.6

# Run client
CLI_LOG=$(mktemp)
START=$(date +%s%N)
"$BIN_DIR/quicfec-client" -addr 10.10.0.2:$PORT -file "$FILE" -N 32 -K 26 -L 1100 -post-wait 2s -ack-every 4 -dgram-warn 1400 >"$CLI_LOG" 2>&1 || true
END=$(date +%s%N)
sleep 0.4; kill $SP 2>/dev/null || true

# Compute checksum and gather ECN line
IN=$(md5sum "$FILE" | awk '{print $1}')
OUT=$(md5sum "$ROOT/go/test_data/$(basename "$FILE").recv" | awk '{print $1}' || true)
DUR_MS=$(( (END-START)/1000000 ))
ECN_LINE=$(grep -E "\[live-client\].*ecn_rx: CE=" "$CLI_LOG" | tail -n1 || true)

echo "[t4] checksum md5_in=$IN md5_out=$OUT dur_ms=$DUR_MS"
echo "[t4] client ECN: $ECN_LINE"
echo "--- qdisc (ns veth1 AQM) ---"; sudo ip netns exec "$NS" tc -s qdisc show dev veth1 | sed -n '1,160p'
echo "--- qdisc (host veth0 netem) ---"; tc -s qdisc show dev veth0 | sed -n '1,160p'
echo "--- client log (t4) ---"; tail -n 40 "$CLI_LOG"
echo "--- server log (t4) ---"; tail -n 40 "$SRV_LOG"
