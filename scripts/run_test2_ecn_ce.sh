#!/usr/bin/env bash
set -euo pipefail
# Test 2: Make client App ECN RX CE > 0 with minimal drops.
# It tries RED ECN at low rate first; if CE==0, falls back to iptables CE marking.

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN_DIR="$ROOT/go/bin"
NS=${1:-qns}
PORT=${2:-45220}

chmod +x "$ROOT/scripts"/*.sh
"$ROOT/scripts/netns_reset.sh" "$NS"

# Build binaries if missing
if [[ ! -x "$BIN_DIR/quicfec-server" ]] || [[ ! -x "$BIN_DIR/quicfec-client" ]]; then
  (cd "$ROOT/go" && go build -o "$BIN_DIR/quicfec-server" ./cmd/quicfec-server && go build -o "$BIN_DIR/quicfec-client" ./cmd/quicfec-client)
fi

FILE="$ROOT/go/test_data/train_FD001.txt"

# First attempt: RED ECN on server egress (veth1) at low rate
sudo ip netns exec "$NS" tc qdisc del dev veth1 root 2>/dev/null || true
sudo ip netns exec "$NS" tc qdisc replace dev veth1 root handle 1: htb default 1
sudo ip netns exec "$NS" tc class replace dev veth1 parent 1: classid 1:1 htb rate 300kbit burst 10k
sudo ip netns exec "$NS" tc qdisc replace dev veth1 parent 1:1 red limit 40000 min 800 max 2400 avpkt 200 burst 10 probability 0.4 ecn bandwidth 300kbit

# Launch server
SRV_LOG=$(mktemp)
sudo ip netns exec "$NS" bash -lc "ulimit -n 1048576; '$BIN_DIR/quicfec-server' -addr 10.10.0.2:$PORT -out '$ROOT/go/test_data' -timeout 25s" >"$SRV_LOG" 2>&1 & SP=$!
sleep 0.6

# Run client (ack-every=1 to elicit frequent return packets)
CLI_LOG=$(mktemp)
"$BIN_DIR/quicfec-client" -addr 10.10.0.2:$PORT -file "$FILE" -N 32 -K 26 -L 1100 -post-wait 1s -ack-every 1 -dgram-warn 1400 >"$CLI_LOG" 2>&1 || true
sleep 0.3; kill $SP 2>/dev/null || true

CE=$(grep -E "\[live-client\].*ecn_rx: CE=" "$CLI_LOG" | tail -n1 | sed -E 's/.*CE=([0-9]+).*/\1/g' || echo 0)
DROP=$(sudo ip netns exec "$NS" tc -s qdisc show dev veth1 | awk '/qdisc red/ {d=0} /dropped/ {print $3; exit}')
echo "[t2] attempt-RED: CE=$CE qdisc_drop=${DROP:-0}"

if [[ "${CE:-0}" -le 0 ]]; then
  echo "[t2] CE still 0, applying iptables CE marking as fallback"
  # Reset ns and apply CE mark on server egress
  "$ROOT/scripts/netns_reset.sh" "$NS"
  sudo ip netns exec "$NS" iptables -t mangle -F || true
  sudo ip netns exec "$NS" iptables -t mangle -A POSTROUTING -o veth1 -p udp -j TOS --set-tos 0x03
  SRV_LOG2=$(mktemp)
  sudo ip netns exec "$NS" bash -lc "ulimit -n 1048576; '$BIN_DIR/quicfec-server' -addr 10.10.0.2:$PORT -out '$ROOT/go/test_data' -timeout 25s" >"$SRV_LOG2" 2>&1 & SP=$!
  sleep 0.5
  CLI_LOG2=$(mktemp)
  "$BIN_DIR/quicfec-client" -addr 10.10.0.2:$PORT -file "$FILE" -N 32 -K 26 -L 1100 -post-wait 1s -ack-every 1 -dgram-warn 1400 >"$CLI_LOG2" 2>&1 || true
  sleep 0.3; kill $SP 2>/dev/null || true
  CE=$(grep -E "\[live-client\].*ecn_rx: CE=" "$CLI_LOG2" | tail -n1 | sed -E 's/.*CE=([0-9]+).*/\1/g' || echo 0)
  echo "[t2] fallback-iptables: CE=$CE"
  echo "--- client log (t2-fallback) ---"; tail -n 40 "$CLI_LOG2"
  echo "--- server log (t2-fallback) ---"; tail -n 40 "$SRV_LOG2"
else
  echo "--- client log (t2) ---"; tail -n 40 "$CLI_LOG"
  echo "--- qdisc (ns veth1) ---"; sudo ip netns exec "$NS" tc -s qdisc show dev veth1 | sed -n '1,160p'
fi
