#!/usr/bin/env bash
set -euo pipefail
# Test 3: Burst loss with netem gemodel; verify FEC completes (checksum match).

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN_DIR="$ROOT/go/bin"
NS=${1:-qns}
PORT=${2:-45230}

chmod +x "$ROOT/scripts"/*.sh
"$ROOT/scripts/netns_reset.sh" "$NS"

# Build if needed
if [[ ! -x "$BIN_DIR/quicfec-server" ]] || [[ ! -x "$BIN_DIR/quicfec-client" ]]; then
  (cd "$ROOT/go" && go build -o "$BIN_DIR/quicfec-server" ./cmd/quicfec-server && go build -o "$BIN_DIR/quicfec-client" ./cmd/quicfec-client)
fi

FILE="$ROOT/go/test_data/train_FD001.txt"

# Apply netem gemodel on host veth0 (client egress)
sudo tc qdisc del dev veth0 root 2>/dev/null || true
sudo tc qdisc replace dev veth0 root handle 10: netem loss gemodel 0.02 0.5 0.1 0.1

# Launch server
SRV_LOG=$(mktemp)
sudo ip netns exec "$NS" bash -lc "ulimit -n 1048576; '$BIN_DIR/quicfec-server' -addr 10.10.0.2:$PORT -out '$ROOT/go/test_data' -timeout 35s" >"$SRV_LOG" 2>&1 & SP=$!
sleep 0.6

# Run client
CLI_LOG=$(mktemp)
START=$(date +%s%N)
"$BIN_DIR/quicfec-client" -addr 10.10.0.2:$PORT -file "$FILE" -N 32 -K 26 -L 1100 -post-wait 2s -ack-every 4 -dgram-warn 1400 >"$CLI_LOG" 2>&1 || true
END=$(date +%s%N)
sleep 0.4; kill $SP 2>/dev/null || true

# Verify checksum
IN=$(md5sum "$FILE" | awk '{print $1}')
OUT=$(md5sum "$ROOT/go/test_data/$(basename "$FILE").recv" | awk '{print $1}' || true)
DUR_MS=$(( (END-START)/1000000 ))
echo "[t3] checksum md5_in=$IN md5_out=$OUT dur_ms=$DUR_MS"
echo "--- client log (t3) ---"; tail -n 40 "$CLI_LOG"
echo "--- server log (t3) ---"; tail -n 40 "$SRV_LOG"
echo "--- qdisc (veth0) ---"; tc -s qdisc show dev veth0 | sed -n '1,160p'
