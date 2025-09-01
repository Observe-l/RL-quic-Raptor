#!/usr/bin/env bash
set -euo pipefail

# Deterministic 5% loss verification using tc netem in a netns sandbox.
# Runs multiple trials on train_FD001.txt with RaptorQ and verifies MD5 each time.

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
GO_DIR="$ROOT_DIR/go"
BIN_DIR="$GO_DIR/bin"

NS=${NS:-qns}
V0=${V0:-veth0}
V1=${V1:-veth1}
HOST_IP=${HOST_IP:-10.10.0.1/24}
NS_IP=${NS_IP:-10.10.0.2/24}
NS_IP_ADDR=${NS_IP_ADDR:-10.10.0.2}

TRIALS=${TRIALS:-20}
N=${N:-46}
K=${K:-40}
L=${L:-1100}
PACE=${PACE:-20us}
BLK_PAUSE=${BLK_PAUSE:-0ms}
POST_WAIT=${POST_WAIT:-0s}

FILE_REL="go/test_data/train_FD001.txt"
FILE="$ROOT_DIR/$FILE_REL"
if [[ ! -f "$FILE" ]]; then echo "missing $FILE_REL"; exit 1; fi

echo "[build] binaries"
mkdir -p "$BIN_DIR"
(cd "$GO_DIR" && \
  go build -o "$BIN_DIR/quicfec-client" ./cmd/quicfec-client && \
  go build -o "$BIN_DIR/quicfec-server" ./cmd/quicfec-server && \
  go build -tags grpcproto -o "$BIN_DIR/quicfec-grpc-server" ./cmd/quicfec-grpc-server && \
  go build -tags grpcproto -o "$BIN_DIR/quicfec-ctl" ./cmd/quicfec-ctl)

echo "[ns] setup $NS"
"$ROOT_DIR/scripts/setup_ns.sh" "$NS" "$V0" "$V1" "$HOST_IP" "$NS_IP"
trap '"$ROOT_DIR/scripts/cleanup_ns.sh" "$NS" "$V0"' EXIT

echo "[srv] start servers in netns"
sudo ip netns exec "$NS" bash -lc "nohup '$BIN_DIR/quicfec-grpc-server' >/tmp/grpc.log 2>&1 & echo \$! > /tmp/grpc.pid"
sleep 0.3
# Use a short idle timeout so the server decodes and finalizes promptly for each run.
sudo ip netns exec "$NS" bash -lc "nohup '$BIN_DIR/quicfec-server' -addr ':4242' -out '$GO_DIR/test_data' -timeout 2s >/tmp/data.log 2>&1 & echo \$! > /tmp/data.pid"
sleep 0.2

LOSS=${LOSS:-0.05}
echo "[tc] apply loss=${LOSS} (fraction) on ingress of $V1 (client->server)"
"$BIN_DIR/quicfec-ctl" -addr "$NS_IP_ADDR:50051" -cmd configure -dev "$V1" -egress=false -ingress=true -rtt 40 -jitter 5 -bw 0 -loss "$LOSS" -reorder 0

PASS=0; FAIL=0
SRC_MD5=$(md5sum "$FILE" | awk '{print $1}')
for i in $(seq 1 "$TRIALS"); do
  echo "[run] $i/$TRIALS"
  rm -f "$GO_DIR/test_data/$(basename "$FILE").recv"
  start_ns=$(date +%s%N)
  "$BIN_DIR/quicfec-client" -addr "$NS_IP_ADDR:4242" -file "$FILE" -scheme raptorq -N "$N" -K "$K" -L "$L" -loss 0.0 -pace "$PACE" -block-pause "$BLK_PAUSE" -post-wait "$POST_WAIT" -dgram-warn 1400 || true
  end_ns=$(date +%s%N)
  OUT="$GO_DIR/test_data/$(basename "$FILE").recv"
  # Wait briefly for server to finalize (depends on its -timeout idle decode)
  WAIT_MS=${WAIT_MS:-1200}
  waited=0
  while [[ ! -f "$OUT" && $waited -lt $WAIT_MS ]]; do
    sleep 0.05
    waited=$((waited+50))
  done
  if [[ ! -f "$OUT" ]]; then
    echo "[fail] missing output"
    echo "--- server logs (data.log last 80) ---"
    sudo ip netns exec "$NS" bash -lc 'tail -n 80 /tmp/data.log || true'
    echo "--- grpc logs (grpc.log last 40) ---"
    sudo ip netns exec "$NS" bash -lc 'tail -n 40 /tmp/grpc.log || true'
    FAIL=$((FAIL+1)); continue
  fi
  RCV_MD5=$(md5sum "$OUT" | awk '{print $1}')
  if [[ "$SRC_MD5" == "$RCV_MD5" ]]; then
    PASS=$((PASS+1))
  else
    echo "[diff] md5 mismatch"
    echo "[stat]"; stat -c '%n %s' "$FILE" "$OUT"
    echo "[cmp] first difference:"; cmp -l "$FILE" "$OUT" | head || true
    echo "[tail] last 4KiB (orig)"; tail -c 4096 "$FILE" | xxd | head
    echo "[tail] last 4KiB (recv)"; tail -c 4096 "$OUT" | xxd | head
    FAIL=$((FAIL+1))
  fi
done

echo "RESULT: PASS=$PASS FAIL=$FAIL (trials=$TRIALS, N=$N K=$K L=$L)"
test "$FAIL" -eq 0
