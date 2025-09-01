#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
GO_DIR="$ROOT_DIR/go"
BIN_DIR="$GO_DIR/bin"
NS=${NS:-qns}
V0=${V0:-veth0}
V1=${V1:-veth1}
HOST_IP=${HOST_IP:-10.10.0.1/24}
NS_IP=${NS_IP:-10.10.0.2/24}
NS_IP_ADDR=${NS_IP_ADDR:-10.10.0.2}

FILE_REL="go/test_data/train_FD001.txt"
FILE="$ROOT_DIR/$FILE_REL"

build() {
  mkdir -p "$BIN_DIR"
  (cd "$GO_DIR" && go build -o "$BIN_DIR/quicfec-client" ./cmd/quicfec-client && \
    go build -o "$BIN_DIR/quicfec-server" ./cmd/quicfec-server && \
    go build -tags grpcproto -o "$BIN_DIR/quicfec-grpc-server" ./cmd/quicfec-grpc-server && \
    go build -tags grpcproto -o "$BIN_DIR/quicfec-ctl" ./cmd/quicfec-ctl)
}

setup() {
  sudo "$ROOT_DIR/scripts/setup_ns.sh" "$NS" "$V0" "$V1" "$HOST_IP" "$NS_IP"
  sudo ip netns exec "$NS" bash -lc "nohup $BIN_DIR/quicfec-grpc-server >/tmp/grpc-netem.log 2>&1 & echo $! >/tmp/grpc-netem.pid"
  sleep 0.5
  sudo ip netns exec "$NS" bash -lc "nohup $BIN_DIR/quicfec-server -addr ':4242' -out $GO_DIR/test_data -rx-budget-bytes $((10*1024*1024)) -rx-ddl 50ms -rx-workers 2 >/tmp/quicfec-data.log 2>&1 & echo $! >/tmp/quicfec-data.pid"
}

cleanup() {
  sudo ip netns exec "$NS" bash -lc "kill $(cat /tmp/quicfec-data.pid 2>/dev/null) 2>/dev/null || true; kill $(cat /tmp/grpc-netem.pid 2>/dev/null) 2>/dev/null || true; rm -f /tmp/*pid"
  sudo "$ROOT_DIR/scripts/cleanup_ns.sh" "$NS" "$V0"
}

configure() {
  "$BIN_DIR/quicfec-ctl" -addr "$NS_IP_ADDR:50051" -cmd configure -dev "$V1" -egress=true -ingress=true -rtt 40 -jitter 5 -bw "$1" -loss "$2" -reorder 0
}

run_case() {
  local bw=$1 loss=$2 transport=$3
  configure "$bw" "$loss"
  local s e
  s=$(date +%s%N)
  "$BIN_DIR/quicfec-client" -addr "$NS_IP_ADDR:4242" -file "$FILE" -N 46 -K 40 -L 1200 -transport "$transport" -ack-every 1 -post-wait 1s -dgram-warn 1400
  e=$(date +%s%N)
  local size dur_ms mbps
  size=$(stat -c%s "$FILE")
  dur_ms=$(( (e - s)/1000000 ))
  mbps=$(python3 - "$size" "$dur_ms" <<'PY'
import sys
size=int(sys.argv[1]); dur_ms=int(sys.argv[2])
print(f"{(size*8/1e6)/max(dur_ms/1e3, 1e-9):.2f}")
PY
)
  echo "[case] bw=${bw}Mbps loss=${loss} transport=${transport} goodput=${mbps}Mbps"
}

trap cleanup EXIT
build
setup

run_case 50 0 dgram
run_case 50 0 stream
run_case 50 0.05 dgram
run_case 50 0.05 stream

echo "done"
