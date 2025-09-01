#!/usr/bin/env bash
set -euo pipefail

# This script automates a subset of the guide's tests (T1–T3) using the
# gRPC netem control, a netns sandbox, and the QUIC-FEC client/server.
# Requirements: sudo, iproute2, tc, and Go binaries built.

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

build_bins() {
  echo "[build] Building binaries..."
  mkdir -p "$BIN_DIR"
  (cd "$GO_DIR" && \
    go build -o "$BIN_DIR/quicfec-client" ./cmd/quicfec-client && \
    go build -o "$BIN_DIR/quicfec-server" ./cmd/quicfec-server && \
    go build -tags grpcproto -o "$BIN_DIR/quicfec-grpc-server" ./cmd/quicfec-grpc-server && \
    go build -tags grpcproto -o "$BIN_DIR/quicfec-ctl" ./cmd/quicfec-ctl)
}

setup_ns() {
  echo "[ns] Setting up $NS with $V0 <-> $V1..."
  sudo "$ROOT_DIR/scripts/setup_ns.sh" "$NS" "$V0" "$V1" "$HOST_IP" "$NS_IP"
}

cleanup_ns() {
  echo "[ns] Cleaning up namespace..."
  sudo "$ROOT_DIR/scripts/cleanup_ns.sh" "$NS" "$V0"
}

start_servers() {
  echo "[srv] Starting gRPC netem server in netns..."
  sudo ip netns exec "$NS" bash -lc "\
    set -e; \
    nohup $BIN_DIR/quicfec-grpc-server > /tmp/grpc-netem.log 2>&1 & echo \$! > /tmp/grpc-netem.pid"
  sleep 0.8
  echo "[srv] Starting QUIC-FEC data server in netns (:4242)..."
  sudo ip netns exec "$NS" bash -lc "\
    set -e; \
    nohup $BIN_DIR/quicfec-server -addr ':4242' -out $GO_DIR/test_data > /tmp/quicfec-data.log 2>&1 & echo \$! > /tmp/quicfec-data.pid"
}

stop_servers() {
  echo "[srv] Stopping servers..."
  sudo ip netns exec "$NS" bash -lc "kill \
    \$(cat /tmp/quicfec-data.pid 2>/dev/null) 2>/dev/null || true; \
    kill \$(cat /tmp/grpc-netem.pid 2>/dev/null) 2>/dev/null || true; \
    rm -f /tmp/quicfec-data.pid /tmp/grpc-netem.pid"
}

configure_netem() {
  local egress=$1 ingress=$2 rtt=$3 jitter=$4 bw=$5 loss=$6 reorder=$7
  echo "[ctl] Configure netem: eg=$egress in=$ingress rtt=${rtt}/${jitter} bw=${bw}Mbps loss=${loss} reorder=${reorder}"
  "$BIN_DIR/quicfec-ctl" \
    -addr "$NS_IP_ADDR:50051" -cmd configure -dev "$V1" \
    -egress="$egress" -ingress="$ingress" -rtt "$rtt" -jitter "$jitter" -bw "$bw" -loss "$loss" -reorder "$reorder"
  sleep 0.3
}

run_client() {
  local scheme=$1 N=$2 K=$3 L=$4 lossP=$5 pace=$6 blockPause=$7 postWait=$8
  local start_ns end_ns
  start_ns=$(date +%s%N)
  "$BIN_DIR/quicfec-client" -addr "$NS_IP_ADDR:4242" -file "$FILE" -N "$N" -K "$K" -L "$L" -loss "$lossP" -pace "$pace" -block-pause "$blockPause" -post-wait "$postWait" -dgram-warn 1400
  end_ns=$(date +%s%N)
  echo "$start_ns $end_ns"
}

calc_goodput() {
  local start_ns=$1 end_ns=$2
  local size bytes_per_sec mbps dur_ms
  size=$(stat -c%s "$FILE")
  dur_ms=$(( (end_ns - start_ns)/1000000 ))
  python3 - "$size" "$dur_ms" <<'PY'
import sys
size=int(sys.argv[1]); dur_ms=int(sys.argv[2])
mbps = (size*8/1e6)/max(dur_ms/1e3, 1e-9)
print(f"{mbps:.2f}")
PY
}

verify_md5() {
  local in="$FILE" out="$GO_DIR/test_data/$(basename "$FILE").recv"
  # wait up to 3s for the server to finalize rename
  for i in {1..30}; do
    [[ -f "$out" ]] && break
    sleep 0.1
  done
  if [[ ! -f "$out" ]]; then echo "[verify] output missing: $out"; return 2; fi
  local a b; a=$(md5sum "$in" | awk '{print $1}'); b=$(md5sum "$out" | awk '{print $1}')
  if [[ "$a" != "$b" ]]; then echo "[verify] MD5 mismatch"; return 3; fi
  echo "[verify] OK"
  return 0
}

main() {
  if [[ ! -f "$FILE" ]]; then echo "Missing $FILE_REL"; exit 1; fi
  build_bins
  trap cleanup_ns EXIT
  setup_ns
  start_servers

  # T1: Ingress-only shaping (server inbound) 20 Mbps, 40±5 ms, loss=0
  configure_netem false true 40 5 20 0 0
  read s1 e1 < <(run_client raptorq 8 6 1100 0.0 100us 0 1s)
  g1=$(calc_goodput "$s1" "$e1")
  echo "[T1] goodput_mbps=$g1 (expect ~19-20)"; verify_md5 || true

  # T2: Egress+Ingress both 10 Mbps
  configure_netem true true 40 5 10 0 0
  read s2 e2 < <(run_client raptorq 8 6 1100 0.0 100us 0 1s)
  g2=$(calc_goodput "$s2" "$e2")
  echo "[T2] goodput_mbps=$g2 (expect ~9-10)"; verify_md5 || true

  # T3: Random loss 5%: compare no FEC overhead vs 15% overhead (K=40,N=46)
  configure_netem true true 40 5 50 0.05 0
  # No extra repairs (N=K=40): expect higher failure probability
  read s3a e3a < <(run_client raptorq 40 40 1100 0.0 300us 1ms 2ms)
  resA=0; verify_md5 || resA=$?
  # With ~15% overhead (K=40,N=46): expect success
  read s3b e3b < <(run_client raptorq 46 40 1100 0.0 300us 1ms 2ms)
  g3b=$(calc_goodput "$s3b" "$e3b")
  resB=0; verify_md5 || resB=$?
  echo "[T3] no-overhead result=$resA; with-overhead goodput_mbps=$g3b result=$resB (expect resB==0)"

  stop_servers
}

main "$@"
