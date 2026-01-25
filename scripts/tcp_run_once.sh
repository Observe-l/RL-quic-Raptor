#!/usr/bin/env bash
set -euo pipefail

# Single trial TCP file transfer baseline using netcat.
# Reuses the same netns + tc shaping setup as quicfec_run_once.sh.

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN_DIR="$ROOT/go/bin"

NS=${NS:-qns}
PORT=${PORT:-45302}

BITRATE_MBPS=${BITRATE_MBPS:-50}
RTT_MS=${RTT_MS:-20}
LOSS_PCT=${LOSS_PCT:-0}
LOSS_MODE=${LOSS_MODE:-}
RATE="${BITRATE_MBPS}mbit"

FILE=${FILE:-"$ROOT/go/test_data/train_FD001.txt"}
OUT_DIR=${OUT_DIR:-"$ROOT/go/test_data"}

TIMEOUT_S=${TIMEOUT_S:-15}

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

# Build tcpraw binaries if missing or stale
NEED_BUILD=0
if [[ ! -x "$BIN_DIR/tcpraw-server" || ! -x "$BIN_DIR/tcpraw-client" ]]; then
  NEED_BUILD=1
else
  if find "$ROOT/go" -type f -name '*.go' -newer "$BIN_DIR/tcpraw-server" -print -quit | grep -q .; then NEED_BUILD=1; fi
  if find "$ROOT/go" -type f -name '*.go' -newer "$BIN_DIR/tcpraw-client" -print -quit | grep -q .; then NEED_BUILD=1; fi
fi
if [[ "$NEED_BUILD" == "1" ]]; then
  mkdir -p "$BIN_DIR"
  (cd "$ROOT/go" && go build -o "$BIN_DIR/tcpraw-server" ./cmd/tcpraw-server && go build -o "$BIN_DIR/tcpraw-client" ./cmd/tcpraw-client)
fi

# Configure qdiscs: same as quicfec_run_once.sh
half=$(( RTT_MS / 2 ))
sudo tc qdisc del dev veth0 root 2>/dev/null || true
NETEM_ARGS=(delay ${half}ms)
case "$LOSS_MODE" in
  none)
    NETEM_ARGS+=(loss 0%) ;;
  iid:*)
    pct=${LOSS_MODE#iid:}
    NETEM_ARGS+=(loss ${pct}%) ;;
  gemodel:*)
    params=${LOSS_MODE#gemodel:}
    IFS=',' read -r p r h k <<<"$params"
    NETEM_ARGS+=(loss gemodel ${p}% ${r}% ${k}% ${h}%) ;;
  ""|*)
    NETEM_ARGS+=(loss ${LOSS_PCT}%) ;;
esac
sudo tc qdisc replace dev veth0 root handle 1: tbf rate ${RATE} burst 32kb latency 400ms
sudo tc qdisc replace dev veth0 parent 1:1 handle 10: netem "${NETEM_ARGS[@]}"
sudo ip netns exec "$NS" tc qdisc del dev veth1 root 2>/dev/null || true
sudo ip netns exec "$NS" tc qdisc replace dev veth1 root netem delay ${half}ms

mkdir -p "$OUT_DIR"
OUT_FILE="$OUT_DIR/$(basename "$FILE").recv_tcp"
rm -f "$OUT_FILE" 2>/dev/null || true

# Start TCP receiver inside netns
SRV_LOG=$(mktemp -t tcpraw_srv.XXXXXX.log)
CLI_LOG=$(mktemp -t tcpraw_cli.XXXXXX.log)

sudo ip netns exec "$NS" bash -lc "ulimit -n 1048576; '$BIN_DIR/tcpraw-server' -addr 10.10.0.2:$PORT -out '$OUT_DIR' -timeout ${TIMEOUT_S}s" >"$SRV_LOG" 2>&1 & SP=$!
sleep 0.05

START=$(date +%s%N)
TIMED_OUT=0
if command -v timeout >/dev/null 2>&1; then
  timeout --signal=KILL ${TIMEOUT_S}s \
    "$BIN_DIR/tcpraw-client" -addr 10.10.0.2:$PORT -file "$FILE" -timeout ${TIMEOUT_S}s -measure-delay=true -packet-bytes 1200 \
    >"$CLI_LOG" 2>&1 || RC=$?
else
  "$BIN_DIR/tcpraw-client" -addr 10.10.0.2:$PORT -file "$FILE" -timeout ${TIMEOUT_S}s -measure-delay=true -packet-bytes 1200 \
    >"$CLI_LOG" 2>&1 || RC=$?
fi
RC=${RC:-0}
if [[ "$RC" == "124" || "$RC" == "137" ]]; then
  TIMED_OUT=1
fi
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

# Timeout => count as failure.
if [[ "$TIMED_OUT" == "1" ]]; then
  S_MBPS=0
  MD5_OK=0
fi

echo "[run] proto=tcp_raw bitrate=${BITRATE_MBPS}Mbps rtt=${RTT_MS}ms loss=${LOSS_PCT}% dur_ms=${DUR_MS} timed_out=${TIMED_OUT} md5_ok=${MD5_OK} s_mbps=${S_MBPS}" >&2

# Emit AoI-style average one-way delay from server output.
DELAY_LINE=$(grep -E '^\[delay\] ' "$SRV_LOG" | tail -n1 || true)
if [[ -n "$DELAY_LINE" && "$TIMED_OUT" != "1" ]]; then
  echo "$DELAY_LINE" >&2
fi
if [[ "$MD5_OK" != "1" ]]; then
  echo "[diag] md5 mismatch; server log: $SRV_LOG" >&2
  echo "[diag] client log: $CLI_LOG" >&2
  tail -n 80 "$SRV_LOG" >&2 || true
  tail -n 80 "$CLI_LOG" >&2 || true
fi
