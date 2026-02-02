#!/usr/bin/env bash
set -euo pipefail

# Single trial raw QUIC stream file transfer (no FEC/ARQ).
# Reuses the same netns + tc shaping setup as quicfec_run_once.sh.

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN_DIR="$ROOT/go/bin"

NS=${NS:-qns}
PORT=${PORT:-45301}

# Parallel-safe overrides (used by Python training to run multiple workers concurrently).
VETH_HOST=${VETH_HOST:-veth0}
VETH_NS=${VETH_NS:-veth1}
HOST_IP=${HOST_IP:-10.10.0.1/24}
NS_IP=${NS_IP:-10.10.0.2/24}
SRV_IP=${SRV_IP:-${NS_IP%%/*}}

BITRATE_MBPS=${BITRATE_MBPS:-50}
RTT_MS=${RTT_MS:-20}
LOSS_PCT=${LOSS_PCT:-0}
LOSS_MODE=${LOSS_MODE:-}
RATE="${BITRATE_MBPS}mbit"

FILE=${FILE:-"$ROOT/go/test_data/train_FD001.txt"}
OUT_DIR=${OUT_DIR:-"$ROOT/go/test_data"}

TIMEOUT_S=${TIMEOUT_S:-15}

# Training / experiment speed flags (match quicfec_run_once.sh semantics):
#   SETUP_ONLY=1         Only prepare netns/tc (and optional build), then exit 0.
#   SKIP_NETNS_RESET=1   Assume netns/veth already exist; do not recreate.
#   SKIP_TC_CONFIG=1     Assume tc qdiscs already configured; do not replace.
#   SKIP_BUILD=1         Skip go build / rebuild checks (requires existing binaries).
SETUP_ONLY=${SETUP_ONLY:-0}
SKIP_NETNS_RESET=${SKIP_NETNS_RESET:-0}
SKIP_TC_CONFIG=${SKIP_TC_CONFIG:-0}
SKIP_BUILD=${SKIP_BUILD:-0}

if ! sudo -n true 2>/dev/null; then
  echo "[error] sudo privileges are required. Run 'sudo -v' once and rerun." >&2
  exit 1
fi

chmod +x "$ROOT/scripts"/*.sh || true
mkdir -p "$ROOT/go/test_data"
if [[ ! -f "$FILE" ]]; then
  head -c $((3*1024*1024)) </dev/urandom >"$FILE"
fi

if [[ "$SKIP_NETNS_RESET" != "1" ]]; then
  VETH_HOST="$VETH_HOST" VETH_NS="$VETH_NS" HOST_IP="$HOST_IP" NS_IP="$NS_IP" "$ROOT/scripts/netns_reset.sh" "$NS"
else
  # Validate the expected topology exists.
  if ! sudo ip netns list | awk '{print $1}' | grep -qx "$NS"; then
    echo "[error] netns '$NS' not found but SKIP_NETNS_RESET=1" >&2
    exit 2
  fi
  if ! ip link show "$VETH_HOST" &>/dev/null; then
    echo "[error] host $VETH_HOST not found but SKIP_NETNS_RESET=1" >&2
    exit 2
  fi
  if ! sudo ip netns exec "$NS" ip link show "$VETH_NS" &>/dev/null; then
    echo "[error] ns $VETH_NS not found but SKIP_NETNS_RESET=1" >&2
    exit 2
  fi
fi

# Build binaries if missing or stale (can be skipped for faster repeated trials).
if [[ "$SKIP_BUILD" == "1" ]]; then
  if [[ ! -x "$BIN_DIR/quicraw-server" || ! -x "$BIN_DIR/quicraw-client" ]]; then
    echo "[error] SKIP_BUILD=1 but binaries missing in $BIN_DIR" >&2
    exit 2
  fi
else
  NEED_BUILD=0
  if [[ ! -x "$BIN_DIR/quicraw-server" || ! -x "$BIN_DIR/quicraw-client" ]]; then
    NEED_BUILD=1
  else
    if find "$ROOT/go" -type f -name '*.go' -newer "$BIN_DIR/quicraw-server" -print -quit | grep -q .; then NEED_BUILD=1; fi
    if find "$ROOT/go" -type f -name '*.go' -newer "$BIN_DIR/quicraw-client" -print -quit | grep -q .; then NEED_BUILD=1; fi
  fi
  if [[ "$NEED_BUILD" == "1" ]]; then
    mkdir -p "$BIN_DIR"
    (cd "$ROOT/go" && go build -o "$BIN_DIR/quicraw-server" ./cmd/quicraw-server && go build -o "$BIN_DIR/quicraw-client" ./cmd/quicraw-client)
  fi
fi

# Configure qdiscs: same as quicfec_run_once.sh
half=$(( RTT_MS / 2 ))
if [[ "$SKIP_TC_CONFIG" != "1" ]]; then
  sudo tc qdisc del dev "$VETH_HOST" root 2>/dev/null || true
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
      # See quicfec_run_once.sh for parameter mapping rationale.
      NETEM_ARGS+=(loss gemodel ${p}% ${r}% ${k}% ${h}%) ;;
    ""|*)
      NETEM_ARGS+=(loss ${LOSS_PCT}%) ;;
  esac
  sudo tc qdisc replace dev "$VETH_HOST" root handle 1: tbf rate ${RATE} burst 32kb latency 400ms
  sudo tc qdisc replace dev "$VETH_HOST" parent 1:1 handle 10: netem "${NETEM_ARGS[@]}"
  sudo ip netns exec "$NS" tc qdisc del dev "$VETH_NS" root 2>/dev/null || true
  sudo ip netns exec "$NS" tc qdisc replace dev "$VETH_NS" root netem delay ${half}ms
fi

if [[ "$SETUP_ONLY" == "1" ]]; then
  exit 0
fi

# Run server
SRV_LOG=$(mktemp -t quic_raw_srv.XXXXXX.log)
rm -f "$OUT_DIR/$(basename "$FILE").recv" 2>/dev/null || true
sudo ip netns exec "$NS" bash -lc "ulimit -n 1048576; '$BIN_DIR/quicraw-server' -addr ${SRV_IP}:$PORT -out '$OUT_DIR' -timeout 45s" >"$SRV_LOG" 2>&1 & SP=$!

# Wait for server UDP socket to be ready (best-effort). A fixed sleep can be flaky under load.
ready=0
if command -v ss >/dev/null 2>&1; then
  for _ in $(seq 1 30); do
    if sudo ip netns exec "$NS" ss -lunH 2>/dev/null | awk '{print $5}' | grep -q ":$PORT$"; then
      ready=1
      break
    fi
    sleep 0.02
  done
fi
if [[ "$ready" != "1" ]]; then
  sleep 0.1
fi

# Run client
CLI_LOG=$(mktemp -t quic_raw_cli.XXXXXX.log)
START=$(date +%s%N)
QUIC_FEC_CC_BYPASS=${QUIC_FEC_CC_BYPASS:-0} \
QUIC_FEC_CC_ALGO=${QUIC_FEC_CC_ALGO:-} \
TIMED_OUT=0

# Byte counters on host veth (network-layer; includes headers).
TX0=0; RX0=0
if [[ -r "/sys/class/net/${VETH_HOST}/statistics/tx_bytes" ]]; then
  TX0=$(cat "/sys/class/net/${VETH_HOST}/statistics/tx_bytes" 2>/dev/null || echo 0)
  RX0=$(cat "/sys/class/net/${VETH_HOST}/statistics/rx_bytes" 2>/dev/null || echo 0)
fi
if command -v timeout >/dev/null 2>&1; then
  timeout --signal=KILL ${TIMEOUT_S}s \
    "$BIN_DIR/quicraw-client" -addr ${SRV_IP}:$PORT -file "$FILE" -timeout ${TIMEOUT_S}s -measure-delay=true -packet-bytes 1200 \
    >"$CLI_LOG" 2>&1 || RC=$?
else
  "$BIN_DIR/quicraw-client" -addr ${SRV_IP}:$PORT -file "$FILE" -timeout ${TIMEOUT_S}s -measure-delay=true -packet-bytes 1200 \
    >"$CLI_LOG" 2>&1 || RC=$?
fi
RC=${RC:-0}
CLIENT_OK=1
if [[ "$RC" != "0" ]]; then
  CLIENT_OK=0
fi
if [[ "$RC" == "124" || "$RC" == "137" ]]; then
  TIMED_OUT=1
fi
END=$(date +%s%N)

TX1=$TX0; RX1=$RX0
if [[ -r "/sys/class/net/${VETH_HOST}/statistics/tx_bytes" ]]; then
  TX1=$(cat "/sys/class/net/${VETH_HOST}/statistics/tx_bytes" 2>/dev/null || echo "$TX0")
  RX1=$(cat "/sys/class/net/${VETH_HOST}/statistics/rx_bytes" 2>/dev/null || echo "$RX0")
fi
TX_BYTES=$(( TX1 - TX0 ))
RX_BYTES=$(( RX1 - RX0 ))
if [[ "$TX_BYTES" -lt 0 ]]; then TX_BYTES=0; fi
if [[ "$RX_BYTES" -lt 0 ]]; then RX_BYTES=0; fi

# Wait for server to finish writing (bounded).
IN_SIZE=$(stat -c%s "$FILE")
tries=0
max_tries=100  # ~10s
while [[ $tries -lt $max_tries ]]; do
  if grep -q "^\[raw-server\]" "$SRV_LOG" 2>/dev/null; then
    break
  fi
  if [[ -f "$OUT_DIR/$(basename "$FILE").recv" ]]; then
    OUT_SIZE=$(stat -c%s "$OUT_DIR/$(basename "$FILE").recv" 2>/dev/null || echo 0)
    if [[ "$OUT_SIZE" -ge "$IN_SIZE" ]]; then
      break
    fi
  fi
  sleep 0.1
  tries=$((tries+1))
done

sleep 0.05; kill $SP 2>/dev/null || true
sleep 0.05; kill -9 $SP 2>/dev/null || true

IN_MD5=$(md5sum "$FILE" | awk '{print $1}')
OUT_MD5=$(md5sum "$OUT_DIR/$(basename "$FILE").recv" | awk '{print $1}' || true)
MD5_OK=0; [[ "$IN_MD5" == "$OUT_MD5" ]] && MD5_OK=1

# Client wall duration (includes dial/open/header/send/ack; does not include md5 below).
DUR_MS_CLIENT=$(( (END-START)/1000000 ))

# Prefer server-side duration when available.
SRV_LINE=$(grep -E '^\[raw-server\] ' "$SRV_LOG" | tail -n1 || true)
DUR_MS_SERVER=$(echo "$SRV_LINE" | sed -n 's/.*dur_ms=\([0-9]\+\).*/\1/p')
if [[ -z "$DUR_MS_SERVER" ]]; then
  DUR_MS_SERVER=$DUR_MS_CLIENT
fi

FILE_SIZE=$(stat -c%s "$FILE")

# Throughput metric:
# - s_mbps: computed from dur_ms (server duration when available), so it matches dur_ms.
S_MBPS=0
if [[ "$DUR_MS_SERVER" -gt 0 ]]; then
  S_MBPS=$(awk -v sz="$FILE_SIZE" -v ms="$DUR_MS_SERVER" 'BEGIN{printf "%.3f", (sz*8.0/1000000.0)/(ms/1000.0)}')
fi

# Timeout => count as failure.
if [[ "$TIMED_OUT" == "1" ]]; then
  S_MBPS=0
  MD5_OK=0
fi

# Extract client total_ms (more detailed phase timing) when available.
STAGES_LINE=$(grep -E '^\[raw-client-stages\] ' "$CLI_LOG" | tail -n1 || true)
TOTAL_MS=$(echo "$STAGES_LINE" | sed -n 's/.*total_ms=\([0-9]\+\).*/\1/p')
if [[ -n "$TOTAL_MS" ]]; then
  DUR_MS_CLIENT=$TOTAL_MS
fi

LOSS_TAG="${LOSS_PCT}%"
if [[ -n "${LOSS_MODE}" ]]; then
  LOSS_TAG="${LOSS_MODE}"
fi

echo "[run] proto=quic_raw bitrate=${BITRATE_MBPS}Mbps rtt=${RTT_MS}ms loss=${LOSS_TAG} dur_ms=${DUR_MS_SERVER} dur_ms_client=${DUR_MS_CLIENT} timed_out=${TIMED_OUT} client_ok=${CLIENT_OK} client_rc=${RC} md5_ok=${MD5_OK} s_mbps=${S_MBPS} file_bytes=${FILE_SIZE} tx_bytes=${TX_BYTES} rx_bytes=${RX_BYTES}" >&2

# Emit AoI-style average one-way delay from server output.
DELAY_LINE=$(grep -E '^\[delay\] ' "$SRV_LOG" | tail -n1 || true)
if [[ -n "$DELAY_LINE" && "$TIMED_OUT" != "1" ]]; then
  echo "$DELAY_LINE" >&2
fi
# keep logs on failure
if [[ "$MD5_OK" != "1" ]]; then
  echo "[diag] md5 mismatch; server log: $SRV_LOG" >&2
  echo "[diag] client log: $CLI_LOG" >&2
  tail -n 80 "$SRV_LOG" >&2 || true
  tail -n 80 "$CLI_LOG" >&2 || true
fi
