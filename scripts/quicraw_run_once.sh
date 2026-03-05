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

# Connection establishment guard:
# - CONNECT_TIMEOUT_S bounds dialing + QUIC handshake (client-side).
# - CONNECT_RETRIES controls how many times we retry on dial/handshake failures.
CONNECT_TIMEOUT_S=${CONNECT_TIMEOUT_S:-2}
CONNECT_RETRIES=${CONNECT_RETRIES:-5}

# Training / experiment speed flags (match quicfec_run_once.sh semantics):
#   SETUP_ONLY=1         Only prepare netns/tc (and optional build), then exit 0.
#   SKIP_NETNS_RESET=1   Assume netns/veth already exist; do not recreate.
#   SKIP_TC_CONFIG=1     Assume tc qdiscs already configured; do not replace.
#   SKIP_BUILD=1         Skip go build / rebuild checks (requires existing binaries).
SETUP_ONLY=${SETUP_ONLY:-0}
SKIP_NETNS_RESET=${SKIP_NETNS_RESET:-0}
SKIP_TC_CONFIG=${SKIP_TC_CONFIG:-0}
SKIP_BUILD=${SKIP_BUILD:-0}

T_SCRIPT_START=$(date +%s%N)

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
T_TC_START=$(date +%s%N)
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
T_TC_END=$(date +%s%N)

if [[ "$SETUP_ONLY" == "1" ]]; then
  exit 0
fi

# Run server
SRV_LOG=$(mktemp -t quic_raw_srv.XXXXXX.log)
rm -f "$OUT_DIR/$(basename "$FILE").recv" 2>/dev/null || true
T_SRV_START=$(date +%s%N)
sudo ip netns exec "$NS" bash -lc "ulimit -n 1048576; '$BIN_DIR/quicraw-server' -addr ${SRV_IP}:$PORT -out '$OUT_DIR' -timeout 45s" >"$SRV_LOG" 2>&1 & SP=$!

# Wait for server UDP socket to be ready (best-effort). A fixed sleep can be flaky under load.
ready=0
if command -v ss >/dev/null 2>&1; then
  # Keep this fast: client already has dial/handshake retries.
  if sudo ip netns exec "$NS" bash -lc "for _ in \$(seq 1 8); do if ss -lunH 2>/dev/null | awk '{print \$5}' | grep -q ':$PORT$'; then exit 0; fi; sleep 0.01; done; exit 1"; then
    ready=1
  fi
fi
if [[ "$ready" != "1" ]]; then
  sleep 0.05
fi
T_SRV_READY=$(date +%s%N)

# Run client
CLI_LOG=$(mktemp -t quic_raw_cli.XXXXXX.log)
START=$(date +%s%N)

# Congestion control selection (kept consistent with quicfec_run_once.sh):
# These env vars are consumed by the Go binaries.
export QUIC_FEC_CC_BYPASS=${QUIC_FEC_CC_BYPASS:-0}
export QUIC_FEC_CC_ALGO=${QUIC_FEC_CC_ALGO:-bbrv2}

# Optional QUIC-layer stats (disabled by default to avoid affecting performance).
# When enabled, quicraw-client prints one line: [raw-client-quic-stats] key=value...
RAW_STATS=${RAW_STATS:-0}
if [[ "$RAW_STATS" == "1" ]]; then
  export QUIC_RAW_STATS=1
fi

TIMED_OUT=0
CONNECT_ATTEMPTS=0

# Byte counters on host veth (network-layer; includes headers).
TX0=0; RX0=0
if [[ -r "/sys/class/net/${VETH_HOST}/statistics/tx_bytes" ]]; then
  TX0=$(cat "/sys/class/net/${VETH_HOST}/statistics/tx_bytes" 2>/dev/null || echo 0)
  RX0=$(cat "/sys/class/net/${VETH_HOST}/statistics/rx_bytes" 2>/dev/null || echo 0)
fi
while true; do
  CONNECT_ATTEMPTS=$((CONNECT_ATTEMPTS + 1))
  : >"$CLI_LOG" || true
  unset RC || true

  if command -v timeout >/dev/null 2>&1; then
    timeout --signal=KILL ${TIMEOUT_S}s \
      "$BIN_DIR/quicraw-client" -addr ${SRV_IP}:$PORT -file "$FILE" -timeout ${TIMEOUT_S}s -connect-timeout ${CONNECT_TIMEOUT_S}s -measure-delay=true -packet-bytes 1200 \
      >"$CLI_LOG" 2>&1 || RC=$?
  else
    "$BIN_DIR/quicraw-client" -addr ${SRV_IP}:$PORT -file "$FILE" -timeout ${TIMEOUT_S}s -connect-timeout ${CONNECT_TIMEOUT_S}s -measure-delay=true -packet-bytes 1200 \
      >"$CLI_LOG" 2>&1 || RC=$?
  fi
  RC=${RC:-0}

  # If dialing / handshake failed, retry a few times instead of counting this as a rep.
  if [[ "$RC" != "0" ]]; then
    if grep -qE "^dial timeout:|^dial error:" "$CLI_LOG" 2>/dev/null; then
      if [[ "$CONNECT_RETRIES" -gt 0 && "$CONNECT_ATTEMPTS" -lt "$CONNECT_RETRIES" ]]; then
        # Restart server in case it crashed or is wedged.
        kill $SP 2>/dev/null || true
        kill -9 $SP 2>/dev/null || true
        sudo ip netns exec "$NS" bash -lc "ulimit -n 1048576; '$BIN_DIR/quicraw-server' -addr ${SRV_IP}:$PORT -out '$OUT_DIR' -timeout 45s" >"$SRV_LOG" 2>&1 & SP=$!
        sleep 0.05
        continue
      fi
    fi
  fi
  break
done

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

# Capture netem stats (host egress), to validate realized loss.
NETEM_SENT_PKTS=0
NETEM_DROPPED_PKTS=0
NETEM_SENT_BYTES=0
if command -v tc >/dev/null 2>&1; then
  # Example line:
  #   Sent 123456 bytes 789 pkt (dropped 12, overlimits 0 requeues 0)
  netem_sent_line=$(tc -s qdisc show dev "$VETH_HOST" 2>/dev/null | awk '/qdisc netem 10:/{f=1} f && /Sent [0-9]+ bytes/{print; exit}')
  if [[ -n "$netem_sent_line" ]]; then
    NETEM_SENT_BYTES=$(echo "$netem_sent_line" | sed -n 's/.*Sent \([0-9]\+\) bytes.*/\1/p')
    NETEM_SENT_PKTS=$(echo "$netem_sent_line" | sed -n 's/.* bytes \([0-9]\+\) pkt.*/\1/p')
    NETEM_DROPPED_PKTS=$(echo "$netem_sent_line" | sed -n 's/.*(dropped \([0-9]\+\).*/\1/p')
  fi
fi

# Netem drop rate: dropped / (sent + dropped).
NETEM_DROP_RATE=
if [[ "$NETEM_SENT_PKTS" -gt 0 || "$NETEM_DROPPED_PKTS" -gt 0 ]]; then
  NETEM_DROP_RATE=$(awk -v s="$NETEM_SENT_PKTS" -v d="$NETEM_DROPPED_PKTS" 'BEGIN{t=s+d; if(t<=0){print "0"; exit} printf "%.6f", d/t}')
fi

# Wait for server to finish writing (bounded).
IN_SIZE=$(stat -c%s "$FILE")
tries=0
max_tries=100  # ~10s
T_WAIT_SRV_START=$(date +%s%N)
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
T_WAIT_SRV_END=$(date +%s%N)

sleep 0.05; kill $SP 2>/dev/null || true
sleep 0.05; kill -9 $SP 2>/dev/null || true

T_MD5_START=$(date +%s%N)
IN_MD5=$(md5sum "$FILE" | awk '{print $1}')
OUT_MD5=$(md5sum "$OUT_DIR/$(basename "$FILE").recv" | awk '{print $1}' || true)
MD5_OK=0; [[ "$IN_MD5" == "$OUT_MD5" ]] && MD5_OK=1
T_MD5_END=$(date +%s%N)

# Client wall duration (includes dial/open/header/send/ack; does not include md5 below).
DUR_MS_CLIENT=$(( (END-START)/1000000 ))

# Prefer server-side duration when available.
SRV_LINE=$(grep -E '^\[raw-server\] ' "$SRV_LOG" | tail -n1 || true)
DUR_MS_SERVER=$(echo "$SRV_LINE" | sed -n 's/.*dur_ms=\([0-9]\+\).*/\1/p')
if [[ -z "$DUR_MS_SERVER" ]]; then
  DUR_MS_SERVER=$DUR_MS_CLIENT
fi

FILE_SIZE=$(stat -c%s "$FILE")

# Overhead ratio: extra transmitted bytes over payload bytes.
OVERHEAD_RATIO=0
if [[ "$FILE_SIZE" -gt 0 && "$TX_BYTES" -gt 0 ]]; then
  OVERHEAD_RATIO=$(awk -v tx="$TX_BYTES" -v fb="$FILE_SIZE" 'BEGIN{v=(tx-fb)/fb; if(v<0)v=0; printf "%.6f", v}')
fi

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

# Extract raw client phase breakdown when available.
RAW_DIAL_MS=$(echo "$STAGES_LINE" | sed -n 's/.*dial_ms=\([0-9]\+\).*/\1/p')
RAW_OPEN_STREAM_MS=$(echo "$STAGES_LINE" | sed -n 's/.*open_stream_ms=\([0-9]\+\).*/\1/p')
RAW_HEADER_MS=$(echo "$STAGES_LINE" | sed -n 's/.*header_ms=\([0-9]\+\).*/\1/p')
RAW_SEND_MS=$(echo "$STAGES_LINE" | sed -n 's/.*send_ms=\([0-9]\+\).*/\1/p')
RAW_ACK_MS=$(echo "$STAGES_LINE" | sed -n 's/.*ack_ms=\([0-9]\+\).*/\1/p')
RAW_ACK_OK=$(echo "$STAGES_LINE" | sed -n 's/.*ack_ok=\([0-9]\+\).*/\1/p')
RAW_POST_WAIT_MS=$(echo "$STAGES_LINE" | sed -n 's/.*post_wait_ms=\([0-9]\+\).*/\1/p')

# Optional QUIC-layer stats (attempted sends, including packets later dropped by qdisc).
RAW_QUIC_SENT_PKTS=
RAW_QUIC_SENT_BYTES=
RAW_QUIC_SENT_SHORT_PKTS=
RAW_QUIC_SENT_SHORT_BYTES=
RAW_QUIC_LOST_1RTT_PKTS=
RAW_QUIC_ACKED_1RTT_PKTS=
RAW_QUIC_RETX_1RTT_PKTS=
RAW_QUIC_RETX_1RTT_BYTES=
RAW_QUIC_RECOVERY_TRIGGERS=
RAW_QUIC_LOSS_DETECTION_EVENTS=
RAW_QUIC_LTE_ACK=
RAW_QUIC_LTE_PTO=
RAW_QUIC_LTE_PATH_PROBE=
RAW_QUIC_PTO_EVENTS=
RAW_QUIC_SRTT_MS=
RAW_QUIC_MIN_RTT_MS=
RAW_QUIC_LATEST_RTT_MS=
RAW_QUIC_CWND_BYTES=
RAW_QUIC_INFLIGHT_BYTES=
RAW_QUIC_INFLIGHT_PKTS=
RAW_QUIC_OVERHEAD_RATIO=
RAW_QUIC_LINE=$(grep -E '^\[raw-client-quic-stats\] ' "$CLI_LOG" | tail -n1 || true)
if [[ -n "$RAW_QUIC_LINE" ]]; then
  RAW_QUIC_SENT_PKTS=$(echo "$RAW_QUIC_LINE" | sed -n 's/.*sent_pkts=\([0-9]\+\).*/\1/p')
  RAW_QUIC_SENT_BYTES=$(echo "$RAW_QUIC_LINE" | sed -n 's/.*sent_bytes=\([0-9]\+\).*/\1/p')
  RAW_QUIC_SENT_SHORT_PKTS=$(echo "$RAW_QUIC_LINE" | sed -n 's/.*sent_short_pkts=\([0-9]\+\).*/\1/p')
  RAW_QUIC_SENT_SHORT_BYTES=$(echo "$RAW_QUIC_LINE" | sed -n 's/.*sent_short_bytes=\([0-9]\+\).*/\1/p')
  RAW_QUIC_LOST_1RTT_PKTS=$(echo "$RAW_QUIC_LINE" | sed -n 's/.*lost_1rtt_pkts=\([0-9]\+\).*/\1/p')
  RAW_QUIC_ACKED_1RTT_PKTS=$(echo "$RAW_QUIC_LINE" | sed -n 's/.*acked_1rtt_pkts=\([0-9]\+\).*/\1/p')
  RAW_QUIC_RETX_1RTT_PKTS=$(echo "$RAW_QUIC_LINE" | sed -n 's/.*retx_1rtt_pkts=\([0-9]\+\).*/\1/p')
  RAW_QUIC_RETX_1RTT_BYTES=$(echo "$RAW_QUIC_LINE" | sed -n 's/.*retx_1rtt_bytes=\([0-9]\+\).*/\1/p')
  RAW_QUIC_RECOVERY_TRIGGERS=$(echo "$RAW_QUIC_LINE" | sed -n 's/.*recovery_triggers=\([0-9]\+\).*/\1/p')
  RAW_QUIC_LOSS_DETECTION_EVENTS=$(echo "$RAW_QUIC_LINE" | sed -n 's/.*loss_detection_events=\([0-9]\+\).*/\1/p')
  RAW_QUIC_LTE_ACK=$(echo "$RAW_QUIC_LINE" | sed -n 's/.*loss_timer_expired_ack=\([0-9]\+\).*/\1/p')
  RAW_QUIC_LTE_PTO=$(echo "$RAW_QUIC_LINE" | sed -n 's/.*loss_timer_expired_pto=\([0-9]\+\).*/\1/p')
  RAW_QUIC_LTE_PATH_PROBE=$(echo "$RAW_QUIC_LINE" | sed -n 's/.*loss_timer_expired_path_probe=\([0-9]\+\).*/\1/p')
  RAW_QUIC_PTO_EVENTS=$(echo "$RAW_QUIC_LINE" | sed -n 's/.*pto_events=\([0-9]\+\).*/\1/p')
  RAW_QUIC_SRTT_MS=$(echo "$RAW_QUIC_LINE" | sed -n 's/.*srtt_ms=\([0-9]\+\).*/\1/p')
  RAW_QUIC_MIN_RTT_MS=$(echo "$RAW_QUIC_LINE" | sed -n 's/.*min_rtt_ms=\([0-9]\+\).*/\1/p')
  RAW_QUIC_LATEST_RTT_MS=$(echo "$RAW_QUIC_LINE" | sed -n 's/.*latest_rtt_ms=\([0-9]\+\).*/\1/p')
  RAW_QUIC_CWND_BYTES=$(echo "$RAW_QUIC_LINE" | sed -n 's/.*cwnd_bytes=\([0-9]\+\).*/\1/p')
  RAW_QUIC_INFLIGHT_BYTES=$(echo "$RAW_QUIC_LINE" | sed -n 's/.*inflight_bytes=\([0-9]\+\).*/\1/p')
  RAW_QUIC_INFLIGHT_PKTS=$(echo "$RAW_QUIC_LINE" | sed -n 's/.*inflight_pkts=\([0-9\-]\+\).*/\1/p')
  if [[ -n "${RAW_QUIC_SENT_BYTES}" && "$FILE_SIZE" -gt 0 ]]; then
    RAW_QUIC_OVERHEAD_RATIO=$(awk -v tx="$RAW_QUIC_SENT_BYTES" -v fb="$FILE_SIZE" 'BEGIN{v=(tx-fb)/fb; if(v<0)v=0; printf "%.6f", v}')
  fi
fi

LOSS_TAG="${LOSS_PCT}%"
if [[ -n "${LOSS_MODE}" ]]; then
  LOSS_TAG="${LOSS_MODE}"
fi

echo "[run] proto=quic_raw bitrate=${BITRATE_MBPS}Mbps rtt=${RTT_MS}ms loss=${LOSS_TAG} dur_ms=${DUR_MS_SERVER} dur_ms_client=${DUR_MS_CLIENT} timed_out=${TIMED_OUT} client_ok=${CLIENT_OK} client_rc=${RC} md5_ok=${MD5_OK} s_mbps=${S_MBPS} overhead_ratio=${OVERHEAD_RATIO} file_bytes=${FILE_SIZE} tx_bytes=${TX_BYTES} rx_bytes=${RX_BYTES} netem_sent_pkts=${NETEM_SENT_PKTS} netem_dropped_pkts=${NETEM_DROPPED_PKTS} netem_sent_bytes=${NETEM_SENT_BYTES} netem_drop_rate=${NETEM_DROP_RATE:-} raw_dial_ms=${RAW_DIAL_MS:-} raw_open_stream_ms=${RAW_OPEN_STREAM_MS:-} raw_header_ms=${RAW_HEADER_MS:-} raw_send_ms=${RAW_SEND_MS:-} raw_ack_ms=${RAW_ACK_MS:-} raw_ack_ok=${RAW_ACK_OK:-} raw_post_wait_ms=${RAW_POST_WAIT_MS:-} raw_total_ms=${TOTAL_MS:-} raw_quic_sent_pkts=${RAW_QUIC_SENT_PKTS:-} raw_quic_sent_bytes=${RAW_QUIC_SENT_BYTES:-} raw_quic_sent_short_pkts=${RAW_QUIC_SENT_SHORT_PKTS:-} raw_quic_sent_short_bytes=${RAW_QUIC_SENT_SHORT_BYTES:-} raw_quic_lost_1rtt_pkts=${RAW_QUIC_LOST_1RTT_PKTS:-} raw_quic_acked_1rtt_pkts=${RAW_QUIC_ACKED_1RTT_PKTS:-} raw_quic_retx_1rtt_pkts=${RAW_QUIC_RETX_1RTT_PKTS:-} raw_quic_retx_1rtt_bytes=${RAW_QUIC_RETX_1RTT_BYTES:-} raw_quic_recovery_triggers=${RAW_QUIC_RECOVERY_TRIGGERS:-} raw_quic_loss_detection_events=${RAW_QUIC_LOSS_DETECTION_EVENTS:-} raw_quic_loss_timer_expired_ack=${RAW_QUIC_LTE_ACK:-} raw_quic_loss_timer_expired_pto=${RAW_QUIC_LTE_PTO:-} raw_quic_loss_timer_expired_path_probe=${RAW_QUIC_LTE_PATH_PROBE:-} raw_quic_pto_events=${RAW_QUIC_PTO_EVENTS:-} raw_quic_srtt_ms=${RAW_QUIC_SRTT_MS:-} raw_quic_min_rtt_ms=${RAW_QUIC_MIN_RTT_MS:-} raw_quic_latest_rtt_ms=${RAW_QUIC_LATEST_RTT_MS:-} raw_quic_cwnd_bytes=${RAW_QUIC_CWND_BYTES:-} raw_quic_inflight_bytes=${RAW_QUIC_INFLIGHT_BYTES:-} raw_quic_inflight_pkts=${RAW_QUIC_INFLIGHT_PKTS:-} raw_quic_overhead_ratio=${RAW_QUIC_OVERHEAD_RATIO:-}" >&2

# Phase timings (ms). Useful to explain why python-side wall_ms >> dur_ms.
tc_ms=$(( (T_TC_END - T_TC_START) / 1000000 ))
srv_ready_ms=$(( (T_SRV_READY - T_SRV_START) / 1000000 ))
wait_srv_ms=$(( (T_WAIT_SRV_END - T_WAIT_SRV_START) / 1000000 ))
md5_ms=$(( (T_MD5_END - T_MD5_START) / 1000000 ))
total_ms=$(( (T_MD5_END - T_SCRIPT_START) / 1000000 ))
echo "[timing] tc_ms=${tc_ms} srv_ready_ms=${srv_ready_ms} wait_srv_ms=${wait_srv_ms} md5_ms=${md5_ms} total_ms=${total_ms}" >&2

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
