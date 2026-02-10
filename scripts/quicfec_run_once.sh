#!/usr/bin/env bash
set -euo pipefail

# Single trial QUIC-FEC run for RL. Configurable via env vars.
# - Sets up/refreshes a netns and veth pair, configures tc for RTT/loss/rate.
# - Starts server in the namespace, runs client on host once.
# - Extracts last [rl-observation] line from server log and appends to OBS_JSON.
#
# Training speed flags:
#   SETUP_ONLY=1         Only prepare netns/tc (and optional build), then exit 0.
#   SKIP_NETNS_RESET=1   Assume netns/veth already exist; do not recreate.
#   SKIP_TC_CONFIG=1     Assume tc qdiscs already configured; do not replace.
#   SKIP_SYSCTL=1        Skip UDP buffer sysctl tuning.
#   SKIP_BUILD=1         Skip go build / rebuild checks (requires existing binaries).
#
# Env vars (with defaults):
#   NS=qns, PORT=45300
#   BITRATE_MBPS=10, RTT_MS=100, LOSS_PCT=0
#   LOSS_MODE=  # optional; overrides LOSS_PCT when set. Formats:
#               #   none
#               #   iid:5           (5% i.i.d. loss)
#               #   gemodel:p,r,h,k (Gilbert-Elliott model, percents)
#   FILE=$ROOT/go/test_data/train_FD001.txt
#   K=40, SYMBOL_BYTES=1200, R0=6, W=8, DDL_MS=150, DECODE_DDL_MS=25, RSTEP=4, ACK_EVERY=8, MAX_ATTEMPTS=8
#   OBS_JSON=/tmp/quicfec_rl_${NS}.json
#   POST_WAIT=0s (linger after client send; keep at 0s for fastest runs)
#   SRV_TIMEOUT=10s (server max lifetime; lower keeps runs bounded)
#   FORCE_BUILD=0 (set to 1 to force rebuilding Go binaries)

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN_DIR="$ROOT/go/bin"

NS=${NS:-qns}
PORT=${PORT:-45300}

# Parallel-safe overrides (used by Python training to run multiple workers concurrently).
VETH_HOST=${VETH_HOST:-veth0}
VETH_NS=${VETH_NS:-veth1}
HOST_IP=${HOST_IP:-10.10.0.1/24}
NS_IP=${NS_IP:-10.10.0.2/24}
SRV_IP=${SRV_IP:-${NS_IP%%/*}}

BITRATE_MBPS=${BITRATE_MBPS:-10}
RTT_MS=${RTT_MS:-550}
LOSS_PCT=${LOSS_PCT:-0}
RATE="${BITRATE_MBPS}mbit"

FILE=${FILE:-"$ROOT/go/test_data/train_FD001.txt"}
OUT_DIR=${OUT_DIR:-"$ROOT/go/test_data"}
# Default OBS path is namespaced to avoid collisions across parallel runs.
OBS_JSON=${OBS_JSON:-/tmp/quicfec_rl_${NS}.json}

K=${K:-30}
SYMBOL_BYTES=${SYMBOL_BYTES:-1032}
R0=${R0:-6}
W=${W:-8}
DDL_MS=${DDL_MS:-200}
DECODE_DDL_MS=${DECODE_DDL_MS:-25}
RSTEP=${RSTEP:-4}
ALPHA=${ALPHA:-0.6}
ACK_EVERY=${ACK_EVERY:-8}
MAX_ATTEMPTS=${MAX_ATTEMPTS:-0}
USE_ARQ=${USE_ARQ:-1}
PACE_US=${PACE_US:-0}
TRANSPORT=${TRANSPORT:-dgram}
if [[ -z "${POST_WAIT+x}" || -z "${POST_WAIT}" ]]; then
  # Default linger: 0s. QUIC-FEC now waits for an explicit server->client DONE ACK.
  POST_WAIT="0s"
fi
# Experiment-level transfer timeout in seconds (15s by default).
TIMEOUT_S=${TIMEOUT_S:-15}
# Connection establishment guard (client-side dial + QUIC handshake).
CONNECT_TIMEOUT_S=${CONNECT_TIMEOUT_S:-2}
CONNECT_RETRIES=${CONNECT_RETRIES:-5}
# Server / client lifetime caps (defaults to TIMEOUT_S).
SRV_TIMEOUT=${SRV_TIMEOUT:-${TIMEOUT_S}s}
CLI_TIMEOUT=${CLI_TIMEOUT:-${TIMEOUT_S}s}
# Observation wait budget in seconds (default: derived from SRV_TIMEOUT if of the form \d+s, else 30s)
if [[ -z "${OBS_WAIT_SECS:-}" ]]; then
  if [[ "$SRV_TIMEOUT" =~ ^([0-9]+)s$ ]]; then
    OBS_WAIT_SECS=${BASH_REMATCH[1]}
  else
    OBS_WAIT_SECS=30
  fi
fi

SETUP_ONLY=${SETUP_ONLY:-0}
SKIP_NETNS_RESET=${SKIP_NETNS_RESET:-0}
SKIP_TC_CONFIG=${SKIP_TC_CONFIG:-0}
SKIP_SYSCTL=${SKIP_SYSCTL:-0}
SKIP_BUILD=${SKIP_BUILD:-0}

# DDL_MS already defaulted above; kept here historically but now intentionally a no-op.

chmod +x "$ROOT/scripts"/*.sh || true
mkdir -p "$ROOT/go/test_data" "$OUT_DIR"
# Ensure test file exists (repo ignores test_data). Create a deterministic ~3MB file if missing.
if [[ ! -f "$FILE" ]]; then
  head -c $((3*1024*1024)) </dev/urandom >"$FILE"
fi

# Require cached sudo privileges to avoid interactive prompts under RL.
if ! sudo -n true 2>/dev/null; then
  echo "[error] sudo privileges are required. Run 'sudo -v' once (or set SUDO_ASKPASS/SUDO_PASSWORD) and rerun." >&2
  exit 1
fi

# Reset netns (unless explicitly reusing an existing one)
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

# Quic-go attempts to increase UDP socket buffers. If the kernel caps are low,
# this can cause drops under bursty senders (even when LOSS_PCT=0), which shows up
# as run-to-run instability / occasional residual erasures.
TUNE_UDP_BUFFERS=${TUNE_UDP_BUFFERS:-1}
if [[ "${TUNE_UDP_BUFFERS}" == "1" && "$SKIP_SYSCTL" != "1" ]]; then
  # Best-effort: keep silent and don't fail the run if sysctl is restricted.
  sudo sysctl -w net.core.rmem_max=33554432 net.core.wmem_max=33554432 >/dev/null 2>&1 || true
  sudo sysctl -w net.core.rmem_default=33554432 net.core.wmem_default=33554432 >/dev/null 2>&1 || true
fi
# Rebuild if forced, binaries missing, or any Go source is newer than the binaries
NEED_BUILD=0
if [[ "$SKIP_BUILD" == "1" ]]; then
  if [[ ! -x "$BIN_DIR/quicfec-server" || ! -x "$BIN_DIR/quicfec-client" ]]; then
    echo "[error] SKIP_BUILD=1 but binaries missing in $BIN_DIR" >&2
    exit 2
  fi
else
  if [[ "${FORCE_BUILD:-0}" == "1" || ! -x "$BIN_DIR/quicfec-server" || ! -x "$BIN_DIR/quicfec-client" ]]; then
  NEED_BUILD=1
  else
  # If any Go file is newer than either binary, trigger rebuild
  if find "$ROOT/go" -type f -name '*.go' -newer "$BIN_DIR/quicfec-server" -print -quit | grep -q .; then NEED_BUILD=1; fi
  if find "$ROOT/go" -type f -name '*.go' -newer "$BIN_DIR/quicfec-client" -print -quit | grep -q .; then NEED_BUILD=1; fi
  fi
  if [[ "$NEED_BUILD" == "1" ]]; then
  mkdir -p "$BIN_DIR"
  (cd "$ROOT/go" && go build -o "$BIN_DIR/quicfec-server" ./cmd/quicfec-server && go build -o "$BIN_DIR/quicfec-client" ./cmd/quicfec-client)
fi
fi

FILE_SIZE=$(stat -c%s "$FILE")

# Configure qdiscs: half RTT on each direction; apply TBF at root and NETEM as child on host side
half=$(( RTT_MS / 2 ))
if [[ "$SKIP_TC_CONFIG" != "1" ]]; then
  sudo tc qdisc del dev "$VETH_HOST" root 2>/dev/null || true

  # Build NETEM args for loss model
  LOSS_MODE=${LOSS_MODE:-}
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
      # IMPORTANT: `tc netem loss gemodel` expects parameters as:
      #   p r 1-h 1-k
      # where 1-h is the BAD-state loss probability and 1-k is the GOOD-state
      # loss probability (see `man tc-netem`).
      # Our LOSS_MODE=gemodel:p,r,h,k uses h=GOOD loss probability, k=BAD loss
      # probability, so we pass (1-h)=k and (1-k)=h.
      NETEM_ARGS+=(loss gemodel ${p}% ${r}% ${k}% ${h}%) ;;
    ""|*)
      NETEM_ARGS+=(loss ${LOSS_PCT}%) ;;
  esac

  # Apply TBF at root to enforce rate, then NETEM as child for delay/loss
  sudo tc qdisc replace dev "$VETH_HOST" root handle 1: tbf rate ${RATE} burst 32kb latency 400ms
  sudo tc qdisc replace dev "$VETH_HOST" parent 1:1 handle 10: netem "${NETEM_ARGS[@]}"
  sudo ip netns exec "$NS" tc qdisc del dev "$VETH_NS" root 2>/dev/null || true
  sudo ip netns exec "$NS" tc qdisc replace dev "$VETH_NS" root netem delay ${half}ms
fi

# JSON (line-oriented) for RL obs
touch "$OBS_JSON"

if [[ "$SETUP_ONLY" == "1" ]]; then
  # Network is configured; nothing else to do.
  exit 0
fi

# Run server (logs in /tmp/quic_fec_srv.* for easy tailing)
SRV_LOG=$(mktemp -t quic_fec_srv.XXXXXX.log)
# Remove any stale outputs from previous runs; otherwise md5_ok can be a false positive
# if this run fails before producing a new file.
rm -f "$OUT_DIR/$(basename "$FILE").recv" "$OUT_DIR/$(basename "$FILE").recv.part" 2>/dev/null || true
sudo ip netns exec "$NS" bash -lc "ulimit -n 1048576; '$BIN_DIR/quicfec-server' -addr ${SRV_IP}:$PORT -out '$OUT_DIR' -timeout ${SRV_TIMEOUT} -decode-ddl ${DECODE_DDL_MS}ms" >"$SRV_LOG" 2>&1 & SP=$!

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

# Run client (logs in /tmp/quic_fec_cli.*)
CLI_LOG=$(mktemp -t quic_fec_cli.XXXXXX.log)
export QUIC_FEC_CC_BYPASS=${QUIC_FEC_CC_BYPASS:-1}

# Optional QUIC-layer stats (disabled by default to avoid affecting performance).
# When enabled, fecquic.ClientSendFile prints one line: [fec-client-quic-stats] key=value...
FEC_STATS=${FEC_STATS:-0}
if [[ "$FEC_STATS" == "1" ]]; then
  export QUIC_FEC_STATS=1
fi

# Byte counters on host veth (network-layer; includes headers). These are used
# to estimate overhead (extra transmitted bytes over the file payload).
TX0=0; RX0=0
if [[ -r "/sys/class/net/${VETH_HOST}/statistics/tx_bytes" ]]; then
  TX0=$(cat "/sys/class/net/${VETH_HOST}/statistics/tx_bytes" 2>/dev/null || echo 0)
  RX0=$(cat "/sys/class/net/${VETH_HOST}/statistics/rx_bytes" 2>/dev/null || echo 0)
fi
START=$(date +%s%N)
pace_arg=""
# Pacing:
# - If PACE_US is unset, auto-compute an inter-packet gap targeting BITRATE_MBPS.
# - If PACE_US=0, disable app-level pacing and rely on QUIC + tc shaping.
# - If PACE_US>0, use the provided microsecond gap.
if [[ -n "${PACE_US}" && "${PACE_US}" -gt 0 ]]; then
  pace_arg="-pace ${PACE_US}us"
fi

arq_flag=""
if [[ "${USE_ARQ}" == "1" ]]; then
  arq_flag="-arq"
fi
if command -v timeout >/dev/null 2>&1; then
  CONNECT_ATTEMPTS=0
  while true; do
    CONNECT_ATTEMPTS=$((CONNECT_ATTEMPTS + 1))
    : >"$CLI_LOG" || true
    unset RC || true
    timeout --signal=KILL ${TIMEOUT_S}s \
      "$BIN_DIR/quicfec-client" -addr ${SRV_IP}:$PORT -file "$FILE" -timeout ${TIMEOUT_S}s -connect-timeout ${CONNECT_TIMEOUT_S}s \
        -N $((K+R0)) -K "$K" -L "$SYMBOL_BYTES" \
        -post-wait "$POST_WAIT" -ack-every "$ACK_EVERY" -dgram-warn 1400 -transport "$TRANSPORT" $arq_flag -rx-ddl ${DDL_MS}ms -R0 "$R0" -W "$W" -Rstep "$RSTEP" -max-attempts "$MAX_ATTEMPTS" -loss 0 $pace_arg \
        >"$CLI_LOG" 2>&1 || RC=$?
    RC=${RC:-0}
    if [[ "$RC" != "0" ]]; then
      if grep -qE "^error: .*context deadline exceeded|^error:.*timeout|context deadline exceeded" "$CLI_LOG" 2>/dev/null; then
        if [[ "$CONNECT_RETRIES" -gt 0 && "$CONNECT_ATTEMPTS" -lt "$CONNECT_RETRIES" ]]; then
          kill $SP 2>/dev/null || true
          kill -9 $SP 2>/dev/null || true
          sudo ip netns exec "$NS" bash -lc "ulimit -n 1048576; '$BIN_DIR/quicfec-server' -addr ${SRV_IP}:$PORT -out '$OUT_DIR' -timeout ${SRV_TIMEOUT} -decode-ddl ${DECODE_DDL_MS}ms" >"$SRV_LOG" 2>&1 & SP=$!
          sleep 0.05
          continue
        fi
      fi
    fi
    break
  done
else
  CONNECT_ATTEMPTS=0
  while true; do
    CONNECT_ATTEMPTS=$((CONNECT_ATTEMPTS + 1))
    : >"$CLI_LOG" || true
    unset RC || true
    "$BIN_DIR/quicfec-client" -addr ${SRV_IP}:$PORT -file "$FILE" -timeout ${TIMEOUT_S}s -connect-timeout ${CONNECT_TIMEOUT_S}s \
      -N $((K+R0)) -K "$K" -L "$SYMBOL_BYTES" \
      -post-wait "$POST_WAIT" -ack-every "$ACK_EVERY" -dgram-warn 1400 -transport "$TRANSPORT" $arq_flag -rx-ddl ${DDL_MS}ms -R0 "$R0" -W "$W" -Rstep "$RSTEP" -max-attempts "$MAX_ATTEMPTS" -loss 0 $pace_arg \
      >"$CLI_LOG" 2>&1 || RC=$?
    RC=${RC:-0}
    if [[ "$RC" != "0" ]]; then
      if grep -qE "^error: .*context deadline exceeded|^error:.*timeout|context deadline exceeded" "$CLI_LOG" 2>/dev/null; then
        if [[ "$CONNECT_RETRIES" -gt 0 && "$CONNECT_ATTEMPTS" -lt "$CONNECT_RETRIES" ]]; then
          kill $SP 2>/dev/null || true
          kill -9 $SP 2>/dev/null || true
          sudo ip netns exec "$NS" bash -lc "ulimit -n 1048576; '$BIN_DIR/quicfec-server' -addr ${SRV_IP}:$PORT -out '$OUT_DIR' -timeout ${SRV_TIMEOUT} -decode-ddl ${DECODE_DDL_MS}ms" >"$SRV_LOG" 2>&1 & SP=$!
          sleep 0.05
          continue
        fi
      fi
    fi
    break
  done
fi
RC=${RC:-0}
TIMED_OUT=0
if [[ "$RC" == "124" || "$RC" == "137" ]]; then
  TIMED_OUT=1
fi
CLIENT_OK=1
if [[ "$RC" != "0" ]]; then
  CLIENT_OK=0
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

# Overhead ratio: extra transmitted bytes over payload bytes.
OVERHEAD_RATIO=0
if [[ "$FILE_SIZE" -gt 0 && "$TX_BYTES" -gt 0 ]]; then
  OVERHEAD_RATIO=$(awk -v tx="$TX_BYTES" -v fb="$FILE_SIZE" 'BEGIN{v=(tx-fb)/fb; if(v<0)v=0; printf "%.6f", v}')
fi

# Capture netem stats (host egress), to validate realized loss.
NETEM_SENT_PKTS=0
NETEM_DROPPED_PKTS=0
NETEM_SENT_BYTES=0
if command -v tc >/dev/null 2>&1; then
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

# Wait for server to emit the observation before stopping it (cap by OBS_WAIT_SECS)
tries=0
RL_OBS=""
max_tries=$(( OBS_WAIT_SECS * 10 ))
while [[ $tries -lt $max_tries ]]; do
  RL_OBS=$(grep -E "^\[rl-observation\]" "$SRV_LOG" | tail -n1 || true)
  if [[ -n "$RL_OBS" ]]; then
    break
  fi
  sleep 0.1
  tries=$((tries+1))
done
sleep 0.05; kill $SP 2>/dev/null || true
sleep 0.05; kill -9 $SP 2>/dev/null || true

# Basic metrics
IN_MD5=$(md5sum "$FILE" | awk '{print $1}')
OUT_MD5=$(md5sum "$OUT_DIR/$(basename "$FILE").recv" | awk '{print $1}' || true)
MD5_OK=0; [[ "$IN_MD5" == "$OUT_MD5" ]] && MD5_OK=1

# Any client failure (including timeout) => count as failure.
if [[ "$CLIENT_OK" == "0" ]]; then
  MD5_OK=0
fi

# Client wall duration (includes optional ARQ drain / post-wait), does NOT include md5.
DUR_MS_CLIENT=$(( (END-START)/1000000 ))

# Prefer server-side E2E completion time when available.
# This excludes closeAndFinalize() (disk write + SHA verification) and matches:
#   sender starts sending -> receiver finished decoding all data.
E2E_LINE=$(grep -E '^\[server-e2e\] ' "$SRV_LOG" | tail -n1 || true)
E2E_MS=""
E2E_OK=""
if [[ -n "$E2E_LINE" ]]; then
  E2E_MS=$(echo "$E2E_LINE" | sed -n 's/.*e2e_ms=\([0-9]\+\).*/\1/p')
  E2E_OK=$(echo "$E2E_LINE" | sed -n 's/.*ok=\([0-9]\+\).*/\1/p')
fi

DUR_MS=$DUR_MS_CLIENT
if [[ -n "$E2E_MS" && "$E2E_OK" == "1" ]]; then
  DUR_MS=$E2E_MS
fi

# Build RL observation.
# Design: contextual bandit controls TX only. Therefore, all observation fields
# except residual_erasures are sourced from the sender (client) logs.
KEEP_LOGS=0
CC_EST=$(grep -E '^\[cc-estimate\] ' "$CLI_LOG" | tail -n1 || true)
ARQ_STATS=$(grep -E '^\[arq-stats\] ' "$CLI_LOG" | tail -n1 || true)
CLI_STAGES=$(grep -E '^\[fec-client-stages\] ' "$CLI_LOG" | tail -n1 || true)
MERGED_LINE=$(RL_OBS_LINE="$RL_OBS" CC_EST_LINE="$CC_EST" ARQ_STATS_LINE="$ARQ_STATS" CLI_STAGES_LINE="$CLI_STAGES" FILE_SIZE="$FILE_SIZE" K_VAL="$K" R0_VAL="$R0" DDL_MS_VAL="$DDL_MS" MD5_OK_VAL="$MD5_OK" TIMED_OUT_VAL="$TIMED_OUT" python3 - <<'PY'
import json
import os
import sys

line = os.environ.get('RL_OBS_LINE', '')
cc = os.environ.get('CC_EST_LINE', '')
arq = os.environ.get('ARQ_STATS_LINE', '')
stg = os.environ.get('CLI_STAGES_LINE', '')

try:
  file_size = int(os.environ.get('FILE_SIZE', '0') or '0')
except Exception:
  file_size = 0

try:
  K = int(os.environ.get('K_VAL', '0') or '0')
except Exception:
  K = 0

try:
  R0 = int(os.environ.get('R0_VAL', '0') or '0')
except Exception:
  R0 = 0

try:
  ddl_ms = int(os.environ.get('DDL_MS_VAL', '0') or '0')
except Exception:
  ddl_ms = 0

try:
  md5_ok = int(os.environ.get('MD5_OK_VAL', '1') or '1')
except Exception:
  md5_ok = 1

try:
  timed_out = int(os.environ.get('TIMED_OUT_VAL', '0') or '0')
except Exception:
  timed_out = 0

# Global info (receiver): residual erasures flag.
residual_erasures = 1
if (line or '').startswith('[rl-observation] '):
  try:
    rx_payload = json.loads(line.split(' ', 1)[1])
    residual_erasures = int(rx_payload.get('residual_erasures', 1) or 0)
  except Exception:
    residual_erasures = 1

payload = {
  'goodput': 0.0,
  'goodput_mbps': 0.0,
  'fec_overhead': 0.0,
  'ctrl_tx_nack_msgs': 0,
  'arq_attempts_mean': 0.0,
  'residual_erasures': int(residual_erasures),
  'fec_rate': float(R0) / float(max(1, K)),
  'ddl_ms': float(max(0, ddl_ms)),
  # Validity markers (not used by the policy; env uses them to ignore invalid runs).
  'md5_ok': int(md5_ok),
  'timed_out': int(timed_out),
}

def parse_cc_line(s: str):
  s = (s or '').strip()
  if not s.startswith('[cc-estimate] '):
    return None
  try:
    return json.loads(s.split(' ', 1)[1])
  except Exception:
    return None

def parse_kv_line(prefix: str, s: str):
  s = (s or '').strip()
  if not s.startswith(prefix):
    return None
  rest = s[len(prefix):].strip()
  out = {}
  for tok in rest.split():
    if '=' not in tok:
      continue
    k, v = tok.split('=', 1)
    k = k.strip()
    v = v.strip()
    if not k:
      continue
    # Heuristic: try int, then float, else string.
    vv = None
    try:
      vv = int(v)
    except Exception:
      try:
        vv = float(v)
      except Exception:
        vv = v
    out[k] = vv
  return out

ccj = parse_cc_line(cc)
if isinstance(ccj, dict):
  # Prefer BBRv2's delivery-rate sample (bw_mbps). Keep pacing bandwidth too.
  bw = ccj.get('bw_mbps', None)
  try:
    bw = float(bw)
  except Exception:
    bw = None
  # Basic sanity clamp: ignore insane values (e.g., ack compression artifacts).
  if bw is not None and bw > 0 and bw < 100000:
    payload['estimated_available_bw_mbps'] = bw
    payload['estimated_available_bw_cc_mbps'] = bw
  pbw = ccj.get('pacing_bw_mbps', None)
  try:
    pbw = float(pbw)
  except Exception:
    pbw = None
  if pbw is not None and pbw > 0:
    payload['estimated_pacing_bw_cc_mbps'] = pbw
  algo = ccj.get('algo', None)
  if algo is not None:
    payload['cc_algo_reported'] = algo
  mode = ccj.get('mode', None)
  if mode is not None:
    payload['cc_mode'] = mode

# Merge sender-side FEC tx counters / overhead from the client.
arqj = parse_kv_line('[arq-stats]', arq)
tx_source = 0
tx_repairs = 0
arq_attempts_total = 0
arq_clusters_total = 0
if isinstance(arqj, dict) and arqj:
  try:
    tx_source = int(arqj.get('tx_source_symbols', 0) or 0)
  except Exception:
    tx_source = 0
  try:
    tx_repairs = int(arqj.get('tx_repairs', arqj.get('tx_repair_symbols', 0)) or 0)
  except Exception:
    tx_repairs = 0
  try:
    arq_attempts_total = int(arqj.get('attempts', 0) or 0)
  except Exception:
    arq_attempts_total = 0
  try:
    arq_clusters_total = int(arqj.get('clusters', 0) or 0)
  except Exception:
    arq_clusters_total = 0

  # ctrl_tx_nack_msgs: sender-side count of NACK messages received.
  # The client reports total "attempts" (NACK rounds processed).
  payload['ctrl_tx_nack_msgs'] = int(max(0, arq_attempts_total))

  # ARQ attempts mean per cluster (tx-side).
  if arq_clusters_total > 0:
    payload['arq_attempts_mean'] = float(arq_attempts_total) / float(arq_clusters_total)
  else:
    payload['arq_attempts_mean'] = 0.0

  # fec_overhead: repairs/source across initial R0 and ARQ appended repairs.
  try:
    if tx_source > 0:
      payload['fec_overhead'] = float(tx_repairs) / float(tx_source)
    else:
      payload['fec_overhead'] = 0.0
  except Exception:
    payload['fec_overhead'] = 0.0

stgj = parse_kv_line('[fec-client-stages]', stg)
total_ms = None
if isinstance(stgj, dict) and stgj:
  try:
    total_ms = float(stgj.get('total_ms', None))
  except Exception:
    total_ms = None

# Sender-side goodput estimate: file_size over sender-observed total_ms.
try:
  if total_ms is not None and total_ms > 0 and file_size > 0:
    goodput_mbps = (float(file_size) * 8.0 / 1e6) / (float(total_ms) / 1000.0)
    payload['goodput'] = float(goodput_mbps)
    payload['goodput_mbps'] = float(goodput_mbps)
except Exception:
  pass

sys.stdout.write('[rl-observation] ' + json.dumps(payload, separators=(',', ':')))
PY
)
echo "$MERGED_LINE" >>"$OBS_JSON"
echo "$MERGED_LINE" >&2

# If residual_erasures reported (or server obs missing), keep logs for diagnosis and print tails.
if [[ -z "$RL_OBS" ]] || echo "$MERGED_LINE" | grep -q '"residual_erasures"[[:space:]]*:[[:space:]]*1'; then
  KEEP_LOGS=1
  if [[ -z "$RL_OBS" ]]; then
    echo "[warn] no [rl-observation] found in server logs; using tx-only obs with residual_erasures=1" >&2
  else
    echo "[diag] residual_erasures=1 detected; preserving logs:" >&2
  fi
  echo "[diag] server log: $SRV_LOG" >&2
  echo "[diag] client log: $CLI_LOG" >&2
  echo "[diag] ---- server log tail ----" >&2
  tail -n 120 "$SRV_LOG" >&2 || true
  echo "[diag] ---- client log tail ----" >&2
  tail -n 120 "$CLI_LOG" >&2 || true
fi

# Preserve logs on any integrity failure (md5 mismatch) or runtime failure.
# Copy into the repo so they are accessible from the workspace.
if [[ "$MD5_OK" == "0" || "$CLIENT_OK" == "0" || "$TIMED_OUT" == "1" ]]; then
  KEEP_LOGS=1
  echo "[diag] failure detected (md5_ok=${MD5_OK} client_ok=${CLIENT_OK} timed_out=${TIMED_OUT}); preserving logs" >&2
  echo "[diag] server log: $SRV_LOG" >&2
  echo "[diag] client log: $CLI_LOG" >&2
  echo "[diag] ---- server log tail ----" >&2
  tail -n 120 "$SRV_LOG" >&2 || true
  echo "[diag] ---- client log tail ----" >&2
  tail -n 120 "$CLI_LOG" >&2 || true
fi

if [[ "$KEEP_LOGS" == "1" && "${BG:-0}" != "1" ]]; then
  LOG_DIR="$ROOT/go/test_data/logs"
  mkdir -p "$LOG_DIR" 2>/dev/null || true
  stamp=$(date +%Y%m%d_%H%M%S_%N)
  srv_copy="$LOG_DIR/quic_fec_srv.${stamp}.log"
  cli_copy="$LOG_DIR/quic_fec_cli.${stamp}.log"
  cp -f "$SRV_LOG" "$srv_copy" 2>/dev/null || true
  cp -f "$CLI_LOG" "$cli_copy" 2>/dev/null || true
  echo "[diag] copied logs into workspace:" >&2
  echo "[diag]   $srv_copy" >&2
  echo "[diag]   $cli_copy" >&2
fi

# Echo a concise run summary (always)
S_LINE=$(grep -E "^\[server-stats\]" "$SRV_LOG" | tail -n1 || true)
S_DUR=""
if [[ -n "$S_LINE" ]]; then
  S_DUR=$(echo "$S_LINE" | sed -n 's/.*dur_s=\([0-9.\-]\+\).*/\1/p')
fi

# Throughput metrics:
# - s_mbps: computed from DUR_MS (server-e2e when available), to match dur_ms.
# - s_mbps_total: computed from server-stats dur_s (includes tx-stats grace period + finalize), useful for diagnostics.
S_MBPS=0
if [[ "$DUR_MS" -gt 0 ]]; then
  S_MBPS=$(awk -v sz="$FILE_SIZE" -v ms="$DUR_MS" 'BEGIN{printf "%.2f", (sz*8.0/1000000.0)/(ms/1000.0)}')
fi

S_MBPS_TOTAL=""
if [[ -n "$S_DUR" && "$S_DUR" != "0" ]]; then
  S_MBPS_TOTAL=$(awk -v sz="$FILE_SIZE" -v ds="$S_DUR" 'BEGIN{printf "%.2f", (sz*8.0/1000000.0)/ds}')
fi

if [[ "$TIMED_OUT" == "1" ]]; then
  S_MBPS=0
  S_MBPS_TOTAL=0
fi

LOSS_DESC="${LOSS_PCT}%"
if [[ -n "${LOSS_MODE:-}" ]]; then
  LOSS_DESC="${LOSS_MODE}"
fi

run_tail=""
if [[ -n "$S_MBPS_TOTAL" ]]; then
  run_tail=" s_mbps_total=${S_MBPS_TOTAL}"
fi

# Optional QUIC-layer stats (attempted sends, including packets later dropped by qdisc).
FEC_QUIC_SENT_PKTS=
FEC_QUIC_SENT_BYTES=
FEC_QUIC_SENT_SHORT_PKTS=
FEC_QUIC_SENT_SHORT_BYTES=
FEC_QUIC_LOST_1RTT_PKTS=
FEC_QUIC_ACKED_1RTT_PKTS=
FEC_QUIC_SRTT_MS=
FEC_QUIC_MIN_RTT_MS=
FEC_QUIC_LATEST_RTT_MS=
FEC_QUIC_CWND_BYTES=
FEC_QUIC_INFLIGHT_BYTES=
FEC_QUIC_INFLIGHT_PKTS=
FEC_QUIC_OVERHEAD_RATIO=
FEC_QUIC_LINE=$(grep -E '^\[fec-client-quic-stats\] ' "$CLI_LOG" | tail -n1 || true)
if [[ -n "$FEC_QUIC_LINE" ]]; then
  FEC_QUIC_SENT_PKTS=$(echo "$FEC_QUIC_LINE" | sed -n 's/.*sent_pkts=\([0-9]\+\).*/\1/p')
  FEC_QUIC_SENT_BYTES=$(echo "$FEC_QUIC_LINE" | sed -n 's/.*sent_bytes=\([0-9]\+\).*/\1/p')
  FEC_QUIC_SENT_SHORT_PKTS=$(echo "$FEC_QUIC_LINE" | sed -n 's/.*sent_short_pkts=\([0-9]\+\).*/\1/p')
  FEC_QUIC_SENT_SHORT_BYTES=$(echo "$FEC_QUIC_LINE" | sed -n 's/.*sent_short_bytes=\([0-9]\+\).*/\1/p')
  FEC_QUIC_LOST_1RTT_PKTS=$(echo "$FEC_QUIC_LINE" | sed -n 's/.*lost_1rtt_pkts=\([0-9]\+\).*/\1/p')
  FEC_QUIC_ACKED_1RTT_PKTS=$(echo "$FEC_QUIC_LINE" | sed -n 's/.*acked_1rtt_pkts=\([0-9]\+\).*/\1/p')
  FEC_QUIC_SRTT_MS=$(echo "$FEC_QUIC_LINE" | sed -n 's/.*srtt_ms=\([0-9]\+\).*/\1/p')
  FEC_QUIC_MIN_RTT_MS=$(echo "$FEC_QUIC_LINE" | sed -n 's/.*min_rtt_ms=\([0-9]\+\).*/\1/p')
  FEC_QUIC_LATEST_RTT_MS=$(echo "$FEC_QUIC_LINE" | sed -n 's/.*latest_rtt_ms=\([0-9]\+\).*/\1/p')
  FEC_QUIC_CWND_BYTES=$(echo "$FEC_QUIC_LINE" | sed -n 's/.*cwnd_bytes=\([0-9]\+\).*/\1/p')
  FEC_QUIC_INFLIGHT_BYTES=$(echo "$FEC_QUIC_LINE" | sed -n 's/.*inflight_bytes=\([0-9]\+\).*/\1/p')
  FEC_QUIC_INFLIGHT_PKTS=$(echo "$FEC_QUIC_LINE" | sed -n 's/.*inflight_pkts=\([0-9\-]\+\).*/\1/p')
  if [[ -n "${FEC_QUIC_SENT_BYTES}" && "$FILE_SIZE" -gt 0 ]]; then
    FEC_QUIC_OVERHEAD_RATIO=$(awk -v tx="$FEC_QUIC_SENT_BYTES" -v fb="$FILE_SIZE" 'BEGIN{v=(tx-fb)/fb; if(v<0)v=0; printf "%.6f", v}')
  fi
fi

# Sender-side ARQ counters (helps attribute overhead to appended repairs).
FEC_ARQ_TX_SOURCE_SYMBOLS=
FEC_ARQ_TX_REPAIRS=
FEC_ARQ_FEC_OVERHEAD=
FEC_ARQ_CLUSTERS=
FEC_ARQ_ATTEMPTS=
if [[ -n "${ARQ_STATS:-}" ]]; then
  FEC_ARQ_TX_SOURCE_SYMBOLS=$(echo "$ARQ_STATS" | sed -n 's/.*tx_source_symbols=\([0-9]\+\).*/\1/p')
  FEC_ARQ_TX_REPAIRS=$(echo "$ARQ_STATS" | sed -n 's/.*tx_repairs=\([0-9]\+\).*/\1/p')
  FEC_ARQ_FEC_OVERHEAD=$(echo "$ARQ_STATS" | sed -n 's/.*fec_overhead=\([0-9.\-]\+\).*/\1/p')
  FEC_ARQ_CLUSTERS=$(echo "$ARQ_STATS" | sed -n 's/.*clusters=\([0-9]\+\).*/\1/p')
  FEC_ARQ_ATTEMPTS=$(echo "$ARQ_STATS" | sed -n 's/.*attempts=\([0-9]\+\).*/\1/p')
fi

# Extract client stage timing breakdown when available.
FEC_STAGES_LINE=$(grep -E '^\[fec-client-stages\] ' "$CLI_LOG" | tail -n1 || true)
FEC_DIAL_MS=$(echo "$FEC_STAGES_LINE" | sed -n 's/.*dial_ms=\([0-9]\+\).*/\1/p')
FEC_HEADER_MS=$(echo "$FEC_STAGES_LINE" | sed -n 's/.*header_ms=\([0-9]\+\).*/\1/p')
FEC_SEND_BLOCKS_MS=$(echo "$FEC_STAGES_LINE" | sed -n 's/.*send_blocks_ms=\([0-9]\+\).*/\1/p')
FEC_ARQ_DRAIN_MS=$(echo "$FEC_STAGES_LINE" | sed -n 's/.*arq_drain_ms=\([0-9]\+\).*/\1/p')
FEC_TX_STATS_MS=$(echo "$FEC_STAGES_LINE" | sed -n 's/.*tx_stats_ms=\([0-9]\+\).*/\1/p')
FEC_POST_WAIT_MS=$(echo "$FEC_STAGES_LINE" | sed -n 's/.*post_wait_ms=\([0-9]\+\).*/\1/p')
FEC_KEEP_STOP_MS=$(echo "$FEC_STAGES_LINE" | sed -n 's/.*keep_stop_ms=\([0-9]\+\).*/\1/p')
FEC_TOTAL_MS=$(echo "$FEC_STAGES_LINE" | sed -n 's/.*total_ms=\([0-9]\+\).*/\1/p')

# Extract receiver DONE wait time (client-side).
FEC_DONE_LINE=$(grep -E '^\[fec-client-done\] ' "$CLI_LOG" | tail -n1 || true)
FEC_DONE_WAIT_MS=$(echo "$FEC_DONE_LINE" | sed -n 's/.*wait_ms=\([0-9]\+\).*/\1/p')
FEC_DONE_OK=$(echo "$FEC_DONE_LINE" | sed -n 's/.*ok=\([0-9]\+\).*/\1/p')
FEC_DONE_WRITTEN=$(echo "$FEC_DONE_LINE" | sed -n 's/.*written=\([0-9]\+\).*/\1/p')

# Extract encode/send time from client-stats line (diagnostic: RaptorQ encode + actual send call time).
FEC_CLIENT_STATS_LINE=$(grep -E '^\[client-stats\] ' "$CLI_LOG" | tail -n1 || true)
FEC_ENC_MS=$(echo "$FEC_CLIENT_STATS_LINE" | sed -n 's/.*enc_ms=\([0-9.\-]\+\).*/\1/p')
FEC_SEND_MS=$(echo "$FEC_CLIENT_STATS_LINE" | sed -n 's/.*send_ms=\([0-9.\-]\+\).*/\1/p')

echo "[run] proto=quic_fec bitrate=${BITRATE_MBPS}Mbps rtt=${RTT_MS}ms loss=${LOSS_DESC} dur_ms=${DUR_MS} dur_ms_client=${DUR_MS_CLIENT} timed_out=${TIMED_OUT} client_ok=${CLIENT_OK} client_rc=${RC} md5_ok=${MD5_OK} s_mbps=${S_MBPS}${run_tail} overhead_ratio=${OVERHEAD_RATIO} file_bytes=${FILE_SIZE} tx_bytes=${TX_BYTES} rx_bytes=${RX_BYTES} netem_sent_pkts=${NETEM_SENT_PKTS} netem_dropped_pkts=${NETEM_DROPPED_PKTS} netem_sent_bytes=${NETEM_SENT_BYTES} netem_drop_rate=${NETEM_DROP_RATE:-} fec_dial_ms=${FEC_DIAL_MS:-} fec_header_ms=${FEC_HEADER_MS:-} fec_send_blocks_ms=${FEC_SEND_BLOCKS_MS:-} fec_arq_drain_ms=${FEC_ARQ_DRAIN_MS:-} fec_tx_stats_ms=${FEC_TX_STATS_MS:-} fec_post_wait_ms=${FEC_POST_WAIT_MS:-} fec_keep_stop_ms=${FEC_KEEP_STOP_MS:-} fec_total_ms=${FEC_TOTAL_MS:-} fec_done_wait_ms=${FEC_DONE_WAIT_MS:-} fec_done_ok=${FEC_DONE_OK:-} fec_done_written=${FEC_DONE_WRITTEN:-} fec_enc_ms=${FEC_ENC_MS:-} fec_send_ms=${FEC_SEND_MS:-} fec_quic_sent_pkts=${FEC_QUIC_SENT_PKTS:-} fec_quic_sent_bytes=${FEC_QUIC_SENT_BYTES:-} fec_quic_sent_short_pkts=${FEC_QUIC_SENT_SHORT_PKTS:-} fec_quic_sent_short_bytes=${FEC_QUIC_SENT_SHORT_BYTES:-} fec_quic_lost_1rtt_pkts=${FEC_QUIC_LOST_1RTT_PKTS:-} fec_quic_acked_1rtt_pkts=${FEC_QUIC_ACKED_1RTT_PKTS:-} fec_quic_srtt_ms=${FEC_QUIC_SRTT_MS:-} fec_quic_min_rtt_ms=${FEC_QUIC_MIN_RTT_MS:-} fec_quic_latest_rtt_ms=${FEC_QUIC_LATEST_RTT_MS:-} fec_quic_cwnd_bytes=${FEC_QUIC_CWND_BYTES:-} fec_quic_inflight_bytes=${FEC_QUIC_INFLIGHT_BYTES:-} fec_quic_inflight_pkts=${FEC_QUIC_INFLIGHT_PKTS:-} fec_quic_overhead_ratio=${FEC_QUIC_OVERHEAD_RATIO:-} arq_clusters=${FEC_ARQ_CLUSTERS:-} arq_attempts=${FEC_ARQ_ATTEMPTS:-} arq_tx_source_symbols=${FEC_ARQ_TX_SOURCE_SYMBOLS:-} arq_tx_repairs=${FEC_ARQ_TX_REPAIRS:-} arq_fec_overhead=${FEC_ARQ_FEC_OVERHEAD:-}" >&2

# Cleanup temp logs
# - Keep logs when a failure occurs (no RL_OBS) or residual_erasures=1.
# - Also keep logs when BG=1 (debug mode).
if [[ "${BG:-0}" == "1" ]]; then
  echo "[bg] server log: $SRV_LOG" >&2
  echo "[bg] client log: $CLI_LOG" >&2
else
  if [[ -n "$RL_OBS" && "$KEEP_LOGS" == "0" ]]; then
    rm -f "$CLI_LOG" "$SRV_LOG"
  fi
fi

exit 0
