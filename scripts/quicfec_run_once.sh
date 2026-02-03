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
#   K=40, SYMBOL_BYTES=1200, R0=6, W=8, RSTEP=4, ACK_EVERY=8, MAX_ATTEMPTS=8
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

K=${K:-16}
SYMBOL_BYTES=${SYMBOL_BYTES:-1200}
R0=${R0:-0}
W=${W:-8}
RSTEP=${RSTEP:-4}
ACK_EVERY=${ACK_EVERY:-8}
MAX_ATTEMPTS=${MAX_ATTEMPTS:-0}
USE_ARQ=${USE_ARQ:-1}
PACE_US=${PACE_US:-}
TRANSPORT=${TRANSPORT:-dgram}
if [[ -z "${POST_WAIT+x}" || -z "${POST_WAIT}" ]]; then
  # Default linger: 0s. QUIC-FEC now waits for an explicit server->client DONE ACK.
  POST_WAIT="0s"
fi
# Experiment-level transfer timeout in seconds (15s by default).
TIMEOUT_S=${TIMEOUT_S:-15}
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

if ! sudo -n true 2>/dev/null; then
  echo "[error] sudo privileges are required. Run 'sudo -v' once and rerun." >&2
  exit 1
fi

SETUP_ONLY=${SETUP_ONLY:-0}
SKIP_NETNS_RESET=${SKIP_NETNS_RESET:-0}
SKIP_TC_CONFIG=${SKIP_TC_CONFIG:-0}
SKIP_SYSCTL=${SKIP_SYSCTL:-0}
SKIP_BUILD=${SKIP_BUILD:-0}



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
sudo ip netns exec "$NS" bash -lc "ulimit -n 1048576; '$BIN_DIR/quicfec-server' -addr ${SRV_IP}:$PORT -out '$OUT_DIR' -timeout ${SRV_TIMEOUT}" >"$SRV_LOG" 2>&1 & SP=$!

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
# Congestion control defaults:
# - Always enable CC by default (bypass is lab-only).
# - Default algorithm: BBRv2.
export QUIC_FEC_CC_BYPASS=${QUIC_FEC_CC_BYPASS:-0}
export QUIC_FEC_CC_ALGO=${QUIC_FEC_CC_ALGO:-bbrv2}

# Optional: override initial congestion window (packets).
# This is a lab-only knob to reduce short-flow startup artifacts at higher RTT.
#
# Priority:
#   1) If QUIC_GO_INITIAL_CWND_PKTS is already set by caller, keep it.
#   2) Else if INITIAL_CWND_PKTS is set, export it.
#   3) Else if AUTO_CWND=1 and loss=0, set cwnd to approx BDP in packets.
INITIAL_CWND_PKTS=${INITIAL_CWND_PKTS:-}
AUTO_CWND=${AUTO_CWND:-0}
if [[ -z "${QUIC_GO_INITIAL_CWND_PKTS:-}" ]]; then
  if [[ -n "${INITIAL_CWND_PKTS}" ]]; then
    export QUIC_GO_INITIAL_CWND_PKTS="${INITIAL_CWND_PKTS}"
  elif [[ "${AUTO_CWND}" == "1" ]]; then
    loss_is_zero=0
    if [[ -n "${LOSS_MODE:-}" ]]; then
      [[ "${LOSS_MODE}" == "none" ]] && loss_is_zero=1
    else
      [[ "${LOSS_PCT}" == "0" ]] && loss_is_zero=1
    fi
    if [[ "${loss_is_zero}" == "1" && "${BITRATE_MBPS}" -gt 0 && "${RTT_MS}" -gt 0 ]]; then
      # BDP bytes = rate(bytes/s) * RTT(s)
      # rate(bytes/s) = Mbps * 1e6 / 8
      # pkts ~= ceil(BDP_bytes / InitialPacketSize)
      # Use SYMBOL_BYTES+64 as a conservative packet size proxy (matches pacing calc).
      pkt_bytes=$(( SYMBOL_BYTES + 64 ))
      bdp_bytes=$(( (BITRATE_MBPS * 1000000 / 8) * RTT_MS / 1000 ))
      cwnd_pkts=$(( (bdp_bytes + pkt_bytes - 1) / pkt_bytes ))
      # Keep within a sane range; default quic-go is 32.
      if [[ ${cwnd_pkts} -lt 32 ]]; then cwnd_pkts=32; fi
      if [[ ${cwnd_pkts} -gt 256 ]]; then cwnd_pkts=256; fi
      export QUIC_GO_INITIAL_CWND_PKTS="${cwnd_pkts}"
    fi
  fi
fi

# Byte counters on host veth (network-layer; includes headers). These are used
# to estimate overhead (extra transmitted bytes over the file payload).
TX0=0; RX0=0
if [[ -r "/sys/class/net/${VETH_HOST}/statistics/tx_bytes" ]]; then
  TX0=$(cat "/sys/class/net/${VETH_HOST}/statistics/tx_bytes" 2>/dev/null || echo 0)
  RX0=$(cat "/sys/class/net/${VETH_HOST}/statistics/rx_bytes" 2>/dev/null || echo 0)
fi

# IMPORTANT: tc netem drops happen in the qdisc. Dropped packets usually do NOT
# contribute to /sys tx_bytes, which would under-report overhead under loss.
qdisc_dropped_pkts() {
  # Count drops from the netem qdisc only (tbf also reports the same drop count).
  # Token can appear as "(dropped" depending on tc version.
  sudo tc -s qdisc show dev "$VETH_HOST" 2>/dev/null | awk '
    /^qdisc/ { in_netem = ($2 == "netem"); next }
    in_netem && /dropped/ {
      for (i=1; i<=NF; i++) {
        if ($i ~ /dropped/) {
          v = $(i+1)
          gsub(/[^0-9]/, "", v)
          if (v != "") sum += v
        }
      }
    }
    END { print sum+0 }
  '
}
DROP0=$(qdisc_dropped_pkts)
START=$(date +%s%N)
pace_arg=""
# Pacing:
# - By default, disable app-level pacing and rely on QUIC (BBRv2) + tc shaping.
#   The previous auto-pacing mode uses microsecond sleeps which can oversleep and
#   underfill the link, significantly lowering measured goodput.
# - Set PACE_US=0 to explicitly disable.
# - Set PACE_US>0 to force a fixed inter-packet gap.
# - Set PACE_AUTO=1 to restore the old auto-computed pacing behavior.
PACE_AUTO=${PACE_AUTO:-0}
if [[ -z "${PACE_US}" ]]; then
  if [[ "${PACE_AUTO}" == "1" ]]; then
    # Auto pace: approximate dgram size (symbol + FEC header + QUIC/UDP/IP overhead)
    # Use a conservative +64B overhead fudge.
    local_sz=$(( SYMBOL_BYTES + 64 ))
    # Inter-packet gap microseconds at the target rate: us = (bytes*8 / (Mbps*1e6)) * 1e6
    # Simplifies to us = (bytes*8) / (Mbps)
    if [[ ${BITRATE_MBPS} -gt 0 && ${local_sz} -gt 0 ]]; then
      PACE_US=$(( (local_sz * 8 + BITRATE_MBPS - 1) / BITRATE_MBPS ))
      # Clamp to a minimum to avoid tight spinning on very high rates.
      if [[ ${PACE_US} -lt 50 ]]; then PACE_US=50; fi
    else
      PACE_US=0
    fi
  else
    PACE_US=0
  fi
fi
if [[ -n "${PACE_US}" && "${PACE_US}" -gt 0 ]]; then
  pace_arg="-pace ${PACE_US}us"
fi

arq_flag=""
if [[ "${USE_ARQ}" == "1" ]]; then
  arq_flag="-arq"
fi
if command -v timeout >/dev/null 2>&1; then
  TIMEOUT_SIGNAL=${TIMEOUT_SIGNAL:-KILL}
  timeout --signal=${TIMEOUT_SIGNAL} ${TIMEOUT_S}s \
    "$BIN_DIR/quicfec-client" -addr ${SRV_IP}:$PORT -file "$FILE" -N $((K+R0)) -K "$K" -L "$SYMBOL_BYTES" \
      -post-wait "$POST_WAIT" -ack-every "$ACK_EVERY" -dgram-warn 1400 -transport "$TRANSPORT" $arq_flag -R0 "$R0" -W "$W" -Rstep "$RSTEP" -max-attempts "$MAX_ATTEMPTS" -loss 0 $pace_arg \
      >"$CLI_LOG" 2>&1 || RC=$?
else
  "$BIN_DIR/quicfec-client" -addr ${SRV_IP}:$PORT -file "$FILE" -N $((K+R0)) -K "$K" -L "$SYMBOL_BYTES" \
    -post-wait "$POST_WAIT" -ack-every "$ACK_EVERY" -dgram-warn 1400 -transport "$TRANSPORT" $arq_flag -R0 "$R0" -W "$W" -Rstep "$RSTEP" -max-attempts "$MAX_ATTEMPTS" -loss 0 $pace_arg \
    >"$CLI_LOG" 2>&1 || RC=$?
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

DROP1=$(qdisc_dropped_pkts)
DROP_PKTS=$(( DROP1 - DROP0 ))
if [[ "$DROP_PKTS" -lt 0 ]]; then DROP_PKTS=0; fi

TX1=$TX0; RX1=$RX0
if [[ -r "/sys/class/net/${VETH_HOST}/statistics/tx_bytes" ]]; then
  TX1=$(cat "/sys/class/net/${VETH_HOST}/statistics/tx_bytes" 2>/dev/null || echo "$TX0")
  RX1=$(cat "/sys/class/net/${VETH_HOST}/statistics/rx_bytes" 2>/dev/null || echo "$RX0")
fi
TX_BYTES=$(( TX1 - TX0 ))
RX_BYTES=$(( RX1 - RX0 ))
if [[ "$TX_BYTES" -lt 0 ]]; then TX_BYTES=0; fi
if [[ "$RX_BYTES" -lt 0 ]]; then RX_BYTES=0; fi

# Adjust tx_bytes to include locally-dropped packets (best-effort estimate).
# Use the same conservative size estimate as pacing (symbol + 64B overhead).
EST_WIRE_BYTES=${EST_WIRE_BYTES:-$(( SYMBOL_BYTES + 64 ))}
DROP_BYTES_EST=$(( DROP_PKTS * EST_WIRE_BYTES ))
TX_BYTES_ADJ=$(( TX_BYTES + DROP_BYTES_EST ))

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
wait $SP 2>/dev/null || true

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
MERGED_LINE=$(RL_OBS_LINE="$RL_OBS" CC_EST_LINE="$CC_EST" ARQ_STATS_LINE="$ARQ_STATS" CLI_STAGES_LINE="$CLI_STAGES" FILE_SIZE="$FILE_SIZE" K_VAL="$K" R0_VAL="$R0" DUR_MS_VAL="$DUR_MS" MD5_OK_VAL="$MD5_OK" TIMED_OUT_VAL="$TIMED_OUT" python3 - <<'PY'
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
  md5_ok = int(os.environ.get('MD5_OK_VAL', '1') or '1')
except Exception:
  md5_ok = 1

try:
  timed_out = int(os.environ.get('TIMED_OUT_VAL', '0') or '0')
except Exception:
  timed_out = 0

try:
  dur_ms = float(os.environ.get('DUR_MS_VAL', '0') or '0')
except Exception:
  dur_ms = 0.0

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
  # tx_retx_rounds: sender-side count of repair rounds appended (RSTEP-trigger events)
  # in this transfer. This is the new policy signal replacing old NACK/ARQ metrics.
  'tx_retx_rounds': 0,
  'residual_erasures': int(residual_erasures),
  'fec_rate': float(R0) / float(max(1, K)),
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

  # tx_retx_rounds: sender-side count of repair rounds appended.
  # The client reports total "attempts" (each non-empty repair batch increments it).
  payload['tx_retx_rounds'] = int(max(0, arq_attempts_total))

  # Keep derived debug-only field (not used by policy) for analysis.
  if arq_clusters_total > 0:
    payload['tx_retx_rounds_mean'] = float(arq_attempts_total) / float(arq_clusters_total)

  # fec_overhead: repairs/source across initial R0 and ARQ appended repairs.
  try:
    if tx_source > 0:
      payload['fec_overhead'] = float(tx_repairs) / float(tx_source)
    else:
      payload['fec_overhead'] = 0.0
  except Exception:
    payload['fec_overhead'] = 0.0

stgj = parse_kv_line('[fec-client-stages]', stg)

# Goodput estimate: file_size over DUR_MS.
# DUR_MS prefers server-e2e when available, otherwise falls back to client wall time.
try:
  if dur_ms is not None and dur_ms > 0 and file_size > 0:
    goodput_mbps = (float(file_size) * 8.0 / 1e6) / (float(dur_ms) / 1000.0)
    payload['goodput'] = float(goodput_mbps)
    payload['goodput_mbps'] = float(goodput_mbps)
except Exception:
  pass

sys.stdout.write('[rl-observation] ' + json.dumps(payload, separators=(',', ':')))
PY
)
echo "$MERGED_LINE" >>"$OBS_JSON"
echo "$MERGED_LINE" >&2

# Preserve logs for any failing run (md5 mismatch / timeout / client error), even if
# residual_erasures=0. Without this, intermittent failures are hard to diagnose.
if [[ "$MD5_OK" == "0" || "$CLIENT_OK" == "0" || "$TIMED_OUT" == "1" ]]; then
  KEEP_LOGS=1
  echo "[diag] run failed (md5_ok=${MD5_OK} timed_out=${TIMED_OUT} client_ok=${CLIENT_OK} rc=${RC}); preserving logs:" >&2
  echo "[diag] server log: $SRV_LOG" >&2
  echo "[diag] client log: $CLI_LOG" >&2
  echo "[diag] ---- server log tail ----" >&2
  tail -n 200 "$SRV_LOG" >&2 || true
  echo "[diag] ---- client log tail ----" >&2
  tail -n 200 "$CLI_LOG" >&2 || true
fi

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

# Echo a concise run summary (always)
S_LINE=$(grep -E "^\[server-stats\]" "$SRV_LOG" | tail -n1 || true)
S_DUR=""
if [[ -n "$S_LINE" ]]; then
  S_DUR=$(echo "$S_LINE" | sed -n 's/.*dur_s=\([0-9.\-]\+\).*/\1/p')
fi

# Symbol-plane metrics from the client (excludes handshake / control):
# [client-stats] dgrams=... bytes=... dur_s=... mbps=...
CLI_STATS_LINE=$(grep -E '^\[client-stats\] ' "$CLI_LOG" | tail -n1 || true)
CLI_SYM_BYTES=""
CLI_SYM_MBPS=""
if [[ -n "$CLI_STATS_LINE" ]]; then
  CLI_SYM_BYTES=$(echo "$CLI_STATS_LINE" | sed -n 's/.*bytes=\([0-9]\+\).*/\1/p')
  CLI_SYM_MBPS=$(echo "$CLI_STATS_LINE" | sed -n 's/.*mbps=\([0-9.\-]\+\).*/\1/p')
fi

# Sender-reported repair overhead (repairs/source), when ARQ is enabled:
# [arq-stats] ... tx_source_symbols=... tx_repairs=... fec_overhead=...
CLI_ARQ_LINE=$(grep -E '^\[arq-stats\] ' "$CLI_LOG" | tail -n1 || true)
CLI_TX_SOURCE=""
CLI_TX_REPAIRS=""
CLI_FEC_OVH=""
if [[ -n "$CLI_ARQ_LINE" ]]; then
  CLI_TX_SOURCE=$(echo "$CLI_ARQ_LINE" | sed -n 's/.*tx_source_symbols=\([0-9]\+\).*/\1/p')
  CLI_TX_REPAIRS=$(echo "$CLI_ARQ_LINE" | sed -n 's/.*tx_repairs=\([0-9]\+\).*/\1/p')
  CLI_FEC_OVH=$(echo "$CLI_ARQ_LINE" | sed -n 's/.*fec_overhead=\([0-9.\-]\+\).*/\1/p')
fi
SYM_OVERHEAD=""
if [[ -n "$CLI_SYM_BYTES" && "$FILE_SIZE" -gt 0 ]]; then
  # overhead ratio = (symbol_bytes - file_bytes) / file_bytes
  SYM_OVERHEAD=$(awk -v sb="$CLI_SYM_BYTES" -v fb="$FILE_SIZE" 'BEGIN{printf "%.3f", (sb-fb)/fb}')
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
sym_tail=""
if [[ -n "$CLI_SYM_BYTES" ]]; then
  sym_tail+=" sym_bytes=${CLI_SYM_BYTES}"
fi
if [[ -n "$SYM_OVERHEAD" ]]; then
  sym_tail+=" sym_overhead=${SYM_OVERHEAD}"
fi
if [[ -n "$CLI_SYM_MBPS" ]]; then
  sym_tail+=" cli_mbps=${CLI_SYM_MBPS}"
fi
if [[ -n "$CLI_FEC_OVH" ]]; then
  sym_tail+=" fec_ovh=${CLI_FEC_OVH}"
fi
if [[ -n "$CLI_TX_SOURCE" ]]; then
  sym_tail+=" tx_source_symbols=${CLI_TX_SOURCE}"
fi
if [[ -n "$CLI_TX_REPAIRS" ]]; then
  sym_tail+=" tx_repairs=${CLI_TX_REPAIRS}"
fi

OVERHEAD_SYS=""
OVERHEAD=""
if [[ "$FILE_SIZE" -gt 0 ]]; then
  OVERHEAD_SYS=$(awk -v tb="$TX_BYTES" -v fb="$FILE_SIZE" 'BEGIN{printf "%.3f", (tb-fb)/fb}')
  OVERHEAD=$(awk -v tb="$TX_BYTES_ADJ" -v fb="$FILE_SIZE" 'BEGIN{printf "%.3f", (tb-fb)/fb}')
fi

# Real E2E delay (sender start -> receiver finished decode/deliver), using shared host clock.
SENDER_LINE=$(grep -E '^\[sender-e2e\] ' "$CLI_LOG" | tail -n1 || true)
SENDER_START_NS=$(echo "$SENDER_LINE" | sed -n 's/.*start_ns=\([0-9]\+\).*/\1/p')
RECV_LINE_REAL=$(grep -E '^\[receiver-e2e\] ' "$SRV_LOG" | tail -n1 || true)
RECV_END_NS=$(echo "$RECV_LINE_REAL" | sed -n 's/.*end_ns=\([0-9]\+\).*/\1/p')
RECV_OK_REAL=$(echo "$RECV_LINE_REAL" | sed -n 's/.*ok=\([0-9]\+\).*/\1/p')
E2E_DELAY_MS="nan"
if [[ -n "$SENDER_START_NS" && -n "$RECV_END_NS" && "${RECV_OK_REAL:-0}" == "1" ]]; then
  E2E_DELAY_MS=$(awk -v a="$SENDER_START_NS" -v b="$RECV_END_NS" 'BEGIN{d=(b-a)/1000000.0; if(d<0)d=0; printf "%.3f", d}')
fi

echo "[run] proto=quic_fec bitrate=${BITRATE_MBPS}Mbps rtt=${RTT_MS}ms loss=${LOSS_DESC} dur_ms=${DUR_MS} dur_ms_client=${DUR_MS_CLIENT} e2e_delay_ms=${E2E_DELAY_MS} sender_start_ns=${SENDER_START_NS:-} receiver_end_ns=${RECV_END_NS:-} srv_log=${SRV_LOG} cli_log=${CLI_LOG} timed_out=${TIMED_OUT} client_ok=${CLIENT_OK} client_rc=${RC} md5_ok=${MD5_OK} s_mbps=${S_MBPS}${run_tail}${sym_tail} file_bytes=${FILE_SIZE} tx_bytes=${TX_BYTES} tx_bytes_adj=${TX_BYTES_ADJ} drop_pkts=${DROP_PKTS} overhead_sys=${OVERHEAD_SYS} overhead=${OVERHEAD} rx_bytes=${RX_BYTES}" >&2

OVERHEAD_ADJ="${OVERHEAD}"
echo "[run-adj] proto=quic_fec drop_pkts=${DROP_PKTS} tx_bytes_adj=${TX_BYTES_ADJ} overhead_adj=${OVERHEAD_ADJ}" >&2

# Cleanup temp logs
# - Keep logs when a failure occurs (no RL_OBS) or residual_erasures=1.
# - Also keep logs when BG=1 (debug mode).
if [[ "${BG:-0}" == "1" ]]; then
  echo "[bg] server log: $SRV_LOG" >&2
  echo "[bg] client log: $CLI_LOG" >&2
else
  if [[ "${KEEP_E2E_LOGS:-0}" == "1" ]]; then
    KEEP_LOGS=1
    echo "[diag] KEEP_E2E_LOGS=1; preserving logs:" >&2
    echo "[diag] server log: $SRV_LOG" >&2
    echo "[diag] client log: $CLI_LOG" >&2
  fi
  if [[ -n "$RL_OBS" && "$KEEP_LOGS" == "0" ]]; then
    rm -f "$CLI_LOG" "$SRV_LOG"
  fi
fi

exit 0
