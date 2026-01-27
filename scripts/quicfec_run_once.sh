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
#   K=40, SYMBOL_BYTES=1200, R0=6, W=8, DDL_MS=150, RSTEP=4, ALPHA=0.6, ACK_EVERY=8, MAX_ATTEMPTS=8
#   OBS_JSON=/tmp/quicfec_rl.json
#   POST_WAIT=0s (linger after client send; keep at 0s for fastest runs)
#   SRV_TIMEOUT=10s (server max lifetime; lower keeps runs bounded)
#   FORCE_BUILD=0 (set to 1 to force rebuilding Go binaries)

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN_DIR="$ROOT/go/bin"

NS=${NS:-qns}
PORT=${PORT:-45300}

BITRATE_MBPS=${BITRATE_MBPS:-10}
RTT_MS=${RTT_MS:-550}
LOSS_PCT=${LOSS_PCT:-0}
RATE="${BITRATE_MBPS}mbit"

FILE=${FILE:-"$ROOT/go/test_data/train_FD001.txt"}
OBS_JSON=${OBS_JSON:-/tmp/quicfec_rl.json}

K=${K:-30}
SYMBOL_BYTES=${SYMBOL_BYTES:-1032}
R0=${R0:-6}
W=${W:-8}
DDL_MS=${DDL_MS:-150}
RSTEP=${RSTEP:-4}
ALPHA=${ALPHA:-0.6}
ACK_EVERY=${ACK_EVERY:-8}
MAX_ATTEMPTS=${MAX_ATTEMPTS:-0}
USE_ARQ=${USE_ARQ:-1}
PACE_US=${PACE_US:-}
TRANSPORT=${TRANSPORT:-dgram}
if [[ -z "${POST_WAIT+x}" || -z "${POST_WAIT}" ]]; then
  # Default linger: ~3*RTT, clamped to [200ms, 800ms] to let tail datagrams/ARQ settle
  WAIT_MS=$(( RTT_MS * 3 ))
  if [[ $WAIT_MS -lt 200 ]]; then WAIT_MS=200; fi
  if [[ $WAIT_MS -gt 800 ]]; then WAIT_MS=800; fi
  POST_WAIT="${WAIT_MS}ms"
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

SETUP_ONLY=${SETUP_ONLY:-0}
SKIP_NETNS_RESET=${SKIP_NETNS_RESET:-0}
SKIP_TC_CONFIG=${SKIP_TC_CONFIG:-0}
SKIP_SYSCTL=${SKIP_SYSCTL:-0}
SKIP_BUILD=${SKIP_BUILD:-0}

# DDL_MS already defaulted above; kept here historically but now intentionally a no-op.

chmod +x "$ROOT/scripts"/*.sh || true
mkdir -p "$ROOT/go/test_data"
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
  "$ROOT/scripts/netns_reset.sh" "$NS"
else
  # Validate the expected topology exists.
  if ! sudo ip netns list | awk '{print $1}' | grep -qx "$NS"; then
    echo "[error] netns '$NS' not found but SKIP_NETNS_RESET=1" >&2
    exit 2
  fi
  if ! ip link show veth0 &>/dev/null; then
    echo "[error] host veth0 not found but SKIP_NETNS_RESET=1" >&2
    exit 2
  fi
  if ! sudo ip netns exec "$NS" ip link show veth1 &>/dev/null; then
    echo "[error] ns veth1 not found but SKIP_NETNS_RESET=1" >&2
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
  sudo tc qdisc del dev veth0 root 2>/dev/null || true

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
  sudo tc qdisc replace dev veth0 root handle 1: tbf rate ${RATE} burst 32kb latency 400ms
  sudo tc qdisc replace dev veth0 parent 1:1 handle 10: netem "${NETEM_ARGS[@]}"
  sudo ip netns exec "$NS" tc qdisc del dev veth1 root 2>/dev/null || true
  sudo ip netns exec "$NS" tc qdisc replace dev veth1 root netem delay ${half}ms
fi

# JSON (line-oriented) for RL obs
touch "$OBS_JSON"

if [[ "$SETUP_ONLY" == "1" ]]; then
  # Network is configured; nothing else to do.
  exit 0
fi

# Run server (logs in /tmp/quic_fec_srv.* for easy tailing)
SRV_LOG=$(mktemp -t quic_fec_srv.XXXXXX.log)
sudo ip netns exec "$NS" bash -lc "ulimit -n 1048576; '$BIN_DIR/quicfec-server' -addr 10.10.0.2:$PORT -out '$ROOT/go/test_data' -rx-ddl ${DDL_MS}ms -timeout ${SRV_TIMEOUT}" >"$SRV_LOG" 2>&1 & SP=$!
sleep 0.1

# Run client (logs in /tmp/quic_fec_cli.*)
CLI_LOG=$(mktemp -t quic_fec_cli.XXXXXX.log)
export QUIC_FEC_CC_BYPASS=${QUIC_FEC_CC_BYPASS:-1}

# Byte counters on host veth0 (network-layer; includes headers). These are used
# to estimate overhead (extra transmitted bytes over the file payload).
TX0=0; RX0=0
if [[ -r /sys/class/net/veth0/statistics/tx_bytes ]]; then
  TX0=$(cat /sys/class/net/veth0/statistics/tx_bytes 2>/dev/null || echo 0)
  RX0=$(cat /sys/class/net/veth0/statistics/rx_bytes 2>/dev/null || echo 0)
fi
START=$(date +%s%N)
pace_arg=""
# Pacing:
# - If PACE_US is unset, auto-compute an inter-packet gap targeting BITRATE_MBPS.
# - If PACE_US=0, disable app-level pacing and rely on QUIC + tc shaping.
# - If PACE_US>0, use the provided microsecond gap.
if [[ -z "${PACE_US}" ]]; then
  # Auto pace: approximate dgram size (symbol + FEC header + QUIC/UDP/IP overhead)
  # Use a conservative +64B overhead fudge.
  local_sz=$(( SYMBOL_BYTES + 64 ))
  # Inter-packet gap microseconds at the target rate: us = (bytes*8 / (Mbps*1e6)) * 1e6
  # Simplifies to us = (bytes*8) / (Mbps)
  if [[ ${BITRATE_MBPS} -gt 0 && ${local_sz} -gt 0 ]]; then
    PACE_US=$(( (local_sz * 8 + BITRATE_MBPS - 1) / BITRATE_MBPS ))
    # Clamp to a minimum to avoid tight spinning on very high rates.
    # For high-rate experiments (e.g., 100 Mbps), 200us would cap throughput too low.
    if [[ ${PACE_US} -lt 50 ]]; then PACE_US=50; fi
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
  timeout --signal=KILL ${TIMEOUT_S}s \
    "$BIN_DIR/quicfec-client" -addr 10.10.0.2:$PORT -file "$FILE" -N $((K+R0)) -K "$K" -L "$SYMBOL_BYTES" \
      -post-wait "$POST_WAIT" -ack-every "$ACK_EVERY" -dgram-warn 1400 -transport "$TRANSPORT" $arq_flag -R0 "$R0" -W "$W" -Rstep "$RSTEP" -alpha "$ALPHA" -max-attempts "$MAX_ATTEMPTS" -loss 0 $pace_arg \
      >"$CLI_LOG" 2>&1 || RC=$?
else
  "$BIN_DIR/quicfec-client" -addr 10.10.0.2:$PORT -file "$FILE" -N $((K+R0)) -K "$K" -L "$SYMBOL_BYTES" \
    -post-wait "$POST_WAIT" -ack-every "$ACK_EVERY" -dgram-warn 1400 -transport "$TRANSPORT" $arq_flag -R0 "$R0" -W "$W" -Rstep "$RSTEP" -alpha "$ALPHA" -max-attempts "$MAX_ATTEMPTS" -loss 0 $pace_arg \
    >"$CLI_LOG" 2>&1 || RC=$?
fi
RC=${RC:-0}
TIMED_OUT=0
if [[ "$RC" == "124" || "$RC" == "137" ]]; then
  TIMED_OUT=1
fi
END=$(date +%s%N)

TX1=$TX0; RX1=$RX0
if [[ -r /sys/class/net/veth0/statistics/tx_bytes ]]; then
  TX1=$(cat /sys/class/net/veth0/statistics/tx_bytes 2>/dev/null || echo "$TX0")
  RX1=$(cat /sys/class/net/veth0/statistics/rx_bytes 2>/dev/null || echo "$RX0")
fi
TX_BYTES=$(( TX1 - TX0 ))
RX_BYTES=$(( RX1 - RX0 ))
if [[ "$TX_BYTES" -lt 0 ]]; then TX_BYTES=0; fi
if [[ "$RX_BYTES" -lt 0 ]]; then RX_BYTES=0; fi

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
OUT_MD5=$(md5sum "$ROOT/go/test_data/$(basename "$FILE").recv" | awk '{print $1}' || true)
MD5_OK=0; [[ "$IN_MD5" == "$OUT_MD5" ]] && MD5_OK=1

# Timeout => count as failure.
if [[ "$TIMED_OUT" == "1" ]]; then
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

# Extract server observation (preferred)
KEEP_LOGS=0
if [[ -n "$RL_OBS" ]]; then
  # Post-process observation:
  # - Server-side estimated_available_bw_mbps is an arrival-rate estimator and can
  #   collapse to goodput when the sender is app-limited or transfers are short.
  # - For RL we want a sender-side bandwidth estimate derived from transport signals.
  #   We extract the congestion-controller estimate emitted by the client and merge it.
  # Preserve the server estimator under estimated_available_bw_arrival_mbps.
  CC_EST=$(grep -E '^\[cc-estimate\] ' "$CLI_LOG" | tail -n1 || true)
  MERGED_LINE=$(RL_OBS_LINE="$RL_OBS" CC_EST_LINE="$CC_EST" python3 - <<'PY'
import json
import os
import sys

line = os.environ.get('RL_OBS_LINE', '')
cc = os.environ.get('CC_EST_LINE', '')

if not line.startswith('[rl-observation] '):
    sys.stdout.write(line)
    sys.exit(0)

try:
    payload = json.loads(line.split(' ', 1)[1])
except Exception:
    sys.stdout.write(line)
    sys.exit(0)

# Keep a copy of the server's arrival-based estimator.
try:
    payload['estimated_available_bw_arrival_mbps'] = float(payload.get('estimated_available_bw_mbps', 0.0))
except Exception:
    payload['estimated_available_bw_arrival_mbps'] = 0.0

def parse_cc_line(s: str):
  s = (s or '').strip()
  if not s.startswith('[cc-estimate] '):
    return None
  try:
    return json.loads(s.split(' ', 1)[1])
  except Exception:
    return None

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

sys.stdout.write('[rl-observation] ' + json.dumps(payload, separators=(',', ':')))
PY
  )
  echo "$MERGED_LINE" >>"$OBS_JSON"
  echo "$MERGED_LINE" >&2
  # If residual_erasures reported, keep logs for diagnosis and print tails
  if echo "$MERGED_LINE" | grep -q '"residual_erasures"[[:space:]]*:[[:space:]]*1'; then
    KEEP_LOGS=1
    echo "[diag] residual_erasures=1 detected; preserving logs:" >&2
    echo "[diag] server log: $SRV_LOG" >&2
    echo "[diag] client log: $CLI_LOG" >&2
    echo "[diag] ---- server log tail ----" >&2
    tail -n 120 "$SRV_LOG" >&2 || true
    echo "[diag] ---- client log tail ----" >&2
    tail -n 120 "$CLI_LOG" >&2 || true
  fi
else
  echo "[warn] no [rl-observation] found in server logs" >&2
  echo "[warn] server log tail:" >&2
  tail -n 50 "$SRV_LOG" >&2 || true
  echo "[warn] client log tail:" >&2
  tail -n 50 "$CLI_LOG" >&2 || true
fi

# Echo a concise run summary (always)
S_LINE=$(grep -E "^\[server-stats\]" "$SRV_LOG" | tail -n1 || true)
S_DUR=""
if [[ -n "$S_LINE" ]]; then
  S_DUR=$(echo "$S_LINE" | sed -n 's/.*dur_s=\([0-9.\-]\+\).*/\1/p')
fi
if [[ -n "$S_DUR" && "$S_DUR" != "0" ]]; then
  S_MBPS=$(awk -v sz="$FILE_SIZE" -v ds="$S_DUR" 'BEGIN{printf "%.2f", (sz*8.0/1000000.0)/ds}')
else
  if [[ "$DUR_MS" -gt 0 ]]; then
    S_MBPS=$(awk -v sz="$FILE_SIZE" -v ms="$DUR_MS" 'BEGIN{printf "%.2f", (sz*8.0/1000000.0)/(ms/1000.0)}')
  else
    S_MBPS=0
  fi
fi

if [[ "$TIMED_OUT" == "1" ]]; then
  S_MBPS=0
fi

LOSS_DESC="${LOSS_PCT}%"
if [[ -n "${LOSS_MODE:-}" ]]; then
  LOSS_DESC="${LOSS_MODE}"
fi

echo "[run] proto=quic_fec bitrate=${BITRATE_MBPS}Mbps rtt=${RTT_MS}ms loss=${LOSS_DESC} dur_ms=${DUR_MS} dur_ms_client=${DUR_MS_CLIENT} timed_out=${TIMED_OUT} md5_ok=${MD5_OK} s_mbps=${S_MBPS} file_bytes=${FILE_SIZE} tx_bytes=${TX_BYTES} rx_bytes=${RX_BYTES}" >&2

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
