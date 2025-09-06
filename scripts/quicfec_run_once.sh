#!/usr/bin/env bash
set -euo pipefail

# Single trial QUIC-FEC run for RL. Configurable via env vars.
# - Sets up/refreshes a netns and veth pair, configures tc for RTT/loss/rate.
# - Starts server in the namespace, runs client on host once.
# - Extracts last [rl-observation] line from server log and appends to OBS_JSONL.
#
# Env vars (with defaults):
#   NS=qns, PORT=45300
#   BITRATE_MBPS=10, RTT_MS=100, LOSS_PCT=0
#   LOSS_MODE=  # optional; overrides LOSS_PCT when set. Formats:
#               #   none
#               #   iid:5           (5% i.i.d. loss)
#               #   gemodel:p,r,h,k (Gilbert-Elliott model, percents)
#   FILE=$ROOT/go/test_data/train_FD001.txt
#   K=40, SYMBOL_BYTES=1200, R0=6, W=8, DDL_MS=50, RSTEP=4, ALPHA=0.6, ACK_EVERY=8, MAX_ATTEMPTS=8
#   OBS_JSONL=/tmp/quicfec_rl.jsonl
#   POST_WAIT=0s (linger after client send; keep at 0s for fastest runs)
#   SRV_TIMEOUT=10s (server max lifetime; lower keeps runs bounded)
#   FORCE_BUILD=0 (set to 1 to force rebuilding Go binaries)

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN_DIR="$ROOT/go/bin"

NS=${NS:-qns}
PORT=${PORT:-45300}

BITRATE_MBPS=${BITRATE_MBPS:-10}
RTT_MS=${RTT_MS:-100}
LOSS_PCT=${LOSS_PCT:-0}
RATE="${BITRATE_MBPS}mbit"

FILE=${FILE:-"$ROOT/go/test_data/train_FD001.txt"}
OBS_JSONL=${OBS_JSONL:-/tmp/quicfec_rl.jsonl}

K=${K:-40}
SYMBOL_BYTES=${SYMBOL_BYTES:-1200}
R0=${R0:-6}
W=${W:-8}
DDL_MS=${DDL_MS:-150}
RSTEP=${RSTEP:-4}
ALPHA=${ALPHA:-0.6}
ACK_EVERY=${ACK_EVERY:-8}
MAX_ATTEMPTS=${MAX_ATTEMPTS:-8}
PACE_US=${PACE_US:-0}
if [[ -z "${POST_WAIT+x}" || -z "${POST_WAIT}" ]]; then
  # Default linger: ~3*RTT, clamped to [200ms, 800ms] to let tail datagrams/ARQ settle
  WAIT_MS=$(( RTT_MS * 3 ))
  if [[ $WAIT_MS -lt 200 ]]; then WAIT_MS=200; fi
  if [[ $WAIT_MS -gt 800 ]]; then WAIT_MS=800; fi
  POST_WAIT="${WAIT_MS}ms"
fi
SRV_TIMEOUT=${SRV_TIMEOUT:-15s}
# Observation wait budget in seconds (default: derived from SRV_TIMEOUT if of the form \d+s, else 30s)
if [[ -z "${OBS_WAIT_SECS:-}" ]]; then
  if [[ "$SRV_TIMEOUT" =~ ^([0-9]+)s$ ]]; then
    OBS_WAIT_SECS=${BASH_REMATCH[1]}
  else
    OBS_WAIT_SECS=30
  fi
fi

# Allow overriding DDL via env; default aligns with DDL_MS used elsewhere
DDL_MS=${DDL_MS:-150}

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

# Reset netns and (re)build binaries
"$ROOT/scripts/netns_reset.sh" "$NS"
# Rebuild if forced, binaries missing, or any Go source is newer than the binaries
NEED_BUILD=0
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

FILE_SIZE=$(stat -c%s "$FILE")

# Configure qdiscs: half RTT on each direction; apply TBF at root and NETEM as child on host side
half=$(( RTT_MS / 2 ))
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
    NETEM_ARGS+=(loss gemodel ${p}% ${r}% ${h}% ${k}%) ;;
  ""|*)
    NETEM_ARGS+=(loss ${LOSS_PCT}%) ;;
esac

# Apply TBF at root to enforce rate, then NETEM as child for delay/loss
sudo tc qdisc replace dev veth0 root handle 1: tbf rate ${RATE} burst 32kb latency 400ms
sudo tc qdisc replace dev veth0 parent 1:1 handle 10: netem "${NETEM_ARGS[@]}"
sudo ip netns exec "$NS" tc qdisc del dev veth1 root 2>/dev/null || true
sudo ip netns exec "$NS" tc qdisc replace dev veth1 root netem delay ${half}ms

# JSONL for RL obs
touch "$OBS_JSONL"

# Run server (logs in /tmp/quic_fec_srv.* for easy tailing)
SRV_LOG=$(mktemp -t quic_fec_srv.XXXXXX.log)
sudo ip netns exec "$NS" bash -lc "ulimit -n 1048576; '$BIN_DIR/quicfec-server' -addr 10.10.0.2:$PORT -out '$ROOT/go/test_data' -rx-ddl ${DDL_MS}ms -timeout ${SRV_TIMEOUT}" >"$SRV_LOG" 2>&1 & SP=$!
sleep 0.1

# Run client (logs in /tmp/quic_fec_cli.*)
CLI_LOG=$(mktemp -t quic_fec_cli.XXXXXX.log)
export QUIC_FEC_CC_BYPASS=1
START=$(date +%s%N)
pace_arg=""
if [[ "${PACE_US:-0}" -le 0 ]]; then
  # Auto pace: approximate dgram size (symbol + FEC header + QUIC/UDP/IP overhead)
  # Use a conservative +64B overhead fudge.
  local_sz=$(( SYMBOL_BYTES + 64 ))
  # Inter-packet gap microseconds at the target rate: us = (bytes*8 / (Mbps*1e6)) * 1e6
  # Simplifies to us = (bytes*8) / (Mbps)
  if [[ ${BITRATE_MBPS} -gt 0 && ${local_sz} -gt 0 ]]; then
    PACE_US=$(( (local_sz * 8 + BITRATE_MBPS - 1) / BITRATE_MBPS ))
    # Clamp to a minimum of 200us to avoid tight spinning on very high rates
    if [[ ${PACE_US} -lt 200 ]]; then PACE_US=200; fi
  else
    PACE_US=0
  fi
fi
if [[ "${PACE_US}" -gt 0 ]]; then
  pace_arg="-pace ${PACE_US}us"
fi
"$BIN_DIR/quicfec-client" -addr 10.10.0.2:$PORT -file "$FILE" -N $((K+R0)) -K "$K" -L "$SYMBOL_BYTES" \
  -post-wait "$POST_WAIT" -ack-every "$ACK_EVERY" -dgram-warn 1400 -arq -R0 "$R0" -W "$W" -Rstep "$RSTEP" -alpha "$ALPHA" -max-attempts "$MAX_ATTEMPTS" -loss 0 $pace_arg \
  >"$CLI_LOG" 2>&1 || true
END=$(date +%s%N)

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

DUR_MS=$(( (END-START)/1000000 ))

# Extract server observation (preferred)
KEEP_LOGS=0
if [[ -n "$RL_OBS" ]]; then
  echo "$RL_OBS" >>"$OBS_JSONL"
  echo "$RL_OBS" >&2
  # If residual_erasures reported, keep logs for diagnosis and print tails
  if echo "$RL_OBS" | grep -q '"residual_erasures"[[:space:]]*:[[:space:]]*1'; then
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

# Optional: echo a concise run summary
S_LINE=$(grep -E "^\[server-stats\]" "$SRV_LOG" | tail -n1 || true)
if [[ -n "$S_LINE" ]]; then
  S_DUR=$(echo "$S_LINE" | sed -n 's/.*dur_s=\([0-9.\-]\+\).*/\1/p')
  if [[ -n "$S_DUR" && "$S_DUR" != "0" ]]; then
    S_MBPS=$(awk -v sz="$FILE_SIZE" -v ds="$S_DUR" 'BEGIN{printf "%.2f", (sz*8.0/1000000.0)/ds}')
  else
    if [[ "$DUR_MS" -gt 0 ]]; then
      S_MBPS=$(awk -v sz="$FILE_SIZE" -v ms="$DUR_MS" 'BEGIN{printf "%.2f", (sz*8.0/1000000.0)/(ms/1000.0)}')
    else
      S_MBPS=0
    fi
  fi
  LOSS_DESC="${LOSS_PCT}%"
  if [[ -n "${LOSS_MODE:-}" ]]; then
    LOSS_DESC="${LOSS_MODE}"
  fi
  echo "[run] bitrate=${BITRATE_MBPS}Mbps rtt=${RTT_MS}ms loss=${LOSS_DESC} dur_ms=${DUR_MS} md5_ok=${MD5_OK} s_mbps=${S_MBPS}" >&2
fi

# Cleanup temp logs
# Keep logs when a failure occurs (no RL_OBS) or residual_erasures=1; otherwise clean up
if [[ -n "$RL_OBS" && "$KEEP_LOGS" == "0" ]]; then
  rm -f "$CLI_LOG" "$SRV_LOG"
fi

# If BG=1, print log locations and return immediately so caller can tail /tmp/quic_fec*
if [[ "${BG:-0}" == "1" ]]; then
  echo "[bg] server log: $SRV_LOG" >&2
  echo "[bg] client log: $CLI_LOG" >&2
fi

exit 0
