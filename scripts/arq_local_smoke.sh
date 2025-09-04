#!/usr/bin/env bash
set -euo pipefail

# Localhost smoke test: run one or more file transfers without netns/tc, capture [rl-observation].
# No sudo required. Useful for CI or quick validation of metrics and end-to-end flow.

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN_DIR="$ROOT/go/bin"
PORT=${PORT:-45310}
REPS=${REPS:-1}

K=${K:-40}
R0=${R0:-6}
W=${W:-8}
DDL_MS=${DDL_MS:-50}
RSTEP=${RSTEP:-4}
ALPHA=${ALPHA:-0.6}
ACK_EVERY=${ACK_EVERY:-0}
SYMBOL_BYTES=${SYMBOL_BYTES:-1200}

OBS_JSONL=${OBS_JSONL:-/tmp/arq_local_smoke_rl.jsonl}
echo -n >"$OBS_JSONL"

chmod +x "$ROOT/scripts"/*.sh || true

# Build binaries
(cd "$ROOT/go" && go build -o "$BIN_DIR/quicfec-server" ./cmd/quicfec-server && go build -o "$BIN_DIR/quicfec-client" ./cmd/quicfec-client)

FILE="$ROOT/go/test_data/train_FD001.txt"
mkdir -p "$ROOT/go/test_data"

for run in $(seq 1 "$REPS"); do
  SRV_LOG=$(mktemp)
  CLI_LOG=$(mktemp)
  # Start server on localhost
  "$BIN_DIR/quicfec-server" -addr 127.0.0.1:$PORT -out "$ROOT/go/test_data" -rx-ddl ${DDL_MS}ms -timeout 30s >"$SRV_LOG" 2>&1 & SP=$!
  sleep 0.3
  # Client with CC bypass for determinism
  export QUIC_FEC_CC_BYPASS=1
  "$BIN_DIR/quicfec-client" -addr 127.0.0.1:$PORT -file "$FILE" -N $((K+R0)) -K "$K" -L "$SYMBOL_BYTES" \
    -post-wait 300ms -ack-every "$ACK_EVERY" -dgram-warn 1400 -arq -R0 "$R0" -W "$W" -Rstep "$RSTEP" -alpha "$ALPHA" -max-attempts 5 \
    >"$CLI_LOG" 2>&1 || true
  # Wait briefly for server to emit observation (up to 5s) before stopping it
  tries=0
  while [[ $tries -lt 50 ]]; do
    RL_OBS=$(grep -E '^\[rl-observation\]' "$SRV_LOG" | tail -n1 || true)
    if [[ -n "$RL_OBS" ]]; then
      break
    fi
    sleep 0.1; tries=$((tries+1))
  done
  sleep 0.2; kill $SP 2>/dev/null || true

  RL_OBS=$(grep -E "^\[rl-observation\]" "$SRV_LOG" | tail -n1 || true)
  if [[ -n "$RL_OBS" ]]; then
    echo "$RL_OBS" | tee -a "$OBS_JSONL" >&2
  else
    echo "[warn] no [rl-observation] line found" >&2
    tail -n +1 "$SRV_LOG" >&2 || true
  fi
  rm -f "$CLI_LOG" "$SRV_LOG"
done

echo "[done] observations: $OBS_JSONL" >&2
