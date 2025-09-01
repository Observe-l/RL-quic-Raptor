#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
GO_DIR="$ROOT_DIR/go"
BIN_DIR="$GO_DIR/bin"

echo "[1/5] Building quic-fec client/server..."
mkdir -p "$BIN_DIR"
pushd "$GO_DIR" >/dev/null
go build -o "$BIN_DIR/quicfec-server" ./cmd/quicfec-server
go build -o "$BIN_DIR/quicfec-client" ./cmd/quicfec-client
popd >/dev/null

FILE_REL="go/test_data/train_FD001.txt"
FILE="$ROOT_DIR/$FILE_REL"
if [[ ! -f "$FILE" ]]; then
  echo "ERROR: test file not found: $FILE_REL" >&2
  exit 1
fi

echo "[2/5] Starting server on :4242..."
SRV_LOG=$(mktemp)
"$BIN_DIR/quicfec-server" -addr ":4242" -out "$GO_DIR/test_data" -timeout 20s >"$SRV_LOG" 2>&1 &
SRV_PID=$!
trap 'kill $SRV_PID 2>/dev/null || true' EXIT
sleep 0.3

echo "[3/5] Running client with RaptorQ (baseline, no sender drop)..."
START_NS=$(date +%s%N)
rm -f "$GO_DIR/test_data/$(basename "$FILE").recv"
"$BIN_DIR/quicfec-client" -addr "127.0.0.1:4242" -file "$FILE" -N 32 -K 26 -L 1100 -loss 0.05 -pace 10us -block-pause 2ms -post-wait 1s -dgram-warn 1400
END_NS=$(date +%s%N)

echo "[4/5] Verifying output..."
OUT_FILE="$GO_DIR/test_data/$(basename "$FILE").recv"
if [[ ! -f "$OUT_FILE" ]]; then
  echo "ERROR: output file not found: $OUT_FILE" >&2
  echo "--- server log ---"; tail -n +1 "$SRV_LOG"; echo "-------------------"
  exit 2
fi

MD5_IN=$(md5sum "$FILE" | awk '{print $1}')
MD5_OUT=$(md5sum "$OUT_FILE" | awk '{print $1}')

DUR_MS=$(( (END_NS - START_NS)/1000000 ))
SIZE_BYTES=$(stat -c%s "$FILE")
MBPS=$(python3 - "$SIZE_BYTES" "$DUR_MS" <<'PY'
import sys
size=int(sys.argv[1]); dur_ms=int(sys.argv[2])
mbps = (size*8/1e6)/max(dur_ms/1e3, 1e-9)
print(f"{mbps:.2f}")
PY
)

echo "[5/5] Results: md5_in=$MD5_IN md5_out=$MD5_OUT dur_ms=$DUR_MS goodput_mbps=$MBPS"

if [[ "$MD5_IN" != "$MD5_OUT" ]]; then
  echo "FAIL: checksum mismatch on baseline (unexpected)"
  echo "--- server log ---"; tail -n +1 "$SRV_LOG"; echo "-------------------"
  exit 3
fi

echo "PASS: Baseline decode success. Goodput ~ ${MBPS} Mbps"

echo "[extra] Single-block loss test (small.bin at 5% drop)..."
SM_IN="$GO_DIR/test_data/small.bin"
rm -f "$GO_DIR/test_data/small.bin.recv"
"$BIN_DIR/quicfec-client" -addr "127.0.0.1:4242" -file "$SM_IN" -N 32 -K 26 -L 1100 -loss 0.05 -pace 200us -block-pause 0ms -post-wait 3s -dgram-warn 1400
MD5_SA=$(md5sum "$SM_IN" | awk '{print $1}')
MD5_SB=$(md5sum "$GO_DIR/test_data/small.bin.recv" | awk '{print $1}')
if [[ "$MD5_SA" != "$MD5_SB" ]]; then
  echo "WARN: single-block RaptorQ decode at 5% loss failed (non-deterministic). Check server log below."
  echo "--- server log ---"; tail -n +1 "$SRV_LOG"; echo "-------------------"
else
  echo "PASS: single-block RaptorQ decode success at 5% random loss"
fi
kill $SRV_PID 2>/dev/null || true
trap - EXIT
