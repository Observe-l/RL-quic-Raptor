#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
GO_DIR="$ROOT_DIR/go"
BIN_DIR="$GO_DIR/bin"
FILE_REL="go/test_data/train_FD001.txt"
FILE="$ROOT_DIR/$FILE_REL"

echo "[build] quic-fec client/server"
mkdir -p "$BIN_DIR"
pushd "$GO_DIR" >/dev/null
go build -o "$BIN_DIR/quicfec-server" ./cmd/quicfec-server
go build -o "$BIN_DIR/quicfec-client" ./cmd/quicfec-client
popd >/dev/null

if [[ ! -f "$FILE" ]]; then
  echo "missing test file: $FILE_REL" >&2
  exit 1
fi

# choose a free UDP port
choose_port() {
  for i in {1..20}; do
    p=$(shuf -i 45000-55000 -n 1)
    if ! ss -lun | awk '{print $5}' | grep -q ":$p$"; then
      echo "$p"; return 0
    fi
  done
  return 1
}
PORT=$(choose_port)
if [[ -z "${PORT:-}" ]]; then echo "no free port" >&2; exit 2; fi
echo "[run] server on :$PORT"
SRV_LOG=$(mktemp)
"$BIN_DIR/quicfec-server" -addr ":$PORT" -out "$GO_DIR/test_data" -timeout 30s >"$SRV_LOG" 2>&1 &
SRV_PID=$!
trap 'kill $SRV_PID 2>/dev/null || true' EXIT
sleep 0.4

echo "[run] client -> 127.0.0.1:$PORT (loss=0)"
START_NS=$(date +%s%N)
OUT_FILE="$GO_DIR/test_data/$(basename "$FILE").recv"
rm -f "$OUT_FILE"
"$BIN_DIR/quicfec-client" -addr "127.0.0.1:$PORT" -file "$FILE" -N 32 -K 26 -L 1100 -loss 0.00 -pace 10us -block-pause 2ms -post-wait 1s -dgram-warn 1400
END_NS=$(date +%s%N)

echo "[wait] finalize .recv"
for i in {1..50}; do
  [[ -f "$OUT_FILE" ]] && break
  sleep 0.2
done
if [[ ! -f "$OUT_FILE" ]]; then
  echo "ERROR: output file not found: $OUT_FILE" >&2
  echo "--- server log ---"; tail -n +1 "$SRV_LOG"; echo "-------------------"
  exit 3
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

echo "[result] md5_in=$MD5_IN md5_out=$MD5_OUT dur_ms=$DUR_MS goodput_mbps=$MBPS"
if [[ "$MD5_IN" != "$MD5_OUT" ]]; then
  echo "FAIL: checksum mismatch" >&2
  echo "--- server log ---"; tail -n +1 "$SRV_LOG"; echo "-------------------"
  exit 4
fi
echo "PASS: end-to-end success"