#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
PROTO_DIR="$ROOT_DIR/go/proto"
GO_OUT="$ROOT_DIR/go/gen"

if ! command -v protoc >/dev/null 2>&1; then
  echo "protoc not found. Install with: sudo apt install -y protobuf-compiler" >&2
  exit 1
fi

mkdir -p "$GO_OUT"
protoc -I "$PROTO_DIR" "$PROTO_DIR/quicfec.proto" \
  --go_out="$GO_OUT" --go-grpc_out="$GO_OUT"

echo "Generated Go stubs at $GO_OUT"
