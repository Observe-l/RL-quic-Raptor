#!/usr/bin/env bash
set -eo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VEINS_SAMPLE_ROOT="/opt/omnetpp-6.1/samples/veins"

source "/opt/omnetpp-6.1/setenv"
cd "$VEINS_SAMPLE_ROOT"
source ./setenv
cd "$PROJECT_DIR"
set -u

mkdir -p bin
cd "$PROJECT_DIR/../go"
go build -o "$PROJECT_DIR/bin/quicfec-veins-client" ./cmd/quicfec-veins-client
go build -o "$PROJECT_DIR/bin/quicfec-veins-server" ./cmd/quicfec-veins-server

cd "$PROJECT_DIR/src"
opp_makemake -f --deep --make-so \
    -I "$VEINS_SAMPLE_ROOT/src" \
    -L "$VEINS_SAMPLE_ROOT/src" -lveins \
    -o veins_quicfec_cosim -O ../out -p VEINS_QUICFEC_COSIM
make -j"$(nproc)"
