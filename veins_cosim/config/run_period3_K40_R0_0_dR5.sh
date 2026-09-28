#!/usr/bin/env bash
set -eo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VEINS_SAMPLE_ROOT="/opt/omnetpp-6.1/samples/veins"

source "/opt/omnetpp-6.1/setenv"
cd "$VEINS_SAMPLE_ROOT"
source ./setenv
cd "$PROJECT_DIR"
set -u
export LD_LIBRARY_PATH="$PROJECT_DIR/out/gcc-release:$VEINS_SAMPLE_ROOT/src${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
exec python3 "$PROJECT_DIR/run_period3.py" "$@"
