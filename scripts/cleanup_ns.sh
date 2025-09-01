#!/usr/bin/env bash
set -euo pipefail
ns=${1:-qns}
v0=${2:-veth0}

sudo ip netns del "$ns" 2>/dev/null || true
sudo ip link del "$v0" 2>/dev/null || true
echo "[ns] cleaned"
