#!/usr/bin/env bash
set -euo pipefail
NS=${1:-qns}
set +e
sudo ip netns exec "$NS" tc qdisc del dev veth1 root 2>/dev/null
sudo ip netns exec "$NS" tc qdisc del dev veth1 ingress 2>/dev/null
sudo tc qdisc del dev veth0 root 2>/dev/null
sudo ip netns del "$NS" 2>/dev/null
set -e
echo "cleaned qdiscs and netns $NS"
