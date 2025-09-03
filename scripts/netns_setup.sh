#!/usr/bin/env bash
set -euo pipefail
NS=${1:-qns}
sudo ip netns add "$NS" || true
sudo ip link add veth0 type veth peer name veth1 || true
sudo ip link set veth1 netns "$NS" || true
sudo ip addr add 10.10.0.1/24 dev veth0 || true
sudo ip link set veth0 up || true
sudo ip netns exec "$NS" ip addr add 10.10.0.2/24 dev veth1 || true
sudo ip netns exec "$NS" ip link set veth1 up || true
sudo ip netns exec "$NS" ip link set lo up || true
echo "netns $NS with veth0<->veth1 up"
