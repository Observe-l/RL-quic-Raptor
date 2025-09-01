#!/usr/bin/env bash
set -euo pipefail

ns=${1:-qns}
v0=${2:-veth0}
v1=${3:-veth1}
host_ip=${4:-10.10.0.1/24}
ns_ip=${5:-10.10.0.2/24}

sudo ip netns add "$ns" || true
sudo ip link add "$v0" type veth peer name "$v1" || true
sudo ip link set "$v1" netns "$ns"
sudo ip addr add "$host_ip" dev "$v0" || true
sudo ip link set "$v0" up
sudo ip netns exec "$ns" ip addr add "$ns_ip" dev "$v1" || true
sudo ip netns exec "$ns" ip link set "$v1" up
sudo ip netns exec "$ns" ip link set lo up
echo "[ns] $ns up: $v0 <-> $v1 with $host_ip / $ns_ip"
