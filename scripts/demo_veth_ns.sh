#!/usr/bin/env bash
set -euo pipefail

# Create namespace + veth pair
sudo ip netns add qns || true
sudo ip link add veth0 type veth peer name veth1 || true
sudo ip link set veth1 netns qns

# Assign IPs
sudo ip addr add 10.10.0.1/24 dev veth0 || true
sudo ip link set veth0 up
sudo ip netns exec qns ip addr add 10.10.0.2/24 dev veth1 || true
sudo ip netns exec qns ip link set veth1 up
sudo ip netns exec qns ip link set lo up

echo "[OK] veth+netns ready. Start server inside the namespace:"
echo "  sudo ip netns exec qns ./go/bin/quicfec-grpc-server"

echo "Press Enter to CLEANUP..."
read -r _

sudo ip netns del qns || true
sudo ip link del veth0 2>/dev/null || true

echo "[OK] cleaned."
