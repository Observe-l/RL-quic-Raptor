#!/usr/bin/env bash
set -euo pipefail
# Recreate a clean network namespace with a veth pair.
# Usage: netns_reset.sh [ns=qns]

NS=${1:-qns}

if sudo ip netns list | awk '{print $1}' | grep -qx "$NS"; then
  # Kill any lingering processes in the ns to allow delete
  for pid in $(sudo ip netns pids "$NS"); do sudo kill -9 "$pid" || true; done
  sudo ip netns del "$NS" || true
fi

# Clean any leftover veth0 on host
if ip link show veth0 &>/dev/null; then
  sudo ip link del veth0 || true
fi

# Create namespace and veth pair
sudo ip netns add "$NS"
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth1 netns "$NS"

# Configure addresses
sudo ip addr add 10.10.0.1/24 dev veth0
sudo ip link set veth0 up
sudo ip netns exec "$NS" ip addr add 10.10.0.2/24 dev veth1
sudo ip netns exec "$NS" ip link set veth1 up
sudo ip netns exec "$NS" ip link set lo up

# Some environments (e.g., Cisco Secure Client VPN) install an iptables chain
# that drops traffic by default. Allow local traffic over veth0 so the host
# client can reach the server in the netns.
if sudo iptables -S ciscovpn &>/dev/null; then
  # Insert at top to ensure it matches before any DROP.
  sudo iptables -C ciscovpn -o veth0 -s 10.10.0.1/32 -d 10.10.0.2/32 -j RETURN 2>/dev/null || \
    sudo iptables -I ciscovpn 1 -o veth0 -s 10.10.0.1/32 -d 10.10.0.2/32 -j RETURN
  sudo iptables -C ciscovpn -i veth0 -s 10.10.0.2/32 -d 10.10.0.1/32 -j RETURN 2>/dev/null || \
    sudo iptables -I ciscovpn 1 -i veth0 -s 10.10.0.2/32 -d 10.10.0.1/32 -j RETURN
fi

echo "reset netns $NS with veth0(10.10.0.1)<->veth1(10.10.0.2)"
