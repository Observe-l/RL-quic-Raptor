#!/usr/bin/env bash
set -euo pipefail
# Recreate a clean network namespace with a veth pair.
# Usage: netns_reset.sh [ns=qns]
#
# Supports parallel-safe isolation via env vars:
#   VETH_HOST=...   host-side veth interface name (default: veth0)
#   VETH_NS=...     netns-side veth interface name (default: veth1)
#   HOST_IP=...     host-side IP with CIDR (default: 10.10.0.1/24)
#   NS_IP=...       netns-side IP with CIDR (default: 10.10.0.2/24)

NS=${1:-qns}

VETH_HOST=${VETH_HOST:-veth0}
VETH_NS=${VETH_NS:-veth1}

HOST_IP=${HOST_IP:-10.10.0.1/24}
NS_IP=${NS_IP:-10.10.0.2/24}

# Raw IPs (without CIDR) for neigh / iptables.
HOST_IP_RAW=${HOST_IP%%/*}
NS_IP_RAW=${NS_IP%%/*}

if sudo ip netns list | awk '{print $1}' | grep -qx "$NS"; then
  # Kill any lingering processes in the ns to allow delete
  for pid in $(sudo ip netns pids "$NS"); do sudo kill -9 "$pid" || true; done
  sudo ip netns del "$NS" || true
fi

# Clean any leftover veth on host
if ip link show "$VETH_HOST" &>/dev/null; then
  sudo ip link del "$VETH_HOST" || true
fi

# Create namespace and veth pair
sudo ip netns add "$NS"
sudo ip link add "$VETH_HOST" type veth peer name "$VETH_NS"
sudo ip link set "$VETH_NS" netns "$NS"

# Configure addresses
sudo ip addr add "$HOST_IP" dev "$VETH_HOST"
sudo ip link set "$VETH_HOST" up
sudo ip netns exec "$NS" ip addr add "$NS_IP" dev "$VETH_NS"
sudo ip netns exec "$NS" ip link set "$VETH_NS" up
sudo ip netns exec "$NS" ip link set lo up

# Install permanent neighbor entries so ARP resolution doesn't depend on packets
# getting through tc-netem loss (which can otherwise blackhole the link).
VETH0_MAC=$(cat "/sys/class/net/${VETH_HOST}/address")
VETH1_MAC=$(sudo ip netns exec "$NS" cat "/sys/class/net/${VETH_NS}/address")
sudo ip neigh replace "$NS_IP_RAW" lladdr "$VETH1_MAC" dev "$VETH_HOST" nud permanent || true
sudo ip netns exec "$NS" ip neigh replace "$HOST_IP_RAW" lladdr "$VETH0_MAC" dev "$VETH_NS" nud permanent || true

# Some environments (e.g., Cisco Secure Client VPN) install an iptables chain
# that drops traffic by default. Allow local traffic over veth0 so the host
# client can reach the server in the netns.
if sudo iptables -S ciscovpn &>/dev/null; then
  # Insert at top to ensure it matches before any DROP.
  sudo iptables -C ciscovpn -o "$VETH_HOST" -s "${HOST_IP_RAW}/32" -d "${NS_IP_RAW}/32" -j RETURN 2>/dev/null || \
    sudo iptables -I ciscovpn 1 -o "$VETH_HOST" -s "${HOST_IP_RAW}/32" -d "${NS_IP_RAW}/32" -j RETURN
  sudo iptables -C ciscovpn -i "$VETH_HOST" -s "${NS_IP_RAW}/32" -d "${HOST_IP_RAW}/32" -j RETURN 2>/dev/null || \
    sudo iptables -I ciscovpn 1 -i "$VETH_HOST" -s "${NS_IP_RAW}/32" -d "${HOST_IP_RAW}/32" -j RETURN
fi

echo "reset netns $NS with ${VETH_HOST}(${HOST_IP_RAW})<->${VETH_NS}(${NS_IP_RAW})"
