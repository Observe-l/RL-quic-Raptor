#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)

NS=${NS:-qns}
VETH_HOST=${VETH_HOST:-veth0}
VETH_NS=${VETH_NS:-veth1}
HOST_IP=${HOST_IP:-10.10.0.1/24}
NS_IP=${NS_IP:-10.10.0.2/24}
PORT=${PORT:-25569}
RTT_MS=${RTT_MS:-50}
RATE=${RATE:-1000mbit}
LOSS_MODE=${LOSS_MODE:-none}
TUNE_UDP_BUFFERS=${TUNE_UDP_BUFFERS:-1}

CLEANUP_ONLY=0

usage() {
  cat <<EOF
Create or clean a local netns + veth testbed for QUIC-FEC device client/server.

Usage:
  $0 [options]

Options:
  --ns NAME                 Namespace name (default: $NS)
  --veth-host IFACE         Host-side veth name (default: $VETH_HOST)
  --veth-ns IFACE           Netns-side veth name (default: $VETH_NS)
  --host-ip CIDR            Host-side IP/CIDR (default: $HOST_IP)
  --ns-ip CIDR              Netns-side IP/CIDR (default: $NS_IP)
  --port PORT               Server UDP port (default: $PORT)
  --rtt-ms MS               End-to-end RTT in ms (default: $RTT_MS)
  --rate RATE               Host-side TBF rate, e.g. 100mbit (default: $RATE)
  --loss-mode MODE          none | iid:PCT | gemodel:p,r,h,k (default: $LOSS_MODE)
  --cleanup-only            Remove existing namespace / veth and exit
  -h, --help                Show this help

Examples:
  $0 --loss-mode gemodel:2,80,0.1,99 --rtt-ms 40
  $0 --cleanup-only
EOF
}

require_sudo() {
  if ! sudo -n true 2>/dev/null; then
    echo "[error] sudo privileges are required. Run 'sudo -v' once and retry." >&2
    exit 1
  fi
}

cleanup() {
  if sudo ip netns list | awk '{print $1}' | grep -qx "$NS"; then
    for pid in $(sudo ip netns pids "$NS"); do
      sudo kill -9 "$pid" 2>/dev/null || true
    done
    sudo ip netns del "$NS" 2>/dev/null || true
  fi
  if ip link show "$VETH_HOST" &>/dev/null; then
    sudo ip link del "$VETH_HOST" 2>/dev/null || true
  fi
  echo "[cleanup] removed namespace=$NS veth_host=$VETH_HOST"
}

configure_tc() {
  local half
  half=$(( RTT_MS / 2 ))

  sudo tc qdisc del dev "$VETH_HOST" root 2>/dev/null || true
  sudo ip netns exec "$NS" tc qdisc del dev "$VETH_NS" root 2>/dev/null || true

  local -a netem_args
  netem_args=(delay "${half}ms")
  case "$LOSS_MODE" in
    none)
      netem_args+=(loss 0%)
      ;;
    iid:*)
      local pct
      pct=${LOSS_MODE#iid:}
      netem_args+=(loss "${pct}%")
      ;;
    gemodel:*)
      local params p r h k
      params=${LOSS_MODE#gemodel:}
      IFS=',' read -r p r h k <<<"$params"
      if [[ -z "${p:-}" || -z "${r:-}" || -z "${h:-}" || -z "${k:-}" ]]; then
        echo "[error] bad --loss-mode gemodel format, expected gemodel:p,r,h,k" >&2
        exit 2
      fi
      # tc netem expects: p r 1-h 1-k.
      # Our convention uses h=good-state loss, k=bad-state loss.
      netem_args+=(loss gemodel "${p}%" "${r}%" "${k}%" "${h}%")
      ;;
    *)
      echo "[error] unsupported --loss-mode: $LOSS_MODE" >&2
      exit 2
      ;;
  esac

  sudo tc qdisc replace dev "$VETH_HOST" root handle 1: tbf rate "$RATE" burst 32kb latency 400ms
  sudo tc qdisc replace dev "$VETH_HOST" parent 1:1 handle 10: netem "${netem_args[@]}"
  sudo ip netns exec "$NS" tc qdisc replace dev "$VETH_NS" root netem delay "${half}ms"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ns)
      NS=$2; shift 2 ;;
    --veth-host)
      VETH_HOST=$2; shift 2 ;;
    --veth-ns)
      VETH_NS=$2; shift 2 ;;
    --host-ip)
      HOST_IP=$2; shift 2 ;;
    --ns-ip)
      NS_IP=$2; shift 2 ;;
    --port)
      PORT=$2; shift 2 ;;
    --rtt-ms)
      RTT_MS=$2; shift 2 ;;
    --rate)
      RATE=$2; shift 2 ;;
    --loss-mode)
      LOSS_MODE=$2; shift 2 ;;
    --cleanup-only)
      CLEANUP_ONLY=1; shift ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      echo "[error] unknown option: $1" >&2
      usage
      exit 2 ;;
  esac
done

HOST_IP_ADDR=${HOST_IP%%/*}
NS_IP_ADDR=${NS_IP%%/*}

require_sudo
cleanup

if [[ "$CLEANUP_ONLY" == "1" ]]; then
  exit 0
fi

if [[ "$TUNE_UDP_BUFFERS" == "1" ]]; then
  sudo sysctl -w net.core.rmem_max=33554432 net.core.wmem_max=33554432 >/dev/null 2>&1 || true
  sudo sysctl -w net.core.rmem_default=33554432 net.core.wmem_default=33554432 >/dev/null 2>&1 || true
fi

VETH_HOST="$VETH_HOST" \
VETH_NS="$VETH_NS" \
HOST_IP="$HOST_IP" \
NS_IP="$NS_IP" \
"$ROOT/scripts/netns_reset.sh" "$NS"

configure_tc

cat <<EOF
[ready] namespace=$NS
[ready] host_veth=$VETH_HOST host_ip=$HOST_IP
[ready] ns_veth=$VETH_NS ns_ip=$NS_IP
[ready] port=$PORT rtt_ms=$RTT_MS rate=$RATE loss_mode=$LOSS_MODE

Run server inside the namespace:
  sudo ip netns exec $NS python3 python/quicfec_device_server.py --addr ${NS_IP_ADDR}:$PORT --out data/receive.bin

Run client on the host:
  python3 python/quicfec_device_client.py --server ${NS_IP_ADDR} --port $PORT

Cleanup only:
  $0 --ns $NS --veth-host $VETH_HOST --cleanup-only
EOF
