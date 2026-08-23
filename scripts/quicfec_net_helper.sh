#!/usr/bin/env bash
set -euo pipefail

# Privileged helper for the QUIC-FEC experiments.
#
# This file is intended to be copied to a root-owned path and exposed through
# sudoers.  It deliberately does not accept an arbitrary command or shell
# expression.  The experiment scripts opt into it with:
#
#   QUIC_FEC_PRIV_HELPER=/usr/local/libexec/quicfec-net-helper
#
# The default experiment path still uses sudo directly.

if [[ "$(id -u)" != "0" ]]; then
  echo "quicfec-net-helper must be invoked through sudo" >&2
  exit 1
fi

IP=/usr/bin/ip
TC=/sbin/tc
SYSCTL=/sbin/sysctl
RUNUSER=/usr/sbin/runuser
SETSID=/usr/bin/setsid
SS=/usr/bin/ss
IPTABLES=/usr/sbin/iptables
FIND=/usr/bin/find
CHOWN=/usr/bin/chown

die() { echo "quicfec-net-helper: $*" >&2; exit 2; }

need_cmd() {
  [[ -x "$1" ]] || die "missing required command: $1"
}

valid_name() {
  [[ "$1" =~ ^[A-Za-z0-9_.-]{1,63}$ ]]
}

valid_iface() {
  [[ "$1" =~ ^[A-Za-z0-9_.-]{1,15}$ ]]
}

valid_uint() {
  [[ "$1" =~ ^[0-9]+$ ]]
}

valid_percent() {
  [[ "$1" =~ ^[0-9]+([.][0-9]+)?$ ]]
}

valid_cidr() {
  [[ "$1" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$ ]]
}

require_netns_args() {
  local ns=$1 vh=$2 vn=$3 hip=$4 nip=$5
  valid_name "$ns" || die "invalid namespace name"
  valid_iface "$vh" || die "invalid host interface name"
  valid_iface "$vn" || die "invalid namespace interface name"
  valid_cidr "$hip" || die "invalid host CIDR"
  valid_cidr "$nip" || die "invalid namespace CIDR"
}

sudo_uid=${SUDO_UID:-}
sudo_user=${SUDO_USER:-}
if [[ -n "$sudo_uid" ]]; then
  valid_uint "$sudo_uid" || die "invalid SUDO_UID"
fi

cmd_self_test() {
  need_cmd "$IP"
  need_cmd "$TC"
  need_cmd "$SYSCTL"
  need_cmd "$SETSID"
  need_cmd "$SS"
  need_cmd "$FIND"
  need_cmd "$CHOWN"
  [[ -n "$sudo_uid" && -n "$sudo_user" ]] || die "missing sudo caller identity"
  id -u "$sudo_user" >/dev/null 2>&1 || die "unknown sudo caller: $sudo_user"
  [[ "$(id -u "$sudo_user")" == "$sudo_uid" ]] || die "sudo caller identity mismatch"
  echo "ok"
}

cmd_reset() {
  [[ $# == 5 ]] || die "reset expects: NS VETH_HOST VETH_NS HOST_CIDR NS_CIDR"
  local ns=$1 vh=$2 vn=$3 hip=$4 nip=$5
  require_netns_args "$@"
  local hip_raw=${hip%%/*} nip_raw=${nip%%/*}
  local pid vh_mac vn_mac

  if "$IP" netns list | awk '{print $1}' | grep -qx "$ns"; then
    while read -r pid; do
      [[ -z "$pid" ]] || kill -KILL "$pid" 2>/dev/null || true
    done < <("$IP" netns pids "$ns" 2>/dev/null || true)
    "$IP" netns del "$ns" || true
  fi

  if "$IP" link show "$vh" >/dev/null 2>&1; then
    "$IP" link del "$vh" || true
  fi

  "$IP" netns add "$ns"
  "$IP" link add "$vh" type veth peer name "$vn"
  "$IP" link set "$vn" netns "$ns"
  "$IP" addr add "$hip" dev "$vh"
  "$IP" link set "$vh" up
  "$IP" netns exec "$ns" "$IP" addr add "$nip" dev "$vn"
  "$IP" netns exec "$ns" "$IP" link set "$vn" up
  "$IP" netns exec "$ns" "$IP" link set lo up

  vh_mac=$(<"/sys/class/net/$vh/address")
  vn_mac=$("$IP" netns exec "$ns" cat "/sys/class/net/$vn/address")
  "$IP" neigh replace "$nip_raw" lladdr "$vn_mac" dev "$vh" nud permanent || true
  "$IP" netns exec "$ns" "$IP" neigh replace "$hip_raw" lladdr "$vh_mac" dev "$vn" nud permanent || true

  # Preserve the existing VPN workaround, but do not require iptables to be installed.
  if [[ -x "$IPTABLES" ]] && "$IPTABLES" -S ciscovpn >/dev/null 2>&1; then
    "$IPTABLES" -C ciscovpn -o "$vh" -s "${hip_raw}/32" -d "${nip_raw}/32" -j RETURN 2>/dev/null || \
      "$IPTABLES" -I ciscovpn 1 -o "$vh" -s "${hip_raw}/32" -d "${nip_raw}/32" -j RETURN
    "$IPTABLES" -C ciscovpn -i "$vh" -s "${nip_raw}/32" -d "${hip_raw}/32" -j RETURN 2>/dev/null || \
      "$IPTABLES" -I ciscovpn 1 -i "$vh" -s "${nip_raw}/32" -d "${hip_raw}/32" -j RETURN
  fi
  echo "reset netns $ns with ${vh}(${hip_raw})<->${vn}(${nip_raw})"
}

cmd_check() {
  [[ $# == 3 ]] || die "check expects: NS VETH_HOST VETH_NS"
  local ns=$1 vh=$2 vn=$3
  valid_name "$ns" || die "invalid namespace name"
  valid_iface "$vh" || die "invalid host interface name"
  valid_iface "$vn" || die "invalid namespace interface name"
  "$IP" netns list | awk '{print $1}' | grep -qx "$ns" || die "namespace not found: $ns"
  "$IP" link show "$vh" >/dev/null 2>&1 || die "host interface not found: $vh"
  "$IP" netns exec "$ns" "$IP" link show "$vn" >/dev/null 2>&1 || die "namespace interface not found: $vn"
}

cmd_cleanup() {
  [[ $# == 2 ]] || die "cleanup expects: NS VETH_HOST"
  local ns=$1 vh=$2 pid
  valid_name "$ns" || die "invalid namespace name"
  valid_iface "$vh" || die "invalid host interface name"
  if "$IP" netns list | awk '{print $1}' | grep -qx "$ns"; then
    while read -r pid; do
      [[ -z "$pid" ]] || kill -KILL "$pid" 2>/dev/null || true
    done < <("$IP" netns pids "$ns" 2>/dev/null || true)
    "$IP" netns del "$ns" || true
  fi
  if "$IP" link show "$vh" >/dev/null 2>&1; then
    "$IP" link del "$vh" || true
  fi
}

cmd_buffers() {
  "$SYSCTL" -w net.core.rmem_max=33554432 net.core.wmem_max=33554432 >/dev/null 2>&1 || true
  "$SYSCTL" -w net.core.rmem_default=33554432 net.core.wmem_default=33554432 >/dev/null 2>&1 || true
}

cmd_tc_config() {
  [[ $# == 7 ]] || die "tc-config expects: VETH_HOST VETH_NS NS RATE_MBPS RTT_MS LOSS_MODE LOSS_PCT"
  local vh=$1 vn=$2 ns=$3 rate=$4 rtt=$5 loss_mode=$6 loss_pct=$7
  valid_iface "$vh" || die "invalid host interface name"
  valid_iface "$vn" || die "invalid namespace interface name"
  valid_name "$ns" || die "invalid namespace name"
  valid_uint "$rate" || die "invalid rate"
  valid_uint "$rtt" || die "invalid RTT"
  valid_percent "$loss_pct" || die "invalid loss percentage"
  local half=$((rtt / 2))
  local -a netem=(delay "${half}ms")
  local p r h k params
  case "$loss_mode" in
    none) netem+=(loss 0%) ;;
    iid:*)
      p=${loss_mode#iid:}; valid_percent "$p" || die "invalid iid loss"; netem+=(loss "${p}%") ;;
    gemodel:*)
      params=${loss_mode#gemodel:}
      IFS=',' read -r p r h k <<<"$params"
      valid_percent "$p" && valid_percent "$r" && valid_percent "$h" && valid_percent "$k" || die "invalid gemodel loss"
      netem+=(loss gemodel "${p}%" "${r}%" "${k}%" "${h}%")
      ;;
    *) netem+=(loss "${loss_pct}%") ;;
  esac

  "$TC" qdisc del dev "$vh" root 2>/dev/null || true
  "$TC" qdisc replace dev "$vh" root handle 1: tbf rate "${rate}mbit" burst 32kb latency 400ms
  "$TC" qdisc replace dev "$vh" parent 1:1 handle 10: netem "${netem[@]}"
  "$IP" netns exec "$ns" "$TC" qdisc del dev "$vn" root 2>/dev/null || true
  "$IP" netns exec "$ns" "$TC" qdisc replace dev "$vn" root netem delay "${half}ms"
}

caller_out_dir_ok() {
  local out=$1
  [[ "$out" != *$'\n'* && "$out" != *$'\r'* ]] || return 1
  [[ -d "$out" ]] || return 1
  [[ -n "$sudo_user" ]] || return 1
  [[ "$(stat -c '%U' "$out" 2>/dev/null || true)" == "$sudo_user" ]]
}

cmd_server_start() {
  [[ $# == 6 ]] || die "server-start expects: NS SERVER_BIN ADDR OUT_DIR TIMEOUT DECODE_DDL_MS"
  local ns=$1 bin=$2 addr=$3 out=$4 timeout=$5 ddl=$6
  valid_name "$ns" || die "invalid namespace name"
  [[ "$bin" == */quicfec-server && -x "$bin" ]] || die "server binary must be an executable quicfec-server"
  [[ "$addr" =~ ^[0-9.]+:[0-9]+$ ]] || die "invalid server address"
  caller_out_dir_ok "$out" || die "output directory must exist and belong to the sudo caller"
  [[ "$timeout" =~ ^[0-9]+(ms|s|m)$ ]] || die "invalid server timeout"
  valid_uint "$ddl" || die "invalid decode DDL"
  [[ -n "$sudo_user" ]] || die "missing sudo caller"

  # The experiment records the PID returned by sudo. When sudo execs this
  # helper, that PID is our parent PID; use it as the stable launcher key.
  local state="/tmp/quicfec-helper-${sudo_uid}-${PPID}"
  local child rc=0
  repair_output_owner() {
    # The server runs with the privilege needed by the original experiment
    # path. Return only generated receive artifacts to the invoking user.
    "$FIND" "$out" -maxdepth 1 -type f \( -name '*.recv' -o -name '*.part' \) \
      -exec "$CHOWN" "$sudo_uid:$sudo_uid" {} + 2>/dev/null || true
  }
  trap 'if [[ -n "${child:-}" ]]; then kill -TERM "$child" 2>/dev/null || true; fi; repair_output_owner; rm -f "$state"; exit 143' TERM INT
  # Match the original sudo ip-netns-exec path: the server runs as root inside
  # the isolated namespace. Only receive artifacts are handed back to the user.
  "$SETSID" "$IP" netns exec "$ns" "$bin" \
    -addr "$addr" -out "$out" -timeout "$timeout" -decode-ddl "${ddl}ms" &
  child=$!
  printf '%s\n' "$child" >"$state"
  wait "$child" || rc=$?
  repair_output_owner
  rm -f "$state"
  trap - TERM INT
  exit "$rc"
}

cmd_server_stop() {
  [[ $# == 1 ]] || die "server-stop expects: LAUNCHER_PID"
  local launcher=$1 child state
  valid_uint "$launcher" || die "invalid launcher pid"
  state="/tmp/quicfec-helper-${sudo_uid}-${launcher}"
  child=$(cat "$state" 2>/dev/null || true)
  if [[ -n "$child" ]] && valid_uint "$child"; then
    kill -TERM "$child" 2>/dev/null || true
  fi
  kill -TERM "$launcher" 2>/dev/null || true
  for _ in {1..20}; do
    kill -0 "$launcher" 2>/dev/null || break
    sleep 0.05
  done
  kill -KILL "$child" 2>/dev/null || true
  kill -KILL "$launcher" 2>/dev/null || true
  rm -f "$state"
}

cmd_server_stop_ns() {
  [[ $# == 1 ]] || die "server-stop-ns expects: NS"
  local ns=$1 pid
  valid_name "$ns" || die "invalid namespace name"
  while read -r pid; do
    [[ -z "$pid" ]] || kill -TERM "$pid" 2>/dev/null || true
  done < <("$IP" netns pids "$ns" 2>/dev/null || true)
  sleep 0.1
  while read -r pid; do
    [[ -z "$pid" ]] || kill -KILL "$pid" 2>/dev/null || true
  done < <("$IP" netns pids "$ns" 2>/dev/null || true)
}

cmd_wait_port() {
  [[ $# == 2 ]] || die "wait-port expects: NS PORT"
  local ns=$1 port=$2
  valid_name "$ns" || die "invalid namespace name"
  valid_uint "$port" || die "invalid port"
  for _ in {1..8}; do
    if "$IP" netns exec "$ns" "$SS" -lunH 2>/dev/null | awk -v p=":${port}" 'index($4,p) || index($5,p) {found=1} END {exit(found ? 0 : 1)}'; then
      exit 0
    fi
    sleep 0.01
  done
  exit 1
}

cmd_tc_stats() {
  [[ $# == 1 ]] || die "tc-stats expects: VETH_HOST"
  valid_iface "$1" || die "invalid host interface name"
  "$TC" -s qdisc show dev "$1"
}

case "${1:-}" in
  self-test) shift; [[ $# == 0 ]] || die "self-test takes no arguments"; cmd_self_test ;;
  reset) shift; cmd_reset "$@" ;;
  check) shift; cmd_check "$@" ;;
  cleanup) shift; cmd_cleanup "$@" ;;
  buffers) shift; [[ $# == 0 ]] || die "buffers takes no arguments"; cmd_buffers ;;
  tc-config) shift; cmd_tc_config "$@" ;;
  server-start) shift; cmd_server_start "$@" ;;
  server-stop) shift; cmd_server_stop "$@" ;;
  server-stop-ns) shift; cmd_server_stop_ns "$@" ;;
  wait-port) shift; cmd_wait_port "$@" ;;
  tc-stats) shift; cmd_tc_stats "$@" ;;
  *) die "unknown command" ;;
esac
