#!/usr/bin/env bash
set -euo pipefail
NS=${1:?ns}
DEV=${2:?dev}
KIND=${3:?fq_codel|red}
ECN=${4:?on|off}
LIMIT=${5:-1000}
RATE=${6:-}

if [[ -n "${RATE}" ]]; then
  sudo ip netns exec "$NS" tc qdisc replace dev "$DEV" root handle 1: htb default 1
  sudo ip netns exec "$NS" tc class replace dev "$DEV" parent 1: classid 1:1 htb rate "$RATE"
  PARENT="parent 1:1"
else
  PARENT="root"
fi

if [[ "$KIND" == "fq_codel" ]]; then
  if [[ "$ECN" == "on" ]]; then ECNFLAG="ecn"; else ECNFLAG="noecn"; fi
  sudo ip netns exec "$NS" tc qdisc replace dev "$DEV" $PARENT fq_codel $ECNFLAG limit "$LIMIT"
elif [[ "$KIND" == "red" ]]; then
  if [[ "$ECN" == "on" ]]; then ECNFLAG="ecn"; else ECNFLAG=""; fi
  sudo ip netns exec "$NS" tc qdisc replace dev "$DEV" $PARENT red limit 400000 min 30000 max 90000 \
    avpkt 1000 burst 55 probability 0.2 $ECNFLAG ${RATE:+bandwidth $RATE}
else
  echo "Unknown KIND=$KIND" >&2; exit 1
fi
