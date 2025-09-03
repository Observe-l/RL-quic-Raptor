#!/usr/bin/env bash
set -euo pipefail
NS=${1:-}
DEV=${2:?dev}
MODE=${3:?none|gemodel|state}
shift 3
if [[ -n "$NS" ]]; then RUN=(sudo ip netns exec "$NS"); else RUN=(sudo); fi
"${RUN[@]}" tc qdisc replace dev "$DEV" root handle 10: netem
case "$MODE" in
  none)
    "${RUN[@]}" tc qdisc replace dev "$DEV" root netem loss 0%
    ;;
  gemodel)
    p=${1:?p}; r=${2:?r}; one_m_h=${3:?1-h}; one_m_k=${4:?1-k}
    "${RUN[@]}" tc qdisc replace dev "$DEV" root netem loss gemodel "$p" "$r" "$one_m_h" "$one_m_k"
    ;;
  state)
    "${RUN[@]}" tc qdisc replace dev "$DEV" root netem loss state "$@"
    ;;
  *)
    echo "Unknown MODE=$MODE" >&2; exit 1
    ;;
esac
