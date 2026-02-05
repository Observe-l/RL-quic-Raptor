#!/usr/bin/env bash
set -euo pipefail

# Sweep scenarios for 10 Mbps with RTT in {50,100,150,200} ms and loss in {1,3,5,10} %.
# Produces a raw CSV and an aggregated CSV with per-scenario averages.

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN_DIR="$ROOT/go/bin"
NS=${NS:-qns}
PORT=${PORT:-45300}

# Fixed rate for this sweep
RATE="10mbit"
RTTS=(50 100 150 200)
LOSSES=(1 3 5 10)
REPS=${REPS:-30}

OUT_RAW=${OUT_RAW:-/tmp/arq_sweep_10mbps_raw.csv}
OUT_AGG=${OUT_AGG:-/tmp/arq_sweep_10mbps_agg.csv}

K=${K:-40}
R0=${R0:-6}
W=${W:-8}
DDL_MS=${DDL_MS:-50}
RSTEP=${RSTEP:-4}
ACK_EVERY=${ACK_EVERY:-0}

chmod +x "$ROOT/scripts"/*.sh

# Require cached sudo privileges up front to avoid hidden prompts under pipes.
if ! sudo -n true 2>/dev/null; then
  echo "[error] sudo privileges are required. Run 'sudo -v' once and rerun this script." >&2
  exit 1
fi

# Reset namespaces and (re)build binaries once
"$ROOT/scripts/netns_reset.sh" "$NS"
(cd "$ROOT/go" && go build -o "$BIN_DIR/quicfec-server" ./cmd/quicfec-server && go build -o "$BIN_DIR/quicfec-client" ./cmd/quicfec-client)

FILE="$ROOT/go/test_data/train_FD001.txt"
FILE_SIZE=$(stat -c%s "$FILE")

# JSON (line-oriented) file for rl-observation lines
OBS_JSON=${OBS_JSON:-/tmp/arq_sweep_10mbps_rl.json}
echo -n >"$OBS_JSON"

# CSV headers
echo "rate_mbps,rtt_ms,loss_pct,run,client_bytes,client_dgrams,client_send_mbps,server_goodput_mbps,dur_ms,clusters,attempts,repairs,symbols_total,overhead_pct,md5_ok" >"$OUT_RAW"

configure_qdisc() {
  local rtt_ms=$1
  local loss_pct=$2
  local half=$(( rtt_ms / 2 ))
  # Host side (veth0): netem delay+loss + tbf for rate
  sudo tc qdisc del dev veth0 root 2>/dev/null || true
  sudo tc qdisc replace dev veth0 root handle 1: netem delay ${half}ms loss ${loss_pct}%
  sudo tc qdisc replace dev veth0 parent 1:1 handle 10: tbf rate ${RATE} burst 32kb latency 400ms
  # Netns side (veth1): mirror half RTT delay, no loss, no shaping
  sudo ip netns exec "$NS" tc qdisc del dev veth1 root 2>/dev/null || true
  sudo ip netns exec "$NS" tc qdisc replace dev veth1 root netem delay ${half}ms
}

for rtt in "${RTTS[@]}"; do
  for loss in "${LOSSES[@]}"; do
    echo "[sweep] rate=${RATE} rtt=${rtt}ms loss=${loss}% reps=${REPS}" >&2
    configure_qdisc "$rtt" "$loss"
    for run in $(seq 1 "$REPS"); do
      SRV_LOG=$(mktemp)
      # Start server
      sudo ip netns exec "$NS" bash -lc "ulimit -n 1048576; '$BIN_DIR/quicfec-server' -addr 10.10.0.2:$PORT -out '$ROOT/go/test_data' -rx-ddl ${DDL_MS}ms -timeout 45s" >"$SRV_LOG" 2>&1 & SP=$!
      sleep 0.4
      # Run client (CC bypass)
      CLI_LOG=$(mktemp)
      export QUIC_FEC_CC_BYPASS=1
      START=$(date +%s%N)
      "$BIN_DIR/quicfec-client" -addr 10.10.0.2:$PORT -file "$FILE" -N $((K+R0)) -K "$K" -L 1200 \
        -post-wait 1s -ack-every "$ACK_EVERY" -dgram-warn 1400 -arq -R0 "$R0" -W "$W" -Rstep "$RSTEP" -max-attempts 5 \
        >"$CLI_LOG" 2>&1 || true
      END=$(date +%s%N)
      sleep 0.2; kill $SP 2>/dev/null || true

      IN_MD5=$(md5sum "$FILE" | awk '{print $1}')
      OUT_MD5=$(md5sum "$ROOT/go/test_data/$(basename "$FILE").recv" | awk '{print $1}' || true)
      MD5_OK=0; [[ "$IN_MD5" == "$OUT_MD5" ]] && MD5_OK=1

      DUR_MS=$(( (END-START)/1000000 ))
      # Parse client stats
      C_LINE=$(grep -E "^\[client-stats\]" "$CLI_LOG" | tail -n1 || true)
      C_DGRAMS=$(echo "$C_LINE" | sed -n 's/.*dgrams=\([0-9]\+\).*/\1/p')
      C_BYTES=$(echo "$C_LINE" | sed -n 's/.*bytes=\([0-9]\+\).*/\1/p')
      C_MBPS=$(echo "$C_LINE" | sed -n 's/.*mbps=\([0-9.\-]\+\).*/\1/p')
      # Parse ARQ stats
      A_LINE=$(grep -E "^\[arq-stats\]" "$CLI_LOG" | tail -n1 || true)
      CLUSTERS=$(echo "$A_LINE" | sed -n 's/.*clusters=\([0-9]\+\).*/\1/p')
      ATTEMPTS=$(echo "$A_LINE" | sed -n 's/.*attempts=\([0-9]\+\).*/\1/p')
      SYMBOLS=$(echo "$A_LINE" | sed -n 's/.*symbols_total=\([0-9]\+\).*/\1/p')
      REPAIRS=$(echo "$A_LINE" | sed -n 's/.*repairs=\([0-9]\+\).*/\1/p')
      OVER_PCT=$(echo "$A_LINE" | sed -n 's/.*overhead_pct=\([0-9.\-]\+\).*/\1/p')
      # Parse server goodput
      S_LINE=$(grep -E "^\[server-stats\]" "$SRV_LOG" | tail -n1 || true)
  RL_OBS=$(grep -E "^\[rl-observation\]" "$SRV_LOG" | tail -n1 || true)
      # Prefer computing goodput from server dur_s to avoid parsing issues
      S_DUR=$(echo "$S_LINE" | sed -n 's/.*dur_s=\([0-9.\-]\+\).*/\1/p')
      if [[ -n "$S_DUR" && "$S_DUR" != "0" ]]; then
        S_MBPS=$(awk -v sz="$FILE_SIZE" -v ds="$S_DUR" 'BEGIN{printf "%.2f", (sz*8.0/1000000.0)/ds}')
      else
        # Fallback to client wall time if server dur missing
        if [[ "$DUR_MS" -gt 0 ]]; then
          S_MBPS=$(awk -v sz="$FILE_SIZE" -v ms="$DUR_MS" 'BEGIN{printf "%.2f", (sz*8.0/1000000.0)/(ms/1000.0)}')
        else
          S_MBPS=0
        fi
      fi

      # Append CSV row
      echo "10,${rtt},${loss},${run},${C_BYTES:-0},${C_DGRAMS:-0},${C_MBPS:-0},${S_MBPS:-0},${DUR_MS},${CLUSTERS:-0},${ATTEMPTS:-0},${REPAIRS:-0},${SYMBOLS:-0},${OVER_PCT:-0},${MD5_OK}" \
        >>"$OUT_RAW"

      echo "[run] rate=10 rtt=${rtt}ms loss=${loss}% run=${run} dur_ms=${DUR_MS} md5_ok=${MD5_OK} c_mbps=${C_MBPS} s_mbps=${S_MBPS} attempts=${ATTEMPTS} overhead=${OVER_PCT}%" >&2
      if [[ -n "$RL_OBS" ]]; then
        echo "$RL_OBS" >>"$OBS_JSON"
        echo "$RL_OBS" >&2
      fi

      rm -f "$CLI_LOG" "$SRV_LOG"
    done
  done
done

# Aggregate means per (rtt,loss)
{
  echo "rate_mbps,rtt_ms,loss_pct,runs,avg_client_bytes,avg_client_dgrams,avg_client_send_mbps,avg_server_goodput_mbps,avg_dur_ms,avg_clusters,avg_attempts,avg_repairs,avg_symbols_total,avg_overhead_pct,success_rate"
  awk -F, 'NR>1{ key=$2"/"$3; cnt[key]++; sumB[key]+=$5; sumD[key]+=$6; sumCM[key]+=$7; sumSM[key]+=$8; sumDur[key]+=$9; sumCl[key]+=$10; sumAt[key]+=$11; sumRp[key]+=$12; sumSy[key]+=$13; sumOv[key]+=$14; ok[key]+=$15; rate=$1 }
    END{ for (k in cnt){ split(k,a,"/"); rtt=a[1]; loss=a[2]; c=cnt[k]; printf "%s,%s,%s,%d,%.0f,%.2f,%.2f,%.2f,%.0f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f\n", rate,rtt,loss,c,sumB[k]/c,sumD[k]/c,sumCM[k]/c,sumSM[k]/c,sumDur[k]/c,sumCl[k]/c,sumAt[k]/c,sumRp[k]/c,sumSy[k]/c,sumOv[k]/c, ok[k]/c } }' "$OUT_RAW"
} >"$OUT_AGG"

echo "[done] raw=$OUT_RAW agg=$OUT_AGG" >&2
