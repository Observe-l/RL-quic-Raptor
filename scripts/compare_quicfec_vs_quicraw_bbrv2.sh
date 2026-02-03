#!/usr/bin/env bash
set -euo pipefail

# Compare QUIC-FEC (BBRv2) vs raw QUIC (BBRv2) under:
#   1) no loss
#   2) GE loss
# Report mean / p50 / p95 for: goodput_mbps, dur_ms, over_head, e2e_delay_ms.
#
# e2e_delay_ms is computed from real sender/receiver timestamps emitted by:
# - sender:   [sender-e2e] start_ns=...
# - receiver: [receiver-e2e] end_ns=... ok=...
# and then surfaced in each runner's [run] line as e2e_delay_ms=...

ROOT=$(cd "$(dirname "$0")/.." && pwd)

RUNS=${RUNS:-20}
BITRATE_MBPS=${BITRATE_MBPS:-10}
RTT_MS=${RTT_MS:-50}

# Default GE model under test.
GE_MODEL=${GE_MODEL:-gemodel:1.905626,10.377358,0.000000,99.000000}

# File sizes to test (bytes). Defaults per user request: 128KB and 1MB.
# - Override with FILE_BYTES_LIST="131072 1048576 ..."
# - Or set FILE to test a single custom path.
FILE_BYTES_LIST=${FILE_BYTES_LIST:-"131072 1048576"}
FILE=${FILE:-}

# QUIC-FEC knobs (override via env if desired)
K=${K:-30}
R0=${R0:-4}
W=${W:-8}
RSTEP=${RSTEP:-4}
ACK_EVERY=${ACK_EVERY:-8}
MAX_ATTEMPTS=${MAX_ATTEMPTS:-0}
USE_ARQ=${USE_ARQ:-1}
TRANSPORT=${TRANSPORT:-dgram}

NS=${NS:-qns}
OUT_JSONL=${OUT_JSONL:-"/tmp/compare_quicfec_vs_quicraw_${NS}_$(date +%s).jsonl"}

if ! command -v python3 >/dev/null 2>&1; then
	echo "[error] python3 is required" >&2
	exit 2
fi

ensure_file() {
	local fpath="$1"
	local fbytes="$2"
	mkdir -p "$(dirname "$fpath")"
	if [[ ! -f "$fpath" ]]; then
		head -c "$fbytes" </dev/urandom >"$fpath"
	fi
}

if [[ -n "$FILE" ]]; then
	if [[ ! -f "$FILE" ]]; then
		echo "[error] FILE is set but does not exist: $FILE" >&2
		exit 2
	fi
else
	# Pre-create the requested benchmark files.
	for fb in $FILE_BYTES_LIST; do
		ensure_file "$ROOT/go/test_data/bench_${fb}.bin" "$fb"
	done
fi

# Best-effort warm build and netns init.
# - Let quicfec create/reset netns.
# - Let quicraw reuse that netns.
WARM_FILE="$FILE"
if [[ -z "$WARM_FILE" ]]; then
	# Use the first size in FILE_BYTES_LIST.
	first_fb=${FILE_BYTES_LIST%% *}
	WARM_FILE="$ROOT/go/test_data/bench_${first_fb}.bin"
fi

BITRATE_MBPS="$BITRATE_MBPS" RTT_MS="$RTT_MS" LOSS_MODE=none FILE="$WARM_FILE" \
	K="$K" R0="$R0" W="$W" RSTEP="$RSTEP" ACK_EVERY="$ACK_EVERY" MAX_ATTEMPTS="$MAX_ATTEMPTS" USE_ARQ="$USE_ARQ" TRANSPORT="$TRANSPORT" \
	NS="$NS" SETUP_ONLY=1 \
	"$ROOT/scripts/quicfec_run_once.sh" >/dev/null 2>&1 || true

BITRATE_MBPS="$BITRATE_MBPS" RTT_MS="$RTT_MS" LOSS_MODE=none FILE="$WARM_FILE" \
	NS="$NS" SETUP_ONLY=1 SKIP_NETNS_RESET=1 SKIP_TC_CONFIG=1 \
	"$ROOT/scripts/quicraw_run_once.sh" >/dev/null 2>&1 || true

: >"$OUT_JSONL"

run_one() {
	local proto="$1"
	local loss_mode="$2"
	local file_path="$3"
	local file_bytes="$4"

	local out
	if [[ "$proto" == "quic_fec" ]]; then
		out=$(KEEP_E2E_LOGS=1 BITRATE_MBPS="$BITRATE_MBPS" RTT_MS="$RTT_MS" LOSS_MODE="$loss_mode" FILE="$file_path" \
			K="$K" R0="$R0" W="$W" RSTEP="$RSTEP" ACK_EVERY="$ACK_EVERY" MAX_ATTEMPTS="$MAX_ATTEMPTS" USE_ARQ="$USE_ARQ" TRANSPORT="$TRANSPORT" \
			NS="$NS" SKIP_NETNS_RESET=1 SKIP_BUILD=1 \
			"$ROOT/scripts/quicfec_run_once.sh" 2>&1 >/dev/null || true)
	elif [[ "$proto" == "quic_raw" ]]; then
		out=$(BITRATE_MBPS="$BITRATE_MBPS" RTT_MS="$RTT_MS" LOSS_MODE="$loss_mode" FILE="$file_path" \
			NS="$NS" SKIP_NETNS_RESET=1 SKIP_BUILD=1 \
			"$ROOT/scripts/quicraw_run_once.sh" 2>&1 >/dev/null || true)
	else
		echo "[error] unknown proto: $proto" >&2
		return 2
	fi

	OUT="$out" RTT_MS="$RTT_MS" PROTO="$proto" LOSS_MODE="$loss_mode" FILE_BYTES="$file_bytes" python3 - <<'PY' >>"$OUT_JSONL"
import json
import os
import sys

proto = os.environ.get('PROTO', '')
loss_mode = os.environ.get('LOSS_MODE', '')
try:
	rtt_ms = float(os.environ.get('RTT_MS', '0') or '0')
except Exception:
	rtt_ms = 0.0

out_text = os.environ.get('OUT', '')
file_bytes = os.environ.get('FILE_BYTES', '')

lines = (out_text or '').splitlines()

run_line = ''
run_adj_line = ''
for line in lines:
	if line.startswith('[run] '):
		run_line = line
	elif line.startswith('[run-adj] '):
		run_adj_line = line

def parse_kv(line: str):
	out = {}
	for tok in line.split():
		if '=' not in tok:
			continue
		k, v = tok.split('=', 1)
		out[k.strip()] = v.strip()
	return out

kv = parse_kv(run_line) if run_line else {}
kv_adj = parse_kv(run_adj_line) if run_adj_line else {}

def to_int(x, default=0):
	try:
		return int(float(x))
	except Exception:
		return default

def to_float(x, default=0.0):
	try:
		return float(x)
	except Exception:
		return default

over_head_val = kv_adj.get('overhead_adj', kv.get('overhead', ''))
dur_ms = to_float(kv.get('dur_ms', ''), 0.0)
e2e_delay_ms = to_float(kv.get('e2e_delay_ms', 'nan'), float('nan'))
sender_start_ns = to_int(kv.get('sender_start_ns', ''), 0)
receiver_end_ns = to_int(kv.get('receiver_end_ns', ''), 0)
srv_log = kv.get('srv_log', '')
cli_log = kv.get('cli_log', '')

row = {
	'proto': proto or kv.get('proto', ''),
	'scenario': 'noloss' if loss_mode in ('', 'none') else 'ge' if loss_mode.startswith('gemodel:') else 'loss',
	'loss_mode': loss_mode,
	'file_bytes': to_int(file_bytes, 0),
	'rtt_ms': rtt_ms,
	'dur_ms': dur_ms,
	'e2e_delay_ms': e2e_delay_ms,
	'sender_start_ns': sender_start_ns,
	'receiver_end_ns': receiver_end_ns,
	'srv_log': srv_log,
	'cli_log': cli_log,
	'goodput_mbps': to_float(kv.get('s_mbps', ''), 0.0),
	'over_head': to_float(over_head_val, 0.0),
	'md5_ok': to_int(kv.get('md5_ok', '0'), 0),
	'timed_out': to_int(kv.get('timed_out', '0'), 0),
	'client_ok': to_int(kv.get('client_ok', '0'), 0),
}
row['ok'] = int(row['md5_ok'] == 1 and row['timed_out'] == 0 and row['client_ok'] == 1)

sys.stdout.write(json.dumps(row, separators=(',', ':')) + '\n')
PY
}

FILES_TO_TEST=()
if [[ -n "$FILE" ]]; then
	FILES_TO_TEST+=("$FILE")
else
	for fb in $FILE_BYTES_LIST; do
		FILES_TO_TEST+=("$ROOT/go/test_data/bench_${fb}.bin")
	done
fi

for file_path in "${FILES_TO_TEST[@]}"; do
	file_bytes=$(stat -c%s "$file_path" 2>/dev/null || echo 0)

	for scenario in noloss ge; do
		loss_mode="none"
		if [[ "$scenario" == "ge" ]]; then
			loss_mode="$GE_MODEL"
		fi

		for proto in quic_fec quic_raw; do
			for i in $(seq 1 "$RUNS"); do
				echo "[bench] file_bytes=$file_bytes scenario=$scenario proto=$proto run=$i/$RUNS" >&2
				run_one "$proto" "$loss_mode" "$file_path" "$file_bytes"
			done
		done
	done
done

python3 - <<'PY' "$OUT_JSONL"
import json
import math
import sys

path = sys.argv[1]
rows = []
with open(path, 'r', encoding='utf-8') as f:
	for line in f:
		line = line.strip()
		if not line:
			continue
		try:
			rows.append(json.loads(line))
		except Exception:
			pass

if not rows:
	print('[error] no rows parsed', file=sys.stderr)
	sys.exit(2)

groups = {}
for r in rows:
	key = (int(r.get('file_bytes', 0) or 0), r.get('scenario',''), r.get('proto',''))
	groups.setdefault(key, []).append(r)

def pct(values, p):
	if not values:
		return float('nan')
	vs = sorted(values)
	if len(vs) == 1:
		return float(vs[0])
	k = (len(vs)-1) * (p/100.0)
	f = math.floor(k)
	c = math.ceil(k)
	if f == c:
		return float(vs[int(k)])
	return float(vs[f]) * (c-k) + float(vs[c]) * (k-f)

def mean(values):
	return sum(values)/len(values) if values else float('nan')

def fmt(x):
	if x != x:
		return 'nan'
	return f"{x:.3f}"

metrics = [
	('goodput_mbps', 'goodput_mbps'),
	('dur_ms', 'dur_ms'),
	('over_head', 'over_head'),
	('e2e_delay_ms', 'e2e_delay_ms'),
]

print(f"[summary] runs_file={path}")
print("[summary] e2e_delay_ms is taken from each runner's [run] line")
print()

file_sizes = sorted({k[0] for k in groups.keys()})
order = [
	('noloss', 'quic_fec'),
	('noloss', 'quic_raw'),
	('ge', 'quic_fec'),
	('ge', 'quic_raw'),
]

for fb in file_sizes:
	print(f"file_bytes={fb}")
	for scen, proto in order:
		key = (fb, scen, proto)
		rs = groups.get(key, [])
		if not rs:
			continue
		ok = [r for r in rs if int(r.get('ok',0)) == 1]
		print(f"  case scenario={scen} proto={proto} total={len(rs)} ok={len(ok)}")
		for field, label in metrics:
			vals = [float(r.get(field, float('nan'))) for r in ok]
			vals = [v for v in vals if v == v]
			print(f"    {label}: mean={fmt(mean(vals))} p50={fmt(pct(vals,50))} p95={fmt(pct(vals,95))}")
	print()
PY

echo "[done] raw_results=$OUT_JSONL" >&2