package fecquic

import (
	"encoding/json"
	"math"
	"os"
	"sort"
	"sync"
	"time"
)

// Observation mirrors the doc (subset implemented now).
type Observation struct {
	GoodputDecodeMbps float64 `json:"goodput_decode_mbps"`
	// GoodputArrivalMbps estimates link throughput based on arrival of the last unique
	// symbol, excluding decoder compute and finalization.
	GoodputArrivalMbps float64 `json:"goodput_arrival_mbps"`
	// DurationTransferMs is the wall-clock time from the first unique symbol arrival
	// to completion (used for goodput estimation).
	DurationTransferMs int64 `json:"duration_transfer_ms"`
	// DurationArrivalMs is the wall-clock time from first unique symbol arrival to
	// last unique symbol arrival.
	DurationArrivalMs int64 `json:"duration_arrival_ms"`
	// DurationDecodeMs is the decoder compute time (sum over blocks), in milliseconds.
	// This matches the common expectation of "raptorq decode time".
	DurationDecodeMs int64 `json:"duration_decode_ms"`
	ResidualErasures int32 `json:"residual_erasures"`
	// FECOverheadPctArrival is an arrival-side redundancy percentage based on UNIQUE symbol arrivals:
	//   100 * rx_repair_symbols / rx_total_symbols.
	// It excludes duplicates/retransmissions and does not represent link-level tx overhead.
	FECOverheadPctArrival float64 `json:"fec_overhead_pct_arrival"`
	// Arrival-side accounting (unique symbols at receiver)
	RxTotalSymbols      int64 `json:"rx_total_symbols"`
	RxRepairSymbols     int64 `json:"rx_repair_symbols"`
	RxSourceSymbols     int64 `json:"rx_source_symbols"`
	RxTotalSymbolBytes  int64 `json:"rx_total_symbol_bytes"`
	RxRepairSymbolBytes int64 `json:"rx_repair_symbol_bytes"`
	RxSourceSymbolBytes int64 `json:"rx_source_symbol_bytes"`
	// Control-plane accounting (server->client ARQ messages)
	CtrlTxBytes              int64   `json:"ctrl_tx_bytes"`
	CtrlTxAckMsgs            int64   `json:"ctrl_tx_ack_msgs"`
	CtrlTxNackMsgs           int64   `json:"ctrl_tx_nack_msgs"`
	CtrlTxDroppedMsgs        int64   `json:"ctrl_tx_dropped_msgs"`
	ARQAttemptsMean          float64 `json:"arq_attempts_mean"`
	ARQAttemptsP95           float64 `json:"arq_attempts_p95"`
	RxUniqueAtDDLMean        float64 `json:"rx_unique_at_ddl_mean"`
	RxUniqueAtDDLP95         float64 `json:"rx_unique_at_ddl_p95"`
	DecodeLatencyP50Ms       float64 `json:"decode_latency_p50_ms"`
	DecodeLatencyP95Ms       float64 `json:"decode_latency_p95_ms"`
	DecodeLatencyMeanMs      float64 `json:"decode_latency_mean_ms"`
	ArrivalSymbolRateKppsP95 float64 `json:"arrival_symbol_rate_kpps_p95"`
	EstimatedAvailableBwMbps float64 `json:"estimated_available_bw_mbps"`
}

// serverMetrics collects metrics on the server.
type serverMetrics struct {
	mu sync.Mutex

	fileBytes  int
	t0First    time.Time
	tLastUniq  time.Time
	tLastWrite time.Time
	gotFirst   bool

	// arrival windows (200ms buckets, 10 buckets => 2s horizon)
	bucketDur  time.Duration
	buckets    []arrBucket
	startTick  time.Time
	lastBucket int // last bucket index we've written to; -1 if none yet

	// distributions
	ddlSamples      []int   // rx_unique at DDL
	decodeLatencyMs []int64 // per-cluster latency ms
	attempts        []int   // attempts at success

	// decoder compute time (sum over blocks)
	decodeComputeTotalNs int64

	// totals for arrival-side overhead
	totalSymbols      int64
	repairSymbols     int64
	totalSymbolBytes  int64
	repairSymbolBytes int64

	// control-plane accounting (server -> client)
	ctrlTxBytes       int64
	ctrlTxAckMsgs     int64
	ctrlTxNackMsgs    int64
	ctrlTxDroppedMsgs int64
}

type arrBucket struct {
	bytes   int64
	symbols int64
}

func newServerMetrics(fileBytes int) *serverMetrics {
	return &serverMetrics{
		fileBytes:  fileBytes,
		bucketDur:  200 * time.Millisecond,
		buckets:    make([]arrBucket, 10),
		lastBucket: -1,
	}
}

func (m *serverMetrics) OnFirstUniqueSymbol(when time.Time) {
	m.mu.Lock()
	if !m.gotFirst {
		m.gotFirst = true
		m.t0First = when
		m.startTick = when
	}
	m.mu.Unlock()
}

func (m *serverMetrics) OnUniqueSymbol(nBytes int, when time.Time, isRepair bool) {
	m.mu.Lock()
	if !m.gotFirst {
		m.gotFirst = true
		m.t0First = when
		m.startTick = when
	}
	if isRepair {
		m.repairSymbols++
		m.repairSymbolBytes += int64(nBytes)
	}
	m.totalSymbols++
	m.totalSymbolBytes += int64(nBytes)
	m.tLastUniq = when
	if !m.startTick.IsZero() {
		// compute bucket index
		delta := when.Sub(m.startTick)
		if delta < 0 {
			delta = 0
		}
		n := len(m.buckets)
		idx := int((delta / m.bucketDur) % time.Duration(n))
		// Clear intermediate buckets when advancing to avoid stale accumulation.
		if m.lastBucket == -1 {
			m.lastBucket = idx
		} else if idx != m.lastBucket {
			// steps ahead (modulo n)
			steps := (idx - m.lastBucket + n) % n
			for s := 1; s <= steps; s++ {
				bidx := (m.lastBucket + s) % n
				// zero this bucket before writing new values into it
				m.buckets[bidx] = arrBucket{}
			}
			m.lastBucket = idx
		}
		m.buckets[idx].bytes += int64(nBytes)
		m.buckets[idx].symbols++
	}
	m.mu.Unlock()
}

// OnWrite marks completion progress of writing decoded / reconstructed bytes to the output.
// This is used to compute decode/write goodput excluding finalize (e.g., SHA verification).
func (m *serverMetrics) OnWrite(when time.Time) {
	m.mu.Lock()
	if !m.gotFirst {
		m.gotFirst = true
		m.t0First = when
		m.startTick = when
	}
	if m.tLastWrite.IsZero() || when.After(m.tLastWrite) {
		m.tLastWrite = when
	}
	m.mu.Unlock()
}

func (m *serverMetrics) OnCtrlTx(nBytes int, msgType string, dropped bool) {
	m.mu.Lock()
	if nBytes > 0 {
		m.ctrlTxBytes += int64(nBytes)
	}
	if dropped {
		m.ctrlTxDroppedMsgs++
		m.mu.Unlock()
		return
	}
	switch msgType {
	case "ack":
		m.ctrlTxAckMsgs++
	case "nack":
		m.ctrlTxNackMsgs++
	}
	m.mu.Unlock()
}

func (m *serverMetrics) OnDDLTick(rxUnique int) {
	m.mu.Lock()
	m.ddlSamples = append(m.ddlSamples, rxUnique)
	m.mu.Unlock()
}

func (m *serverMetrics) OnClusterDecoded(firstSeen time.Time, when time.Time, attempts int, usedRepairs int) {
	m.mu.Lock()
	// per-cluster decode latency
	if !firstSeen.IsZero() {
		m.decodeLatencyMs = append(m.decodeLatencyMs, when.Sub(firstSeen).Milliseconds())
	}
	if attempts < 0 {
		attempts = 0
	}
	m.attempts = append(m.attempts, attempts)
	m.mu.Unlock()
}

// OnDecodeComputeNs records decoder compute time for a successfully decoded block.
func (m *serverMetrics) OnDecodeComputeNs(ns int64) {
	m.mu.Lock()
	if ns > 0 {
		m.decodeComputeTotalNs += ns
	}
	m.mu.Unlock()
}

func (m *serverMetrics) Snapshot(now time.Time) Observation {
	m.mu.Lock()
	defer m.mu.Unlock()
	var durTransferMs int64
	var goodput float64
	var durArrivalMs int64
	var goodputArrival float64
	if m.gotFirst {
		end := now
		// For decode/write goodput, use the last-write timestamp if available.
		// This intentionally excludes finalize (e.g., SHA verification) time.
		if !m.tLastWrite.IsZero() {
			end = m.tLastWrite
		}
		durTransferMs = end.Sub(m.t0First).Milliseconds()
		durSec := float64(durTransferMs) / 1000.0
		if durSec > 1e-9 {
			goodput = (float64(m.fileBytes) * 8.0 / 1e6) / durSec
		}
		if !m.tLastUniq.IsZero() {
			durArrivalMs = m.tLastUniq.Sub(m.t0First).Milliseconds()
			durArrivalSec := float64(durArrivalMs) / 1000.0
			if durArrivalSec > 1e-9 {
				goodputArrival = (float64(m.fileBytes) * 8.0 / 1e6) / durArrivalSec
			}
		}
	}
	// arrival-side overhead
	var overPct float64
	if m.totalSymbols > 0 {
		overPct = float64(m.repairSymbols) / float64(m.totalSymbols) * 100.0
	}
	rxSourceSymbols := m.totalSymbols - m.repairSymbols
	if rxSourceSymbols < 0 {
		rxSourceSymbols = 0
	}
	rxSourceBytes := m.totalSymbolBytes - m.repairSymbolBytes
	if rxSourceBytes < 0 {
		rxSourceBytes = 0
	}
	// attempts mean/p95
	meanAttempts, p95Attempts := meanAndP(intsToFloat(m.attempts), 0.95)
	// rx_unique@DDL mean/p95
	meanDDL, p95DDL := meanAndP(intsToFloat(m.ddlSamples), 0.95)
	// decode latency p50/p95
	decLatFloats := int64sToFloat(m.decodeLatencyMs)
	p50Dec, p95Dec := percentiles(decLatFloats, []float64{0.50, 0.95})
	meanDec, _ := meanAndP(decLatFloats, 0.50)
	// arrival rates per bucket and robust BW estimate
	bytesSum := int64(0)
	symSum := int64(0)
	n := len(m.buckets)
	active := 0
	rates := make([]float64, 0, n)
	bucketSec := float64(m.bucketDur) / float64(time.Second)
	for _, b := range m.buckets {
		bytesSum += b.bytes
		symSum += b.symbols
		if b.bytes <= 0 {
			continue
		}
		active++
		rate := (float64(b.bytes) * 8.0 / 1e6)
		if bucketSec > 0 {
			rate = rate / bucketSec
		} else {
			rate = 0
		}
		rates = append(rates, rate)
	}
	// Trimmed mean (20%) as robust available bandwidth estimate
	estBW := 0.0
	if len(rates) > 0 {
		srates := append([]float64(nil), rates...)
		sort.Float64s(srates)
		trim := int(math.Floor(0.2 * float64(len(srates))))
		lo := trim
		hi := len(srates) - trim
		if hi <= lo {
			// fallback to simple mean
			sum := 0.0
			for _, r := range srates {
				sum += r
			}
			estBW = sum / float64(len(srates))
		} else {
			sum := 0.0
			for _, r := range srates[lo:hi] {
				sum += r
			}
			estBW = sum / float64(hi-lo)
		}
	}
	return Observation{
		GoodputDecodeMbps:     goodput,
		GoodputArrivalMbps:    goodputArrival,
		DurationTransferMs:    durTransferMs,
		DurationArrivalMs:     durArrivalMs,
		DurationDecodeMs:      (m.decodeComputeTotalNs + 999_999) / 1_000_000, // ceil(ns->ms)
		ResidualErasures:      0,                                              // non-residual path only; finalize checks integrity
		FECOverheadPctArrival: overPct,
		RxTotalSymbols:        m.totalSymbols,
		RxRepairSymbols:       m.repairSymbols,
		RxSourceSymbols:       rxSourceSymbols,
		RxTotalSymbolBytes:    m.totalSymbolBytes,
		RxRepairSymbolBytes:   m.repairSymbolBytes,
		RxSourceSymbolBytes:   rxSourceBytes,
		CtrlTxBytes:           m.ctrlTxBytes,
		CtrlTxAckMsgs:         m.ctrlTxAckMsgs,
		CtrlTxNackMsgs:        m.ctrlTxNackMsgs,
		CtrlTxDroppedMsgs:     m.ctrlTxDroppedMsgs,
		ARQAttemptsMean:       meanAttempts,
		ARQAttemptsP95:        p95Attempts,
		RxUniqueAtDDLMean:     meanDDL,
		RxUniqueAtDDLP95:      p95DDL,
		DecodeLatencyP50Ms:    p50Dec,
		DecodeLatencyP95Ms:    p95Dec,
		DecodeLatencyMeanMs:   meanDec,
		// Use active bucket count to avoid dilution from idle buckets (common for short transfers).
		ArrivalSymbolRateKppsP95: func() float64 {
			if active <= 0 || bucketSec <= 0 {
				return 0
			}
			return (float64(symSum) / (float64(active) * bucketSec)) / 1000.0
		}(),
		EstimatedAvailableBwMbps: estBW,
	}
}

func (o Observation) PrintJSON() {
	// write a single line prefixed tag
	b, _ := json.Marshal(o)
	os.Stderr.WriteString("[rl-observation] ")
	os.Stderr.Write(b)
	os.Stderr.WriteString("\n")
}

func intsToFloat(a []int) []float64 {
	out := make([]float64, len(a))
	for i, v := range a {
		out[i] = float64(v)
	}
	return out
}
func int64sToFloat(a []int64) []float64 {
	out := make([]float64, len(a))
	for i, v := range a {
		out[i] = float64(v)
	}
	return out
}

func meanAndP(vals []float64, p float64) (mean, pctl float64) {
	if len(vals) == 0 {
		return 0, 0
	}
	s := 0.0
	for _, v := range vals {
		s += v
	}
	mean = s / float64(len(vals))
	sort.Float64s(vals)
	idx := int(math.Ceil(p*float64(len(vals))) - 1)
	if idx < 0 {
		idx = 0
	}
	if idx >= len(vals) {
		idx = len(vals) - 1
	}
	pctl = vals[idx]
	return
}

func percentiles(vals []float64, ps []float64) (p50, p95 float64) {
	if len(vals) == 0 {
		return 0, 0
	}
	sort.Float64s(vals)
	pick := func(q float64) float64 {
		idx := int(math.Ceil(q*float64(len(vals))) - 1)
		if idx < 0 {
			idx = 0
		}
		if idx >= len(vals) {
			idx = len(vals) - 1
		}
		return vals[idx]
	}
	return pick(0.50), pick(0.95)
}
