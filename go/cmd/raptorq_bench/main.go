package main

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	mrand "math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/quic-go/quic-go/fec"
	"golang.org/x/sys/unix"
)

type config struct {
	FileBytes int
	SizeLabel string
	K         int
	R         int
	L         int
}

type encodedBlock struct {
	OriginalBytes int
	K             int
	Symbols       [][]byte // short systematic payloads followed by full repair symbols
}

type trialRecord struct {
	FileSizeLabel               string  `json:"file_size_label"`
	FileSizeBytes               int     `json:"file_size_bytes"`
	K                           int     `json:"k"`
	R                           int     `json:"r"`
	L                           int     `json:"symbol_bytes"`
	Trial                       int     `json:"trial"`
	BlockCount                  int     `json:"block_count"`
	PaddedBytes                 int     `json:"padded_bytes"`
	SourceSymbolsEncoded        int     `json:"source_symbols_encoded"`
	RepairSymbolsEncoded        int     `json:"repair_symbols_encoded"`
	SourceSymbolsErased         int     `json:"source_symbols_erased"`
	DecodeSymbolMargin          int     `json:"decode_symbol_margin"`
	RepairSymbolsGivenToDecoder int     `json:"repair_symbols_given_to_decoder"`
	EncodeTimeMs                float64 `json:"encode_time_ms"`
	DecodeTimeMs                float64 `json:"decode_time_ms"`
	EncodeCPUPercentAllCores    float64 `json:"encode_cpu_percent_all_cores"`
	DecodeCPUPercentAllCores    float64 `json:"decode_cpu_percent_all_cores"`
	RSSAfterEncodeMiB           float64 `json:"rss_after_encode_mib"`
	RSSAfterDecodeMiB           float64 `json:"rss_after_decode_mib"`
	RoundTripOK                 bool    `json:"round_trip_ok"`
}

type workerSummary struct {
	LogicalCPUs        int     `json:"logical_cpus"`
	HostSystemCPU      float64 `json:"host_system_cpu_percent_during_group"`
	GroupPeakRSSMiB    float64 `json:"group_peak_rss_mib"`
	CompletedTrials    int     `json:"completed_trials"`
	RoundTripPassCount int     `json:"round_trip_pass_count"`
}

type workerMessage struct {
	Kind    string         `json:"kind"`
	Trial   *trialRecord   `json:"trial,omitempty"`
	Summary *workerSummary `json:"summary,omitempty"`
}

type summaryRecord struct {
	Config        config
	Repeats       int
	LogicalCPUs   int
	HostSystemCPU float64
	GroupPeakRSS  float64
	EncodeMean    float64
	EncodeP50     float64
	EncodeP95     float64
	DecodeMean    float64
	DecodeP50     float64
	DecodeP95     float64
	EncodeCPUMean float64
	DecodeCPUMean float64
	EncodeRSSMean float64
	DecodeRSSMean float64
	EncodeRSSPeak float64
	DecodeRSSPeak float64
	RoundTripPass int
}

func main() {
	worker := flag.Bool("worker", false, "internal worker mode")
	fileBytes := flag.Int("file-bytes", 100*1024, "file size in bytes (binary units are used by the parent runner)")
	sizeLabel := flag.String("size-label", "", "display label for this file size")
	k := flag.Int("K", 20, "source symbols per full block")
	r := flag.Int("R", 5, "repair symbols per block")
	l := flag.Int("L", 1200, "symbol payload bytes, matching quicfec-client default")
	repeats := flag.Int("repeats", 1000, "repetitions per configuration")
	seed := flag.Int64("seed", 20260923, "deterministic payload seed")
	outPrefix := flag.String("out-prefix", "", "output filename prefix; defaults to a timestamped path under ../python/results")
	flag.Parse()

	if *worker {
		label := *sizeLabel
		if label == "" {
			label = fmt.Sprintf("%dB", *fileBytes)
		}
		if err := runWorker(config{FileBytes: *fileBytes, SizeLabel: label, K: *k, R: *r, L: *l}, *repeats, *seed); err != nil {
			fmt.Fprintln(os.Stderr, "raptorq benchmark worker:", err)
			os.Exit(1)
		}
		return
	}

	if *repeats <= 0 {
		fatalf("repeats must be positive")
	}
	prefix := *outPrefix
	if prefix == "" {
		prefix = filepath.Join("..", "python", "results", "raptorq_encode_decode_"+time.Now().Format("20060102_150405"))
	}
	if err := runParent(prefix, *repeats, *seed, *l); err != nil {
		fatalf("%v", err)
	}
}

func runParent(prefix string, repeats int, seed int64, symbolBytes int) error {
	if symbolBytes <= 0 {
		return errors.New("L must be positive")
	}
	configs := []config{
		{FileBytes: 100 * 1024, SizeLabel: "100KB", K: 20, R: 5, L: symbolBytes},
		{FileBytes: 100 * 1024, SizeLabel: "100KB", K: 40, R: 10, L: symbolBytes},
		{FileBytes: 100 * 1024, SizeLabel: "100KB", K: 60, R: 15, L: symbolBytes},
		{FileBytes: 1024 * 1024, SizeLabel: "1MB", K: 20, R: 5, L: symbolBytes},
		{FileBytes: 1024 * 1024, SizeLabel: "1MB", K: 40, R: 10, L: symbolBytes},
		{FileBytes: 1024 * 1024, SizeLabel: "1MB", K: 60, R: 15, L: symbolBytes},
	}
	if err := os.MkdirAll(filepath.Dir(prefix), 0o755); err != nil {
		return err
	}
	rawPath := prefix + "_raw.csv"
	summaryPath := prefix + "_summary.csv"
	for _, p := range []string{rawPath, summaryPath} {
		if _, err := os.Stat(p); err == nil {
			return fmt.Errorf("refusing to overwrite existing output %s", p)
		} else if !os.IsNotExist(err) {
			return err
		}
	}

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	allRows := make([]trialRecord, 0, len(configs)*repeats)
	summaries := make([]summaryRecord, 0, len(configs))
	for _, cfg := range configs {
		fmt.Fprintf(os.Stderr, "[raptorq-bench] start size=%s K=%d R=%d repeats=%d L=%d\n", cfg.SizeLabel, cfg.K, cfg.R, repeats, cfg.L)
		rows, group, err := runWorkerProcess(exe, cfg, repeats, seed)
		if err != nil {
			return fmt.Errorf("size=%s K=%d R=%d: %w", cfg.SizeLabel, cfg.K, cfg.R, err)
		}
		if len(rows) != repeats || group.CompletedTrials != repeats {
			return fmt.Errorf("incomplete group size=%s K=%d R=%d: got %d/%d trials", cfg.SizeLabel, cfg.K, cfg.R, len(rows), repeats)
		}
		allRows = append(allRows, rows...)
		summaries = append(summaries, makeSummary(cfg, repeats, rows, group))
		fmt.Fprintf(os.Stderr, "[raptorq-bench] done size=%s K=%d R=%d peak_rss=%.2f MiB host_cpu=%.2f%%\n", cfg.SizeLabel, cfg.K, cfg.R, group.GroupPeakRSSMiB, group.HostSystemCPU)
	}

	if err := writeRawCSV(rawPath, allRows, summaries); err != nil {
		return err
	}
	if err := writeSummaryCSV(summaryPath, summaries); err != nil {
		return err
	}
	fmt.Printf("raw_csv=%s\nsummary_csv=%s\n", rawPath, summaryPath)
	return nil
}

func runWorkerProcess(exe string, cfg config, repeats int, seed int64) ([]trialRecord, workerSummary, error) {
	args := []string{
		"-worker=true",
		fmt.Sprintf("-file-bytes=%d", cfg.FileBytes),
		fmt.Sprintf("-size-label=%s", cfg.SizeLabel),
		fmt.Sprintf("-K=%d", cfg.K),
		fmt.Sprintf("-R=%d", cfg.R),
		fmt.Sprintf("-L=%d", cfg.L),
		fmt.Sprintf("-repeats=%d", repeats),
		fmt.Sprintf("-seed=%d", seed),
	}
	cmd := exec.Command(exe, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, workerSummary{}, err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, workerSummary{}, err
	}

	rows := make([]trialRecord, 0, repeats)
	var group workerSummary
	gotSummary := false
	dec := json.NewDecoder(bufio.NewReader(stdout))
	for {
		var msg workerMessage
		err := dec.Decode(&msg)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return nil, workerSummary{}, fmt.Errorf("decode worker output: %w", err)
		}
		switch msg.Kind {
		case "trial":
			if msg.Trial == nil {
				return nil, workerSummary{}, errors.New("worker emitted an empty trial record")
			}
			rows = append(rows, *msg.Trial)
		case "summary":
			if msg.Summary == nil {
				return nil, workerSummary{}, errors.New("worker emitted an empty summary")
			}
			group = *msg.Summary
			gotSummary = true
		default:
			return nil, workerSummary{}, fmt.Errorf("unknown worker message kind %q", msg.Kind)
		}
	}
	if err := cmd.Wait(); err != nil {
		return nil, workerSummary{}, err
	}
	if !gotSummary {
		return nil, workerSummary{}, errors.New("worker did not emit a summary")
	}
	return rows, group, nil
}

func runWorker(cfg config, repeats int, seed int64) error {
	if cfg.FileBytes <= 0 || cfg.K <= 0 || cfg.R < 0 || cfg.L <= 0 {
		return errors.New("file size, K, and L must be positive and R must be nonnegative")
	}
	if cfg.K+cfg.R > 256 {
		return fmt.Errorf("K+R=%d exceeds the symbol id limit 256", cfg.K+cfg.R)
	}
	if repeats <= 0 {
		return errors.New("repeats must be positive")
	}

	payload := make([]byte, cfg.FileBytes)
	rng := mrand.New(mrand.NewSource(seed + int64(cfg.FileBytes)))
	if _, err := rng.Read(payload); err != nil {
		return fmt.Errorf("generate deterministic payload: %w", err)
	}

	encoder := json.NewEncoder(os.Stdout)
	hostCPUStart, hostCPUStartErr := readHostCPUStat()
	passes := 0
	for trial := 1; trial <= repeats; trial++ {
		// Reclaim objects from the previous repetition outside the timed regions.
		// This stabilizes live-heap/RSS observations without charging GC to RaptorQ.
		if trial > 1 {
			// Explicitly collect only between independent file-transfer repetitions.
			runtimeGC()
		}

		blockCount := 0
		paddedBytes := 0
		sourceCount := 0
		repairCount := 0
		var encoded []encodedBlock
		encodeDuration, encodeCPU, err := measure(func() error {
			var encodeErr error
			encoded, blockCount, paddedBytes, sourceCount, repairCount, encodeErr = encodeFile(payload, cfg)
			return encodeErr
		})
		if err != nil {
			return fmt.Errorf("encode trial %d: %w", trial, err)
		}
		rssAfterEncode := currentRSSMiB()

		var decoded []byte
		erasedSources := 0
		repairInputs := 0
		decodeDuration, decodeCPU, err := measure(func() error {
			var decodeErr error
			decoded, erasedSources, repairInputs, decodeErr = decodeFile(encoded, cfg, trial)
			return decodeErr
		})
		if err != nil {
			return fmt.Errorf("decode trial %d: %w", trial, err)
		}
		rssAfterDecode := currentRSSMiB()
		if !bytes.Equal(payload, decoded) {
			return fmt.Errorf("round-trip mismatch at trial %d", trial)
		}
		passes++

		row := trialRecord{
			FileSizeLabel: cfg.SizeLabel, FileSizeBytes: cfg.FileBytes,
			K: cfg.K, R: cfg.R, L: cfg.L, Trial: trial,
			BlockCount: blockCount, PaddedBytes: paddedBytes,
			SourceSymbolsEncoded: sourceCount, RepairSymbolsEncoded: repairCount,
			SourceSymbolsErased: erasedSources, DecodeSymbolMargin: repairInputs - erasedSources,
			RepairSymbolsGivenToDecoder: repairInputs,
			EncodeTimeMs:                float64(encodeDuration.Nanoseconds()) / 1e6,
			DecodeTimeMs:                float64(decodeDuration.Nanoseconds()) / 1e6,
			EncodeCPUPercentAllCores:    encodeCPU, DecodeCPUPercentAllCores: decodeCPU,
			RSSAfterEncodeMiB: rssAfterEncode, RSSAfterDecodeMiB: rssAfterDecode,
			RoundTripOK: true,
		}
		if err := encoder.Encode(workerMessage{Kind: "trial", Trial: &row}); err != nil {
			return err
		}
		if trial%100 == 0 || trial == repeats {
			fmt.Fprintf(os.Stderr, "[raptorq-bench] size=%s K=%d R=%d trial=%d/%d\n", cfg.SizeLabel, cfg.K, cfg.R, trial, repeats)
		}
	}

	hostCPUEnd, hostCPUEndErr := readHostCPUStat()
	hostCPU := -1.0
	if hostCPUStartErr == nil && hostCPUEndErr == nil {
		hostCPU = hostCPUPercent(hostCPUStart, hostCPUEnd)
	}
	var usage unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &usage); err != nil {
		return fmt.Errorf("get group peak RSS: %w", err)
	}
	group := workerSummary{
		LogicalCPUs:        runtimeNumCPU(),
		HostSystemCPU:      hostCPU,
		GroupPeakRSSMiB:    float64(usage.Maxrss) / 1024.0, // Linux reports KiB.
		CompletedTrials:    repeats,
		RoundTripPassCount: passes,
	}
	return encoder.Encode(workerMessage{Kind: "summary", Summary: &group})
}

func encodeFile(payload []byte, cfg config) ([]encodedBlock, int, int, int, int, error) {
	blocks := make([]encodedBlock, 0, (len(payload)+cfg.K*cfg.L-1)/(cfg.K*cfg.L))
	paddedBytes, sourceCount, repairCount := 0, 0, 0
	for offset, blockID := 0, 0; offset < len(payload); blockID++ {
		end := offset + cfg.K*cfg.L
		if end > len(payload) {
			end = len(payload)
		}
		originalLen := end - offset
		curK := (originalLen + cfg.L - 1) / cfg.L // transfer path shrinks the final K.
		if curK < 1 || curK > cfg.K {
			return nil, 0, 0, 0, 0, fmt.Errorf("invalid block K=%d", curK)
		}

		padded := make([]byte, curK*cfg.L)
		copy(padded, payload[offset:end])
		enc, err := fec.NewRaptorQEncoder(padded, curK, cfg.L)
		if err != nil {
			return nil, 0, 0, 0, 0, fmt.Errorf("block %d encoder: %w", blockID, err)
		}
		symbols := make([][]byte, curK+cfg.R)
		for i := 0; i < curK; i++ {
			start := i * cfg.L
			payloadLen := cfg.L
			if remaining := originalLen - start; remaining < payloadLen {
				payloadLen = remaining
			}
			symbols[i] = make([]byte, payloadLen)
			copy(symbols[i], padded[start:start+payloadLen])
		}
		for j := 0; j < cfg.R; j++ {
			id := uint32(curK + j)
			generated := enc.GenSymbol(id)
			if len(generated) != cfg.L {
				return nil, 0, 0, 0, 0, fmt.Errorf("block %d repair ESI %d has %d bytes, want %d", blockID, id, len(generated), cfg.L)
			}
			symbols[curK+j] = append([]byte(nil), generated...)
		}
		blocks = append(blocks, encodedBlock{OriginalBytes: originalLen, K: curK, Symbols: symbols})
		paddedBytes += len(padded)
		sourceCount += curK
		repairCount += cfg.R
		offset = end
	}
	return blocks, len(blocks), paddedBytes, sourceCount, repairCount, nil
}

func decodeFile(blocks []encodedBlock, cfg config, trial int) ([]byte, int, int, error) {
	out := make([]byte, 0, cfg.FileBytes)
	erasedTotal, repairTotal := 0, 0
	for blockIndex, block := range blocks {
		dec, err := fec.NewRaptorQDecoder(block.OriginalBytes, cfg.L)
		if err != nil {
			return nil, 0, 0, fmt.Errorf("block %d decoder: %w", blockIndex, err)
		}
		// Exercise repair decoding while staying within the requested R-1 loss
		// bound. All R generated repairs are supplied to the decoder.
		erasureCount := cfg.R - 1
		if erasureCount < 0 {
			erasureCount = 0
		}
		if erasureCount > block.K {
			erasureCount = block.K
		}
		lost := make([]bool, block.K)
		if erasureCount > 0 {
			start := (trial + blockIndex) % block.K
			for i := 0; i < erasureCount; i++ {
				lost[(start+i)%block.K] = true
			}
		}
		for i := 0; i < block.K; i++ {
			if lost[i] {
				continue
			}
			// Receiver pads a short final source datagram to the configured L bytes.
			symbol := make([]byte, cfg.L)
			copy(symbol, block.Symbols[i])
			if _, err := dec.AddSymbol(uint32(i), symbol); err != nil {
				return nil, 0, 0, fmt.Errorf("block %d source symbol %d: %w", blockIndex, i, err)
			}
		}
		for j := 0; j < cfg.R; j++ {
			id := uint32(block.K + j)
			if _, err := dec.AddSymbol(id, block.Symbols[block.K+j]); err != nil {
				return nil, 0, 0, fmt.Errorf("block %d repair symbol %d: %w", blockIndex, id, err)
			}
		}
		ok, recovered, err := dec.Decode()
		if err != nil {
			return nil, 0, 0, fmt.Errorf("block %d decode: %w", blockIndex, err)
		}
		if !ok || len(recovered) != block.OriginalBytes {
			return nil, 0, 0, fmt.Errorf("block %d decode incomplete: ok=%v got=%d want=%d", blockIndex, ok, len(recovered), block.OriginalBytes)
		}
		out = append(out, recovered...)
		erasedTotal += erasureCount
		repairTotal += cfg.R
	}
	return out, erasedTotal, repairTotal, nil
}

func measure(fn func() error) (time.Duration, float64, error) {
	beforeCPU, err := processCPUSeconds()
	if err != nil {
		return 0, 0, err
	}
	start := time.Now()
	workErr := fn()
	wall := time.Since(start)
	afterCPU, cpuErr := processCPUSeconds()
	if workErr != nil {
		return wall, 0, workErr
	}
	if cpuErr != nil {
		return wall, 0, cpuErr
	}
	cpuDelta := afterCPU - beforeCPU
	pct := 0.0
	if wall > 0 && runtimeNumCPU() > 0 {
		// Aggregate CPU seconds across all process threads, normalized by the
		// total logical CPU capacity, so 100% means all machine CPUs fully used.
		pct = 100.0 * cpuDelta / (wall.Seconds() * float64(runtimeNumCPU()))
	}
	return wall, pct, nil
}

func processCPUSeconds() (float64, error) {
	var usage unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &usage); err != nil {
		return 0, err
	}
	return timevalSeconds(usage.Utime) + timevalSeconds(usage.Stime), nil
}

func timevalSeconds(tv unix.Timeval) float64 {
	return float64(tv.Sec) + float64(tv.Usec)/1e6
}

func currentRSSMiB() float64 {
	f, err := os.Open("/proc/self/statm")
	if err != nil {
		return -1
	}
	defer f.Close()
	var totalPages, residentPages uint64
	if _, err := fmt.Fscan(f, &totalPages, &residentPages); err != nil {
		return -1
	}
	return float64(residentPages*uint64(os.Getpagesize())) / (1024.0 * 1024.0)
}

type hostCPUStat struct {
	Total uint64
	Busy  uint64
}

func readHostCPUStat() (hostCPUStat, error) {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return hostCPUStat{}, err
	}
	fields := strings.Fields(strings.SplitN(string(b), "\n", 2)[0])
	if len(fields) < 9 || fields[0] != "cpu" {
		return hostCPUStat{}, errors.New("unexpected /proc/stat CPU line")
	}
	var total, idle, iowait uint64
	for i := 1; i < len(fields) && i <= 8; i++ {
		v, err := strconv.ParseUint(fields[i], 10, 64)
		if err != nil {
			return hostCPUStat{}, err
		}
		total += v
		if i == 4 {
			idle = v
		}
		if i == 5 {
			iowait = v
		}
	}
	if idle+iowait > total {
		return hostCPUStat{}, errors.New("invalid idle counters in /proc/stat")
	}
	return hostCPUStat{Total: total, Busy: total - idle - iowait}, nil
}

func hostCPUPercent(start, end hostCPUStat) float64 {
	total := end.Total - start.Total
	if total == 0 || end.Busy < start.Busy {
		return -1
	}
	return 100.0 * float64(end.Busy-start.Busy) / float64(total)
}

func makeSummary(cfg config, repeats int, rows []trialRecord, group workerSummary) summaryRecord {
	encTimes, decTimes := make([]float64, 0, len(rows)), make([]float64, 0, len(rows))
	encCPU, decCPU := make([]float64, 0, len(rows)), make([]float64, 0, len(rows))
	encRSS, decRSS := make([]float64, 0, len(rows)), make([]float64, 0, len(rows))
	passes := 0
	for _, row := range rows {
		encTimes = append(encTimes, row.EncodeTimeMs)
		decTimes = append(decTimes, row.DecodeTimeMs)
		encCPU = append(encCPU, row.EncodeCPUPercentAllCores)
		decCPU = append(decCPU, row.DecodeCPUPercentAllCores)
		if row.RSSAfterEncodeMiB >= 0 {
			encRSS = append(encRSS, row.RSSAfterEncodeMiB)
		}
		if row.RSSAfterDecodeMiB >= 0 {
			decRSS = append(decRSS, row.RSSAfterDecodeMiB)
		}
		if row.RoundTripOK {
			passes++
		}
	}
	return summaryRecord{
		Config: cfg, Repeats: repeats, LogicalCPUs: group.LogicalCPUs,
		HostSystemCPU: group.HostSystemCPU, GroupPeakRSS: group.GroupPeakRSSMiB,
		EncodeMean: mean(encTimes), EncodeP50: percentile(encTimes, 0.50), EncodeP95: percentile(encTimes, 0.95),
		DecodeMean: mean(decTimes), DecodeP50: percentile(decTimes, 0.50), DecodeP95: percentile(decTimes, 0.95),
		EncodeCPUMean: mean(encCPU), DecodeCPUMean: mean(decCPU),
		EncodeRSSMean: mean(encRSS), DecodeRSSMean: mean(decRSS),
		EncodeRSSPeak: max(encRSS), DecodeRSSPeak: max(decRSS), RoundTripPass: passes,
	}
}

func writeRawCSV(path string, rows []trialRecord, summaries []summaryRecord) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	if err := w.Write([]string{
		"file_size_label", "file_size_bytes", "K", "R", "symbol_bytes_L", "trial", "block_count", "padded_bytes",
		"source_symbols_encoded", "repair_symbols_encoded", "source_symbols_erased", "decode_symbol_margin", "repair_symbols_given_to_decoder",
		"encode_time_ms", "decode_time_ms", "encode_cpu_pct_all_logical_cpus", "decode_cpu_pct_all_logical_cpus",
		"process_rss_after_encode_mib", "process_rss_after_decode_mib", "round_trip_ok",
	}); err != nil {
		return err
	}
	for _, row := range rows {
		if err := w.Write([]string{
			row.FileSizeLabel, strconv.Itoa(row.FileSizeBytes), strconv.Itoa(row.K), strconv.Itoa(row.R), strconv.Itoa(row.L), strconv.Itoa(row.Trial),
			strconv.Itoa(row.BlockCount), strconv.Itoa(row.PaddedBytes), strconv.Itoa(row.SourceSymbolsEncoded), strconv.Itoa(row.RepairSymbolsEncoded),
			strconv.Itoa(row.SourceSymbolsErased), strconv.Itoa(row.DecodeSymbolMargin), strconv.Itoa(row.RepairSymbolsGivenToDecoder),
			f64(row.EncodeTimeMs), f64(row.DecodeTimeMs), f64(row.EncodeCPUPercentAllCores), f64(row.DecodeCPUPercentAllCores),
			f64(row.RSSAfterEncodeMiB), f64(row.RSSAfterDecodeMiB), strconv.FormatBool(row.RoundTripOK),
		}); err != nil {
			return err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return err
	}
	return f.Sync()
}

func writeSummaryCSV(path string, rows []summaryRecord) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	if err := w.Write([]string{
		"file_size_label", "file_size_bytes", "K", "R", "symbol_bytes_L", "repeats", "logical_cpus",
		"encode_time_mean_ms", "encode_time_p50_ms", "encode_time_p95_ms",
		"decode_time_mean_ms", "decode_time_p50_ms", "decode_time_p95_ms",
		"encode_cpu_pct_all_logical_cpus_mean", "decode_cpu_pct_all_logical_cpus_mean",
		"process_rss_after_encode_mean_mib", "process_rss_after_decode_mean_mib",
		"process_rss_after_encode_peak_mib", "process_rss_after_decode_peak_mib", "group_peak_rss_mib",
		"host_system_cpu_pct_during_group", "round_trip_passes",
	}); err != nil {
		return err
	}
	for _, row := range rows {
		c := row.Config
		if err := w.Write([]string{
			c.SizeLabel, strconv.Itoa(c.FileBytes), strconv.Itoa(c.K), strconv.Itoa(c.R), strconv.Itoa(c.L), strconv.Itoa(row.Repeats), strconv.Itoa(row.LogicalCPUs),
			f64(row.EncodeMean), f64(row.EncodeP50), f64(row.EncodeP95), f64(row.DecodeMean), f64(row.DecodeP50), f64(row.DecodeP95),
			f64(row.EncodeCPUMean), f64(row.DecodeCPUMean), f64(row.EncodeRSSMean), f64(row.DecodeRSSMean),
			f64(row.EncodeRSSPeak), f64(row.DecodeRSSPeak), f64(row.GroupPeakRSS), f64(row.HostSystemCPU), strconv.Itoa(row.RoundTripPass),
		}); err != nil {
			return err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return err
	}
	return f.Sync()
}

func mean(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	sum := 0.0
	for _, x := range xs {
		sum += x
	}
	return sum / float64(len(xs))
}

func max(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	m := xs[0]
	for _, x := range xs[1:] {
		if x > m {
			m = x
		}
	}
	return m
}

func percentile(xs []float64, q float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	sorted := append([]float64(nil), xs...)
	sort.Float64s(sorted)
	pos := q * float64(len(sorted)-1)
	lo := int(pos)
	hi := lo + 1
	if hi >= len(sorted) {
		return sorted[lo]
	}
	fraction := pos - float64(lo)
	return sorted[lo]*(1-fraction) + sorted[hi]*fraction
}

func f64(x float64) string { return strconv.FormatFloat(x, 'f', 6, 64) }

// These wrappers keep measurement logic easy to unit-test in isolation later.
var runtimeGC = func() { runtime.GC() }
var runtimeNumCPU = func() int { return runtime.NumCPU() }

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
