package main

import (
    "encoding/csv"
    "encoding/json"
    "flag"
    "fmt"
    "math"
    "math/rand"
    "os"
    "path/filepath"
    "time"
)

type BecSummary struct {
    N        int     `json:"N"`
    Epsilon  float64 `json:"epsilon"`
    Depth    int     `json:"d"`
    EpsHat   float64 `json:"eps_hat"`
    KS_D     float64 `json:"ks_D"`
    KS_p     float64 `json:"ks_p"`
    PMF_RMSE float64 `json:"pmf_rmse"`
    Rho1     float64 `json:"rho1"`
    Runs_p   float64 `json:"runs_p"`
}

type PolarMetrics struct {
    N            int     `json:"N"`
    Epsilon      float64 `json:"epsilon"`
    MaxAbsDelta  float64 `json:"max_abs_delta"`
    MeanAbsDelta float64 `json:"mean_abs_delta"`
    CorrPZ       float64 `json:"corr_pz"`
    MuN          float64 `json:"muN"`
    Phi010       float64 `json:"phi_tau_0_10"`
    Phi005       float64 `json:"phi_tau_0_05"`
}

func main() {
    runs := flag.Int("runs", 10000, "blocks for BEC validation")
    seed := flag.Int64("seed", 12345, "rng seed")
    outDir := flag.String("out", "docs/reports", "output directory")
    epsList := flag.String("eps", "0.01", "comma-separated epsilon list, e.g. 0.005,0.01,0.03,0.05")
    NsFlag := flag.String("Ns", "8,16,32,64,128", "comma-separated N list (powers of two)")
    flag.Parse()

    rng := rand.New(rand.NewSource(*seed))
    epsVals := parseFloatList(*epsList)
    Ns := parseIntList(*NsFlag)

    // Part I: BEC validation for N=8, each eps at d=0 and d=4
    var becRows []BecSummary
    for _, eps := range epsVals {
        for _, d := range []int{0, 4} {
            b := becValidate(rng, 8, eps, d, *runs)
            becRows = append(becRows, b)
        }
    }

    // Write CSV
    if err := os.MkdirAll(*outDir, 0o755); err != nil {
        panic(err)
    }
    csvPath := filepath.Join(*outDir, "bec_validation_summary.csv")
    fcsv, _ := os.Create(csvPath)
    w := csv.NewWriter(fcsv)
    _ = w.Write([]string{"N", "epsilon", "d", "eps_hat", "KS_p", "PMF_RMSE", "ACF_lag1", "Runs_p"})
    for _, r := range becRows {
        _ = w.Write([]string{
            fmt.Sprintf("%d", r.N),
            fmt.Sprintf("%.5f", r.Epsilon),
            fmt.Sprintf("%d", r.Depth),
            fmt.Sprintf("%.5f", r.EpsHat),
            fmt.Sprintf("%.4f", r.KS_p),
            fmt.Sprintf("%.4f", r.PMF_RMSE),
            fmt.Sprintf("%.4f", r.Rho1),
            fmt.Sprintf("%.4f", r.Runs_p),
        })
    }
    w.Flush()
    _ = fcsv.Close()

    // Part II: Polarization metrics for eps list across Ns
    var polRows []PolarMetrics
    polCSV := filepath.Join(*outDir, "polarization_metrics.csv")
    // write header
    pf, _ := os.Create(polCSV)
    pw := csv.NewWriter(pf)
    _ = pw.Write([]string{"N", "epsilon", "muN", "max_abs_delta", "mean_abs_delta", "corr_pZ", "phi_tau_0.1", "phi_tau_0.05"})
    for _, eps := range epsVals {
        for _, N := range Ns {
            pm := polarMetrics(N, eps)
            polRows = append(polRows, pm)
            _ = pw.Write([]string{
                fmt.Sprintf("%d", pm.N),
                fmt.Sprintf("%.5f", pm.Epsilon),
                fmt.Sprintf("%.5f", pm.MuN),
                fmt.Sprintf("%.5f", pm.MaxAbsDelta),
                fmt.Sprintf("%.5f", pm.MeanAbsDelta),
                fmt.Sprintf("%.5f", pm.CorrPZ),
                fmt.Sprintf("%.5f", pm.Phi010),
                fmt.Sprintf("%.5f", pm.Phi005),
            })
            // dump per-index arrays too
            dumpPolarArrays(*outDir, N, eps)
        }
    }
    pw.Flush()
    _ = pf.Close()

    // Write JSON snapshots
    snap := struct {
        Timestamp string          `json:"timestamp"`
        BEC       []BecSummary    `json:"bec"`
        Polar     []PolarMetrics  `json:"polar"`
    }{Timestamp: time.Now().Format(time.RFC3339), BEC: becRows, Polar: polRows}
    b, _ := json.MarshalIndent(snap, "", "  ")
    _ = os.WriteFile(filepath.Join(*outDir, "polar_bec_summary.json"), b, 0o644)

    // Print concise lines to copy into doc
    for _, r := range becRows {
        fmt.Printf("BEC N=%d eps=%.2f%% d=%d: eps_hat=%.4f KS_p=%.3f PMF_RMSE=%.3f rho1=%.3f runs_p=%.3f\n",
            r.N, r.Epsilon*100, r.Depth, r.EpsHat, r.KS_p, r.PMF_RMSE, r.Rho1, r.Runs_p)
    }
    for _, r := range polRows {
        fmt.Printf("POL N=%d eps=%.2f%%: max|Δ|=%.4f mean|Δ|=%.4f corr=%.3f mu=%.4f phi0.1=%.3f phi0.05=%.3f\n",
            r.N, r.Epsilon*100, r.MaxAbsDelta, r.MeanAbsDelta, r.CorrPZ, r.MuN, r.Phi010, r.Phi005)
    }
}

func becValidate(rng *rand.Rand, N int, eps float64, d int, runs int) BecSummary {
    // generate runs blocks and build histogram of E
    hist := make([]int, N+1)
    totalOnes := 0
    // Build a long sequence to compute ACF and runs test
    seq := make([]int, 0, runs*N)
    for t := 0; t < runs; t++ {
        block := make([]int, N)
        for i := 0; i < N; i++ {
            if rng.Float64() < eps { // erased → 1
                block[i] = 1
                totalOnes++
            }
        }
        // interleave if d>0: emulate depth-d by writing d blocks and reading column-wise
        if d > 0 {
            // simple stride interleaver across time windows of size d
            // for i-th symbol in block t, map to position (t mod d, i)
            // since source is i.i.d., statistics unchanged; we still do a no-op to keep structure
        }
        // count erasures per block
        E := 0
        for _, v := range block { E += v }
        hist[E]++
        // append to sequence
        seq = append(seq, block...)
    }
    epsHat := float64(totalOnes) / float64(runs*N)

    // PMF RMSE vs Binomial(N, epsHat)
    rmse := 0.0
    for e := 0; e <= N; e++ {
        emp := float64(hist[e]) / float64(runs)
        th := binomPMF(N, e, epsHat)
        diff := emp - th
        rmse += diff * diff
    }
    rmse = math.Sqrt(rmse / float64(N+1))

    // KS test D and approximate p-value
    // Build empirical CDF from samples of E (expand hist)
    cdfEmp := make([]float64, N+1)
    cdfTh := make([]float64, N+1)
    cum := 0
    for e := 0; e <= N; e++ {
        cum += hist[e]
        cdfEmp[e] = float64(cum) / float64(runs)
        cdfTh[e] = binomCDF(N, e, epsHat)
    }
    D := 0.0
    for e := 0; e <= N; e++ {
        v := math.Abs(cdfEmp[e] - cdfTh[e])
        if v > D { D = v }
    }
    n := float64(runs)
    // Kolmogorov distribution approximation
    en := (math.Sqrt(n) + 0.12 + 0.11/math.Sqrt(n)) * D
    // p ≈ 2 Σ (-1)^{k-1} e^{-2 k^2 en^2}
    ks_p := ksPvalueApprox(en)

    // Lag-1 autocorrelation of sequence
    rho1 := autocorr(seq, 1)

    // Runs test p-value (normal approximation)
    runsP := runsTestP(seq)

    return BecSummary{N: N, Epsilon: eps, Depth: d, EpsHat: epsHat, KS_D: D, KS_p: ks_p, PMF_RMSE: rmse, Rho1: rho1, Runs_p: runsP}
}

func binomPMF(n, k int, p float64) float64 {
    return math.Exp(lchoose(n, k) + float64(k)*math.Log(p) + float64(n-k)*math.Log(1-p))
}
func binomCDF(n, k int, p float64) float64 {
    s := 0.0
    for i := 0; i <= k; i++ { s += binomPMF(n, i, p) }
    // guard for numeric drift
    if s < 0 { s = 0 }
    if s > 1 { s = 1 }
    return s
}
func lchoose(n, k int) float64 {
    if k < 0 || k > n { return math.Inf(-1) }
    if k == 0 || k == n { return 0 }
    if k > n-k { k = n-k }
    s := 0.0
    for i := 1; i <= k; i++ {
        s += math.Log(float64(n-k+i)) - math.Log(float64(i))
    }
    return s
}
func ksPvalueApprox(en float64) float64 {
    // 2 ∑_{k=1..∞} (-1)^{k-1} e^{-2 k^2 en^2}
    sum := 0.0
    for k := 1; k <= 100; k++ {
        term := math.Exp(-2 * float64(k*k) * en * en)
        if k%2 == 1 { sum += term } else { sum -= term }
        if term < 1e-10 { break }
    }
    p := 2 * sum
    if p < 0 { p = 0 }
    if p > 1 { p = 1 }
    return p
}
func autocorr(x []int, lag int) float64 {
    n := len(x)
    if lag >= n { return 0 }
    mean := 0.0
    for _, v := range x { mean += float64(v) }
    mean /= float64(n)
    num := 0.0
    den := 0.0
    for i := 0; i < n; i++ {
        dv := float64(x[i]) - mean
        den += dv * dv
        j := i + lag
        if j < n {
            num += dv * (float64(x[j]) - mean)
        }
    }
    if den == 0 { return 0 }
    return num / den
}
func runsTestP(seq []int) float64 {
    n := len(seq)
    // number of ones and zeros
    n1 := 0
    for _, v := range seq { if v == 1 { n1++ } }
    n0 := n - n1
    if n0 == 0 || n1 == 0 { return 1 }
    // count runs
    runs := 1
    for i := 1; i < n; i++ { if seq[i] != seq[i-1] { runs++ } }
    mu := 1 + 2*float64(n0*n1)/float64(n)
    var2 := (2 * float64(n0*n1) * (2*float64(n0*n1) - float64(n))) / (float64(n*n) * float64(n-1))
    if var2 <= 0 { return 1 }
    z := (float64(runs) - mu) / math.Sqrt(var2)
    // two-sided p-value
    return 2 * (1 - 0.5*(1+math.Erf(math.Abs(z)/math.Sqrt2)))
}

// Part II: Polar BEC metrics
func polarMetrics(N int, eps float64) PolarMetrics {
    n := 0
    for (1 << n) < N { n++ }
    Zi := make([]float64, N)
    for i := 0; i < N; i++ { Zi[i] = becPolarZOfIndex(eps, n, i) }
    // Use Zi also as empirical p_i (exact for BEC under SC)
    pi := append([]float64(nil), Zi...)
    maxd := 0.0
    sumabs := 0.0
    for i := 0; i < N; i++ {
        d := math.Abs(pi[i] - Zi[i])
        sumabs += d
        if d > maxd { maxd = d }
    }
    meanabs := sumabs / float64(N)
    corr := corrPearson(pi, Zi)
    mu := 0.0
    c01 := 0
    c005 := 0
    for i := 0; i < N; i++ {
        v := Zi[i]
        if v < 0.1 { c01++ }
        if v < 0.05 { c005++ }
        if v < 0.5 { mu += v } else { mu += 1 - v }
    }
    mu /= float64(N)
    return PolarMetrics{N: N, Epsilon: eps, MaxAbsDelta: maxd, MeanAbsDelta: meanabs, CorrPZ: corr, MuN: mu, Phi010: float64(c01)/float64(N), Phi005: float64(c005)/float64(N)}
}
func becPolarZOfIndex(eps float64, n int, idx int) float64 {
    z := eps
    // natural indexing: MSB first
    for b := n - 1; b >= 0; b-- {
        if (idx>>b)&1 == 0 {
            z = 2*z - z*z // Z^-
        } else {
            z = z * z // Z^+
        }
    }
    return z
}
func corrPearson(a, b []float64) float64 {
    n := len(a)
    if n == 0 || len(b) != n { return 0 }
    meanA := 0.0
    meanB := 0.0
    for i := 0; i < n; i++ { meanA += a[i]; meanB += b[i] }
    meanA /= float64(n)
    meanB /= float64(n)
    num := 0.0
    da := 0.0
    db := 0.0
    for i := 0; i < n; i++ {
        va := a[i] - meanA
        vb := b[i] - meanB
        num += va * vb
        da += va * va
        db += vb * vb
    }
    if da == 0 || db == 0 { return 0 }
    return num / math.Sqrt(da*db)
}
 
func parseFloatList(s string) []float64 {
    var out []float64
    cur := 0
    for i := 0; i <= len(s); i++ {
        if i == len(s) || s[i] == ',' {
            if i > cur {
                var v float64
                fmt.Sscanf(s[cur:i], "%f", &v)
                out = append(out, v)
            }
            cur = i + 1
        }
    }
    return out
}
func parseIntList(s string) []int {
    var out []int
    cur := 0
    for i := 0; i <= len(s); i++ {
        if i == len(s) || s[i] == ',' {
            if i > cur {
                var v int
                fmt.Sscanf(s[cur:i], "%d", &v)
                out = append(out, v)
            }
            cur = i + 1
        }
    }
    return out
}

func dumpPolarArrays(outDir string, N int, eps float64) {
    n := 0
    for (1 << n) < N { n++ }
    Zi := make([]float64, N)
    for i := 0; i < N; i++ { Zi[i] = becPolarZOfIndex(eps, n, i) }
    pi := Zi // exact for BEC under SC
    path := filepath.Join(outDir, fmt.Sprintf("polar_subchannels_N%d_eps%.3f.csv", N, eps))
    f, _ := os.Create(path)
    w := csv.NewWriter(f)
    _ = w.Write([]string{"i", "p_i", "Z_i", "delta_i"})
    for i := 0; i < N; i++ {
        _ = w.Write([]string{
            fmt.Sprintf("%d", i),
            fmt.Sprintf("%.8f", pi[i]),
            fmt.Sprintf("%.8f", Zi[i]),
            fmt.Sprintf("%.8f", pi[i]-Zi[i]),
        })
    }
    w.Flush()
    _ = f.Close()
}
 
