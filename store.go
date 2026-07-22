package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

func saveResults(cfg *Config, results []Result) error {
	ts := time.Now().Format("20060102-150405")
	base := filepath.Join(cfg.OutDir, cfg.OutPrefix+"-"+ts)

	if err := os.MkdirAll(cfg.OutDir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", cfg.OutDir, err)
	}

	// JSON
	b, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("json marshal: %w", err)
	}
	if err := os.WriteFile(base+".json", b, 0644); err != nil {
		return fmt.Errorf("write json: %w", err)
	}

	// CSV
	fcsv, err := os.Create(base + ".csv")
	if err != nil {
		return fmt.Errorf("create csv: %w", err)
	}
	w := csv.NewWriter(fcsv)
	if err := w.Write([]string{
		"ip", "port", "latency_ms", "jitter_ms", "loss_pct",
		"tls", "h2", "colo", "cdn", "speed_mbps", "score",
	}); err != nil {
		fcsv.Close()
		return fmt.Errorf("write csv header: %w", err)
	}
	for _, r := range results {
		h2 := "0"
		if r.HTTP2 {
			h2 = "1"
		}
		if err := w.Write([]string{
			r.IP,
			strconv.Itoa(r.Port),
			fmt.Sprintf("%.1f", r.LatencyMs),
			fmt.Sprintf("%.1f", r.JitterMs),
			fmt.Sprintf("%.1f", r.LossPct),
			r.TLSVer,
			h2,
			r.Colo,
			r.CDN,
			fmt.Sprintf("%.2f", r.SpeedMbps),
			fmt.Sprintf("%.1f", r.Score),
		}); err != nil {
			fcsv.Close()
			return fmt.Errorf("write csv row %s: %w", r.IP, err)
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		fcsv.Close()
		return fmt.Errorf("flush csv: %w", err)
	}
	fcsv.Close()

	// TXT — ip:port per line
	ftxt, err := os.Create(base + ".txt")
	if err != nil {
		return fmt.Errorf("create txt: %w", err)
	}
	for _, r := range results {
		if _, err := fmt.Fprintf(ftxt, "%s:%d\n", r.IP, r.Port); err != nil {
			ftxt.Close()
			return fmt.Errorf("write txt %s: %w", r.IP, err)
		}
	}
	ftxt.Close()

	ok("saved: " + base + ".{json,csv,txt}")
	return nil
}

// lastSnapshotPath is a fixed (non-timestamped) filename that always
// holds the most recent scan's results, so the next scan can diff
// against it. This is separate from the timestamped .json history
// saveResults writes above, which is never overwritten.
func lastSnapshotPath(cfg *Config) string {
	return filepath.Join(cfg.OutDir, cfg.OutPrefix+"-last.json")
}

// loadLastSnapshot reads the previous scan's results. A missing file
// is not an error — it just means there is no previous scan yet, so
// (nil, nil) is returned and callers should skip showing a compare box.
func loadLastSnapshot(cfg *Config) ([]Result, error) {
	b, err := os.ReadFile(lastSnapshotPath(cfg))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var results []Result
	if err := json.Unmarshal(b, &results); err != nil {
		return nil, err
	}
	return results, nil
}

// saveLastSnapshot overwrites the fixed last-scan file with the current
// results, so the *next* scan has something to compare against. Call
// this only after loadLastSnapshot has already been read for the
// current comparison — otherwise you'd be comparing a scan to itself.
func saveLastSnapshot(cfg *Config, results []Result) error {
	b, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("json marshal: %w", err)
	}
	if err := os.MkdirAll(cfg.OutDir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", cfg.OutDir, err)
	}
	return os.WriteFile(lastSnapshotPath(cfg), b, 0644)
}

// CompareStats summarizes how the current scan's top results changed
// relative to the previous scan (see loadLastSnapshot). HasPrevious is
// false when there was no earlier snapshot to compare against — every
// other field is meaningless in that case and should not be displayed.
type CompareStats struct {
	HasPrevious   bool
	PrevBestScore float64
	CurrBestScore float64
	NewCount      int
	DroppedCount  int
}

// compareResults diffs the current top-lim results against a previous
// snapshot by IP membership, and compares the #1 best score. curr must
// already be sorted best-first (Scan() guarantees this).
func compareResults(curr []Result, lim int, prev []Result) CompareStats {
	if len(prev) == 0 {
		return CompareStats{HasPrevious: false}
	}
	if lim <= 0 || lim > len(curr) {
		lim = len(curr)
	}

	prevSet := make(map[string]bool, len(prev))
	for _, r := range prev {
		prevSet[r.IP] = true
	}
	currSet := make(map[string]bool, lim)
	for i := 0; i < lim; i++ {
		currSet[curr[i].IP] = true
	}

	newCount := 0
	for ip := range currSet {
		if !prevSet[ip] {
			newCount++
		}
	}
	droppedCount := 0
	for ip := range prevSet {
		if !currSet[ip] {
			droppedCount++
		}
	}

	var prevBest, currBest float64
	prevBest = prev[0].Score
	if lim > 0 {
		currBest = curr[0].Score
	}

	return CompareStats{
		HasPrevious:   true,
		PrevBestScore: prevBest,
		CurrBestScore: currBest,
		NewCount:      newCount,
		DroppedCount:  droppedCount,
	}
}
