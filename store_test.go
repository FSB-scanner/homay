package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSaveResults(t *testing.T) {
	// unwritable directory should return error
	cfg := &Config{
		OutDir:    "/sys/class/nonexistent_homay_dir",
		OutPrefix: "test",
	}
	results := []Result{
		{IP: "1.1.1.1", Port: 443, Score: 85.5, LatencyMs: 45},
	}
	err := saveResults(cfg, results)
	if err == nil {
		t.Error("expected error for unwritable directory")
	}

	// valid directory should produce three output files
	tmpDir, err := os.MkdirTemp("", "homay_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cfg2 := &Config{
		OutDir:    tmpDir,
		OutPrefix: "homay",
	}
	err = saveResults(cfg2, results)
	if err != nil {
		t.Fatalf("unexpected error on valid dir: %v", err)
	}

	// verify three files were created
	files, _ := os.ReadDir(tmpDir)
	if len(files) != 3 {
		t.Errorf("expected 3 output files, got %d", len(files))
	}

	// check file extensions
	exts := map[string]bool{}
	for _, f := range files {
		ext := filepath.Ext(f.Name())
		exts[ext] = true
	}
	for _, want := range []string{".json", ".csv", ".txt"} {
		if !exts[want] {
			t.Errorf("missing output file with extension %s", want)
		}
	}

	// verify txt file content
	for _, f := range files {
		if filepath.Ext(f.Name()) == ".txt" {
			data, _ := os.ReadFile(filepath.Join(tmpDir, f.Name()))
			if !strings.Contains(string(data), "1.1.1.1:443") {
				t.Errorf("txt file missing IP:port entry")
			}
		}
	}
}

func TestCompareResults(t *testing.T) {
	// no previous snapshot: HasPrevious must be false, nothing else checked
	curr := []Result{{IP: "1.1.1.1", Score: 90}}
	if stats := compareResults(curr, 1, nil); stats.HasPrevious {
		t.Error("expected HasPrevious=false with no previous snapshot")
	}

	// with a previous snapshot: verify best-score delta and new/dropped counts
	prev := []Result{
		{IP: "1.1.1.1", Score: 80},
		{IP: "2.2.2.2", Score: 75},
	}
	currNow := []Result{
		{IP: "1.1.1.1", Score: 90}, // still here, score improved
		{IP: "3.3.3.3", Score: 85}, // new
		// 2.2.2.2 dropped out
	}
	stats := compareResults(currNow, 2, prev)
	if !stats.HasPrevious {
		t.Fatal("expected HasPrevious=true")
	}
	if stats.PrevBestScore != 80 {
		t.Errorf("expected PrevBestScore=80, got %f", stats.PrevBestScore)
	}
	if stats.CurrBestScore != 90 {
		t.Errorf("expected CurrBestScore=90, got %f", stats.CurrBestScore)
	}
	if stats.NewCount != 1 {
		t.Errorf("expected NewCount=1 (3.3.3.3), got %d", stats.NewCount)
	}
	if stats.DroppedCount != 1 {
		t.Errorf("expected DroppedCount=1 (2.2.2.2), got %d", stats.DroppedCount)
	}
}
