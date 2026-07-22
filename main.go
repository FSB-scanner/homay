package main

import (
	"math/rand"
	"os"
	"time"
)

func main() {
	cfg, mode, err := parseFlags(os.Args[1:])
	if err != nil {
		errf(err.Error())
		os.Exit(2)
	}
	if mode == "help" {
		return
	}
	if mode == "menu" {
		runMenu()
		return
	}

	banner()
	info(cfg.Summary())

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	ips, err := sampleAcrossCIDRs(cfg.CIDRs, cfg.Sample, rng)
	if err != nil {
		errf("ipgen: " + err.Error())
		os.Exit(1)
	}
	info(itoaPlural(len(ips), "candidate IP"))

	ctx, cancel := ctxWithSignal()
	defer cancel()

	start := time.Now()
	results := Scan(ctx, cfg, ips)
	if len(results) == 0 {
		warn("no usable IPs found")
		return
	}

	if !cfg.NoBench && cfg.BenchTopN > 0 {
		results = benchResults(ctx, results, cfg)
	}

	prevResults, _ := loadLastSnapshot(cfg)

	printHeader()
	lim := cfg.TopK
	if lim > len(results) {
		lim = len(results)
	}
	for i := 0; i < lim; i++ {
		printRow(results[i], cfg.Emoji)
	}
	printSummary(results, lim, time.Since(start))
	printCompare(compareResults(results, lim, prevResults))
	if err := saveLastSnapshot(cfg, results); err != nil {
		warn("could not save history snapshot: " + err.Error())
	}
	ok(itoaPlural(len(results), "usable IP"))
	if err := saveResults(cfg, results); err != nil {
		errf("save failed: " + err.Error())
	}
}
