package main

import (
	"container/heap"
	"context"
	"math/rand"
	"net"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Scan runs the full scan pipeline.
// If exactly one IP is provided (from a vless/trojan link),
// isDirectTarget=true and strict filters are bypassed.
func Scan(ctx context.Context, cfg *Config, ips []string) []Result {
	type job struct {
		ip   string
		port int
	}

	isDirectTarget := len(ips) == 1

	total := len(ips) * len(cfg.Ports)
	if total == 0 {
		return nil
	}

	jobs := make(chan job, cfg.Concurrency*2)
	resultCh := make(chan Result, cfg.Concurrency*4)
	var done int64

	go func() {
		defer close(jobs)
		for _, ip := range ips {
			for _, port := range cfg.Ports {
				select {
				case jobs <- job{ip, port}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	var wg sync.WaitGroup
	for w := 0; w < cfg.Concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				atomic.AddInt64(&done, 1)
				if ctx.Err() != nil {
					continue
				}
				r := probeOne(ctx, j.ip, j.port, cfg, isDirectTarget)
				if r == nil {
					continue
				}
				select {
				case resultCh <- *r:
				case <-ctx.Done():
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	h := &resultHeap{}
	heap.Init(h)
	topK := cfg.TopK
	if topK <= 0 {
		topK = 1
	}
	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case r, open := <-resultCh:
			if !open {
				goto done
			}
			if h.Len() < topK {
				heap.Push(h, r)
			} else if r.Score > (*h)[0].Score {
				heap.Pop(h)
				heap.Push(h, r)
			}
		case <-ticker.C:
			progress(int(atomic.LoadInt64(&done)), total, "scanning")
		}
	}

done:
	clearLine()
	results := make([]Result, 0, h.Len())
	for h.Len() > 0 {
		results = append(results, heap.Pop(h).(Result))
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].Score > results[j].Score
	})
	return results
}

// probeOne probes a single ip:port.
// isDirectTarget=true: strict filters are bypassed and TLS fallback is enabled.
// Required for vless/trojan links with direct non-CF IPs (e.g. AWS).
func probeOne(ctx context.Context, ip string, port int, cfg *Config, isDirectTarget bool) *Result {
	r := &Result{IP: ip, Port: port}

	if cfg.HTTPing && isTLSPort(port) {
		avg, jit, loss, colo, h2 := httpPing(ctx, ip, port, cfg.PingCount, cfg)
		r.LatencyMs = avg
		r.JitterMs = jit
		r.LossPct = loss
		r.Colo = colo
		r.HTTP2 = h2
		if r.Colo == "" && cfg.CDNName == "cloudflare" {
			r.Colo = readColoFromTrace(ctx, ip, port, cfg)
		}
		r.TLSVer, _ = tlsProbe(ctx, ip, port, cfg.SNI, cfg.Timeout)
	} else {
		avg, jit, loss := tcpPing(ctx, ip, port, cfg.PingCount, cfg.Timeout)
		r.LatencyMs = avg
		r.JitterMs = jit
		r.LossPct = loss

		if isTLSPort(port) {
			if loss >= 100 && isDirectTarget && cfg.SNI != "" {
				// FIX: TLS fallback for non-CF IPs (e.g. AWS)
				// tcpPing fails on these IPs but TLS handshake may succeed
				// measure latency from the TCP connect time
				t0 := time.Now()
				dialer := &net.Dialer{Timeout: cfg.Timeout}
				conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
				if err == nil {
					hsMs := float64(time.Since(t0).Microseconds()) / 1000.0
					conn.Close()
					// TCP connect succeeded — tcpPing failed due to forced tcp4
					// use this handshake latency instead
					r.LossPct = 0
					r.LatencyMs = hsMs
					r.TLSVer, r.HTTP2 = tlsProbe(ctx, ip, port, cfg.SNI, cfg.Timeout)
				}
			} else if loss < 100 {
				r.TLSVer, r.HTTP2 = tlsProbe(ctx, ip, port, cfg.SNI, cfg.Timeout)
				if cfg.CDNName == "cloudflare" {
					r.Colo = readColoFromTrace(ctx, ip, port, cfg)
				}
			}
		}
	}

	r.CDN = cfg.CDNName

	// Direct IP: only drop if completely unreachable
	if isDirectTarget {
		if r.LossPct >= 100 && r.LatencyMs == 0 {
			return nil
		}
	} else {
		// Normal scan: apply all filters
		if r.LossPct >= 100 {
			return nil
		}
		if r.LossPct > cfg.MaxLossPct {
			return nil
		}
		if r.LatencyMs > cfg.MaxLatMs {
			return nil
		}
		if cfg.MinLatMs > 0 && r.LatencyMs < cfg.MinLatMs {
			return nil
		}
		if !cfg.matchesColo(r.Colo) {
			return nil
		}
	}

	r.Score = computeScore(*r)
	r.Time = time.Now()
	return r
}

// discoverColos samples 300 random IPs and returns colo frequency map.
func discoverColos(ctx context.Context, cfg *Config, rng *rand.Rand) map[string]int {
	all, err := sampleAcrossCIDRs(cfg.CIDRs, 300, rng)
	if err != nil || len(all) == 0 {
		return nil
	}

	colos := make(map[string]int)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, cfg.Concurrency)
	total := len(all)
	var done int64

	for _, ip := range all {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			colo := readColoFromTrace(ctx, ip, 443, cfg)
			atomic.AddInt64(&done, 1)
			progress(int(atomic.LoadInt64(&done)), total, "discover")
			if colo != "" {
				mu.Lock()
				colos[colo]++
				mu.Unlock()
			}
		}(ip)
	}
	wg.Wait()
	clearLine()
	return colos
}
