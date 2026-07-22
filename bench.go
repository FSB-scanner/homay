package main

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"time"
)

// downloadBench measures download speed by streaming for cfg.BenchSec seconds.
// Returns Mbps. IPv4-only. No UDP, no QUIC, no HTTP/3.
func downloadBench(ctx context.Context, ip string, port int, cfg *Config) float64 {
	if cfg == nil || cfg.BenchSec <= 0 || cfg.Timeout <= 0 || ip == "" || port <= 0 || port > 65535 {
		return 0
	}

	benchURL := cfg.BenchURL
	if benchURL == "" {
		if cfg.Host != "" {
			benchURL = "https://" + cfg.Host + cfg.Path
		} else {
			return 0
		}
	}

	dialAddr := net.JoinHostPort(ip, strconv.Itoa(port))

	dialer := &net.Dialer{
		Timeout:   cfg.Timeout,
		KeepAlive: 0,
	}

	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", dialAddr)
		},
		TLSClientConfig: &tls.Config{
			ServerName:         cfg.SNI,
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2", "http/1.1"},
			MinVersion:         tls.VersionTLS12,
		},
		ForceAttemptHTTP2:     true,
		DisableKeepAlives:     true,
		MaxIdleConns:          0,
		MaxIdleConnsPerHost:   0,
		IdleConnTimeout:       1 * time.Second,
		TLSHandshakeTimeout:   cfg.Timeout,
		ResponseHeaderTimeout: cfg.Timeout,
		ExpectContinueTimeout: 1 * time.Second,
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(cfg.BenchSec)*time.Second + cfg.Timeout + 2*time.Second,
	}

	defer tr.CloseIdleConnections()

	dlCtx, cancel := context.WithTimeout(ctx, time.Duration(cfg.BenchSec)*time.Second+cfg.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(dlCtx, http.MethodGet, benchURL, nil)
	if err != nil {
		return 0
	}

	if cfg.Host != "" {
		req.Host = cfg.Host
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 Homay/2.0")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Connection", "close")

	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0
	}

	buf := make([]byte, 64*1024)
	deadline := time.Now().Add(time.Duration(cfg.BenchSec) * time.Second)
	started := time.Now()

	var total int64

	for time.Now().Before(deadline) {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			total += int64(n)
		}

		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			break
		}

		if dlCtx.Err() != nil {
			break
		}
	}

	elapsed := time.Since(started).Seconds()
	if elapsed <= 0 || total <= 0 {
		return 0
	}

	return float64(total) * 8 / elapsed / 1e6
}

// benchResults runs download bench on top-N results and returns an updated sorted slice.
func benchResults(ctx context.Context, results []Result, cfg *Config) []Result {
	if len(results) == 0 || cfg == nil {
		return results
	}

	updated := make([]Result, len(results))
	copy(updated, results)

	n := cfg.BenchTopN
	if n <= 0 {
		return updated
	}
	if n > len(updated) {
		n = len(updated)
	}

	info("benchmarking top " + strconv.Itoa(n) + " IPs...")

	for i := 0; i < n; i++ {
		if ctx.Err() != nil {
			break
		}

		if updated[i].IP == "" || updated[i].Port <= 0 {
			continue
		}

		mbps := downloadBench(ctx, updated[i].IP, updated[i].Port, cfg)
		updated[i].SpeedMbps = mbps
		updated[i].Score = computeScore(updated[i])
	}

	sort.SliceStable(updated, func(i, j int) bool {
		if updated[i].Score == updated[j].Score {
			if updated[i].LatencyMs == updated[j].LatencyMs {
				return updated[i].LossPct < updated[j].LossPct
			}
			return updated[i].LatencyMs < updated[j].LatencyMs
		}
		return updated[i].Score > updated[j].Score
	})

	return updated
}