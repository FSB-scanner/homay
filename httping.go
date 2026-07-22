package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// randPad generates a random alphanumeric string of length n.
// Used as HTTP padding to defeat DPI pattern matching.
func randPad(n int) string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return string(b)
}

// httpPing sends PingCount HTTP requests to ip:port and measures
// avg latency, jitter, loss, colo, and HTTP/2 support.
// Padding adds a random cookie to defeat DPI — important for Iran.
func httpPing(ctx context.Context, ip string, port, count int, cfg *Config) (avgMs, jitterMs, lossPct float64, colo string, h2 bool) {
	dialAddr := net.JoinHostPort(ip, strconv.Itoa(port))
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := &net.Dialer{Timeout: cfg.Timeout}
			return d.DialContext(ctx, "tcp4", dialAddr)
		},
		TLSClientConfig: &tls.Config{
			ServerName:         cfg.SNI,
			InsecureSkipVerify: true, // intentional: direct IP probe
			NextProtos:         []string{"h2", "http/1.1"},
			MinVersion:         tls.VersionTLS12,
		},
		TLSHandshakeTimeout:   cfg.Timeout,
		ResponseHeaderTimeout: cfg.Timeout,
		ForceAttemptHTTP2:     true,
		DisableKeepAlives:     false,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   cfg.Timeout + 500*time.Millisecond,
	}
	defer tr.CloseIdleConnections()

	url := fmt.Sprintf("https://%s%s", cfg.SNI, cfg.Path)

	samples := make([]float64, 0, count)
	for i := 0; i < count; i++ {
		if ctx.Err() != nil {
			break
		}
		if i > 0 {
			select {
			case <-time.After(50 * time.Millisecond):
			case <-ctx.Done():
				// FIX: labeled break exits the for loop, not just the select
				goto httpDone
			}
		}

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}
		req.Host = cfg.Host
		req.Header.Set("User-Agent", "Mozilla/5.0 Homay/2.0")
		if cfg.Padding {
			req.Header.Set("Cookie", "pad="+randPad(16+rand.Intn(32)))
		}

		t0 := time.Now()
		resp, err := client.Do(req)
		ms := float64(time.Since(t0).Microseconds()) / 1000.0
		if err != nil {
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()

		samples = append(samples, ms)

		if colo == "" {
			if ray := resp.Header.Get("Cf-Ray"); ray != "" {
				if idx := strings.LastIndex(ray, "-"); idx != -1 {
					colo = strings.ToUpper(ray[idx+1:])
				}
			}
		}
		if resp.ProtoMajor == 2 {
			h2 = true
		}
	}

httpDone:
	if len(samples) == 0 {
		return 0, 0, 100, colo, h2
	}

	sum := 0.0
	for _, s := range samples {
		sum += s
	}
	avg := sum / float64(len(samples))

	mad := 0.0
	for _, s := range samples {
		mad += math.Abs(s - avg)
	}
	jitter := mad / float64(len(samples))

	lost := count - len(samples)
	loss := float64(lost) / float64(count) * 100
	return avg, jitter, loss, colo, h2
}

// readColoFromTrace fetches /cdn-cgi/trace and extracts colo= field.
func readColoFromTrace(ctx context.Context, ip string, port int, cfg *Config) string {
	dialAddr := net.JoinHostPort(ip, strconv.Itoa(port))
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := &net.Dialer{Timeout: cfg.Timeout}
			return d.DialContext(ctx, "tcp4", dialAddr)
		},
		TLSClientConfig: &tls.Config{
			ServerName:         cfg.SNI,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
		TLSHandshakeTimeout: cfg.Timeout,
	}
	client := &http.Client{Transport: tr, Timeout: cfg.Timeout + 500*time.Millisecond}
	defer tr.CloseIdleConnections()

	url := fmt.Sprintf("https://%s/cdn-cgi/trace", cfg.SNI)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return ""
	}
	req.Host = cfg.Host
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))

	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "colo=") {
			return strings.ToUpper(strings.TrimSpace(strings.TrimPrefix(line, "colo=")))
		}
	}
	return ""
}
