package main

import (
	"context"
	"crypto/tls"
	"math"
	"net"
	"strconv"
	"time"
)

// tcpPing measures N TCP connect RTTs and returns avg, jitter, loss.
func tcpPing(ctx context.Context, ip string, port, count int, timeout time.Duration) (avgMs, jitterMs, lossPct float64) {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	samples := make([]float64, 0, count)

PingLoop:
	for i := 0; i < count; i++ {
		if ctx.Err() != nil {
			break
		}
		if i > 0 {
			select {
			case <-time.After(30 * time.Millisecond):
			case <-ctx.Done():
				// FIX: labeled break exits the for loop directly
				// previously break only exited the select, then DialTimeout still ran
				break PingLoop
			}
		}
		t0 := time.Now()
		conn, err := net.DialTimeout("tcp4", addr, timeout)
		ms := float64(time.Since(t0).Microseconds()) / 1000.0
		if err != nil {
			continue
		}
		conn.Close()
		samples = append(samples, ms)
	}

	if len(samples) == 0 {
		return 0, 0, 100
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
	return avg, jitter, loss
}

// tlsVersion returns TLS version string.
func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "1.3"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS11:
		return "1.1"
	// Added TLS 1.0 for completeness (rarely seen on modern CDNs)
	case tls.VersionTLS10:
		return "1.0"
	default:
		return ""
	}
}

// tlsProbe does a standalone TLS handshake and returns version + ALPN.
// InsecureSkipVerify is intentional: we probe by IP directly.
func tlsProbe(ctx context.Context, ip string, port int, sni string, timeout time.Duration) (ver string, h2 bool) {
	dialer := &net.Dialer{Timeout: timeout}
	raw, err := dialer.DialContext(ctx, "tcp4", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return "", false
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(timeout))

	conn := tls.Client(raw, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // intentional: direct IP probe
		NextProtos:         []string{"h2", "http/1.1"},
		MinVersion:         tls.VersionTLS12,
	})
	if err := conn.HandshakeContext(ctx); err != nil {
		return "", false
	}
	st := conn.ConnectionState()
	return tlsVersion(st.Version), st.NegotiatedProtocol == "h2"
}
