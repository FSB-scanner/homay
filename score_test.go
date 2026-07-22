package main

import (
	"testing"
)

func TestComputeScore(t *testing.T) {
	// loss=100% should return score 0
	r1 := Result{LatencyMs: 20, JitterMs: 2, LossPct: 100.0, HTTP2: true, SpeedMbps: 50.0}
	if s := computeScore(r1); s != 0 {
		t.Errorf("loss=100%%: expected 0, got %f", s)
	}

	// ideal conditions: score must not exceed 100
	r2 := Result{Port: 443, LatencyMs: 5, JitterMs: 1, LossPct: 0.0, HTTP2: true, TLSVer: "1.3", Colo: "FRA", SpeedMbps: 200.0}
	if s := computeScore(r2); s > 100.0 {
		t.Errorf("perfect: score should clamp to 100, got %f", s)
	}

	// HTTP2 bonus: score with HTTP2 must be higher
	// Port:443 so these aren't caught by the non-TLS-port cap below —
	// this test isolates the HTTP2 bonus specifically.
	rBase := Result{Port: 443, TLSVer: "1.3", LatencyMs: 100, JitterMs: 10, LossPct: 0.0, HTTP2: false, SpeedMbps: 0}
	rH2 := Result{Port: 443, TLSVer: "1.3", LatencyMs: 100, JitterMs: 10, LossPct: 0.0, HTTP2: true, SpeedMbps: 0}
	if computeScore(rH2) <= computeScore(rBase) {
		t.Error("HTTP2 bonus: expected higher score with HTTP2")
	}

	// TLS 1.3 bonus: score with TLS1.3 must be higher
	rTLS12 := Result{Port: 443, LatencyMs: 100, JitterMs: 10, LossPct: 0.0, TLSVer: "1.2"}
	rTLS13 := Result{Port: 443, LatencyMs: 100, JitterMs: 10, LossPct: 0.0, TLSVer: "1.3"}
	if computeScore(rTLS13) <= computeScore(rTLS12) {
		t.Error("TLS1.3 bonus: expected higher score with TLS 1.3")
	}

	// score must always be in range [0, 100]
	rNormal := Result{Port: 443, LatencyMs: 150, JitterMs: 20, LossPct: 5.0, HTTP2: false, SpeedMbps: 10.0}
	s := computeScore(rNormal)
	if s < 0 || s > 100 {
		t.Errorf("score out of bounds [0-100]: got %f", s)
	}

	// non-TLS ports (80, 8080, ...) must be capped at 60 even with
	// otherwise-perfect metrics, since a fast plain-TCP handshake
	// alone doesn't mean a TLS-based proxy config will work through
	// that port.
	rNonTLS := Result{Port: 80, LatencyMs: 5, JitterMs: 1, LossPct: 0.0, HTTP2: false, SpeedMbps: 200.0}
	if s := computeScore(rNonTLS); s > 60 {
		t.Errorf("non-TLS port: expected score capped at 60, got %f", s)
	}
}
