package main

import "math"

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// computeScore returns 0-100 score for a result. Higher is better.
// Base score = latency(55%) + jitter(25%) + loss(20%).
// Speed is an additive bonus (max +10) — never replaces the base.
func computeScore(r Result) float64 {
	if r.LossPct >= 100 {
		return 0
	}

	// latency: 50ms=100, 400ms=0
	latScore := clamp(100-(math.Max(0, r.LatencyMs-50)/350)*100, 0, 100)
	// jitter: 0ms=100, 150ms=0
	jitScore := clamp(100-(r.JitterMs/150)*100, 0, 100)
	// loss: 0%=100, 30%=0
	lossScore := clamp(100-(r.LossPct/30)*100, 0, 100)

	score := latScore*0.55 + jitScore*0.25 + lossScore*0.20

	// protocol bonuses
	if r.HTTP2 {
		score += 5
	}
	if r.TLSVer == "1.3" {
		score += 3
	}
	if r.Colo != "" {
		score += 2
	}

	// FIX: speed is additive bonus (max +10), not a replacement
	// log10 scale: 1Mbps→3pts, 10→6pts, 100→10pts
	if r.SpeedMbps > 0 {
		dlBonus := clamp(math.Log10(r.SpeedMbps+1)/math.Log10(101)*10, 0, 10)
		score += dlBonus
	}

	score = clamp(score, 0, 100)

	// Non-TLS ports (80, 8080, ...) can never carry the TLS-based
	// VLESS/Trojan/etc configs this tool exists to find candidates
	// for — but a bare TCP handshake has no TLS round-trip to slow it
	// down, so it can score deceptively high on latency/jitter alone
	// and outrank genuinely usable TLS results. Cap instead of hiding
	// them outright, so raw TCP reachability is still visible to
	// anyone who specifically wants it.
	if !isTLSPort(r.Port) {
		score = math.Min(score, 60)
	}

	return math.Round(score*10) / 10
}
