package main

import (
	"fmt"
	"time"
)

// Result holds the full measurement of one IP:port probe.
type Result struct {
	IP        string    `json:"ip"`
	Port      int       `json:"port"`
	LatencyMs float64   `json:"latency_ms"`
	JitterMs  float64   `json:"jitter_ms"`
	LossPct   float64   `json:"loss_pct"`
	TLSVer    string    `json:"tls_version"`
	HTTP2     bool      `json:"http2"`
	Colo      string    `json:"colo"`
	CDN       string    `json:"cdn"`
	SpeedMbps float64   `json:"speed_mbps"`
	Score     float64   `json:"score"`
	Time      time.Time `json:"time"`
}

// resultHeap is a min-heap on Score — keeps top-K efficiently.
type resultHeap []Result

func (h resultHeap) Len() int            { return len(h) }
func (h resultHeap) Less(i, j int) bool  { return h[i].Score < h[j].Score }
func (h resultHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *resultHeap) Push(x interface{}) { *h = append(*h, x.(Result)) }
func (h *resultHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

func itoaPlural(n int, word string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", word)
	}
	return fmt.Sprintf("%d %ss", n, word)
}
