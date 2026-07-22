package main

import (
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

const (
	cReset  = "\033[0m"
	cBold   = "\033[1m"
	cDim    = "\033[2m"
	cRed    = "\033[31m"
	cGreen  = "\033[32m"
	cYellow = "\033[33m"
	cBlue   = "\033[34m"
	cPurple = "\033[35m"
	cCyan   = "\033[36m"
	cBRed   = "\033[91m"
	cBGreen = "\033[92m"
	cBYel   = "\033[93m"
	cBBlue  = "\033[94m"
	cBCyan  = "\033[96m"
)

var noColor = false

func init() {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		noColor = true
	}
}

func paint(color, s string) string {
	if noColor || color == "" {
		return s
	}
	return color + s + cReset
}

func sep(n int) string {
	if n <= 0 {
		n = 40
	}
	return paint(cDim, strings.Repeat("-", n))
}

// banner prints a short one-line brand signature before the menu.
// No ASCII art (dropped per design feedback: line-art logos read as
// amateurish in a monospace terminal and the real logo lives on
// GitHub). Just bold, letter-spaced brand text, under 40 columns so
// it never wraps on a narrow Termux phone screen.
func banner() {
	fmt.Println()
	fmt.Println("  " + paint(cBold+cBYel, "H O M A Y") + "  " + paint(cDim, "(") + paint(cBold+cBBlue, "FSB") + paint(cDim, ")"))
	fmt.Println(paint(cDim, "  Multi-CDN Clean-IP Scanner") + "  " + paint(cDim, "v2.0"))
	fmt.Println()
}

func ok(s string) {
	fmt.Println(paint(cBGreen, "[OK] ") + s)
}

func info(s string) {
	fmt.Println(paint(cBCyan, "[i]  ") + s)
}

func warn(s string) {
	fmt.Println(paint(cBYel, "[!]  ") + s)
}

func errf(s string) {
	fmt.Println(paint(cBRed, "[X]  ") + s)
}

// printHeader prints a short section label before results. Results are
// rendered two lines per IP (see printRow), not one wide table row: a
// single-row table needs 65+ visible columns, which wraps mid-value on
// real Termux phone screens (confirmed on-device: ~40-col wrap even
// split a colo code like "FRA" across the line break).
func printHeader() {
	fmt.Println()
	fmt.Println(paint(cBold, "  RESULTS"))
	fmt.Println(paint(cDim, "  (score,lat,jit,loss,tls,h2,colo)"))
	fmt.Println(sep(40))
}

// scoreColor returns a 5-level color gradient for a 0-100 score.
// Higher score = greener, lower score = redder.
func scoreColor(score float64) string {
	switch {
	case score >= 85:
		return cBGreen
	case score >= 65:
		return cGreen
	case score >= 45:
		return cBYel
	case score >= 25:
		return cYellow
	default:
		return cBRed
	}
}

// coloColors maps known CDN colo/datacenter codes to a fixed color so the
// same location always renders the same color across runs and CDNs.
// Unknown codes fall back to a neutral color in coloColor — never a crash.
var coloColors = map[string]string{
	"FRA": cBBlue,
	"GYD": cPurple,
	"ARN": cCyan,
	"MXP": cGreen,
	"IAD": cYellow,
	"MIA": cRed,
	"VIE": cBCyan,
	"MRS": cBGreen,
	"CPH": cBYel,
	"ORD": cBRed,
	"WAW": cBlue,
	"LLK": cGreen,
	"CDG": cPurple,
	"LHR": cCyan,
}

// coloColor returns the fixed color for a colo code, or "" (no color)
// for an empty/placeholder value. Unrecognized codes get a neutral
// fallback color instead of being left uncolored or panicking.
func coloColor(colo string) string {
	if colo == "" || colo == "-" {
		return ""
	}
	if c, ok := coloColors[strings.ToUpper(colo)]; ok {
		return c
	}
	return cDim
}

// printRow renders one result as two short lines instead of one wide
// table row, so it never wraps mid-value on a narrow phone terminal:
//
//	  1.2.3.4:443              (bold, so it reads as the block's header)
//	    98.4  99ms  j3  l0%  tls1.3  h2y  FRA  1.9M
//	                             (blank line separates it from the next IP)
//
// No field here needs fixed-width padding to stay aligned with
// neighboring rows, so there is no risk of ANSI color codes throwing
// off column widths (the bug that hit the old single-row layout).
func printRow(r Result, emoji bool) {
	colo := strings.TrimSpace(r.Colo)
	if colo == "" {
		colo = "-"
	}
	coloStr := colo
	if c := coloColor(colo); c != "" {
		coloStr = paint(c, colo)
	}

	tls := r.TLSVer
	if tls == "" {
		tls = "-"
	}

	h2 := "n"
	if r.HTTP2 {
		h2 = "y"
	}

	spd := "  -"
	if r.SpeedMbps > 0 {
		spd = fmt.Sprintf("  %.1fM", r.SpeedMbps)
	}

	badges := ""
	if emoji {
		if r.TLSVer == "1.3" {
			badges += " \u2705" // check mark: TLS 1.3
		}
		if r.HTTP2 {
			badges += " \u26a1" // lightning bolt: HTTP/2
		}
		if colo != "-" {
			badges += " \U0001F30D" // globe: colo known
		}
	}

	fmt.Printf("  %s%s\n", paint(cBold, fmt.Sprintf("%s:%d", r.IP, r.Port)), badges)
	fmt.Printf("    %s  %.0fms  j%.0f  l%.0f%%  tls%s  h2%s  %s%s\n",
		paint(scoreColor(r.Score), fmt.Sprintf("%.1f", r.Score)),
		r.LatencyMs, r.JitterMs, r.LossPct, tls, h2, coloStr, spd,
	)
	fmt.Println()
}

// printSummary prints a short recap box after a results table: the best
// IP, the average score across the printed (top-lim) results, and the
// total wall-clock time the scan took. Kept to short single lines (not
// wide labeled columns) so it never wraps on a ~40-col phone terminal.
func printSummary(results []Result, lim int, elapsed time.Duration) {
	if lim <= 0 || lim > len(results) {
		lim = len(results)
	}
	if lim == 0 {
		return
	}

	best := results[0]
	var sum float64
	for i := 0; i < lim; i++ {
		sum += results[i].Score
	}
	avg := sum / float64(lim)

	fmt.Println()
	fmt.Println(paint(cBold, "  SUMMARY"))
	fmt.Println(sep(40))
	fmt.Printf("  Best : %s%s (%.1f)\n", paint(cBGreen, best.IP), portSuffix(best.Port), best.Score)
	fmt.Printf("  Avg  : %.1f (top %d)\n", avg, lim)
	fmt.Printf("  Time : %s\n", elapsed.Round(10*time.Millisecond))
	fmt.Println(sep(40))
}

func portSuffix(port int) string {
	if port <= 0 {
		return ""
	}
	return fmt.Sprintf(":%d", port)
}

// printCompare prints a short box showing how this scan's top results
// differ from the previous one (see compareResults in store.go). Does
// nothing if there was no previous scan to compare against.
func printCompare(c CompareStats) {
	if !c.HasPrevious {
		return
	}
	delta := c.CurrBestScore - c.PrevBestScore
	deltaColor := cDim
	if delta > 0.05 {
		deltaColor = cBGreen
	} else if delta < -0.05 {
		deltaColor = cBRed
	}

	fmt.Println()
	fmt.Println(paint(cBold, "  COMPARE (vs last scan)"))
	fmt.Println(sep(40))
	fmt.Printf("  Best score : %.1f -> %.1f (%s)\n",
		c.PrevBestScore, c.CurrBestScore, paint(deltaColor, fmt.Sprintf("%+.1f", delta)))
	fmt.Printf("  New in top : %d\n", c.NewCount)
	fmt.Printf("  Dropped    : %d\n", c.DroppedCount)
	fmt.Println(sep(40))
}

// spinnerFrames are cycled once per progress() call to animate the
// scan indicator. atomic counter keeps this race-safe: progress() is
// called concurrently from multiple worker goroutines (e.g. discoverColos).
var spinnerFrames = [...]string{"\u280b", "\u2819", "\u2839", "\u2838", "\u283c", "\u2834", "\u2826", "\u2827"}
var spinnerTick uint64

func progress(done, total int, label string) {
	if total <= 0 {
		return
	}
	if done < 0 {
		done = 0
	}
	if done > total {
		done = total
	}
	pct := float64(done) / float64(total) * 100
	bar := int(pct / 5)
	if bar < 0 {
		bar = 0
	}
	if bar > 20 {
		bar = 20
	}
	if label == "" {
		label = "progress"
	}

	frame := spinnerFrames[atomic.AddUint64(&spinnerTick, 1)%uint64(len(spinnerFrames))]

	fmt.Fprintf(os.Stderr, "\r  %s %s [%s%s] %.0f%% %d/%d   ",
		paint(cBCyan, frame),
		paint(cBCyan, label),
		strings.Repeat("=", bar),
		strings.Repeat(".", 20-bar),
		pct,
		done,
		total,
	)
}

func clearLine() {
	fmt.Fprint(os.Stderr, "\r"+strings.Repeat(" ", 80)+"\r")
}
