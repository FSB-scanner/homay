package main

import (
	"bufio"
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var stdin = bufio.NewReader(os.Stdin)

var sessionCfg = defaultConfig()

func readLine() string {
	s, _ := stdin.ReadString('\n')
	var b strings.Builder
	for _, r := range s {
		if r >= 32 && r < 127 {
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

func ask(prompt, def string) string {
	if def != "" {
		fmt.Printf("  %s [%s]: ", prompt, def)
	} else {
		fmt.Printf("  %s: ", prompt)
	}
	s := readLine()
	if s == "" {
		return def
	}
	return s
}

func askInt(prompt string, def, min, max int) int {
	for {
		s := ask(prompt, strconv.Itoa(def))
		n, err := strconv.Atoi(s)
		if err == nil && n >= min && n <= max {
			return n
		}
		errf(fmt.Sprintf("enter a number between %d and %d", min, max))
	}
}

func askFloat(prompt string, def float64) float64 {
	s := ask(prompt, fmt.Sprintf("%.1f", def))
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return def
	}
	return f
}

func askBool(prompt string, def bool) bool {
	d := "n"
	if def {
		d = "y"
	}
	s := ask(prompt+" (y/n)", d)
	return strings.ToLower(s) == "y"
}

func ctxWithSignal() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ch
		warn("interrupted...")
		cancel()
	}()
	return ctx, cancel
}

func runMenu() {
	banner()
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	for {
		cdnName := CDNProfiles[sessionCfg.CDNName].Name
		if cdnName == "" {
			cdnName = "Cloudflare"
		}
		fmt.Println()
		fmt.Println(paint(cBold, "  MAIN MENU"))
		fmt.Println(sep(40))
		fmt.Printf("  1) Quick scan  (%s sample 300)\n", cdnName)
		fmt.Printf("  2) Deep scan   (%s sample 2000)\n", cdnName)
		fmt.Println("  3) Custom CIDR / ports")
		fmt.Println("  4) Scan from VLESS/Trojan link")
		fmt.Println("  5) Single IP bench")
		fmt.Println("  6) Discover Colos (find nearest DC)")
		fmt.Println("  7) Settings")
		fmt.Printf("  8) Change CDN  (current: %s)\n", cdnName)
		fmt.Println("  9) Favorites")
		fmt.Println("  0) Exit")
		fmt.Println(sep(40))
		fmt.Print(paint(cBCyan, "  > "))

		switch readLine() {
		case "1":
			profile := CDNProfiles[sessionCfg.CDNName]
			cfg1 := *sessionCfg
			cfg1.CIDRs = append([]string(nil), profile.CIDRs...)
			cfg1.Sample = 300
			cfg1.HTTPing = false
			cfg1.Timeout = 1000 * time.Millisecond
			executeScan(&cfg1, rng)
		case "2":
			profile := CDNProfiles[sessionCfg.CDNName]
			cfg2 := *sessionCfg
			cfg2.CIDRs = append([]string(nil), profile.CIDRs...)
			cfg2.Sample = 2000
			cfg2.HTTPing = false
			cfg2.Timeout = 1000 * time.Millisecond
			executeScan(&cfg2, rng)
		case "3":
			runCustom(rng)
		case "4":
			runLinkFull(rng)
		case "5":
			runSingleBench()
		case "6":
			runDiscoverColos()
		case "7":
			runSettings()
		case "8":
			runChangeCDN()
		case "9":
			runFavorites()
		case "0", "q", "exit", "quit":
			fmt.Println()
			ok("Homay closed.")
			return
		default:
			warn("invalid choice")
		}
	}
}

// runChangeCDN lets the user pick which CDN Quick scan, Deep scan, and
// Custom CIDR's default target use. Discover Colos is intentionally
// excluded — it only ever targets Cloudflare's own trace endpoint
// (see the comment in runDiscoverColos for why that must stay fixed).
func runChangeCDN() {
	fmt.Println()
	fmt.Println(paint(cBold, "  SELECT CDN"))
	fmt.Println(sep(40))
	fmt.Println("  1) Cloudflare")
	fmt.Println("  2) Fastly")
	fmt.Println("  3) Gcore")
	fmt.Println("  0) Cancel")
	fmt.Println(sep(40))
	fmt.Print(paint(cBCyan, "  > "))

	var name string
	switch readLine() {
	case "1":
		name = "cloudflare"
	case "2":
		name = "fastly"
	case "3":
		name = "gcore"
	default:
		return
	}

	profile, exists := CDNProfiles[name]
	if !exists {
		errf("unknown CDN: " + name)
		return
	}

	// Note: Ports is deliberately left untouched here. It's a
	// user-owned setting (Settings menu), not part of a CDN's
	// identity, and Quick/Deep scan already rely on that setting
	// being respected as-is (see runMenu cases "1"/"2") — resetting
	// it on every CDN switch would silently undo the user's choice.
	cfg := *sessionCfg
	cfg.CDNName = name
	cfg.CIDRs = append([]string(nil), profile.CIDRs...)
	cfg.SNI = profile.SNI
	cfg.Host = profile.Host
	cfg.Path = profile.Path
	cfg.BenchURL = profile.BenchURL
	sessionCfg = &cfg

	ok("CDN set to " + profile.Name)
}

// runFavorites shows the saved-favorites submenu: list + live re-test,
// add, and remove. Re-testing reuses the existing Scan() engine with
// an explicit IP list — it never touches scan.go/probe.go logic.
func runFavorites() {
	for {
		favs, err := loadFavorites(sessionCfg)
		if err != nil {
			errf("could not read favorites: " + err.Error())
			return
		}

		fmt.Println()
		fmt.Println(paint(cBold, "  FAVORITES"))
		fmt.Println(sep(40))
		if len(favs) == 0 {
			fmt.Println(paint(cDim, "  (none saved yet)"))
		}
		for i, f := range favs {
			fmt.Printf("  %d) %s:%d\n", i+1, f.IP, f.Port)
		}
		fmt.Println()
		fmt.Println("  t) Test all favorites")
		fmt.Println("  a) Add new")
		fmt.Println("  r) Remove one")
		fmt.Println("  0) Back")
		fmt.Println(sep(40))
		fmt.Print(paint(cBCyan, "  > "))

		switch strings.ToLower(readLine()) {
		case "t":
			testFavorites(favs)
		case "a":
			ip := ask("IP", "")
			if ip == "" {
				continue
			}
			portStr := ask("Port", "443")
			port, perr := strconv.Atoi(portStr)
			if perr != nil || port <= 0 || port > 65535 {
				warn("invalid port")
				continue
			}
			if err := addFavorite(sessionCfg, ip, port); err != nil {
				errf("could not save: " + err.Error())
			} else {
				ok("added to favorites")
			}
		case "r":
			if len(favs) == 0 {
				warn("no favorites to remove")
				continue
			}
			numStr := ask("Remove which number", "")
			num, nerr := strconv.Atoi(numStr)
			if nerr != nil || num < 1 || num > len(favs) {
				warn("invalid number")
				continue
			}
			if err := removeFavoriteAt(sessionCfg, num-1); err != nil {
				errf("could not remove: " + err.Error())
			} else {
				ok("removed")
			}
		case "0", "":
			return
		default:
			warn("invalid choice")
		}
	}
}

// testFavorites re-probes every saved favorite, one at a time. Each
// call passes Scan() exactly one IP so its isDirectTarget bypass
// kicks in (see scan.go) — favorites should always show their real
// current status (even if it's now bad), not silently disappear
// because they no longer pass the general-scan MaxLoss/MaxLat/colo
// filters. Favorites lists are small, so scanning one-by-one instead
// of batching by port has no meaningful cost.
func testFavorites(favs []Favorite) {
	if len(favs) == 0 {
		warn("no favorites saved yet")
		return
	}

	ctx, cancel := ctxWithSignal()
	defer cancel()

	start := time.Now()
	var all []Result
	for _, f := range favs {
		cfg := *sessionCfg
		cfg.Ports = []int{f.Port}
		cfg.TopK = 1
		cfg.HTTPing = false
		cfg.Timeout = 1500 * time.Millisecond
		all = append(all, Scan(ctx, &cfg, []string{f.IP})...)
	}

	if len(all) == 0 {
		warn("none of the favorites responded")
		return
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Score > all[j].Score })

	printHeader()
	for i := range all {
		printRow(all[i], sessionCfg.Emoji)
	}
	printSummary(all, len(all), time.Since(start))
}

func runSettings() {
	cfg := *sessionCfg
	for {
		fmt.Println()
		fmt.Println(paint(cBold, "  SETTINGS"))
		fmt.Println(sep(40))
		fmt.Printf("  1) Ports       : %s\n", joinInts(cfg.Ports))
		fmt.Printf("  2) Concurrency : %d\n", cfg.Concurrency)
		fmt.Printf("  3) Ping count  : %d\n", cfg.PingCount)
		fmt.Printf("  4) Timeout ms  : %d\n", int(cfg.Timeout.Milliseconds()))
		fmt.Printf("  5) Max loss %%  : %.0f\n", cfg.MaxLossPct)
		fmt.Printf("  6) Max lat ms  : %.0f\n", cfg.MaxLatMs)
		fmt.Printf("  7) Top-K keep  : %d\n", cfg.TopK)
		fmt.Printf("  8) Bench top-N : %d\n", cfg.BenchTopN)
		fmt.Printf("  9) Bench secs  : %d\n", cfg.BenchSec)
		fmt.Printf(" 10) HTTPing     : %v\n", cfg.HTTPing)
		fmt.Printf(" 11) Padding     : %v\n", cfg.Padding)
		fmt.Printf(" 12) Colo filter : %s\n", strings.Join(cfg.ColoFilter, ","))
		fmt.Printf(" 13) SNI         : %s\n", cfg.SNI)
		fmt.Printf(" 14) Emoji       : %v\n", cfg.Emoji)
		fmt.Println(" 15) Reset to defaults")
		fmt.Println("  0) Back")
		fmt.Println(sep(40))
		fmt.Print(paint(cBCyan, "  > "))

		switch readLine() {
		case "1":
			s := ask("ports (csv)", joinInts(cfg.Ports))
			if p, err := parsePorts(s); err == nil {
				cfg.Ports = p
			} else {
				errf(err.Error())
			}
		case "2":
			cfg.Concurrency = askInt("concurrency", cfg.Concurrency, 1, 256)
		case "3":
			cfg.PingCount = askInt("ping count", cfg.PingCount, 1, 20)
		case "4":
			cfg.Timeout = msDur(askInt("timeout ms", int(cfg.Timeout.Milliseconds()), 300, 10000))
		case "5":
			cfg.MaxLossPct = askFloat("max loss%", cfg.MaxLossPct)
		case "6":
			cfg.MaxLatMs = askFloat("max lat ms", cfg.MaxLatMs)
		case "7":
			cfg.TopK = askInt("top-K", cfg.TopK, 1, 500)
		case "8":
			cfg.BenchTopN = askInt("bench top-N", cfg.BenchTopN, 0, 50)
		case "9":
			cfg.BenchSec = askInt("bench secs", cfg.BenchSec, 3, 30)
		case "10":
			cfg.HTTPing = askBool("HTTPing", cfg.HTTPing)
		case "11":
			cfg.Padding = askBool("Padding", cfg.Padding)
		case "12":
			s := ask("colo filter (csv, empty=all)", strings.Join(cfg.ColoFilter, ","))
			cfg.ColoFilter = []string{}
			for _, c := range strings.Split(s, ",") {
				c = strings.ToUpper(strings.TrimSpace(c))
				if c != "" {
					cfg.ColoFilter = append(cfg.ColoFilter, c)
				}
			}
		case "13":
			cfg.SNI = ask("SNI", cfg.SNI)
			cfg.Host = cfg.SNI
		case "14":
			cfg.Emoji = askBool("Emoji badges", cfg.Emoji)
		case "15":
			// FIX: Reset to defaults
			cfg = *defaultConfig()
			ok("settings reset to defaults")
		case "0", "":
			sessionCfg = &cfg
			return
		default:
			warn("invalid choice")
		}
	}
}

func executeScan(cfg *Config, rng *rand.Rand) {
	start := time.Now()

	ips, err := sampleAcrossCIDRs(cfg.CIDRs, cfg.Sample, rng)
	if err != nil {
		errf(err.Error())
		return
	}
	info(itoaPlural(len(ips), "IP") + " to scan")

	ctx, cancel := ctxWithSignal()
	defer cancel()

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
	ok(fmt.Sprintf("found %d usable IPs", len(results)))
	if err := saveResults(cfg, results); err != nil {
		errf("save failed: " + err.Error())
	}
	if askBool("Save best IP to favorites", false) {
		if err := addFavorite(cfg, results[0].IP, results[0].Port); err != nil {
			errf("could not save favorite: " + err.Error())
		} else {
			ok("added to favorites")
		}
	}
}

func runCustom(rng *rand.Rand) {
	fmt.Println()
	defCIDR := "104.16.0.0/24"
	if len(sessionCfg.CIDRs) > 0 {
		defCIDR = sessionCfg.CIDRs[0]
	}
	cidrStr := ask("CIDRs (comma-sep)", defCIDR)
	cidrs := []string{}
	for _, c := range strings.Split(cidrStr, ",") {
		c = strings.TrimSpace(c)
		if c != "" {
			cidrs = append(cidrs, c)
		}
	}
	if len(cidrs) == 0 {
		warn("no CIDRs")
		return
	}
	portStr := ask("ports (csv)", joinInts(sessionCfg.Ports))
	ports, err := parsePorts(portStr)
	if err != nil {
		errf(err.Error())
		return
	}
	sni := ask("SNI", sessionCfg.SNI)
	coloStr := ask("colo filter (empty=all)", strings.Join(sessionCfg.ColoFilter, ","))

	cfg := *sessionCfg
	cfg.CIDRs = cidrs
	cfg.Ports = ports
	cfg.SNI = sni
	cfg.Host = sni
	cfg.Sample = 0
	cfg.ColoFilter = []string{}
	for _, c := range strings.Split(coloStr, ",") {
		c = strings.ToUpper(strings.TrimSpace(c))
		if c != "" {
			cfg.ColoFilter = append(cfg.ColoFilter, c)
		}
	}
	executeScan(&cfg, rng)
}

// copyToClipboard copies s to the system clipboard via termux-clipboard-set.
// That command only exists inside Termux with the Termux:API add-on
// installed (the app + `pkg install termux-api`). On any other platform,
// or if it's simply not installed, exec.Command's Run() returns an error
// (typically "executable file not found in $PATH") instead of panicking,
// so the caller can fail gracefully and tell the user why.
func copyToClipboard(s string) error {
	cmd := exec.Command("termux-clipboard-set")
	cmd.Stdin = strings.NewReader(s)
	return cmd.Run()
}

// replaceHostPort replaces both the IP and port in a vless/trojan link.
func replaceHostPort(link, newIP string, newPort int) string {
	link = strings.TrimSpace(link)
	var scheme string
	if strings.HasPrefix(link, "vless://") {
		scheme = "vless://"
	} else if strings.HasPrefix(link, "trojan://") {
		scheme = "trojan://"
	} else {
		return link
	}

	u, err := url.Parse(link)
	if err != nil {
		return link
	}

	// FIX: replace both IP and port
	u.Host = net.JoinHostPort(newIP, strconv.Itoa(newPort))

	result := u.String()
	if !strings.HasPrefix(result, scheme) {
		result = scheme + strings.TrimPrefix(result, strings.ToLower(scheme))
	}
	return result
}

func runLinkFull(rng *rand.Rand) {
	fmt.Println()
	link := ask("paste vless:// or trojan:// link", "")
	if link == "" {
		return
	}

	start := time.Now()

	host, port, sni, err := parseProxyLink(link)
	if err != nil {
		errf(err.Error())
		return
	}

	cfg := *sessionCfg

	// linkSNI and linkPort are used in output links regardless of scan mode
	linkSNI := sni
	linkPort := port
	if linkPort <= 0 {
		linkPort = 443
	}

	// Determine scan mode:
	// workers.dev SNI → always scan CF ranges (IP in link may be dead)
	// CF IP without workers → scan only that IP
	// non-CF IP or domain → scan CF ranges
	hostLower := strings.ToLower(host)
	sniLower := strings.ToLower(sni)
	isWorkers := strings.HasSuffix(hostLower, ".workers.dev") ||
		strings.HasSuffix(sniLower, ".workers.dev")
	isCFDirectIP := !isWorkers &&
		net.ParseIP(host) != nil &&
		net.ParseIP(host).To4() != nil &&
		isCloudflareIP(host)

	if isCFDirectIP {
		// CF IP without workers.dev — scan only that IP
		cfg.CIDRs = []string{host + "/32"}
		cfg.Sample = 1
		cfg.Ports = []int{linkPort}
		if linkSNI != "" {
			cfg.SNI = linkSNI
			cfg.Host = linkSNI
		}
		cfg.ColoFilter = []string{}
		cfg.HTTPing = false
		cfg.Timeout = 2000 * time.Millisecond
	} else {
		// workers.dev or non-CF IP or domain → scan CF ranges
		if isWorkers {
			info("workers.dev SNI detected — scanning CF ranges")
		} else if net.ParseIP(host) != nil {
			info("non-Cloudflare IP detected — scanning CF ranges")
		}
		cfgProfile := CDNProfiles["cloudflare"]
		cfg.CIDRs = append([]string(nil), CloudflareCIDRs...)
		cfg.Sample = 300
		cfg.Ports = []int{443}
		cfg.SNI = cfgProfile.SNI
		cfg.Host = cfgProfile.Host
		cfg.BenchURL = cfgProfile.BenchURL
		cfg.HTTPing = false
		cfg.Timeout = 1000 * time.Millisecond
		cfg.ColoFilter = []string{}
	}

	info(fmt.Sprintf("host=%s port=%d sni=***", host, linkPort))

	ips, err := sampleAcrossCIDRs(cfg.CIDRs, cfg.Sample, rng)
	if err != nil {
		errf(err.Error())
		return
	}
	info(itoaPlural(len(ips), "IP") + " to scan")

	ctx, cancel := ctxWithSignal()
	defer cancel()

	results := Scan(ctx, &cfg, ips)
	if len(results) == 0 {
		warn("no usable IPs found")
		return
	}

	if !cfg.NoBench && cfg.BenchTopN > 0 {
		results = benchResults(ctx, results, &cfg)
	}

	prevResults, _ := loadLastSnapshot(&cfg)

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
	if err := saveLastSnapshot(&cfg, results); err != nil {
		warn("could not save history snapshot: " + err.Error())
	}
	ok(fmt.Sprintf("found %d usable IPs", len(results)))
	if err := saveResults(&cfg, results); err != nil {
		errf("save failed: " + err.Error())
	}

	// FIX: show top 5 links with correct IP and port
	fmt.Println()
	fmt.Println(paint(cBold, "  TOP 5 UPDATED LINKS:"))
	fmt.Println(sep(40))
	max := 5
	if len(results) < max {
		max = len(results)
	}
	for i := 0; i < max; i++ {
		// use linkPort (original link port) not results[i].Port (scan port)
		// because we probe on port 443 but the link may use 2087, 443, etc.
		newLink := replaceHostPort(link, results[i].IP, linkPort)
		fmt.Printf("  %s %s:%d → %s\n",
			paint(cBYel, fmt.Sprintf("#%d", i+1)),
			paint(cBCyan, results[i].IP),
			linkPort,
			paint(cBGreen, newLink),
		)
	}
	fmt.Println(sep(40))
	fmt.Println()

	if askBool("Copy best link to clipboard", true) {
		bestLink := replaceHostPort(link, results[0].IP, linkPort)
		if err := copyToClipboard(bestLink); err != nil {
			warn("clipboard copy failed: " + err.Error())
			info("needs Termux:API app installed + 'pkg install termux-api'")
		} else {
			ok("best link copied to clipboard")
		}
	}

	// Note: linkPort (the proxy's real port), not results[0].Port (the
	// probe port, always 443/CF-TLS) — same reasoning as the "TOP 5
	// UPDATED LINKS" section above.
	if askBool("Save best IP to favorites", false) {
		if err := addFavorite(&cfg, results[0].IP, linkPort); err != nil {
			errf("could not save favorite: " + err.Error())
		} else {
			ok("added to favorites")
		}
	}
}

func runSingleBench() {
	fmt.Println()
	ipStr := ask("IP", "")
	if ipStr == "" {
		return
	}

	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil || ip.To4() == nil {
		errf("invalid IPv4 address: " + ipStr)
		return
	}

	port := askInt("port", 443, 1, 65535)
	cfg := *sessionCfg
	cfg.CIDRs = []string{ip.String() + "/32"}
	cfg.Ports = []int{port}
	cfg.Sample = 1
	cfg.BenchTopN = 1
	cfg.BenchSec = 10
	cfg.TopK = 1
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	executeScan(&cfg, rng)
}

func runDiscoverColos() {
	fmt.Println()
	info("sampling 300 IPs to discover nearest Cloudflare datacenters...")

	// This feature only ever samples Cloudflare CIDRs (below), so it must
	// always use Cloudflare's own SNI/Host — never sessionCfg.CDNName.
	// Bug found in review: previously used CDNProfiles[sessionCfg.CDNName],
	// so switching to Fastly/Gcore in Settings and then running Discover
	// Colos sent that CDN's SNI to real Cloudflare edge IPs, breaking the
	// TLS handshake (SNI/certificate mismatch) and silently returning
	// zero colos.
	profile := CDNProfiles["cloudflare"]
	cfg := *sessionCfg
	cfg.CIDRs = append([]string(nil), CloudflareCIDRs...)
	cfg.SNI = profile.SNI
	cfg.Host = profile.Host

	ctx, cancel := ctxWithSignal()
	defer cancel()

	colos := discoverColos(ctx, &cfg, rand.New(rand.NewSource(time.Now().UnixNano())))
	if len(colos) == 0 {
		warn("no colos found")
		return
	}

	type kv struct {
		k string
		v int
	}
	var sorted []kv
	for k, v := range colos {
		sorted = append(sorted, kv{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].v > sorted[j].v })

	fmt.Println()
	fmt.Println(paint(cBold, "  NEAREST DATACENTERS"))
	fmt.Println(sep(30))

	// BUG FIX: bars used to be strings.Repeat("#", kv.v) with no cap —
	// with up to 300 samples, a dominant nearby colo could produce a
	// 150+ char bar that wraps badly on a ~40-col phone screen (the
	// same class of bug already fixed in the results table). Scale
	// every bar to a fixed max width instead.
	const maxBarWidth = 20
	maxCount := 0
	for _, e := range sorted {
		if e.v > maxCount {
			maxCount = e.v
		}
	}
	for _, kv := range sorted {
		barLen := 0
		if maxCount > 0 {
			barLen = kv.v * maxBarWidth / maxCount
		}
		if barLen < 1 && kv.v > 0 {
			barLen = 1
		}
		bar := strings.Repeat("#", barLen)
		fmt.Printf("  %-6s %3d  %s\n", kv.k, kv.v, paint(cBGreen, bar))
	}
	fmt.Println(sep(30))
	if len(sorted) > 0 {
		info("nearest DC: " + paint(cBGreen, sorted[0].k))
	}
}
