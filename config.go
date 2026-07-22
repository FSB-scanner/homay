package main

import (
	"flag"
	"fmt"
	"net"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Config holds all tunable parameters for a scan session.
type Config struct {
	CIDRs       []string
	Ports       []int
	PingCount   int
	Timeout     time.Duration
	Concurrency int
	TopK        int
	BenchTopN   int
	BenchSec    int
	BenchURL    string
	SNI         string
	Host        string
	Path        string
	HTTPing     bool
	MaxLossPct  float64
	MaxLatMs    float64
	MinLatMs    float64
	OutDir      string
	OutPrefix   string
	NoBench     bool
	Sample      int
	Shuffle     bool
	ColoFilter  []string
	Padding     bool
	CDNName     string
	Emoji       bool
}

func defaultConfig() *Config {
	cpu := runtime.NumCPU()

	conc := cpu * 8
	if conc > 32 {
		conc = 32
	}
	if conc < 8 {
		conc = 8
	}

	p := CDNProfiles["cloudflare"]

	return &Config{
		CIDRs:       append([]string(nil), p.CIDRs...),
		Ports:       append([]int(nil), p.Ports...),
		PingCount:   4,
		Timeout:     1000 * time.Millisecond,
		Concurrency: conc,
		TopK:        15,
		BenchTopN:   5,
		BenchSec:    8,
		BenchURL:    p.BenchURL,
		SNI:         p.SNI,
		Host:        p.Host,
		Path:        p.Path,
		HTTPing:     false,
		MaxLossPct:  30,
		MaxLatMs:    400,
		MinLatMs:    0,
		OutDir:      ".",
		OutPrefix:   "homay",
		Sample:      0,
		Shuffle:     true,
		ColoFilter:  []string{},
		Padding:     true,
		CDNName:     "cloudflare",
		Emoji:       false,
	}
}

func (c *Config) Summary() string {
	colo := "all"
	if len(c.ColoFilter) > 0 {
		colo = strings.Join(c.ColoFilter, ",")
	}

	return fmt.Sprintf("cdn=%s conc=%d ping=%d timeout=%s ports=%v sni=%s httping=%v padding=%v emoji=%v colo=%s sample=%d",
		c.CDNName, c.Concurrency, c.PingCount, c.Timeout, c.Ports, c.SNI,
		c.HTTPing, c.Padding, c.Emoji, colo, c.Sample)
}

// matchesColo returns true if the colo passes the filter or filter is empty.
func (c *Config) matchesColo(colo string) bool {
	if len(c.ColoFilter) == 0 {
		return true
	}

	colo = strings.ToUpper(strings.TrimSpace(colo))
	if colo == "" {
		return false
	}

	for _, f := range c.ColoFilter {
		if strings.ToUpper(strings.TrimSpace(f)) == colo {
			return true
		}
	}

	return false
}

func parseFlags(args []string) (*Config, string, error) {
	cfg := defaultConfig()
	fs := flag.NewFlagSet("homay", flag.ContinueOnError)

	var (
		cidrs   string
		ports   string
		link    string
		colo    string
		cdn     string
		menu    bool
		help    bool
		timeout int
		noBench bool
		padding bool
		sample  int
		outDir  string
	)

	fs.StringVar(&cidrs, "cidr", "", "Comma-separated IPv4 CIDRs or IPv4 addresses")
	fs.StringVar(&ports, "ports", "", "Comma-separated ports")
	fs.StringVar(&link, "link", "", "vless:// or trojan:// link")
	fs.StringVar(&colo, "colo", "", "Filter by colo, e.g. FRA,GYD")
	fs.StringVar(&cdn, "cdn", "cloudflare", "CDN target: cloudflare|fastly|gcore")
	fs.IntVar(&cfg.PingCount, "n", cfg.PingCount, "Ping count per IP")
	fs.IntVar(&cfg.Concurrency, "c", cfg.Concurrency, "Worker concurrency")
	fs.IntVar(&cfg.TopK, "top", cfg.TopK, "Keep top-K results")
	fs.IntVar(&cfg.BenchTopN, "bn", cfg.BenchTopN, "Bench top-N IPs")
	fs.IntVar(&cfg.BenchSec, "bsec", cfg.BenchSec, "Bench duration seconds")
	fs.IntVar(&timeout, "t", int(cfg.Timeout/time.Millisecond), "Probe timeout ms")
	fs.StringVar(&cfg.SNI, "sni", cfg.SNI, "TLS SNI")
	fs.BoolVar(&cfg.HTTPing, "httping", cfg.HTTPing, "Use HTTPing mode")
	fs.BoolVar(&padding, "padding", true, "HTTP request padding")
	fs.BoolVar(&cfg.Emoji, "emoji", false, "Show status emoji badges (may not render on all terminals)")
	fs.Float64Var(&cfg.MaxLossPct, "maxloss", cfg.MaxLossPct, "Max loss percent")
	fs.Float64Var(&cfg.MaxLatMs, "maxlat", cfg.MaxLatMs, "Max latency ms")
	fs.Float64Var(&cfg.MinLatMs, "minlat", cfg.MinLatMs, "Min latency ms")
	fs.IntVar(&sample, "sample", 0, "Sample N IPs, 0 means all")
	fs.BoolVar(&noBench, "nobench", false, "Skip benchmark")
	fs.StringVar(&outDir, "o", ".", "Output directory")
	fs.BoolVar(&menu, "menu", false, "Open interactive menu")
	fs.BoolVar(&help, "h", false, "Show help")

	if err := fs.Parse(args); err != nil {
		return nil, "", err
	}

	if help {
		fs.Usage()
		return nil, "help", nil
	}

	cdn = strings.ToLower(strings.TrimSpace(cdn))
	if cdn == "" {
		cdn = "cloudflare"
	}

	p, ok := CDNProfiles[cdn]
	if !ok {
		return nil, "", fmt.Errorf("unknown cdn: %s", cdn)
	}

	cfg.CDNName = cdn
	cfg.CIDRs = append([]string(nil), p.CIDRs...)
	cfg.SNI = p.SNI
	cfg.Host = p.Host
	cfg.Path = p.Path
	cfg.Ports = append([]int(nil), p.Ports...)
	cfg.BenchURL = p.BenchURL

	if timeout <= 0 {
		return nil, "", fmt.Errorf("timeout must be greater than zero")
	}
	cfg.Timeout = time.Duration(timeout) * time.Millisecond

	cfg.NoBench = noBench
	cfg.Padding = padding
	cfg.Sample = sample
	cfg.OutDir = strings.TrimSpace(outDir)
	if cfg.OutDir == "" {
		cfg.OutDir = "."
	}

	if cfg.PingCount <= 0 {
		return nil, "", fmt.Errorf("ping count must be greater than zero")
	}
	if cfg.Concurrency <= 0 {
		return nil, "", fmt.Errorf("concurrency must be greater than zero")
	}
	if cfg.TopK <= 0 {
		return nil, "", fmt.Errorf("top must be greater than zero")
	}
	if cfg.BenchTopN < 0 {
		return nil, "", fmt.Errorf("bench top-N cannot be negative")
	}
	if cfg.BenchSec <= 0 {
		return nil, "", fmt.Errorf("bench seconds must be greater than zero")
	}
	if cfg.Sample < 0 {
		return nil, "", fmt.Errorf("sample cannot be negative")
	}
	if cfg.MaxLossPct < 0 || cfg.MaxLossPct > 100 {
		return nil, "", fmt.Errorf("maxloss must be between 0 and 100")
	}
	if cfg.MaxLatMs < 0 || cfg.MinLatMs < 0 {
		return nil, "", fmt.Errorf("latency limits cannot be negative")
	}
	if cfg.MaxLatMs > 0 && cfg.MinLatMs > cfg.MaxLatMs {
		return nil, "", fmt.Errorf("minlat cannot be greater than maxlat")
	}

	if ports != "" {
		parsedPorts, err := parsePorts(ports)
		if err != nil {
			return nil, "", err
		}
		cfg.Ports = parsedPorts
	}

	if colo != "" {
		for _, item := range strings.Split(colo, ",") {
			item = strings.ToUpper(strings.TrimSpace(item))
			if item != "" {
				cfg.ColoFilter = append(cfg.ColoFilter, item)
			}
		}
	}

	if link != "" {
		host, port, sni, err := parseProxyLink(link)
		if err != nil {
			return nil, "", err
		}

		if host != "" {
			ip := net.ParseIP(host)
			if ip == nil || ip.To4() == nil {
				return nil, "", fmt.Errorf("link host must be IPv4 address: %s", host)
			}
			cfg.CIDRs = []string{host + "/32"}
		}

		if port > 0 {
			cfg.Ports = []int{port}
		}

		if sni != "" {
			cfg.SNI = sni
			cfg.Host = sni
			cfg.BenchURL = "https://" + sni + "/"
		}
	}

	if cidrs != "" {
		list, err := parseCIDRList(cidrs)
		if err != nil {
			return nil, "", err
		}
		cfg.CIDRs = list
	}

	if cfg.SNI == "" {
		cfg.SNI = cfg.Host
	}
	if cfg.Host == "" {
		cfg.Host = cfg.SNI
	}
	if cfg.BenchURL == "" {
		cfg.BenchURL = "https://" + cfg.Host + cfg.Path
	}

	explicitScan := cidrs != "" || link != ""
	if menu || !explicitScan {
		return cfg, "menu", nil
	}

	return cfg, "cli", nil
}

func parsePorts(s string) ([]int, error) {
	parts := strings.Split(s, ",")
	out := make([]int, 0, len(parts))
	seen := make(map[int]struct{}, len(parts))

	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}

		n, err := strconv.Atoi(p)
		if err != nil || n <= 0 || n > 65535 {
			return nil, fmt.Errorf("invalid port: %s", p)
		}

		if _, ok := seen[n]; ok {
			continue
		}

		seen[n] = struct{}{}
		out = append(out, n)
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("no valid ports")
	}

	return out, nil
}

func parseCIDRList(s string) ([]string, error) {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))

	for _, item := range parts {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}

		if ip := net.ParseIP(item); ip != nil {
			if ip.To4() == nil {
				return nil, fmt.Errorf("IPv6 is not supported: %s", item)
			}
			item = ip.To4().String() + "/32"
		} else {
			ip, ipNet, err := net.ParseCIDR(item)
			if err != nil {
				return nil, fmt.Errorf("invalid IPv4 CIDR: %s", item)
			}
			if ip.To4() == nil {
				return nil, fmt.Errorf("IPv6 is not supported: %s", item)
			}
			item = ipNet.String()
		}

		if _, ok := seen[item]; ok {
			continue
		}

		seen[item] = struct{}{}
		out = append(out, item)
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("no valid CIDR")
	}

	return out, nil
}

func parseProxyLink(link string) (host string, port int, sni string, err error) {
	link = strings.TrimSpace(link)
	if !strings.HasPrefix(link, "vless://") && !strings.HasPrefix(link, "trojan://") {
		return "", 0, "", fmt.Errorf("only vless:// or trojan:// supported")
	}

	u, e := url.Parse(link)
	if e != nil {
		return "", 0, "", e
	}

	host = strings.TrimSpace(u.Hostname())
	if host == "" {
		return "", 0, "", fmt.Errorf("missing link host")
	}

	if p := u.Port(); p != "" {
		port, err = strconv.Atoi(p)
		if err != nil || port <= 0 || port > 65535 {
			return "", 0, "", fmt.Errorf("invalid link port: %s", p)
		}
	}

	q := u.Query()
	sni = strings.TrimSpace(q.Get("sni"))
	if sni == "" {
		sni = strings.TrimSpace(q.Get("host"))
	}
	if sni == "" {
		sni = strings.TrimSpace(q.Get("peer"))
	}

	return host, port, sni, nil
}

func joinInts(v []int) string {
	parts := make([]string, 0, len(v))
	for _, n := range v {
		parts = append(parts, strconv.Itoa(n))
	}
	return strings.Join(parts, ",")
}

func msDur(ms int) time.Duration {
	if ms <= 0 {
		return 0
	}
	return time.Duration(ms) * time.Millisecond
}