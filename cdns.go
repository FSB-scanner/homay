package main

import (
	"net"
)

// CDNProfile defines how to probe a specific CDN.
type CDNProfile struct {
	Name string

	CIDRs []string
	Ports []int

	SNI  string
	Host string
	Path string

	BenchURL string

	// Header key/value that can identify this CDN in HTTP response.
	// If DetectValue is empty, only existence of DetectHeader is checked.
	DetectHeader string
	DetectValue  string
}

// CloudflareCIDRs — official Cloudflare IPv4 ranges.
// Source: https://www.cloudflare.com/ips-v4
var CloudflareCIDRs = []string{
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
}

// CloudflarePorts — TLS ports commonly accepted by Cloudflare edges.
var CloudflarePorts = []int{443, 8443, 2053, 2083, 2087, 2096}

// CDNProfiles — supported CDN targets.
var CDNProfiles = map[string]CDNProfile{
	"cloudflare": {
		Name:         "Cloudflare",
		CIDRs:        CloudflareCIDRs,
		SNI:          "speed.cloudflare.com",
		Host:         "speed.cloudflare.com",
		Path:         "/",
		Ports:        CloudflarePorts,
		BenchURL:     "https://speed.cloudflare.com/__down?bytes=52428800",
		DetectHeader: "Server",
		DetectValue:  "cloudflare",
	},
	"fastly": {
		Name:         "Fastly",
		CIDRs:        []string{"151.101.0.0/16", "199.232.0.0/16", "157.52.192.0/18"},
		SNI:          "www.fastly.com",
		Host:         "www.fastly.com",
		Path:         "/",
		Ports:        []int{443},
		BenchURL:     "https://www.fastly.com/",
		DetectHeader: "X-Served-By",
		DetectValue:  "",
	},
	"gcore": {
		Name:         "Gcore",
		CIDRs:        []string{"92.223.112.0/22", "5.188.206.0/23", "94.140.144.0/21"},
		SNI:          "api.gcore.com",
		Host:         "api.gcore.com",
		Path:         "/",
		Ports:        []int{443},
		BenchURL:     "https://api.gcore.com/",
		DetectHeader: "Server",
		DetectValue:  "nginx",
	},
}

// isCloudflareIP returns true if the given IPv4 address falls within
// any of the official Cloudflare IP ranges.
func isCloudflareIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	ip = ip.To4()
	if ip == nil {
		return false
	}
	for _, cidr := range CloudflareCIDRs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

// isTLSPort returns true for ports this scanner treats as HTTPS/TLS.
func isTLSPort(port int) bool {
	switch port {
	case 443, 8443, 2053, 2083, 2087, 2096:
		return true
	default:
		return false
	}
}