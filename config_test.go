package main

import (
	"testing"
)

func TestParsePorts(t *testing.T) {
	// valid
	ports, err := parsePorts("80,443,8443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 3 || ports[0] != 80 || ports[1] != 443 || ports[2] != 8443 {
		t.Errorf("expected [80 443 8443], got %v", ports)
	}

	// duplicate ports should be deduplicated
	ports2, err := parsePorts("443,443,8443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports2) != 2 {
		t.Errorf("duplicates: expected 2, got %d", len(ports2))
	}

	// invalid string
	_, err = parsePorts("80,abc,443")
	if err == nil {
		t.Error("expected error for invalid port 'abc'")
	}

	// port out of range
	_, err = parsePorts("80,99999")
	if err == nil {
		t.Error("expected error for port 99999")
	}

	// empty
	_, err = parsePorts("")
	if err == nil {
		t.Error("expected error for empty ports")
	}
}

func TestParseCIDRList(t *testing.T) {
	// valid IP and CIDR input
	cidrs, err := parseCIDRList("1.1.1.1,192.168.1.0/24")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cidrs) != 2 {
		t.Errorf("expected 2, got %d", len(cidrs))
	}
	// direct IP should be converted to /32
	if cidrs[0] != "1.1.1.1/32" {
		t.Errorf("expected 1.1.1.1/32, got %s", cidrs[0])
	}

	// IPv6 should return error
	_, err = parseCIDRList("2001:db8::/32")
	if err == nil {
		t.Error("expected error for IPv6")
	}

	// empty
	_, err = parseCIDRList("")
	if err == nil {
		t.Error("expected error for empty input")
	}
}

func TestParseProxyLink(t *testing.T) {
	// vless link with SNI
	link := "vless://60341772-88ec-40ef-bc11-a5cf2b56e9c9@1.1.1.1:443?sni=speed.cloudflare.com"
	host, port, sni, err := parseProxyLink(link)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if host != "1.1.1.1" {
		t.Errorf("host: expected 1.1.1.1, got %s", host)
	}
	if port != 443 {
		t.Errorf("port: expected 443, got %d", port)
	}
	if sni != "speed.cloudflare.com" {
		t.Errorf("sni: expected speed.cloudflare.com, got %s", sni)
	}

	// trojan
	trojan := "trojan://password@2.2.2.2:8443?sni=example.com"
	host2, port2, sni2, err := parseProxyLink(trojan)
	if err != nil {
		t.Fatalf("trojan: unexpected error: %v", err)
	}
	if host2 != "2.2.2.2" || port2 != 8443 || sni2 != "example.com" {
		t.Errorf("trojan parse failed: %s %d %s", host2, port2, sni2)
	}

	// unsupported scheme should return error
	_, _, _, err = parseProxyLink("http://1.1.1.1:443")
	if err == nil {
		t.Error("expected error for unsupported scheme")
	}

	// empty
	_, _, _, err = parseProxyLink("")
	if err == nil {
		t.Error("expected error for empty link")
	}
}
