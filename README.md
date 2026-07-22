# Homay v2.0

A high-performance, zero-dependency, multi-CDN clean IP scanner built in Go 1.21. Designed for network-restricted environments and mobile devices running Termux.

## Features

- **Zero Dependencies** — only Go standard library
- **O(k) Reservoir Sampling** — memory-efficient scanning of large CDN ranges
- **Anti-DPI Padding** — random HTTP headers to defeat deep packet inspection (optimized for Iran)
- **HTTPing** — real HTTP latency measurement, not just TCP ping
- **TLS Detection** — reports TLS version (1.0/1.1/1.2/1.3) and HTTP/2 support
- **Multi-CDN** — Cloudflare, Fastly, Gcore, switchable from the menu (option 8)
- **Cross-Platform** — Linux amd64 and Android arm64 (Termux)
- **Live Spinner** — animated progress indicator during scans
- **Score Gradient & Per-Colo Colors** — 5-level color scoring, consistent color per datacenter
- **Scan Summary** — best IP, average score, and total time after each scan
- **Optional Emoji Badges** — TLS 1.3 / HTTP2 / colo status icons (off by default; toggle in Settings or `-emoji`)
- **Clipboard Export** — copy the best VLESS/Trojan link straight to the clipboard on Termux (needs Termux:API)
- **History / Compare** — each scan is diffed against the previous one: best-score delta, new IPs, dropped IPs
- **Favorites** — save specific IP:Port pairs and re-test just those later without a full scan

---

## Installation on Termux (Android)

```bash
# 1. Update packages
pkg update && pkg upgrade -y

# 2. Install Go and Git
pkg install golang git -y

# 3. Clone the repo
git clone https://github.com/FSB-scanner/homay.git
cd homay

# 4. Build
go build -o homay .

# 5. Run
./homay
```

Or, without cloning first:
```bash
go install github.com/FSB-scanner/homay@latest
$(go env GOPATH)/bin/homay
```

Same steps work on regular Linux (amd64) — just skip the `pkg` commands
and install Go/Git through your distro's package manager instead.

---

## Main Menu

```
1) Quick scan   — 300 sampled IPs from the selected CDN, port 443
2) Deep scan    — 2000 sampled IPs from the selected CDN, port 443
3) Custom CIDR  — Enter your own IP range and ports
4) VLESS/Trojan — Paste a proxy link, find clean IPs, get updated link
                  (optionally copies the best link to clipboard)
5) Single bench — Test one specific IP
6) Discover DC  — Find nearest Cloudflare datacenter
7) Settings     — Adjust all parameters
8) Change CDN   — Switch Quick/Deep/Custom scan target between
                  Cloudflare, Fastly, and Gcore
9) Favorites    — Save/re-test specific IP:Port pairs
0) Exit
```

Discover DC (option 6) always targets Cloudflare regardless of the
selected CDN, since colo discovery relies on Cloudflare's own
`/cdn-cgi/trace` endpoint.

After every scan (Quick/Deep/Custom/VLESS-Trojan), Homay also shows a
**COMPARE** box against the previous scan (best-score delta, new IPs,
dropped IPs) and offers to save the best IP to your favorites.

---

## Clipboard Export

After scanning a VLESS/Trojan link (option 4), Homay offers to copy the
best-scoring updated link straight to your clipboard via
`termux-clipboard-set`. This requires the **Termux:API** add-on app
plus:
```bash
pkg install termux-api
```
If it's not installed, the copy fails gracefully with an explanation —
your scan results are unaffected either way.

---

## Settings

| # | Setting | Default | Description |
|---|---------|---------|-------------|
| 1 | Ports | 443,8443,2053,2083,2087,2096 | TLS ports to scan |
| 2 | Concurrency | 32 | Worker count (lower on weak mobile) |
| 3 | Ping count | 4 | HTTP pings per IP |
| 4 | Timeout ms | 2000 | Connection timeout |
| 5 | Max loss % | 30 | Filter IPs with high packet loss |
| 6 | Max lat ms | 400 | Filter IPs with high latency |
| 7 | Top-K keep | 15 | How many results to keep |
| 8 | Bench top-N | 5 | How many IPs to speed-test |
| 9 | Bench secs | 8 | Download test duration |
| 10 | HTTPing | true | Use real HTTP measurement |
| 11 | Padding | true | Anti-DPI random headers |
| 12 | Colo filter | (empty=all) | Filter by datacenter e.g. FRA,GYD |
| 13 | SNI | speed.cloudflare.com | TLS server name |
| 14 | Emoji | false | Status badges (✅/⚡/🌍); off by default in case your terminal font can't render them |
| 15 | Reset | — | Reset all settings to defaults |

---

## Scan Results

```
IP              PORT  LAT ms  JIT ms  LOSS  TLS  H2  COLO  SCORE
------------------------------------------------------------------------
104.16.155.171  443   92      3       0     1.3  y   FRA   94.2
```

| Column | Meaning |
|--------|---------|
| LAT ms | Average HTTP latency — lower is better |
| JIT ms | Jitter (stability) — lower is better |
| LOSS | Packet loss % — 0 is ideal |
| TLS | TLS version (1.3 is best) |
| H2 | HTTP/2 support (y = yes) |
| COLO | Cloudflare datacenter code |
| SCORE | 0–100 composite score |

> ⚠️ **Non-TLS ports (80, 8080, ...):** these can never carry a
> TLS-based VLESS/Trojan config, so even with perfect latency their
> score is capped at 60 — a fast plain-TCP handshake alone doesn't
> mean the port is actually usable for your proxy. Stick to TLS ports
> (443, 8443, 2053, 2083, 2087, 2096) unless you have a specific
> non-TLS use case.

---

## Output Files

After each scan, three files are saved automatically:

| File | Format | Use |
|------|--------|-----|
| `homay-DATE.json` | JSON | Full data with all fields |
| `homay-DATE.csv` | CSV | Open in Excel/Sheets |
| `homay-DATE.txt` | Text | `ip:port` per line — paste into V2Ray/Xray/Sing-box |

Two more files are kept and overwritten each scan (not timestamped):

| File | Use |
|------|-----|
| `homay-last.json` | Snapshot used to build the COMPARE box next scan |
| `homay-favorites.json` | Your saved favorite IP:Port list |

---

## Warnings

> ⚠️ **Memory on Full Scan:** Setting `-sample 0` or using Full Scan expands all Cloudflare IPs (~1.5M addresses) into RAM. On mobile devices this may use 100MB+. Use Quick Scan or set a sample limit via Settings.

> ⚠️ **IPv4 Only:** IPv6 is not supported yet. All CIDR ranges must be IPv4.

> ⚠️ **CIDR Limit:** For safety, subnets larger than /10 are rejected automatically.

---

## CLI Usage

```bash
./homay                          # interactive menu
./homay -cdn cloudflare -top 20  # quick scan via CLI
./homay -cidr 104.16.0.0/20 -colo FRA,GYD
./homay -link vless://...
./homay -sample 500 -c 16 -t 1500
./homay -cdn cloudflare -top 20 -emoji  # with status emoji badges
```

---

## License

MIT — see [LICENSE](LICENSE).
