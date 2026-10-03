# osdetect v1.3.1

Professional terminal-based OS fingerprinting tool. Performs passive, low-impact network fingerprinting against authorized targets and estimates the likely operating system using probability-based scoring.

## What's New in v1.3.1

**Fixes**
- **Emoji removed from terminal output** - OS icons (penguin, window, apple, etc.) and the check/warning/cross/info symbols are gone; output is plain text and renders the same in every terminal
- **Windows console crash fixed** - emoji could raise `UnicodeEncodeError` on legacy code pages (cp1252/cp437) and abort the report; plain ASCII markers (`+`, `!`, `Error:`, `Info:`) avoid this
- **Dead code removed** - unused `_format_os_name()` helper deleted from `output/terminal.py`; `_OS_META` simplified to (name, colour)
- **Non-ASCII arrows removed** from README text, test comments and a test docstring

## What's New in v1.3.0

**Accuracy**
- **TTL scored once** — the same ping TTL was previously counted once per probe (up to 3×)
- **TTL weighted by rarity** — TTL 64 is shared by Linux/Android/iOS/macOS so it counts for less; TTL 128 (Windows) and 255 (BSD) stay strong
- **Strong vs weak banners** — banners that name an OS or distro (`Ubuntu`, `OpenSSH_for_Windows`) score 25; cross-platform software (nginx, MySQL, generic OpenSSH) scores 8, split across candidate OSes instead of 20 each
- **`OpenSSH_for_Windows` fix** — the Windows SSH patterns were shadowed by the generic OpenSSH pattern and never matched
- **HTTP `Server` OS tags** — `Apache/2.4 (Ubuntu)`, `(Win64)`, `(FreeBSD)` etc. are treated as explicit platform statements and replace the generic nginx/apache guesses
- **No double counting** — open Windows ports were scored twice (port indicator + heuristic); now a single indicator plus a combination bonus. Identical headers on ports 80 and 443 are counted once
- **Redis / Elasticsearch / MongoDB** are no longer treated as Linux-exclusive (they run on Windows); only rpcbind and NFS are
- **Sharper probabilities** — scores are sharpened (score^1.5) so a clear leader commits to a decisive answer
- **Smarter confidence** — counts only evidence supporting the winning OS, groups evidence by real probe family (tcp/ports/http/tls/banner), and rewards a wide lead over the runner-up
- **HEAD -> GET fallback** for embedded web servers that reject `HEAD`

**Speed**
- ICMP TTL probe runs once, in parallel with the port scan (was up to 3 sequential pings)
- HTTP and TLS probes run concurrently
- No more ~2s banner wait on client-speaks-first ports (80, 443, 445, 3389, ...)
- Single `_run_scan()` pipeline for both terminal and JSON modes

**Quality**
- 86 tests (16 new analyzer/banner/confidence regression tests)

## Features

- TCP fingerprinting (TTL via ICMP ping, IPv4 + IPv6)
- Concurrent port scanning with banner grabbing
- Banner analysis with 50+ service/OS patterns
- HTTP/HTTPS header fingerprinting (13 captured headers)
- TLS metadata collection with dedicated cert keyword matching
- Probability-based OS estimation — Linux, Windows, Android, iOS, macOS, BSD
- Windows Firewall-aware heuristics (filtered port cluster detection)
- Mobile device heuristics (port 62078, ADB port 5555, TTL-only ping fallback)
- Confidence scoring with 5 levels (Very Low to Very High)
- Rich terminal UI with progress bar and probability bar chart
- JSON output with optional `--output-file` save
- External JSON signature files — add new OS signatures without touching code
- Cross-platform (Linux, Windows, macOS)

## Installation

```bash
git clone https://github.com/nexera-tech7/OS-Fingerprinting-Tool
cd OS-Fingerprinting-Tool
python -m venv .venv
source .venv/bin/activate      # Linux/macOS
# .venv\Scripts\activate       # Windows
pip install -r requirements.txt
pip install -e .
```

## Usage

```bash
osdetect --help
osdetect 192.168.1.10
osdetect 203.0.113.10 --quick
osdetect 203.0.113.10 --deep
osdetect 203.0.113.10 --json
osdetect 203.0.113.10 --output-file results.json
osdetect 203.0.113.10 --timeout 3
osdetect 203.0.113.10 --ports 22,80,443,135,445,3389
osdetect 203.0.113.10 --verbose
```

## CLI Options

| Option | Description |
|---|---|
| `<IP>` | Target IPv4 or IPv6 address |
| `--quick` | Quick scan — fewer ports, 2s timeout |
| `--deep` | Deep scan — 30 ports, 10s timeout |
| `--json` | Output results as structured JSON |
| `--output-file FILE` | Save JSON results to FILE |
| `--timeout N` | Connection timeout in seconds (default: 5) |
| `--ports P` | Comma-separated list of ports (e.g. `22,80,443`) |
| `--verbose` | Enable debug logging |
| `--version` | Show version |
| `--help` | Show help |

## Example Output

```
╔══════════════════════════════════════════════╗
║           OSDETECT v1.3.1                    ║
║         OS Fingerprinting Tool               ║
╚══════════════════════════════════════════════╝
Target
  IP:          192.168.1.10
  Type:        Private
  Reachable:   Yes
  Scan time:   3.42s

Results
──────────────────────────────────────────────
Likely OS
  Windows

Confidence
  High

Probability
  Windows      78%  ███████████████████████████████████████
  Linux        12%  ██████
  BSD           5%  ██
  macOS         3%  █
  Android       1%
  iOS           1%

Evidence
  • Port 135 open (indicator for Windows)
  • Port 445 open (indicator for Windows)
  • Port 3389 open (indicator for Windows)
  • TTL 128 (initial ~128) matches Windows
  • Service 'msrpc' detected — matches Windows

Warnings
  • OS identification is probabilistic, not definitive
──────────────────────────────────────────────
```

## JSON Output

```json
{
  "target": "192.168.1.10",
  "address_type": "private",
  "reachable": true,
  "os": {
    "name": "Windows",
    "confidence": "high",
    "probability": 78
  },
  "probabilities": {
    "windows": 78,
    "linux": 12,
    "bsd": 5,
    "macos": 3,
    "android": 1,
    "ios": 1,
    "unknown": 0
  },
  "ports": [],
  "services": [],
  "evidence": [],
  "warnings": [],
  "scan_time_seconds": 3.42
}
```

## Architecture

```
src/
├── main.py              Entry point, orchestration, shared _run_scan()
├── cli.py               Argument parsing (--output-file added)
├── config.py            Constants, port lists, ScanConfig
├── scanner/
│   ├── tcp.py           TTL via ICMP ping (IPv4 + IPv6), collect_ttl_only()
│   ├── ports.py         Concurrent port scanning (ThreadPoolExecutor)
│   ├── banners.py       Banner pattern analysis (50+ patterns)
│   ├── http.py          HTTP header fingerprinting (13 headers)
│   └── tls.py           TLS metadata, cert subject/issuer/SAN
├── fingerprint/
│   ├── analyzer.py      Scoring engine + Windows/mobile heuristics
│   ├── signatures.py    JSON loader with lru_cache
│   └── confidence.py    5-level confidence with spread-based conflict detection
├── network/
│   ├── resolver.py      Reverse DNS
│   └── validation.py    IP validation, IPv4 + IPv6
└── output/
    ├── terminal.py      Rich terminal UI with elapsed time
    └── json.py          JSON builder with scan_time_seconds

signatures/              OS signature JSON files (easily extensible)
├── linux.json
├── windows.json
├── macos.json
├── bsd.json
├── android.json
└── ios.json
```

## Changelog

### v1.3.1
- Terminal: removed all emoji OS icons and status symbols; evidence uses `+`, warnings `!`, errors `Error:`, info `Info:`
- Terminal: fixed possible `UnicodeEncodeError` on Windows consoles with legacy code pages
- Terminal: removed unused `_format_os_name()`; `_OS_META` entries are now (name, colour)
- Docs/tests: replaced non-ASCII arrows with plain text
- Version bumped to 1.3.1 (`pyproject.toml`, `config.py`, README)

### v1.3.0
- Analyzer: TTL scored once per scan and weighted by how many OS signatures share it
- Analyzer: banner evidence split into strong (OS-named) and weak (cross-platform software), shared across candidate OSes
- Analyzer: HTTP `Server` header OS tags (`(Ubuntu)`, `(Win64)`, `(FreeBSD)`...) override generic keyword guesses; duplicate HTTP/HTTPS fingerprints deduplicated
- Analyzer: removed Windows open-port double counting; added combined-ports bonus
- Analyzer: Redis/ES/Mongo downgraded from Linux-exclusive to Linux-typical (suppressed when Windows ports are open)
- Analyzer: probability distribution sharpened (score^1.5)
- Banners: `OpenSSH_for_Windows` / Windows SSH patterns moved ahead of the generic OpenSSH pattern; added `strength` field
- Confidence: supporting-evidence-only counting, real probe-family grouping, lead-margin bonus/penalty
- HTTP: `HEAD` → `GET` fallback, User-Agent reports the real version
- Performance: single parallel ping, concurrent HTTP+TLS probes, skip banner wait on silent ports
- Tests: new `tests/test_analyzer.py` (16 tests)

### v1.2.0
- Concurrent port scanning with `ThreadPoolExecutor` (up to 50 workers)
- Windows heuristics: filtered port cluster scoring, ICMP-blocked TTL inference, NTLM/WinRM/NetBIOS banner patterns, `netbios` service keyword, WinRM ports 5985/5986
- iOS fix: port 62078 scored before server-port guard; removed port 80 from iOS contra-ports
- IPv6 ping fix: use `ping -6` on Windows, `ping6` on Linux/macOS
- TTL fallback: `collect_ttl_only()` for fully-firewalled hosts with no open ports
- TLS scoring: dedicated `tls.cert_keywords` per signature instead of reusing banner keywords
- HTTP: 13 captured headers (was 5), `Accept` header sent in request
- Banner patterns: +15 new patterns (NTLM, MSSQL, Redis, Memcached, MySQL, PostgreSQL, Darwin, JDWP, Cisco, MikroTik, Pure-FTPd, Sendmail, MS Exchange, OpenSSH-for-Windows)
- Conflict detection: spread-based (`probs[0] - probs[1] <= 40`) instead of 3-key count
- `load_signatures()` memoised with `lru_cache`
- `--output-file` flag for saving JSON results
- Elapsed scan time in terminal and JSON output
- Deduplicated scan pipeline (`_run_scan()` shared function)
- `cli_entry()` wraps `sys.exit(main())` for correct exit code propagation
- `BannerInfo.os_hints` uses `field(default_factory=list)` instead of `None` sentinel
- `_score_ports`: service keyword loop now has `break` to prevent stacking
- `_score_http`: added `break` after first matching keyword per signature
- TLS dead code fixed: `_parse_der_cert` only runs when `getpeercert()` returns nothing
- Port 8443 removed from plain-HTTP scan set (TLS only)

### v1.0.0
- Initial release

## Accuracy Limitations

- Results are **probability estimates**, not definitive identifications.
- A public IP may belong to a router, firewall, VPN, proxy, load balancer, or carrier NAT.
- Android and iOS cannot be reliably distinguished from a public IP — lower confidence by design.
- Fingerprinting uses ICMP TTL, open ports, banners, HTTP headers and TLS certificates — no raw-socket TCP/IP stack probing, so closely related OSes (e.g. Linux vs. Android) may be hard to separate.
- Firewalled or hardened hosts yield weaker evidence. Windows Firewall in particular blocks ICMP and hides SMB/RDP ports.

## Authorized Use Only

Use only against systems you own, have explicit written authorization to scan, or in controlled lab environments. Unauthorized network scanning may violate laws in your jurisdiction.

## Testing

```bash
pytest tests/ -v
```

86 tests, no network calls — all mocked.

## License

MIT
