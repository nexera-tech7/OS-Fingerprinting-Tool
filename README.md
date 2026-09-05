# osdetect v1.2.0

Professional terminal-based OS fingerprinting tool. Performs passive, low-impact network fingerprinting against authorized targets and estimates the likely operating system using probability-based scoring.

## What's New in v1.2.0

- **Concurrent port scanning** — up to 50 threads in parallel, dramatically faster than sequential scanning
- **Windows detection overhaul** — filtered port cluster heuristic, ICMP-blocked TTL inference, NTLM/WinRM/NetBIOS detection
- **iOS / iPhone IPv6 fix** — port 62078 now scored before the server-port guard; IPv6 ping uses correct `ping -6` / `ping6` command
- **Smarter conflict detection** — `_has_conflicting_evidence` now uses probability spread instead of a raw key count
- **TLS cert keywords** — each OS signature has dedicated `tls.cert_keywords` instead of reusing banner keywords
- **Richer HTTP fingerprinting** — captures 13 headers including `Set-Cookie`, `ETag`, `X-Varnish`, `X-Runtime`
- **Signature caching** — `load_signatures()` is `lru_cache`-memoised, signatures are read from disk once per process
- **`--output-file` flag** — save results as JSON to a file without needing shell redirection
- **Elapsed time** — scan duration shown in terminal output and `scan_time_seconds` field in JSON
- **Deduplicated scan pipeline** — progress-bar and JSON paths share a single `_run_scan()` function
- **50+ banner patterns** — added Redis, Memcached, MySQL, PostgreSQL, MSSQL, MikroTik, Cisco, Darwin, JDWP, OpenSSH-for-Windows, MS Exchange patterns
- **Exit code propagation** — `osdetect` CLI entry point wraps `main()` with `sys.exit()` so `$?` is always correct
- **7 bug fixes** from v1.0 (see Changelog)

## Features

- TCP fingerprinting (TTL via ICMP ping, IPv4 + IPv6)
- Concurrent port scanning with banner grabbing
- Banner analysis with 50+ service/OS patterns
- HTTP/HTTPS header fingerprinting (13 captured headers)
- TLS metadata collection with dedicated cert keyword matching
- Probability-based OS estimation — Linux, Windows, Android, iOS, macOS, BSD
- Windows Firewall-aware heuristics (filtered port cluster detection)
- Mobile device heuristics (port 62078, ADB port 5555, TTL-only ping fallback)
- Confidence scoring with 5 levels (Very Low → Very High)
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
║           OSDETECT v1.2.0                    ║
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
- Firewalled or hardened hosts yield weaker evidence. Windows Firewall in particular blocks ICMP and hides SMB/RDP ports.

## Authorized Use Only

Use only against systems you own, have explicit written authorization to scan, or in controlled lab environments. Unauthorized network scanning may violate laws in your jurisdiction.

## Testing

```bash
pytest tests/ -v
```

56 tests, no network calls — all mocked.

## License

MIT
