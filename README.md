# osdetect

Professional terminal-based OS fingerprinting tool. Performs passive, low-impact network fingerprinting against authorized targets and estimates the likely operating system using probability-based scoring.

## Features

- TCP fingerprinting (TTL, window size, options)
- Port scanning with service detection
- Banner grabbing and analysis
- HTTP/HTTPS header fingerprinting
- TLS metadata collection
- Probability-based OS estimation across Linux, Windows, Android, iOS, macOS, BSD
- Confidence scoring with multiple evidence signals
- JSON-structured output
- Rich terminal UI with progress indication
- External JSON signature files for easy extension
- Cross-platform (Linux, Windows, macOS)

## Installation

```bash
git clone https://github.com/nexera-tech7/OS-Fingerprinting-Tool
cd os-fingerprint
python -m venv .venv
source .venv/bin/activate   # Linux/macOS
# .venv\Scripts\activate    # Windows
pip install -r requirements.txt
```

Install as a CLI tool:

```bash
pip install -e .
```

## Usage

```bash
# Show all available commands and options
osdetect --help

# Scan a target
osdetect 203.0.113.10

# Run without installing (alternative)
python -m src.main 203.0.113.10
```

## CLI Options

| Option | Description |
|---|---|
| `<IP>` | Target IPv4 or IPv6 address |
| `--quick` | Quick scan — fewer ports, shorter timeout |
| `--deep` | Deep scan — more ports, longer timeout |
| `--json` | Output results as structured JSON |
| `--timeout N` | Connection timeout in seconds (default: 5) |
| `--ports P` | Comma-separated list of ports (e.g. `22,80,443`) |
| `--verbose` | Enable debug logging |
| `--version` | Show version |
| `--help` | Show help |

### Examples

```bash
osdetect 192.168.1.10
osdetect 203.0.113.10 --quick
osdetect 203.0.113.10 --deep
osdetect 203.0.113.10 --json
osdetect 203.0.113.10 --timeout 3
osdetect 203.0.113.10 --ports 22,80,443
osdetect 203.0.113.10 --verbose
```

## Example Output

```
╔══════════════════════════════════════════════╗
║              OSDETECT v1.0                   ║
║          OS Fingerprinting Tool              ║
╚══════════════════════════════════════════════╝
Target
  IP:          203.0.113.10
  Type:        Public
  Reachable:   Yes

Results
──────────────────────────────────────────────
Likely OS
  Linux
Confidence
  High
Probability
  Linux        82%  ████████████████████████████████████████
  Windows      10%  █████
  Android       5%  ██
  macOS         2%  █
  BSD           1%
  iOS           0%

Evidence
  • SSH detected
  • OpenSSH banner detected
  • TTL 64 (initial ~64) matches Linux

Warnings
  • Public IP may represent a NAT gateway, router, proxy, or load balancer
  • OS identification is probabilistic, not definitive
──────────────────────────────────────────────
```

## JSON Output

```bash
osdetect 203.0.113.10 --json
```

```json
{
  "target": "203.0.113.10",
  "address_type": "public",
  "reachable": true,
  "os": {
    "name": "Linux",
    "confidence": "high",
    "probability": 82
  },
  "probabilities": {
    "linux": 82,
    "windows": 10,
    "android": 5,
    "macos": 2,
    "bsd": 1,
    "ios": 0
  },
  "ports": [],
  "services": [],
  "evidence": [],
  "warnings": []
}
```

## Architecture

```
src/
├── main.py              Entry point and orchestration
├── cli.py               Argument parsing
├── config.py            Constants and scan configuration
├── scanner/
│   ├── tcp.py           TCP fingerprint collection
│   ├── ports.py         Port scanning and banner grabbing
│   ├── banners.py       Banner pattern analysis
│   ├── http.py          HTTP header fingerprinting
│   └── tls.py           TLS metadata collection
├── fingerprint/
│   ├── analyzer.py      Evidence scoring and probability engine
│   ├── signatures.py    JSON signature loader
│   └── confidence.py    Confidence level calculation
├── network/
│   ├── resolver.py      DNS lookups and reachability
│   └── validation.py    IP address validation and classification
└── output/
    ├── terminal.py      Rich terminal rendering
    └── json.py          JSON output builder

signatures/              External OS signature definitions (JSON)
```

## Accuracy Limitations

- Results are **probability estimates**, never definitive identifications.
- A public IP may belong to a router, firewall, VPN, proxy, load balancer, or carrier NAT — not the end device.
- Android and iOS cannot be reliably distinguished from a public IP alone. These receive lower confidence by design.
- The accuracy depends on the number and strength of observable signals. Firewalled or hardened hosts yield weaker evidence.

## Authorized Use Only

This tool must only be used against:

- Systems you own
- Systems where you have explicit written authorization
- Controlled lab environments
- Permitted internal networks

**Do not** use this tool to scan systems without authorization. Unauthorized network scanning may violate laws in your jurisdiction.

## Development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

## Testing

```bash
pytest tests/ -v
```

Tests use mocked network responses and do not scan external systems.

## License

MIT
