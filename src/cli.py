import argparse
import sys

from .config import VERSION, ScanConfig


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="osdetect",
        description="OS Fingerprinting Tool — estimate the operating system of a target host",
        epilog="Use only against systems you own or have explicit authorization to assess.",
    )
    parser.add_argument("target", nargs="?", help="Target IP address (IPv4 or IPv6)")
    parser.add_argument("--quick", action="store_true", help="Quick scan with fewer ports and shorter timeout")
    parser.add_argument("--deep", action="store_true", help="Deep scan with more ports and longer timeout")
    parser.add_argument("--json", dest="json_output", action="store_true", help="Output results as JSON")
    parser.add_argument("--timeout", type=float, default=None, help="Connection timeout in seconds")
    parser.add_argument("--ports", type=str, default=None, help="Comma-separated list of ports to scan")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose debug output")
    parser.add_argument("--no-banner", dest="no_banner", action="store_true", help="Suppress the startup banner")
    parser.add_argument("--version", "-V", action="version", version=f"osdetect {VERSION}")
    parser.add_argument("--output-file", dest="output_file", default=None, metavar="FILE", help="Save results as JSON to FILE (implies structured output)")
    return parser


def parse_args(argv: list[str] | None = None) -> ScanConfig:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.target is None:
        parser.print_help()
        sys.exit(1)

    config = ScanConfig(target=args.target, verbose=args.verbose, json_output=args.json_output, no_banner=args.no_banner)

    if args.quick and args.deep:
        parser.error("Cannot use --quick and --deep together")

    if args.quick:
        config.mode = "quick"
    elif args.deep:
        config.mode = "deep"

    config.apply_mode()

    if args.timeout is not None:
        config.timeout = args.timeout

    if args.ports is not None:
        try:
            config.ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
            for p in config.ports:
                if not 1 <= p <= 65535:
                    raise ValueError
        except ValueError:
            parser.error("Invalid port specification. Use comma-separated integers 1-65535.")

    if args.output_file is not None:
        config.output_file = args.output_file

    return config
