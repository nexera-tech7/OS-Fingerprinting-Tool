import sys
import time
import logging
from pathlib import Path

from .cli import parse_args
from .config import ScanConfig
from .network.validation import validate_ip, is_scannable, AddressType
from .network.resolver import reverse_dns
from .scanner.ports import scan_ports, PortResult
from .scanner.tcp import collect_tcp_fingerprint, collect_ttl_only, TCPFingerprint
from .scanner.banners import analyze_banner, BannerInfo
from .scanner.http import collect_http_fingerprint, HTTPFingerprint
from .scanner.tls import collect_tls_fingerprint, TLSFingerprint
from .fingerprint.signatures import load_signatures
from .fingerprint.analyzer import Analyzer, AnalysisResult
from .fingerprint.confidence import calculate_confidence
from .output.terminal import (
    print_banner, print_target_info, print_port_table,
    print_results, print_error, print_info, create_progress,
)
from .output.json import build_json_output, render_json

logger = logging.getLogger("osdetect")


def main(argv: list[str] | None = None) -> int:
    try:
        config = parse_args(argv)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 1

    _setup_logging(config.verbose)

    if not config.json_output:
        print_banner()

    validation = validate_ip(config.target)
    if not validation.valid:
        print_error(f"Invalid IP address: {config.target}")
        return 1

    if not is_scannable(validation):
        print_error(f"Address {config.target} is {validation.address_type.value} and cannot be scanned")
        return 1

    is_public = validation.address_type == AddressType.PUBLIC

    rdns = reverse_dns(validation.normalized)

    try:
        scan_start = time.monotonic()

        if not config.json_output:
            progress = create_progress()
            with progress:
                task = progress.add_task("Scanning", total=100)

                logger.debug("Scanning ports")
                port_results = scan_ports(validation.normalized, config.ports, config.timeout)
                progress.update(task, completed=30)

                open_ports = [p for p in port_results if p.state == "open"]
                reachable = len(open_ports) > 0

                logger.debug("Collecting TCP evidence")
                tcp_fps = _collect_tcp_evidence(validation.normalized, open_ports, config.timeout)
                progress.update(task, completed=50)

                logger.debug("Analyzing banners")
                banners = [analyze_banner(p.banner, p.port) for p in open_ports if p.banner]
                progress.update(task, completed=60)

                logger.debug("Collecting HTTP evidence")
                http_fps = _collect_http_evidence(validation.normalized, open_ports, config.timeout)
                progress.update(task, completed=75)

                logger.debug("Collecting TLS evidence")
                tls_fps = _collect_tls_evidence(validation.normalized, open_ports, config.timeout)
                progress.update(task, completed=90)

                logger.debug("Loading signatures and analyzing")
                signatures = load_signatures()
                analyzer = Analyzer(signatures)
                analysis = analyzer.analyze(tcp_fps, port_results, banners, http_fps, tls_fps, is_public)
                confidence = calculate_confidence(analysis, is_public)
                progress.update(task, completed=100)

            elapsed = time.monotonic() - scan_start
            print_target_info(validation, reachable=reachable, rdns=rdns, elapsed=elapsed)
        else:
            port_results, open_ports, reachable, tcp_fps, banners, http_fps, tls_fps, analysis, confidence = _run_scan(
                validation.normalized, config, is_public
            )
            elapsed = time.monotonic() - scan_start

    except KeyboardInterrupt:
        print_error("Scan interrupted by user")
        return 130
    except Exception as exc:
        logger.debug("Scan error: %s", exc, exc_info=True)
        print_error(f"Scan failed: {exc}")
        return 1

    if config.json_output:
        data = build_json_output(validation, reachable, port_results, analysis, confidence, elapsed)
        output = render_json(data)
        print(output)
        if config.output_file:
            try:
                Path(config.output_file).write_text(output, encoding="utf-8")
                print_info(f"Results saved to {config.output_file}")
            except OSError as exc:
                print_error(f"Could not write output file: {exc}")
                return 1
    else:
        print_port_table(port_results)
        print_results(analysis, confidence)
        if config.output_file:
            data = build_json_output(validation, reachable, port_results, analysis, confidence, elapsed)
            try:
                Path(config.output_file).write_text(render_json(data), encoding="utf-8")
                print_info(f"Results saved to {config.output_file}")
            except OSError as exc:
                print_error(f"Could not write output file: {exc}")
                return 1

    return 0


def _run_scan(
    ip: str,
    config: ScanConfig,
    is_public: bool,
):
    """Shared scan pipeline used by the JSON / non-progress path."""
    port_results = scan_ports(ip, config.ports, config.timeout)
    open_ports = [p for p in port_results if p.state == "open"]
    reachable = len(open_ports) > 0
    tcp_fps = _collect_tcp_evidence(ip, open_ports, config.timeout)
    banners = [analyze_banner(p.banner, p.port) for p in open_ports if p.banner]
    http_fps = _collect_http_evidence(ip, open_ports, config.timeout)
    tls_fps = _collect_tls_evidence(ip, open_ports, config.timeout)
    signatures = load_signatures()
    analyzer = Analyzer(signatures)
    analysis = analyzer.analyze(tcp_fps, port_results, banners, http_fps, tls_fps, is_public)
    confidence = calculate_confidence(analysis, is_public)
    return port_results, open_ports, reachable, tcp_fps, banners, http_fps, tls_fps, analysis, confidence


def _collect_tcp_evidence(ip: str, open_ports: list[PortResult], timeout: float) -> list[TCPFingerprint]:
    fps: list[TCPFingerprint] = []
    for p in open_ports[:3]:
        fp = collect_tcp_fingerprint(ip, p.port, timeout)
        fps.append(fp)
    # If no ports are open (e.g. mobile device with firewall) still attempt a
    # ping-based TTL collection so the mobile heuristics have TTL evidence.
    if not fps:
        fp = collect_ttl_only(ip, timeout)
        if fp.ttl is not None:
            fps.append(fp)
    return fps


def _collect_http_evidence(ip: str, open_ports: list[PortResult], timeout: float) -> list[HTTPFingerprint]:
    fps: list[HTTPFingerprint] = []
    http_ports = {80, 8080}
    https_ports = {443, 8443}
    for p in open_ports:
        if p.port in http_ports:
            fps.append(collect_http_fingerprint(ip, p.port, timeout, use_tls=False))
        if p.port in https_ports:
            fps.append(collect_http_fingerprint(ip, p.port, timeout, use_tls=True))
    return fps


def _collect_tls_evidence(ip: str, open_ports: list[PortResult], timeout: float) -> list[TLSFingerprint]:
    fps: list[TLSFingerprint] = []
    tls_ports = {443, 8443, 993, 995}
    for p in open_ports:
        if p.port in tls_ports:
            fps.append(collect_tls_fingerprint(ip, p.port, timeout))
    return fps


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="[%(levelname)s] %(message)s",
        handlers=[logging.StreamHandler()],
    )


if __name__ == "__main__":
    sys.exit(main())


def cli_entry() -> None:
    """Entry point for the installed `osdetect` command.

    Wraps main() and calls sys.exit() so the process exit code is
    correctly propagated to the shell (setuptools entry points discard
    a plain integer return value).
    """
    sys.exit(main())
