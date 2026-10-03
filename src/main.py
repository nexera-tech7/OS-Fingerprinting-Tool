import sys
import time
import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .cli import parse_args
from .config import ScanConfig
from .network.validation import validate_ip, is_scannable, AddressType
from .network.resolver import reverse_dns, detect_mobile_carrier
from .scanner.ports import scan_ports, PortResult
from .scanner.tcp import collect_ttl_only, TCPFingerprint, estimate_hops
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

    if not config.json_output and not config.no_banner:
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
    mobile_carrier = detect_mobile_carrier(rdns)

    try:
        scan_start = time.monotonic()

        if not config.json_output:
            progress = create_progress()
            with progress:
                task = progress.add_task("Scanning ports & probing TTL", total=100)

                def on_stage(done: int, description: str) -> None:
                    progress.update(task, completed=done, description=description)

                port_results, open_ports, reachable, tcp_fps, banners, http_fps, tls_fps, analysis, confidence = _run_scan(
                    validation.normalized, config, is_public, mobile_carrier, on_stage
                )
                progress.update(task, completed=100, description="Done")

            elapsed = time.monotonic() - scan_start
            hops = _estimate_hops_from_fps(tcp_fps)
            print_target_info(validation, reachable=reachable, rdns=rdns, elapsed=elapsed, hops=hops)
        else:
            port_results, open_ports, reachable, tcp_fps, banners, http_fps, tls_fps, analysis, confidence = _run_scan(
                validation.normalized, config, is_public, mobile_carrier
            )
            elapsed = time.monotonic() - scan_start

    except KeyboardInterrupt:
        print_error("Scan interrupted by user")
        return 130
    except Exception as exc:
        logger.debug("Scan error: %s", exc, exc_info=True)
        print_error(f"Scan failed: {exc}")
        return 1

    hops = _estimate_hops_from_fps(tcp_fps)

    if config.json_output:
        data = build_json_output(validation, reachable, port_results, analysis, confidence, elapsed, rdns=rdns, hops=hops)
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
            data = build_json_output(validation, reachable, port_results, analysis, confidence, elapsed, rdns=rdns, hops=hops)
            try:
                Path(config.output_file).write_text(render_json(data), encoding="utf-8")
                print_info(f"Results saved to {config.output_file}")
            except OSError as exc:
                print_error(f"Could not write output file: {exc}")
                return 1

    return 0


def _estimate_hops_from_fps(tcp_fps: list[TCPFingerprint]) -> int | None:
    for fp in tcp_fps:
        h = estimate_hops(fp.ttl)
        if h is not None:
            return h
    return None


def _run_scan(
    ip: str,
    config: ScanConfig,
    is_public: bool,
    mobile_carrier: str | None = None,
    on_stage=None,
):
    """Single scan pipeline shared by the terminal and JSON paths.

    The ICMP TTL probe runs concurrently with the port scan, and the HTTP and
    TLS probes run concurrently with each other, so total time is roughly
    the slowest probe in each phase rather than the sum.
    """
    stage = on_stage or (lambda done, desc: None)

    with ThreadPoolExecutor(max_workers=4) as pool:
        ttl_future = pool.submit(collect_ttl_only, ip, config.timeout)
        port_results = scan_ports(ip, config.ports, config.timeout)
        open_ports = [p for p in port_results if p.state == "open"]
        reachable = len(open_ports) > 0
        stage(40, "HTTP/TLS fingerprinting")

        http_future = pool.submit(_collect_http_evidence, ip, open_ports, config.timeout)
        tls_future = pool.submit(_collect_tls_evidence, ip, open_ports, config.timeout)
        banners = [analyze_banner(p.banner, p.port) for p in open_ports if p.banner]

        ttl_fp = ttl_future.result()
        tcp_fps = [ttl_fp] if ttl_fp.ttl is not None else []
        http_fps = http_future.result()
        tls_fps = tls_future.result()

    stage(90, "Analyzing evidence")
    analyzer = Analyzer(load_signatures())
    analysis = analyzer.analyze(tcp_fps, port_results, banners, http_fps, tls_fps, is_public, mobile_carrier)
    confidence = calculate_confidence(analysis, is_public)
    return port_results, open_ports, reachable, tcp_fps, banners, http_fps, tls_fps, analysis, confidence


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
