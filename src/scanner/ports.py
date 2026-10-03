import socket
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from ..config import SERVICE_MAP, MAX_SCAN_WORKERS

logger = logging.getLogger(__name__)


@dataclass
class PortResult:
    port: int
    state: str
    service: str
    banner: str = ""


# Client-speaks-first protocols never send an unsolicited banner, so waiting
# for one just burns the recv timeout. HTTP/TLS are probed separately.
SILENT_PORTS = frozenset({80, 443, 8080, 8443, 9090, 9200, 9300, 5985, 5986, 993, 995, 3389, 135, 139, 445})


def scan_port(ip: str, port: int, timeout: float = 5.0) -> PortResult:
    service = SERVICE_MAP.get(port, "unknown")
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            banner = "" if port in SILENT_PORTS else _grab_banner(sock, timeout)
            return PortResult(port=port, state="open", service=service, banner=banner)
    except (ConnectionRefusedError,):
        return PortResult(port=port, state="closed", service=service)
    except (OSError, TimeoutError):
        return PortResult(port=port, state="filtered", service=service)


def scan_ports(ip: str, ports: list[int], timeout: float = 5.0) -> list[PortResult]:
    """Scan ports concurrently and return results sorted by port number."""
    results: list[PortResult] = []
    workers = min(MAX_SCAN_WORKERS, len(ports)) if ports else 1
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(scan_port, ip, port, timeout): port for port in ports}
        for future in as_completed(futures):
            port = futures[future]
            try:
                results.append(future.result())
            except Exception as exc:
                logger.debug("Unexpected error scanning port %d: %s", port, exc)
                results.append(PortResult(port=port, state="filtered", service=SERVICE_MAP.get(port, "unknown")))
    results.sort(key=lambda r: r.port)
    return results


def _grab_banner(sock: socket.socket, timeout: float) -> str:
    try:
        sock.settimeout(min(timeout, 2.0))
        data = sock.recv(1024)
        return data.decode("utf-8", errors="replace").strip()
    except (OSError, TimeoutError):
        return ""
