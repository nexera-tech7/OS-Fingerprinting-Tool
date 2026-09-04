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


def scan_port(ip: str, port: int, timeout: float = 5.0) -> PortResult:
    service = SERVICE_MAP.get(port, "unknown")
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            banner = _grab_banner(sock, timeout)
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
