import socket
import logging
import time
from dataclasses import dataclass

from ..config import SERVICE_MAP, RATE_LIMIT_DELAY

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
    results: list[PortResult] = []
    for port in ports:
        logger.debug("Checking port %d", port)
        results.append(scan_port(ip, port, timeout))
        time.sleep(RATE_LIMIT_DELAY)
    return results


def _grab_banner(sock: socket.socket, timeout: float) -> str:
    try:
        sock.settimeout(min(timeout, 2.0))
        data = sock.recv(1024)
        return data.decode("utf-8", errors="replace").strip()
    except (OSError, TimeoutError):
        return ""
