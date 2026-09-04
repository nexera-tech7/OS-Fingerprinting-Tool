import socket
import logging

logger = logging.getLogger(__name__)


def reverse_dns(ip: str) -> str | None:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        logger.debug("Reverse DNS lookup failed for %s", ip)
        return None


def check_reachability(ip: str, port: int = 80, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (OSError, TimeoutError):
        return False
