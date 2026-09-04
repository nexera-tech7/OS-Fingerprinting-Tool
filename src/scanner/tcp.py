import socket
import subprocess
import re
import logging
import platform
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class TCPFingerprint:
    ttl: int | None = None
    window: int | None = None
    options: list[str] = field(default_factory=list)
    mss: int | None = None
    characteristics: dict[str, str | int | bool] = field(default_factory=dict)


def collect_tcp_fingerprint(ip: str, port: int, timeout: float = 5.0) -> TCPFingerprint:
    fp = TCPFingerprint()
    try:
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        fp.characteristics["connected"] = True
        sock.close()
    except (OSError, TimeoutError) as exc:
        logger.debug("TCP connection failed for %s:%d — %s", ip, port, exc)
        fp.characteristics["connected"] = False

    remote_ttl = _ping_ttl(ip, timeout)
    if remote_ttl is not None:
        fp.ttl = remote_ttl

    return fp


def collect_ttl_only(ip: str, timeout: float = 5.0) -> TCPFingerprint:
    """Collect a TTL-only fingerprint via ICMP ping, without needing an open port.

    Used when no ports are open (e.g. mobile devices with all ports filtered)
    so we can still feed TTL-based evidence into the analyzer.
    """
    fp = TCPFingerprint()
    remote_ttl = _ping_ttl(ip, timeout)
    if remote_ttl is not None:
        fp.ttl = remote_ttl
        fp.characteristics["ttl_only"] = True
    return fp


def _ping_ttl(ip: str, timeout: float = 5.0) -> int | None:
    try:
        is_windows = platform.system().lower() == "windows"
        is_ipv6 = ":" in ip

        if is_windows:
            # Windows ping supports -6 for IPv6
            if is_ipv6:
                cmd = ["ping", "-6", "-n", "1", "-w", str(int(timeout * 1000)), ip]
            else:
                cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
        else:
            # Linux/macOS: use ping6 for IPv6, ping for IPv4
            if is_ipv6:
                cmd = ["ping6", "-c", "1", "-W", str(int(timeout)), ip]
            else:
                cmd = ["ping", "-c", "1", "-W", str(int(timeout)), ip]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 5,
        )
        output = result.stdout

        match = re.search(r"[Tt][Tt][Ll][=:](\d+)", output)
        if match:
            return int(match.group(1))

    except (subprocess.TimeoutExpired, OSError, ValueError) as exc:
        logger.debug("Ping TTL extraction failed for %s — %s", ip, exc)
    return None


def normalize_ttl(ttl: int | None) -> int | None:
    if ttl is None:
        return None
    if ttl <= 32:
        return 32
    if ttl <= 64:
        return 64
    if ttl <= 128:
        return 128
    return 255


def estimate_hops(ttl: int | None) -> int | None:
    if ttl is None:
        return None
    initial = normalize_ttl(ttl)
    if initial is None:
        return None
    return initial - ttl
