import socket
import struct
import logging
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
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        fp.ttl = _get_ttl(sock)
        fp.window = _get_window_size(sock)
        fp.characteristics["connected"] = True

        sock.close()
    except (OSError, TimeoutError) as exc:
        logger.debug("TCP fingerprint collection failed for %s:%d — %s", ip, port, exc)
        fp.characteristics["connected"] = False

    return fp


def _get_ttl(sock: socket.socket) -> int | None:
    try:
        if sock.family == socket.AF_INET:
            ttl_opt = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
            return ttl_opt
    except OSError:
        pass
    return None


def _get_window_size(sock: socket.socket) -> int | None:
    try:
        buf = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        return buf
    except OSError:
        pass
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
