import ssl
import socket
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class TLSFingerprint:
    version: str = ""
    cipher_name: str = ""
    cipher_protocol: str = ""
    cipher_bits: int | None = None
    cert_subject: dict[str, str] = field(default_factory=dict)
    cert_issuer: dict[str, str] = field(default_factory=dict)
    cert_san: list[str] = field(default_factory=list)
    alpn_protocol: str = ""
    error: str = ""


def collect_tls_fingerprint(ip: str, port: int = 443, timeout: float = 5.0) -> TLSFingerprint:
    fp = TLSFingerprint()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2", "http/1.1"])

        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=ip) as tls_sock:
                fp.version = tls_sock.version() or ""

                cipher = tls_sock.cipher()
                if cipher:
                    fp.cipher_name = cipher[0]
                    fp.cipher_protocol = cipher[1]
                    fp.cipher_bits = cipher[2]

                fp.alpn_protocol = tls_sock.selected_alpn_protocol() or ""

                cert = tls_sock.getpeercert()
                if cert:
                    fp.cert_subject = _flatten_cert_field(cert.get("subject", ()))
                    fp.cert_issuer = _flatten_cert_field(cert.get("issuer", ()))
                    san = cert.get("subjectAltName", ())
                    fp.cert_san = [v for _, v in san]

    except Exception as exc:
        logger.debug("TLS fingerprint failed for %s:%d — %s", ip, port, exc)
        fp.error = str(exc)

    return fp


def _flatten_cert_field(field_tuple: tuple) -> dict[str, str]:
    result: dict[str, str] = {}
    for rdn in field_tuple:
        if isinstance(rdn, tuple):
            for attr in rdn:
                if isinstance(attr, tuple) and len(attr) == 2:
                    result[attr[0]] = attr[1]
    return result
