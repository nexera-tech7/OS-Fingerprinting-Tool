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
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
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

                der_cert = tls_sock.getpeercert(binary_form=True)

                peer_cert = tls_sock.getpeercert()
                if peer_cert:
                    fp.cert_subject = _flatten_cert_field(peer_cert.get("subject", ()))
                    fp.cert_issuer = _flatten_cert_field(peer_cert.get("issuer", ()))
                    san = peer_cert.get("subjectAltName", ())
                    fp.cert_san = [v for _, v in san]
                elif der_cert:
                    # Fall back to manual DER parsing when the TLS context
                    # cannot decode the certificate (e.g. CERT_NONE mode)
                    _parse_der_cert(der_cert, fp)

    except Exception as exc:
        logger.debug("TLS fingerprint failed for %s:%d — %s", ip, port, exc)
        fp.error = str(exc)

    return fp


def _parse_der_cert(der_bytes: bytes, fp: TLSFingerprint) -> None:
    try:
        text = der_bytes.decode("ascii", errors="replace")
    except Exception:
        text = ""

    cert_strings: list[str] = []
    i = 0
    while i < len(der_bytes):
        if 0x20 <= der_bytes[i] < 0x7F:
            s = []
            while i < len(der_bytes) and 0x20 <= der_bytes[i] < 0x7F:
                s.append(chr(der_bytes[i]))
                i += 1
            token = "".join(s)
            if len(token) >= 3:
                cert_strings.append(token)
        else:
            i += 1

    for s in cert_strings:
        sl = s.lower()
        if not fp.cert_issuer and any(k in sl for k in ("let's encrypt", "digicert", "comodo", "globalsign", "godaddy", "verisign", "sectigo")):
            fp.cert_issuer.setdefault("organizationName", s)
        if any(k in sl for k in ("microsoft", "apple", "canonical", "red hat", "ubuntu", "debian", "android")):
            fp.cert_subject.setdefault("organizationName", s)


def _flatten_cert_field(field_tuple: tuple) -> dict[str, str]:
    result: dict[str, str] = {}
    for rdn in field_tuple:
        if isinstance(rdn, tuple):
            for attr in rdn:
                if isinstance(attr, tuple) and len(attr) == 2:
                    result[attr[0]] = attr[1]
    return result
