import http.client
import logging
import ssl
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class HTTPFingerprint:
    status_code: int | None = None
    server: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    redirect_url: str = ""
    tls_enabled: bool = False
    error: str = ""


def collect_http_fingerprint(ip: str, port: int = 80, timeout: float = 5.0, use_tls: bool = False) -> HTTPFingerprint:
    fp = HTTPFingerprint()
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(ip, port, timeout=timeout, context=ctx)
            fp.tls_enabled = True
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=timeout)

        conn.request("HEAD", "/", headers={"Host": ip, "User-Agent": "osdetect/1.0"})
        resp = conn.getresponse()

        fp.status_code = resp.status
        fp.server = resp.getheader("Server", "")
        fp.redirect_url = resp.getheader("Location", "")

        for name in ("X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator", "Via"):
            val = resp.getheader(name, "")
            if val:
                fp.headers[name] = val

        conn.close()
    except Exception as exc:
        logger.debug("HTTP fingerprint failed for %s:%d — %s", ip, port, exc)
        fp.error = str(exc)

    return fp
