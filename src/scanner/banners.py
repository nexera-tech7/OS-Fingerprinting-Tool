import re
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class BannerInfo:
    raw: str
    service_name: str = ""
    version: str = ""
    os_hints: list[str] = None

    def __post_init__(self) -> None:
        if self.os_hints is None:
            self.os_hints = []


BANNER_PATTERNS: list[tuple[str, str, list[str]]] = [
    (r"OpenSSH[_ ](\S+).*Ubuntu", "OpenSSH", ["linux"]),
    (r"OpenSSH[_ ](\S+).*Debian", "OpenSSH", ["linux"]),
    (r"OpenSSH[_ ](\S+).*FreeBSD", "OpenSSH", ["bsd"]),
    (r"OpenSSH[_ ](\S+)", "OpenSSH", ["linux", "bsd", "macos"]),
    (r"dropbear[_ ]?(\S*)", "Dropbear SSH", ["linux"]),
    (r"SSH-2\.0-.*Windows", "SSH", ["windows"]),
    (r"Microsoft FTP Service", "Microsoft FTP", ["windows"]),
    (r"vsftpd (\S+)", "vsftpd", ["linux"]),
    (r"ProFTPD (\S+)", "ProFTPD", ["linux"]),
    (r"FileZilla Server", "FileZilla FTP", ["windows"]),
    (r"220.*Microsoft ESMTP", "MS SMTP", ["windows"]),
    (r"Postfix", "Postfix", ["linux"]),
    (r"Exim", "Exim", ["linux"]),
    (r"Apache/(\S+).*Win32", "Apache", ["windows"]),
    (r"Apache/(\S+).*Ubuntu", "Apache", ["linux"]),
    (r"Apache/(\S+).*Debian", "Apache", ["linux"]),
    (r"Apache/(\S+).*CentOS", "Apache", ["linux"]),
    (r"Apache/(\S+)", "Apache", ["linux"]),
    (r"nginx/(\S+)", "nginx", ["linux"]),
    (r"Microsoft-IIS/(\S+)", "IIS", ["windows"]),
    (r"Microsoft-HTTPAPI/(\S+)", "HTTP API", ["windows"]),
    (r"lighttpd/(\S+)", "lighttpd", ["linux"]),
    (r"LiteSpeed", "LiteSpeed", ["linux"]),
]


def analyze_banner(raw: str) -> BannerInfo:
    if not raw:
        return BannerInfo(raw="")

    for pattern, service_name, os_hints in BANNER_PATTERNS:
        match = re.search(pattern, raw, re.IGNORECASE)
        if match:
            version = match.group(1) if match.lastindex and match.lastindex >= 1 else ""
            return BannerInfo(raw=raw, service_name=service_name, version=version, os_hints=list(os_hints))

    return BannerInfo(raw=raw)
