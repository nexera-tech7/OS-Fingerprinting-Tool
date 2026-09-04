import re
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class BannerInfo:
    raw: str
    service_name: str = ""
    version: str = ""
    os_hints: list[str] = field(default_factory=list)
    port: int = 0  # source port for traceability


BANNER_PATTERNS: list[tuple[str, str, list[str]]] = [
    # SSH
    (r"OpenSSH[_ ](\S+).*Ubuntu", "OpenSSH", ["linux"]),
    (r"OpenSSH[_ ](\S+).*Debian", "OpenSSH", ["linux"]),
    (r"OpenSSH[_ ](\S+).*FreeBSD", "OpenSSH", ["bsd"]),
    (r"OpenSSH[_ ](\S+).*macOS", "OpenSSH", ["macos"]),
    (r"OpenSSH[_ ](\S+)", "OpenSSH", ["linux", "bsd", "macos"]),
    (r"dropbear[_ ]?(\S*)", "Dropbear SSH", ["linux"]),
    (r"SSH-2\.0-.*Windows", "SSH", ["windows"]),
    (r"SSH-2\.0-libssh", "libssh", ["linux"]),
    # FTP
    (r"Microsoft FTP Service", "Microsoft FTP", ["windows"]),
    (r"vsftpd (\S+)", "vsftpd", ["linux"]),
    (r"ProFTPD (\S+)", "ProFTPD", ["linux"]),
    (r"FileZilla Server", "FileZilla FTP", ["windows"]),
    (r"Pure-FTPd", "Pure-FTPd", ["linux"]),
    (r"wu-ftpd", "wu-ftpd", ["linux"]),
    # SMTP
    (r"220.*Microsoft ESMTP", "MS SMTP", ["windows"]),
    (r"Postfix", "Postfix", ["linux"]),
    (r"Exim", "Exim", ["linux"]),
    (r"Sendmail", "Sendmail", ["linux"]),
    (r"MailEnable", "MailEnable", ["windows"]),
    # HTTP
    (r"Apache/(\S+).*Win32", "Apache", ["windows"]),
    (r"Apache/(\S+).*Ubuntu", "Apache", ["linux"]),
    (r"Apache/(\S+).*Debian", "Apache", ["linux"]),
    (r"Apache/(\S+).*CentOS", "Apache", ["linux"]),
    (r"Apache/(\S+).*Red Hat", "Apache", ["linux"]),
    (r"Apache/(\S+).*Fedora", "Apache", ["linux"]),
    (r"Apache/(\S+)", "Apache", ["linux"]),
    (r"nginx/(\S+)", "nginx", ["linux"]),
    (r"Microsoft-IIS/(\S+)", "IIS", ["windows"]),
    (r"Microsoft-HTTPAPI/(\S+)", "HTTP API", ["windows"]),
    (r"lighttpd/(\S+)", "lighttpd", ["linux"]),
    (r"LiteSpeed", "LiteSpeed", ["linux"]),
    (r"Caddy", "Caddy", ["linux"]),
    # Databases
    (r"MySQL", "MySQL", ["linux"]),
    (r"PostgreSQL", "PostgreSQL", ["linux"]),
    (r"Microsoft SQL Server", "MSSQL", ["windows"]),
    # In-memory / cache
    (r"\+PONG", "Redis", ["linux"]),
    (r"VERSION memcache", "Memcached", ["linux"]),
    # Telnet/console
    (r"Welcome.*Cisco", "Cisco IOS", ["linux"]),
    (r"RouterOS", "MikroTik RouterOS", ["linux"]),
    # macOS / Apple
    (r"Darwin", "Darwin", ["macos"]),
    # Android
    (r"JDWP-Handshake", "ADB JDWP", ["android"]),
]


def analyze_banner(raw: str, port: int = 0) -> BannerInfo:
    if not raw:
        return BannerInfo(raw="", port=port)

    for pattern, service_name, os_hints in BANNER_PATTERNS:
        match = re.search(pattern, raw, re.IGNORECASE)
        if match:
            version = match.group(1) if match.lastindex and match.lastindex >= 1 else ""
            return BannerInfo(raw=raw, service_name=service_name, version=version, os_hints=list(os_hints), port=port)

    return BannerInfo(raw=raw, port=port)
