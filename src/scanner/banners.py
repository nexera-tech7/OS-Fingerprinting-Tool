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
    # "strong" = the banner names an OS/distro; "weak" = cross-platform software
    # (nginx, MySQL, generic OpenSSH...) that merely *tends* to run on that OS.
    strength: str = "strong"


BANNER_PATTERNS: list[tuple[str, str, list[str]]] = [
    # SSH
    (r"SSH-2\.0-.*OpenSSH_for_Windows", "OpenSSH for Windows", ["windows"]),
    (r"SSH-2\.0-.*Windows", "SSH", ["windows"]),
    (r"OpenSSH[_ ](\S+).*Ubuntu", "OpenSSH", ["linux"]),
    (r"OpenSSH[_ ](\S+).*Debian", "OpenSSH", ["linux"]),
    (r"OpenSSH[_ ](\S+).*FreeBSD", "OpenSSH", ["bsd"]),
    (r"OpenSSH[_ ](\S+).*macOS", "OpenSSH", ["macos"]),
    (r"OpenSSH[_ ](\S+).*CentOS", "OpenSSH", ["linux"]),
    (r"OpenSSH[_ ](\S+).*Red.Hat", "OpenSSH", ["linux"]),
    (r"OpenSSH[_ ](\S+).*Fedora", "OpenSSH", ["linux"]),
    (r"OpenSSH[_ ](\S+).*Raspbian", "OpenSSH", ["linux"]),
    (r"OpenSSH[_ ](\S+).*Alpine", "OpenSSH", ["linux"]),
    (r"OpenSSH[_ ](\S+).*Kali", "OpenSSH", ["linux"]),
    (r"OpenSSH[_ ](\S+)", "OpenSSH", ["linux", "bsd", "macos"]),
    (r"dropbear[_ ]?(\S*)", "Dropbear SSH", ["linux"]),
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
    (r"220.*Exchange", "MS Exchange", ["windows"]),
    (r"Postfix", "Postfix", ["linux"]),
    (r"Exim", "Exim", ["linux"]),
    (r"Sendmail", "Sendmail", ["linux"]),
    (r"MailEnable", "MailEnable", ["windows"]),
    # RDP / Windows-specific protocols
    (r"NTLMSSP", "NTLM Auth", ["windows"]),
    (r"Windows NT", "Windows NT", ["windows"]),
    (r"WorkgroupManager", "Windows Workgroup", ["windows"]),
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
    (r"MongoDB", "MongoDB", ["linux"]),
    # In-memory / cache
    (r"\+PONG", "Redis", ["linux"]),
    (r"VERSION memcache", "Memcached", ["linux"]),
    # Elasticsearch / search
    (r"elasticsearch", "Elasticsearch", ["linux"]),
    # Telnet/console
    (r"Welcome.*Cisco", "Cisco IOS", ["linux"]),
    (r"RouterOS", "MikroTik RouterOS", ["linux"]),
    (r"OpenWrt", "OpenWrt", ["linux"]),
    # Printers / embedded Linux
    (r"CUPS/(\S+)", "CUPS", ["linux"]),
    (r"Raspbian", "Raspbian", ["linux"]),
    # macOS / Apple
    (r"Darwin/(\S+)", "Darwin", ["macos"]),
    (r"Darwin", "Darwin", ["macos"]),
    (r"AirTunes/(\S+)", "AirTunes", ["macos"]),
    (r"DAAP-Server: iTunes/(\S+)", "iTunes DAAP", ["macos"]),
    (r"iTunes/(\S+)", "iTunes", ["macos"]),
    # BSD variants
    (r"FreeBSD[/ ](\S+)", "FreeBSD", ["bsd"]),
    (r"OpenBSD[/ ](\S+)", "OpenBSD", ["bsd"]),
    (r"NetBSD[/ ](\S+)", "NetBSD", ["bsd"]),
    (r"pfSense", "pfSense", ["bsd"]),
    (r"OPNsense", "OPNsense", ["bsd"]),
    (r"TrueNAS", "TrueNAS", ["bsd"]),
    (r"FreeNAS", "FreeNAS", ["bsd"]),
    # Android
    (r"JDWP-Handshake", "ADB JDWP", ["android"]),
    (r"Android[/ ](\S+)", "Android", ["android"]),
    (r"okhttp/(\S+)", "OkHttp", ["android"]),
]


# Services that run on several OSes: they hint at an OS but never prove it.
GENERIC_SERVICES = frozenset({
    "OpenSSH", "Dropbear SSH", "libssh", "vsftpd", "ProFTPD", "Pure-FTPd", "wu-ftpd",
    "Postfix", "Exim", "Sendmail", "Apache", "nginx", "lighttpd", "LiteSpeed", "Caddy",
    "MySQL", "PostgreSQL", "MongoDB", "Redis", "Memcached", "Elasticsearch", "CUPS",
})


def analyze_banner(raw: str, port: int = 0) -> BannerInfo:
    if not raw:
        return BannerInfo(raw="", port=port)

    for pattern, service_name, os_hints in BANNER_PATTERNS:
        match = re.search(pattern, raw, re.IGNORECASE)
        if match:
            version = match.group(1) if match.lastindex and match.lastindex >= 1 else ""
            # An OS-specific pattern (single hint on a non-generic service, or a
            # distro-tagged variant) is strong; a generic one is weak.
            weak = service_name in GENERIC_SERVICES and (len(os_hints) > 1 or not _names_os(raw))
            return BannerInfo(
                raw=raw, service_name=service_name, version=version, os_hints=list(os_hints),
                port=port, strength="weak" if weak else "strong",
            )

    return BannerInfo(raw=raw, port=port)


_OS_TAGS = re.compile(
    r"ubuntu|debian|centos|red.?hat|fedora|raspbian|alpine|kali|rocky|alma|suse|arch|"
    r"freebsd|openbsd|netbsd|macos|darwin|win32|win64|windows",
    re.IGNORECASE,
)


def _names_os(raw: str) -> bool:
    return bool(_OS_TAGS.search(raw))
