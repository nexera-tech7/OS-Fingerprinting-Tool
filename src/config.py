from dataclasses import dataclass, field
from pathlib import Path

VERSION = "1.2.1"
APP_NAME = "OSDETECT"

DEFAULT_TIMEOUT = 5
QUICK_TIMEOUT = 2
DEEP_TIMEOUT = 10

DEFAULT_PORTS = [22, 25, 53, 80, 111, 443, 135, 139, 445, 548, 3306, 3389, 5432, 5555, 5900, 5985, 6379, 7000, 8080, 8443, 9200, 62078]
QUICK_PORTS = [22, 80, 443, 135, 445, 3389, 5555, 5900]
DEEP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 514, 515, 548, 631, 993, 995, 1433, 1723, 2049, 3306, 3389, 5037, 5432, 5555, 5900, 5985, 5986, 6379, 7000, 8080, 8443, 9090, 9200, 9300, 27017, 49152, 62078]

SIGNATURES_DIR = Path(__file__).resolve().parent.parent / "signatures"

RATE_LIMIT_DELAY = 0.1

# Maximum number of concurrent port-scan threads
MAX_SCAN_WORKERS = 50

OS_CATEGORIES = ["linux", "windows", "android", "ios", "macos", "bsd", "unknown"]

SERVICE_MAP: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios",
    143: "imap",
    443: "https",
    445: "smb",
    548: "afp",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1723: "pptp",
    2049: "nfs",
    3306: "mysql",
    3389: "rdp",
    5037: "adb-internal",
    5432: "postgresql",
    5555: "adb",
    5900: "vnc",
    5985: "winrm",
    5986: "winrm-ssl",
    6379: "redis",
    7000: "airplay",
    8080: "http-alt",
    8443: "https-alt",
    9090: "web-mgmt",
    9200: "elasticsearch",
    9300: "elasticsearch-cluster",
    27017: "mongodb",
    49152: "upnp",
    62078: "iphone-sync",
}


@dataclass
class ScanConfig:
    target: str = ""
    ports: list[int] = field(default_factory=lambda: list(DEFAULT_PORTS))
    timeout: float = DEFAULT_TIMEOUT
    mode: str = "normal"
    json_output: bool = False
    verbose: bool = False
    no_banner: bool = False
    output_file: str | None = None

    def apply_mode(self) -> None:
        if self.mode == "quick":
            self.ports = list(QUICK_PORTS)
            self.timeout = QUICK_TIMEOUT
        elif self.mode == "deep":
            self.ports = list(DEEP_PORTS)
            self.timeout = DEEP_TIMEOUT
