from dataclasses import dataclass, field
from pathlib import Path

VERSION = "1.0.0"
APP_NAME = "OSDETECT"

DEFAULT_TIMEOUT = 5
QUICK_TIMEOUT = 2
DEEP_TIMEOUT = 10

DEFAULT_PORTS = [22, 80, 443, 135, 139, 445, 3389, 8080, 8443]
QUICK_PORTS = [22, 80, 443]
DEEP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1723, 3306, 3389, 5432, 5900, 8080, 8443, 9090]

SIGNATURES_DIR = Path(__file__).resolve().parent.parent / "signatures"

RATE_LIMIT_DELAY = 0.1

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
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1723: "pptp",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    8080: "http-alt",
    8443: "https-alt",
    9090: "web-mgmt",
}


@dataclass
class ScanConfig:
    target: str = ""
    ports: list[int] = field(default_factory=lambda: list(DEFAULT_PORTS))
    timeout: float = DEFAULT_TIMEOUT
    mode: str = "normal"
    json_output: bool = False
    verbose: bool = False

    def apply_mode(self) -> None:
        if self.mode == "quick":
            self.ports = list(QUICK_PORTS)
            self.timeout = QUICK_TIMEOUT
        elif self.mode == "deep":
            self.ports = list(DEEP_PORTS)
            self.timeout = DEEP_TIMEOUT
