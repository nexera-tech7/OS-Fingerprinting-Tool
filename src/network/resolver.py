import socket
import re
import logging

logger = logging.getLogger(__name__)

# Known mobile carrier hostname patterns (reverse DNS)
# If the rdns of a public IP matches these, it's almost certainly a mobile device.
_MOBILE_CARRIER_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Japan carriers
    (re.compile(r"au-net\.ne\.jp", re.I),            "KDDI (au) Japan"),
    (re.compile(r"softbank\.ne\.jp", re.I),           "SoftBank Japan"),
    (re.compile(r"docomo\.ne\.jp", re.I),             "NTT Docomo Japan"),
    (re.compile(r"rakuten\.ne\.jp", re.I),            "Rakuten Mobile Japan"),
    # India carriers
    (re.compile(r"airtelbroadband\.in", re.I),        "Airtel India"),
    (re.compile(r"jio\.com", re.I),                   "Jio India"),
    (re.compile(r"bsnl\.in", re.I),                   "BSNL India"),
    (re.compile(r"vodafone\.in", re.I),               "Vodafone India"),
    # US carriers
    (re.compile(r"wireless\.att\.net", re.I),         "AT&T Wireless USA"),
    (re.compile(r"tmodns\.net", re.I),                "T-Mobile USA"),
    (re.compile(r"vzwentp", re.I),                    "Verizon Wireless USA"),
    (re.compile(r"sprint\.com", re.I),                "Sprint USA"),
    # Europe
    (re.compile(r"vodafone\.de", re.I),               "Vodafone Germany"),
    (re.compile(r"t-ipconnect\.de", re.I),            "T-Mobile Germany"),
    (re.compile(r"orange\.fr", re.I),                 "Orange France"),
    # Generic mobile patterns
    (re.compile(r"mobile\.apn", re.I),                "Mobile APN"),
    (re.compile(r"gprs\.", re.I),                     "GPRS/Mobile"),
    (re.compile(r"\.lte\.", re.I),                    "LTE Mobile"),
    (re.compile(r"\.4g\.", re.I),                     "4G Mobile"),
    (re.compile(r"\.5g\.", re.I),                     "5G Mobile"),
]


def reverse_dns(ip: str) -> str | None:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        logger.debug("Reverse DNS lookup failed for %s", ip)
        return None


def detect_mobile_carrier(hostname: str | None) -> str | None:
    """Return the carrier name if the hostname matches a known mobile carrier pattern.

    Returns None if no match found.
    """
    if not hostname:
        return None
    for pattern, carrier in _MOBILE_CARRIER_PATTERNS:
        if pattern.search(hostname):
            return carrier
    return None


def check_reachability(ip: str, port: int = 80, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (OSError, TimeoutError):
        return False
