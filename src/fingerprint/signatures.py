import json
import logging
import functools
from dataclasses import dataclass, field
from pathlib import Path

from ..config import SIGNATURES_DIR

logger = logging.getLogger(__name__)


@dataclass
class OSSignature:
    name: str
    key: str
    ttl_values: list[int] = field(default_factory=list)
    window_sizes: list[int] = field(default_factory=list)
    indicator_ports: list[int] = field(default_factory=list)
    contra_ports: list[int] = field(default_factory=list)
    banner_keywords: list[str] = field(default_factory=list)
    http_server_keywords: list[str] = field(default_factory=list)
    service_keywords: list[str] = field(default_factory=list)
    header_keywords: list[str] = field(default_factory=list)
    tls_cert_keywords: list[str] = field(default_factory=list)
    weight: float = 1.0


@functools.lru_cache(maxsize=1)
def load_signatures(directory: Path | None = None) -> list[OSSignature]:
    """Load and cache OS signatures from JSON files.

    The result is memoised so repeated calls within the same process
    (e.g. multiple scans or tests) don't hit the filesystem again.
    Pass a different *directory* to bust the cache intentionally.
    """
    sig_dir = directory or SIGNATURES_DIR
    signatures: list[OSSignature] = []

    if not sig_dir.is_dir():
        logger.warning("Signatures directory not found: %s", sig_dir)
        return signatures

    for json_file in sorted(sig_dir.glob("*.json")):
        try:
            data = json.loads(json_file.read_text(encoding="utf-8"))
            sig = _parse_signature(data, json_file.stem)
            signatures.append(sig)
            logger.debug("Loaded signature: %s from %s", sig.name, json_file.name)
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            logger.warning("Failed to load signature %s: %s", json_file.name, exc)

    return signatures


def _parse_signature(data: dict, fallback_key: str) -> OSSignature:
    signals = data.get("signals", {})
    tcp = signals.get("tcp", {})
    services = signals.get("services", {})
    banners = signals.get("banners", {})
    http = signals.get("http", {})
    tls = signals.get("tls", {})

    return OSSignature(
        name=data.get("name", fallback_key.capitalize()),
        key=data.get("key", fallback_key.lower()),
        ttl_values=tcp.get("ttl_values", []),
        window_sizes=tcp.get("window_sizes", []),
        indicator_ports=services.get("indicator_ports", []),
        contra_ports=services.get("contra_ports", []),
        banner_keywords=banners.get("keywords", []),
        http_server_keywords=http.get("server_keywords", []),
        service_keywords=services.get("keywords", []),
        header_keywords=http.get("header_keywords", []),
        tls_cert_keywords=tls.get("cert_keywords", []),
        weight=data.get("weight", 1.0),
    )
