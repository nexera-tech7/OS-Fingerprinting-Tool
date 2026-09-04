import logging
from dataclasses import dataclass, field

from ..scanner.tcp import TCPFingerprint, normalize_ttl
from ..scanner.ports import PortResult
from ..scanner.banners import BannerInfo
from ..scanner.http import HTTPFingerprint
from ..scanner.tls import TLSFingerprint
from .signatures import OSSignature
from ..config import OS_CATEGORIES

logger = logging.getLogger(__name__)


@dataclass
class Evidence:
    description: str
    os_key: str
    weight: float = 1.0


@dataclass
class AnalysisResult:
    scores: dict[str, float] = field(default_factory=dict)
    probabilities: dict[str, int] = field(default_factory=dict)
    likely_os: str = "unknown"
    evidence: list[Evidence] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        for cat in OS_CATEGORIES:
            self.scores.setdefault(cat, 0.0)
            self.probabilities.setdefault(cat, 0)


class Analyzer:
    def __init__(self, signatures: list[OSSignature]) -> None:
        self._signatures = {s.key: s for s in signatures}

    def analyze(
        self,
        tcp_fps: list[TCPFingerprint],
        port_results: list[PortResult],
        banners: list[BannerInfo],
        http_fps: list[HTTPFingerprint],
        tls_fps: list[TLSFingerprint],
        is_public: bool = False,
    ) -> AnalysisResult:
        result = AnalysisResult()

        self._score_tcp(tcp_fps, result)
        self._score_ports(port_results, result)
        self._score_banners(banners, result)
        self._score_http(http_fps, result)
        self._score_tls(tls_fps, result)
        self._score_mobile_heuristics(port_results, tcp_fps, is_public, result)
        self._add_warnings(result, is_public, port_results)
        self._calculate_probabilities(result)

        return result

    def _score_tcp(self, fps: list[TCPFingerprint], result: AnalysisResult) -> None:
        for fp in fps:
            if fp.ttl is None:
                continue
            initial_ttl = normalize_ttl(fp.ttl)
            for sig in self._signatures.values():
                if initial_ttl in sig.ttl_values:
                    w = 15.0 * sig.weight
                    result.scores[sig.key] += w
                    result.evidence.append(Evidence(f"TTL {fp.ttl} (initial ~{initial_ttl}) matches {sig.name}", sig.key, w))

    def _score_ports(self, ports: list[PortResult], result: AnalysisResult) -> None:
        open_ports = {p.port for p in ports if p.state == "open"}
        open_services = {p.service.lower() for p in ports if p.state == "open" and p.service}

        for sig in self._signatures.values():
            for ip in sig.indicator_ports:
                if ip in open_ports:
                    w = 12.0 * sig.weight
                    result.scores[sig.key] += w
                    result.evidence.append(Evidence(f"Port {ip} open (indicator for {sig.name})", sig.key, w))

            for cp in sig.contra_ports:
                if cp in open_ports:
                    penalty = -5.0 * sig.weight
                    result.scores[sig.key] += penalty

            for skw in sig.service_keywords:
                if skw.lower() in open_services:
                    w = 8.0 * sig.weight
                    result.scores[sig.key] += w
                    result.evidence.append(Evidence(f"Service '{skw}' detected — matches {sig.name}", sig.key, w))

    def _score_banners(self, banners: list[BannerInfo], result: AnalysisResult) -> None:
        for banner in banners:
            if not banner.raw:
                continue

            scored_keys: set[str] = set()
            for os_hint in banner.os_hints:
                hint_key = os_hint.lower()
                if hint_key in self._signatures:
                    w = 20.0
                    result.scores[hint_key] += w
                    label = banner.service_name or "Service"
                    result.evidence.append(Evidence(f"{label} banner suggests {self._signatures[hint_key].name}", hint_key, w))
                    scored_keys.add(hint_key)

            raw_lower = banner.raw.lower()
            for sig in self._signatures.values():
                if sig.key in scored_keys:
                    continue
                for kw in sig.banner_keywords:
                    if kw.lower() in raw_lower:
                        w = 10.0 * sig.weight
                        result.scores[sig.key] += w
                        result.evidence.append(Evidence(f"Banner keyword '{kw}' matches {sig.name}", sig.key, w))
                        scored_keys.add(sig.key)
                        break

    def _score_http(self, fps: list[HTTPFingerprint], result: AnalysisResult) -> None:
        for fp in fps:
            if not fp.server:
                continue

            server_lower = fp.server.lower()
            for sig in self._signatures.values():
                for kw in sig.http_server_keywords:
                    if kw.lower() in server_lower:
                        w = 18.0 * sig.weight
                        result.scores[sig.key] += w
                        result.evidence.append(Evidence(f"HTTP Server '{fp.server}' matches {sig.name}", sig.key, w))
                        break  # only score the first matching keyword per signature

            for name, val in fp.headers.items():
                val_lower = val.lower()
                for sig in self._signatures.values():
                    for kw in sig.header_keywords:
                        if kw.lower() in val_lower:
                            w = 15.0 * sig.weight
                            result.scores[sig.key] += w
                            result.evidence.append(Evidence(f"Header {name}='{val}' matches {sig.name}", sig.key, w))
                            break  # only score the first matching keyword per signature

    def _score_tls(self, fps: list[TLSFingerprint], result: AnalysisResult) -> None:
        for fp in fps:
            if fp.error:
                continue

            if fp.version:
                result.evidence.append(Evidence(f"TLS {fp.version} detected", "", 0))
            if fp.cipher_name:
                result.evidence.append(Evidence(f"Cipher: {fp.cipher_name}", "", 0))

            issuer_lower = " ".join(fp.cert_issuer.values()).lower()
            subject_lower = " ".join(fp.cert_subject.values()).lower()
            san_lower = " ".join(fp.cert_san).lower()
            combined = f"{issuer_lower} {subject_lower} {san_lower}"

            for sig in self._signatures.values():
                for kw in sig.banner_keywords:
                    if kw.lower() in combined:
                        w = 8.0 * sig.weight
                        result.scores[sig.key] += w
                        result.evidence.append(Evidence(f"TLS certificate contains '{kw}' — matches {sig.name}", sig.key, w))

    def _score_mobile_heuristics(self, port_results: list[PortResult], tcp_fps: list[TCPFingerprint], is_public: bool, result: AnalysisResult) -> None:
        open_ports = {p.port for p in port_results if p.state == "open"}
        server_ports = {22, 80, 443, 135, 139, 445, 3389, 8080}

        if open_ports & server_ports:
            return

        if 5555 in open_ports:
            w = 25.0
            result.scores["android"] += w
            result.evidence.append(Evidence("ADB port 5555 open — strong Android indicator", "android", w))
            return

        if not open_ports and not is_public and len(port_results) >= 3:
            for fp in tcp_fps:
                if fp.ttl is not None:
                    initial = normalize_ttl(fp.ttl)
                    if initial == 64:
                        w = 10.0
                        result.scores["android"] += w * 0.6
                        result.scores["ios"] += w * 0.4
                        result.evidence.append(Evidence("No server ports open on private host with TTL ~64 — likely mobile device", "android", w * 0.6))
                        result.evidence.append(Evidence("No server ports open on private host with TTL ~64 — likely mobile device", "ios", w * 0.4))
                        break

        all_filtered = all(p.state == "filtered" for p in port_results) and len(port_results) >= 3
        if all_filtered and not is_public:
            w = 8.0
            result.scores["android"] += w * 0.5
            result.scores["ios"] += w * 0.5
            result.evidence.append(Evidence("All ports filtered on private network — mobile firewall behavior", "android", w * 0.5))
            result.evidence.append(Evidence("All ports filtered on private network — mobile firewall behavior", "ios", w * 0.5))

    def _add_warnings(self, result: AnalysisResult, is_public: bool, ports: list[PortResult]) -> None:
        result.warnings.append("OS identification is probabilistic, not definitive")

        if is_public:
            result.warnings.append("Public IP may represent a NAT gateway, router, proxy, or load balancer")

        open_ports = [p for p in ports if p.state == "open"]
        if not open_ports:
            result.warnings.append("No open ports detected — evidence is very limited")

        total = sum(max(0, s) for s in result.scores.values())
        if total < 10:
            result.warnings.append("Insufficient evidence to determine the operating system")

    def _calculate_probabilities(self, result: AnalysisResult) -> None:
        clamped = {k: max(0.0, v) for k, v in result.scores.items()}
        total = sum(clamped.values())

        if total == 0:
            result.probabilities = {k: 0 for k in OS_CATEGORIES}
            result.probabilities["unknown"] = 100
            result.likely_os = "unknown"
            return

        raw_probs = {k: (v / total) * 100 for k, v in clamped.items()}

        rounded = {k: int(round(v)) for k, v in raw_probs.items()}
        diff = 100 - sum(rounded.values())
        if diff != 0:
            top_key = max(rounded, key=lambda k: raw_probs[k])
            rounded[top_key] += diff

        result.probabilities = rounded
        result.likely_os = max(rounded, key=lambda k: rounded[k])
