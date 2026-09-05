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
        mobile_carrier: str | None = None,
    ) -> AnalysisResult:
        result = AnalysisResult()

        self._score_tcp(tcp_fps, result)
        self._score_ports(port_results, result)
        self._score_banners(banners, result)
        self._score_http(http_fps, result)
        self._score_tls(tls_fps, result)
        self._score_linux_heuristics(port_results, tcp_fps, result)
        self._score_windows_heuristics(port_results, tcp_fps, result)
        self._score_bsd_heuristics(port_results, tcp_fps, result)
        self._score_macos_heuristics(port_results, result)
        self._score_mobile_heuristics(port_results, tcp_fps, is_public, result)
        self._score_carrier_heuristics(port_results, mobile_carrier, result)
        self._add_warnings(result, is_public, port_results, mobile_carrier)
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
        filtered_ports = {p.port for p in ports if p.state == "filtered"}
        open_services = {p.service.lower() for p in ports if p.state == "open" and p.service}

        for sig in self._signatures.values():
            for ip in sig.indicator_ports:
                if ip in open_ports:
                    w = 12.0 * sig.weight
                    result.scores[sig.key] += w
                    result.evidence.append(Evidence(f"Port {ip} open (indicator for {sig.name})", sig.key, w))
                # NOTE: filtered indicator ports are NOT scored here.
                # Generic filtered scoring produced massive false positives —
                # every device with a firewall accumulated Windows points from
                # filtered SMB/RDP ports even when the host was Android/Linux.
                # Filtered port evidence is only added by OS-specific heuristics
                # (_score_windows_heuristics) which require corroborating signals.

            for cp in sig.contra_ports:
                if cp in open_ports:
                    penalty = -5.0 * sig.weight
                    result.scores[sig.key] += penalty

            for skw in sig.service_keywords:
                if skw.lower() in open_services:
                    w = 8.0 * sig.weight
                    result.scores[sig.key] += w
                    result.evidence.append(Evidence(f"Service '{skw}' detected — matches {sig.name}", sig.key, w))
                    break  # one service keyword match per signature is enough

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
                # Prefer dedicated TLS cert keywords when available
                keywords = sig.tls_cert_keywords if sig.tls_cert_keywords else sig.banner_keywords
                for kw in keywords:
                    if kw.lower() in combined:
                        w = 8.0 * sig.weight
                        result.scores[sig.key] += w
                        result.evidence.append(Evidence(f"TLS certificate contains '{kw}' — matches {sig.name}", sig.key, w))
                        break  # one keyword match per signature is enough

    def _score_linux_heuristics(self, port_results: list[PortResult], tcp_fps: list[TCPFingerprint], result: AnalysisResult) -> None:
        """Linux-specific heuristics that go beyond individual port/banner scoring.

        Covers three common real-world scenarios:
        1. Linux server cluster — SSH + a database/service port is a very strong
           combined signal that generic per-port scoring underweights.
        2. TTL=64 disambiguation — shared with macOS/Android/iOS, but combined
           with Linux-exclusive service ports it becomes reliable.
        3. Linux-only service port combinations that no other OS exposes.
        """
        all_ports = {p.port: p.state for p in port_results}
        open_ports  = {p for p, s in all_ports.items() if s == "open"}
        filtered_ports = {p for p, s in all_ports.items() if s == "filtered"}

        # Ports exclusive to Linux in practice
        linux_exclusive = {111, 2049, 6379, 9200, 9300, 27017}  # rpcbind, NFS, Redis, ES, Mongo
        linux_server    = {22, 25, 53, 3306, 5432}              # SSH, SMTP, DNS, MySQL, Postgres

        exclusive_open = linux_exclusive & open_ports
        server_open    = linux_server & open_ports

        # Any Linux-exclusive service port open → strong signal
        for port in exclusive_open:
            port_names = {
                111: "rpcbind", 2049: "NFS", 6379: "Redis",
                9200: "Elasticsearch", 9300: "Elasticsearch cluster", 27017: "MongoDB",
            }
            w = 18.0
            result.scores["linux"] += w
            result.evidence.append(Evidence(
                f"Port {port} ({port_names.get(port, 'Linux service')}) open — Linux-exclusive service",
                "linux", w
            ))

        # SSH + any database/service port is a classic Linux server stack
        if 22 in open_ports and (server_open - {22}):
            extra = sorted((server_open - {22}) & open_ports)
            port_names = {25: "SMTP", 53: "DNS", 3306: "MySQL", 5432: "PostgreSQL"}
            extra_str = ", ".join(f"{p} ({port_names.get(p, 'service')})" for p in extra)
            w = 15.0
            result.scores["linux"] += w
            result.evidence.append(Evidence(
                f"SSH + {extra_str} — classic Linux server stack",
                "linux", w
            ))

        # TTL=64 with no Windows/Apple ports and SSH open → confidently Linux
        has_ttl64 = any(
            normalize_ttl(fp.ttl) == 64
            for fp in tcp_fps if fp.ttl is not None
        )
        windows_ports = {135, 139, 445, 3389} & open_ports
        apple_ports   = {548, 5900, 7000, 62078} & open_ports

        if has_ttl64 and 22 in open_ports and not windows_ports and not apple_ports:
            w = 12.0
            result.scores["linux"] += w
            result.evidence.append(Evidence(
                "TTL ~64 + SSH open + no Windows/Apple ports — consistent with Linux",
                "linux", w
            ))

        # Multiple open ports with no Windows/Apple services → soft Linux nudge.
        # Require at least 2 actually *open* ports to avoid boosting Linux for
        # firewalled Android/mobile devices that have everything filtered.
        if len(open_ports) >= 2 and not windows_ports and not apple_ports:
            w = 6.0
            result.scores["linux"] += w
            result.evidence.append(Evidence(
                "Multiple open ports with no Windows or Apple services — Linux likely",
                "linux", w
            ))

    def _score_windows_heuristics(self, port_results: list[PortResult], tcp_fps: list[TCPFingerprint], result: AnalysisResult) -> None:
        """Windows-specific heuristics: filtered port cluster + TTL inference.

        Filtered port scoring is intentionally gated behind corroborating evidence
        to prevent false positives on Android/Linux/mobile devices where Windows
        ports also appear filtered (because the firewall drops everything).
        """
        all_ports = {p.port: p.state for p in port_results}

        windows_cluster = {135, 139, 445, 3389}
        cluster_seen     = {p for p in windows_cluster if p in all_ports}
        cluster_filtered = {p for p in cluster_seen if all_ports[p] == "filtered"}
        cluster_open     = {p for p in cluster_seen if all_ports[p] == "open"}

        # --- Corroboration check ---
        # Only apply filtered-port heuristics when something else already hints
        # at Windows — TTL=128, a Windows banner, or an IIS/ASP.NET HTTP header.
        has_ttl128 = any(normalize_ttl(fp.ttl) == 128 for fp in tcp_fps if fp.ttl is not None)
        has_windows_evidence = (
            has_ttl128
            or result.scores.get("windows", 0) > 0
        )

        # Open Windows ports: always score regardless
        for port in cluster_open:
            w = 12.0
            result.scores["windows"] += w
            result.evidence.append(Evidence(
                f"Port {port} open (indicator for Windows)",
                "windows", w
            ))

        # Filtered cluster: only score when corroborated
        if len(cluster_filtered) >= 2 and not cluster_open and has_windows_evidence:
            w = 18.0
            result.scores["windows"] += w
            ports_str = ", ".join(str(p) for p in sorted(cluster_filtered))
            result.evidence.append(Evidence(
                f"Windows port cluster ({ports_str}) all filtered — consistent with Windows Firewall",
                "windows", w
            ))

        # TTL absent but port pattern clearly Windows → infer TTL=128
        has_ttl = any(fp.ttl is not None for fp in tcp_fps)
        has_windows_ports = bool(cluster_open) or (len(cluster_filtered) >= 2 and has_windows_evidence)
        if not has_ttl and has_windows_ports:
            w = 10.0
            result.scores["windows"] += w
            result.evidence.append(Evidence(
                "Windows port pattern present but ICMP blocked — inferred TTL ~128",
                "windows", w
            ))

    def _score_bsd_heuristics(self, port_results: list[PortResult], tcp_fps: list[TCPFingerprint], result: AnalysisResult) -> None:
        """BSD-specific heuristics.

        TTL=255 is the strongest single BSD indicator — Linux never uses it.
        Also detects pfSense/OPNsense by their characteristic port exposure.
        """
        # TTL 255 is almost exclusively BSD (FreeBSD default, OpenBSD default)
        for fp in tcp_fps:
            if fp.ttl is not None:
                initial = normalize_ttl(fp.ttl)
                if initial == 255:
                    w = 25.0
                    result.scores["bsd"] += w
                    result.evidence.append(Evidence(
                        f"TTL {fp.ttl} (initial ~255) — strong BSD indicator",
                        "bsd", w
                    ))
                    break

        # pfSense / OPNsense commonly expose 80+443 with no SSH or Windows ports.
        # Require them to actually be *open* (not just filtered) to avoid
        # triggering on mobile/Android devices where everything is filtered.
        all_ports = {p.port: p.state for p in port_results}
        open_ports = {p for p, s in all_ports.items() if s == "open"}
        pfsense_pattern = {80, 443} & open_ports
        windows_ports = {135, 139, 445, 3389} & open_ports
        ssh_open = 22 in open_ports

        if pfsense_pattern and not windows_ports and not ssh_open:
            w = 6.0
            result.scores["bsd"] += w
            result.evidence.append(Evidence(
                "Web-only exposure without SSH/Windows ports — consistent with pfSense/OPNsense",
                "bsd", w
            ))

    def _score_macos_heuristics(self, port_results: list[PortResult], result: AnalysisResult) -> None:
        """macOS-specific heuristics.

        macOS exposes unique Apple service ports that no other OS uses by default.
        AFP (548), VNC (5900), AirPlay (7000), and UPnP (49152) together are a
        strong macOS fingerprint.
        """
        all_ports = {p.port: p.state for p in port_results}
        open_ports = {p for p, s in all_ports.items() if s == "open"}

        apple_ports = {548, 5900, 7000, 49152}
        apple_open = apple_ports & open_ports

        if len(apple_open) >= 2:
            w = 20.0
            result.scores["macos"] += w
            ports_str = ", ".join(str(p) for p in sorted(apple_open))
            result.evidence.append(Evidence(
                f"Multiple Apple service ports open ({ports_str}) — strong macOS indicator",
                "macos", w
            ))
        elif len(apple_open) == 1:
            port = next(iter(apple_open))
            port_names = {548: "AFP", 5900: "VNC/Screen Sharing", 7000: "AirPlay", 49152: "UPnP"}
            w = 10.0
            result.scores["macos"] += w
            result.evidence.append(Evidence(
                f"Port {port} ({port_names.get(port, 'Apple service')}) open — macOS indicator",
                "macos", w
            ))

        # AFP filtered is a weak macOS signal only on private/LAN hosts.
        # On a public IP every port may be filtered by the carrier NAT/firewall,
        # so this heuristic would fire spuriously for any unresponsive device.
        # Skip it entirely — the open-port checks above are sufficient.

    def _score_mobile_heuristics(self, port_results: list[PortResult], tcp_fps: list[TCPFingerprint], is_public: bool, result: AnalysisResult) -> None:
        open_ports = {p.port for p in port_results if p.state == "open"}

        # ADB port 5555 — strongest Android indicator. Check BEFORE the
        # server-port guard so a rooted Android running SSH/HTTP still scores.
        if 5555 in open_ports:
            w = 30.0
            result.scores["android"] += w
            result.evidence.append(Evidence("ADB port 5555 open — strong Android indicator", "android", w))

        # ADB internal port 5037 (local ADB daemon forwarded) — secondary indicator
        if 5037 in open_ports:
            w = 20.0
            result.scores["android"] += w
            result.evidence.append(Evidence("ADB daemon port 5037 open — Android indicator", "android", w))

        # Port 62078 is the iTunes/iphone-sync port — strongest iOS indicator.
        # Check this BEFORE the server-port guard so an iPhone on the LAN is
        # never silently skipped just because it also responds on e.g. port 443.
        if 62078 in open_ports:
            w = 30.0
            result.scores["ios"] += w
            result.evidence.append(Evidence("Port 62078 (iphone-sync) open — strong iOS indicator", "ios", w))

        # If well-known server ports are open and neither ADB nor iphone-sync
        # fired, this is almost certainly not a mobile device — skip low-signal
        # heuristics to avoid polluting scores for Linux/Windows/macOS targets.
        server_ports = {22, 80, 443, 135, 139, 445, 3389, 8080}
        if open_ports & server_ports:
            return

        # Already handled ADB above; skip the old inner check
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

    def _score_carrier_heuristics(self, port_results: list[PortResult], mobile_carrier: str | None, result: AnalysisResult) -> None:
        """Use reverse-DNS carrier detection to score mobile OS when TCP evidence is absent.

        When a public IP belongs to a known mobile carrier (au, SoftBank, Jio, etc.)
        and all ports are filtered, the device is almost certainly a mobile phone.
        We split the score evenly between Android and iOS since we cannot distinguish
        them from the outside — Android simply gets a slight edge (more common globally).
        """
        if not mobile_carrier:
            return

        open_ports = {p.port for p in port_results if p.state == "open"}
        all_filtered = len(open_ports) == 0 and len(port_results) > 0

        if all_filtered:
            # Strong signal: known mobile carrier + completely firewalled
            android_w = 35.0
            ios_w = 25.0
            result.scores["android"] += android_w
            result.scores["ios"] += ios_w
            result.evidence.append(Evidence(
                f"Reverse DNS matches mobile carrier '{mobile_carrier}' — likely Android or iOS device behind NAT",
                "android", android_w
            ))
            result.evidence.append(Evidence(
                f"Reverse DNS matches mobile carrier '{mobile_carrier}' — possible iOS device behind NAT",
                "ios", ios_w
            ))
        else:
            # Carrier IP with some open ports — weaker signal, could be a carrier server
            w = 12.0
            result.scores["android"] += w
            result.evidence.append(Evidence(
                f"Reverse DNS matches mobile carrier '{mobile_carrier}'",
                "android", w
            ))

    def _add_warnings(self, result: AnalysisResult, is_public: bool, ports: list[PortResult], mobile_carrier: str | None = None) -> None:
        result.warnings.append("OS identification is probabilistic, not definitive")

        open_ports = [p for p in ports if p.state == "open"]
        filtered_ports = [p for p in ports if p.state == "filtered"]
        all_filtered = len(filtered_ports) > 0 and len(open_ports) == 0

        if is_public:
            if mobile_carrier:
                result.warnings.append(
                    f"IP reverse-DNS matches mobile carrier '{mobile_carrier}'. "
                    f"This is the carrier's NAT gateway — the actual device (likely Android or iOS) "
                    f"is not directly reachable from the internet."
                )
            else:
                result.warnings.append("Public IP may represent a NAT gateway, router, proxy, or load balancer")
                if all_filtered:
                    result.warnings.append(
                        "All ports are filtered — device is behind a firewall or carrier NAT. "
                        "OS fingerprinting requires observable open ports or TTL data."
                    )

        if not open_ports:
            result.warnings.append("No open ports detected — evidence is very limited")

        total = sum(max(0, s) for s in result.scores.values())
        if total < 12:
            result.warnings.append("Insufficient evidence to determine the operating system")

    def _calculate_probabilities(self, result: AnalysisResult) -> None:
        clamped = {k: max(0.0, v) for k, v in result.scores.items()}
        total = sum(clamped.values())

        # Require a minimum total score before committing to any OS.
        # Below this threshold the evidence is too weak to be meaningful —
        # a single filtered port or one ambiguous TTL should not produce
        # a confident OS label at 100%.
        MIN_SCORE_THRESHOLD = 12.0

        if total == 0 or total < MIN_SCORE_THRESHOLD:
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
