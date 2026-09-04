import pytest
from pathlib import Path

from src.fingerprint.signatures import load_signatures, OSSignature
from src.fingerprint.analyzer import Analyzer, AnalysisResult, Evidence
from src.scanner.tcp import TCPFingerprint
from src.scanner.ports import PortResult
from src.scanner.banners import BannerInfo, analyze_banner
from src.scanner.http import HTTPFingerprint
from src.scanner.tls import TLSFingerprint

SIGNATURES_DIR = Path(__file__).resolve().parent.parent / "signatures"


class TestSignatureLoading:
    def test_load_all(self):
        sigs = load_signatures(SIGNATURES_DIR)
        assert len(sigs) >= 6
        keys = {s.key for s in sigs}
        assert "linux" in keys
        assert "windows" in keys
        assert "android" in keys
        assert "ios" in keys
        assert "macos" in keys
        assert "bsd" in keys

    def test_signature_has_fields(self):
        sigs = load_signatures(SIGNATURES_DIR)
        linux = next(s for s in sigs if s.key == "linux")
        assert linux.name == "Linux"
        assert 64 in linux.ttl_values
        assert len(linux.banner_keywords) > 0

    def test_missing_directory(self):
        sigs = load_signatures(Path("/nonexistent"))
        assert sigs == []


class TestAnalyzer:
    @pytest.fixture
    def analyzer(self):
        return Analyzer(load_signatures(SIGNATURES_DIR))

    def test_linux_ssh_fingerprint(self, analyzer):
        ports = [
            PortResult(22, "open", "ssh", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"),
            PortResult(80, "open", "http"),
            PortResult(3389, "closed", "rdp"),
        ]
        banners = [analyze_banner(p.banner) for p in ports if p.banner]
        tcp = [TCPFingerprint(ttl=64)]
        http = [HTTPFingerprint(server="nginx/1.18")]

        result = analyzer.analyze(tcp, ports, banners, http, [])
        assert result.likely_os == "linux"
        assert result.probabilities["linux"] > result.probabilities["windows"]

    def test_linux_server_stack(self, analyzer):
        """SSH + MySQL + DNS — classic Linux server."""
        ports = [
            PortResult(22, "open", "ssh"),
            PortResult(53, "open", "dns"),
            PortResult(3306, "open", "mysql"),
            PortResult(80, "open", "http"),
        ]
        tcp = [TCPFingerprint(ttl=64)]
        http = [HTTPFingerprint(server="nginx/1.24.0")]
        result = analyzer.analyze(tcp, ports, [], http, [])
        assert result.likely_os == "linux"
        assert result.probabilities["linux"] > result.probabilities["windows"]

    def test_linux_exclusive_port(self, analyzer):
        """Redis port open — Linux-exclusive service."""
        ports = [
            PortResult(22, "open", "ssh"),
            PortResult(6379, "open", "redis"),
        ]
        tcp = [TCPFingerprint(ttl=64)]
        result = analyzer.analyze(tcp, ports, [], [], [])
        assert result.likely_os == "linux"

    def test_linux_no_windows_ports(self, analyzer):
        """TTL 64 + SSH + no Windows ports → Linux over macOS."""
        ports = [
            PortResult(22, "open", "ssh"),
            PortResult(80, "open", "http"),
            PortResult(443, "open", "https"),
        ]
        tcp = [TCPFingerprint(ttl=62)]  # 2 hops away, still ~64
        http = [HTTPFingerprint(server="Apache/2.4.54")]
        result = analyzer.analyze(tcp, ports, [], http, [])
        assert result.likely_os == "linux"
        assert result.probabilities["linux"] > result.probabilities["macos"]

    def test_windows_fingerprint(self, analyzer):
        ports = [
            PortResult(135, "open", "msrpc"),
            PortResult(445, "open", "smb"),
            PortResult(3389, "open", "rdp"),
        ]
        tcp = [TCPFingerprint(ttl=128)]
        http = [HTTPFingerprint(server="Microsoft-IIS/10.0")]

        result = analyzer.analyze(tcp, ports, [], http, [])
        assert result.likely_os == "windows"
        assert result.probabilities["windows"] > result.probabilities["linux"]

    def test_android_adb_fingerprint(self, analyzer):
        ports = [
            PortResult(5555, "open", "adb"),
            PortResult(80, "filtered", "http"),
            PortResult(443, "filtered", "https"),
        ]
        tcp = [TCPFingerprint(ttl=64)]
        result = analyzer.analyze(tcp, ports, [], [], [])
        assert result.likely_os == "android"
        assert result.probabilities["android"] > result.probabilities["linux"]

    def test_android_adb_with_server_ports(self, analyzer):
        """Rooted Android running SSH should still detect Android via ADB port."""
        ports = [
            PortResult(5555, "open", "adb"),
            PortResult(22, "open", "ssh"),
        ]
        tcp = [TCPFingerprint(ttl=64)]
        result = analyzer.analyze(tcp, ports, [], [], [])
        assert result.probabilities["android"] > 0

    def test_bsd_ttl255_fingerprint(self, analyzer):
        ports = [
            PortResult(22, "open", "ssh", "SSH-2.0-OpenSSH_9.3 FreeBSD-20230719"),
            PortResult(80, "open", "http"),
        ]
        banners = [analyze_banner(p.banner) for p in ports if p.banner]
        tcp = [TCPFingerprint(ttl=255)]
        result = analyzer.analyze(tcp, ports, banners, [], [])
        assert result.likely_os == "bsd"
        assert result.probabilities["bsd"] > result.probabilities["linux"]

    def test_macos_apple_ports(self, analyzer):
        ports = [
            PortResult(548, "open", "afp"),
            PortResult(5900, "open", "vnc"),
            PortResult(22, "open", "ssh", "SSH-2.0-OpenSSH_9.0 macOS"),
        ]
        banners = [analyze_banner(p.banner) for p in ports if p.banner]
        tcp = [TCPFingerprint(ttl=64)]
        result = analyzer.analyze(tcp, ports, banners, [], [])
        assert result.likely_os == "macos"
        assert result.probabilities["macos"] > result.probabilities["linux"]

    def test_no_evidence(self, analyzer):
        ports = [PortResult(80, "filtered", "http")]
        result = analyzer.analyze([], ports, [], [], [])
        assert result.likely_os == "unknown"
        assert result.probabilities["unknown"] == 100

    def test_public_warning(self, analyzer):
        ports = [PortResult(80, "open", "http")]
        result = analyzer.analyze([], ports, [], [], [], is_public=True)
        assert any("Public IP" in w for w in result.warnings)

    def test_probabilities_sum_to_100(self, analyzer):
        ports = [
            PortResult(22, "open", "ssh", "SSH-2.0-OpenSSH_8.9p1"),
            PortResult(80, "open", "http"),
        ]
        banners = [analyze_banner("SSH-2.0-OpenSSH_8.9p1")]
        tcp = [TCPFingerprint(ttl=64)]
        http = [HTTPFingerprint(server="Apache/2.4")]
        result = analyzer.analyze(tcp, ports, banners, http, [])
        assert sum(result.probabilities.values()) == 100


class TestBannerAnalysis:
    def test_openssh_ubuntu(self):
        b = analyze_banner("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3")
        assert b.service_name == "OpenSSH"
        assert "linux" in b.os_hints

    def test_openssh_centos(self):
        b = analyze_banner("SSH-2.0-OpenSSH_7.4 CentOS")
        assert "linux" in b.os_hints

    def test_openssh_raspbian(self):
        b = analyze_banner("SSH-2.0-OpenSSH_9.2p1 Raspbian")
        assert "linux" in b.os_hints
        assert "bsd" not in b.os_hints

    def test_redis_banner(self):
        b = analyze_banner("+PONG")
        assert b.service_name == "Redis"
        assert "linux" in b.os_hints

    def test_mongodb_banner(self):
        b = analyze_banner("MongoDB 7.0.1")
        assert "linux" in b.os_hints

    def test_openwrt_banner(self):
        b = analyze_banner("OpenWrt LuCI")
        assert "linux" in b.os_hints

    def test_iis(self):
        b = analyze_banner("Microsoft-IIS/10.0")
        assert b.service_name == "IIS"
        assert "windows" in b.os_hints

    def test_freebsd_ssh(self):
        b = analyze_banner("SSH-2.0-OpenSSH_9.3 FreeBSD-20230719")
        assert "bsd" in b.os_hints

    def test_darwin_banner(self):
        b = analyze_banner("Darwin/22.6.0")
        assert "macos" in b.os_hints

    def test_empty(self):
        b = analyze_banner("")
        assert b.service_name == ""
        assert b.os_hints == []

    def test_unknown_banner(self):
        b = analyze_banner("SOME-CUSTOM-SERVICE/1.0")
        assert b.service_name == ""
