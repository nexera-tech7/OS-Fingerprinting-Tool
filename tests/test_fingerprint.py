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

    def test_iis(self):
        b = analyze_banner("Microsoft-IIS/10.0")
        assert b.service_name == "IIS"
        assert "windows" in b.os_hints

    def test_empty(self):
        b = analyze_banner("")
        assert b.service_name == ""
        assert b.os_hints == []

    def test_unknown_banner(self):
        b = analyze_banner("SOME-CUSTOM-SERVICE/1.0")
        assert b.service_name == ""
