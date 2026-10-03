import pytest

from src.fingerprint.analyzer import Analyzer
from src.fingerprint.confidence import calculate_confidence, ConfidenceLevel
from src.fingerprint.signatures import load_signatures
from src.scanner.banners import analyze_banner
from src.scanner.http import HTTPFingerprint
from src.scanner.ports import PortResult
from src.scanner.tcp import TCPFingerprint


@pytest.fixture(scope="module")
def analyzer():
    return Analyzer(load_signatures())


def open_port(port, service=""):
    return PortResult(port=port, state="open", service=service)


class TestBanners:
    def test_openssh_for_windows_is_windows(self):
        b = analyze_banner("SSH-2.0-OpenSSH_for_Windows_8.1", 22)
        assert b.os_hints == ["windows"]
        assert b.strength == "strong"

    def test_generic_openssh_is_weak(self):
        b = analyze_banner("SSH-2.0-OpenSSH_9.6", 22)
        assert b.strength == "weak"

    def test_distro_tagged_openssh_is_strong(self):
        b = analyze_banner("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1", 22)
        assert b.os_hints == ["linux"]
        assert b.strength == "strong"


class TestScoring:
    def test_ttl_scored_once(self, analyzer):
        one = analyzer.analyze([TCPFingerprint(ttl=128)], [], [], [], [])
        three = analyzer.analyze([TCPFingerprint(ttl=128)] * 3, [], [], [], [])
        assert one.scores["windows"] == three.scores["windows"]

    def test_shared_ttl_is_weaker_than_unique_ttl(self, analyzer):
        win = analyzer.analyze([TCPFingerprint(ttl=128)], [], [], [], []).scores["windows"]
        lin = analyzer.analyze([TCPFingerprint(ttl=64)], [], [], [], []).scores["linux"]
        assert win > lin

    def test_generic_openssh_does_not_inflate_bsd_or_macos(self, analyzer):
        banner = analyze_banner("SSH-2.0-OpenSSH_9.6", 22)
        r = analyzer.analyze([], [open_port(22, "ssh")], [banner], [], [])
        assert r.scores["linux"] > r.scores["bsd"]
        assert r.scores["linux"] > r.scores["macos"]

    def test_windows_ports_not_double_counted(self, analyzer):
        r = analyzer.analyze([], [open_port(445, "smb")], [], [], [])
        # one indicator-port hit (12) + service keyword (8); no extra heuristic hit
        assert r.scores["windows"] == pytest.approx(12.0 + 8.0 + 10.0)  # + inferred-TTL bonus

    def test_apache_win64_server_is_windows(self, analyzer):
        http = HTTPFingerprint(status_code=200, server="Apache/2.4.58 (Win64) PHP/8.2")
        r = analyzer.analyze([], [open_port(80, "http")], [], [http], [])
        assert r.scores["windows"] > r.scores["linux"]

    def test_apache_ubuntu_server_is_linux(self, analyzer):
        http = HTTPFingerprint(status_code=200, server="Apache/2.4.52 (Ubuntu)")
        r = analyzer.analyze([], [open_port(80, "http")], [], [http], [])
        assert r.likely_os == "linux"

    def test_same_http_headers_on_80_and_443_counted_once(self, analyzer):
        http = HTTPFingerprint(status_code=200, server="nginx/1.24")
        once = analyzer.analyze([], [], [], [http], []).scores["linux"]
        twice = analyzer.analyze([], [], [], [http, http], []).scores["linux"]
        assert once == twice

    def test_redis_on_windows_host_not_called_linux(self, analyzer):
        ports = [open_port(6379, "redis"), open_port(445, "smb"), open_port(3389, "rdp")]
        r = analyzer.analyze([TCPFingerprint(ttl=128)], ports, [], [], [])
        assert r.likely_os == "windows"


class TestEndToEnd:
    def test_windows_host(self, analyzer):
        ports = [open_port(135, "msrpc"), open_port(445, "smb"), open_port(3389, "rdp")]
        r = analyzer.analyze([TCPFingerprint(ttl=127)], ports, [], [], [])
        assert r.likely_os == "windows"
        assert r.probabilities["windows"] >= 90
        assert calculate_confidence(r) in (ConfidenceLevel.HIGH, ConfidenceLevel.VERY_HIGH)

    def test_linux_server(self, analyzer):
        ports = [open_port(22, "ssh"), open_port(3306, "mysql"), open_port(80, "http")]
        banner = analyze_banner("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1", 22)
        r = analyzer.analyze([TCPFingerprint(ttl=58)], ports, [banner], [], [])
        assert r.likely_os == "linux"
        assert calculate_confidence(r) in (ConfidenceLevel.HIGH, ConfidenceLevel.VERY_HIGH)

    def test_bsd_by_ttl_255(self, analyzer):
        r = analyzer.analyze([TCPFingerprint(ttl=250)], [open_port(443, "https")], [], [], [])
        assert r.likely_os == "bsd"

    def test_ios_by_sync_port(self, analyzer):
        r = analyzer.analyze([TCPFingerprint(ttl=60)], [open_port(62078, "iphone-sync")], [], [], [])
        assert r.likely_os == "ios"

    def test_no_evidence_is_unknown(self, analyzer):
        r = analyzer.analyze([], [], [], [], [])
        assert r.likely_os == "unknown"
        assert calculate_confidence(r) == ConfidenceLevel.VERY_LOW
