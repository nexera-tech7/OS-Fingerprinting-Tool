import pytest
from src.scanner.tcp import TCPFingerprint, normalize_ttl, estimate_hops


class TestNormalizeTTL:
    def test_none(self):
        assert normalize_ttl(None) is None

    def test_linux_ttl(self):
        assert normalize_ttl(64) == 64
        assert normalize_ttl(55) == 64

    def test_windows_ttl(self):
        assert normalize_ttl(128) == 128
        assert normalize_ttl(120) == 128

    def test_solaris_ttl(self):
        assert normalize_ttl(255) == 255
        assert normalize_ttl(240) == 255

    def test_low_ttl(self):
        assert normalize_ttl(30) == 32
        assert normalize_ttl(1) == 32


class TestEstimateHops:
    def test_none(self):
        assert estimate_hops(None) is None

    def test_zero_hops(self):
        assert estimate_hops(64) == 0

    def test_some_hops(self):
        assert estimate_hops(55) == 9

    def test_windows_hops(self):
        assert estimate_hops(120) == 8


class TestTCPFingerprint:
    def test_default(self):
        fp = TCPFingerprint()
        assert fp.ttl is None
        assert fp.window is None
        assert fp.options == []
        assert fp.mss is None
        assert fp.characteristics == {}
