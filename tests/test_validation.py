import pytest
from src.network.validation import validate_ip, is_scannable, AddressType


class TestIPv4Validation:
    def test_public_ipv4(self):
        r = validate_ip("8.8.8.8")
        assert r.valid
        assert r.address_type == AddressType.PUBLIC
        assert r.ip_version == 4

    def test_private_ipv4_class_a(self):
        r = validate_ip("10.0.0.1")
        assert r.valid
        assert r.address_type == AddressType.PRIVATE

    def test_private_ipv4_class_b(self):
        r = validate_ip("172.16.0.1")
        assert r.valid
        assert r.address_type == AddressType.PRIVATE

    def test_private_ipv4_class_c(self):
        r = validate_ip("192.168.1.1")
        assert r.valid
        assert r.address_type == AddressType.PRIVATE

    def test_loopback(self):
        r = validate_ip("127.0.0.1")
        assert r.valid
        assert r.address_type == AddressType.LOOPBACK

    def test_multicast(self):
        r = validate_ip("224.0.0.1")
        assert r.valid
        assert r.address_type == AddressType.MULTICAST

    def test_link_local(self):
        r = validate_ip("169.254.1.1")
        assert r.valid
        assert r.address_type == AddressType.LINK_LOCAL

    def test_broadcast_reserved(self):
        r = validate_ip("255.255.255.255")
        assert r.valid
        assert r.address_type == AddressType.RESERVED


class TestIPv6Validation:
    def test_loopback_v6(self):
        r = validate_ip("::1")
        assert r.valid
        assert r.address_type == AddressType.LOOPBACK
        assert r.ip_version == 6

    def test_public_v6(self):
        r = validate_ip("2001:4860:4860::8888")
        assert r.valid
        assert r.address_type == AddressType.PUBLIC
        assert r.ip_version == 6

    def test_link_local_v6(self):
        r = validate_ip("fe80::1")
        assert r.valid
        assert r.address_type == AddressType.LINK_LOCAL

    def test_multicast_v6(self):
        r = validate_ip("ff02::1")
        assert r.valid
        assert r.address_type == AddressType.MULTICAST


class TestInvalidAddresses:
    def test_empty(self):
        r = validate_ip("")
        assert not r.valid
        assert r.address_type == AddressType.INVALID

    def test_garbage(self):
        r = validate_ip("not_an_ip")
        assert not r.valid

    def test_too_many_octets(self):
        r = validate_ip("1.2.3.4.5")
        assert not r.valid

    def test_octet_overflow(self):
        r = validate_ip("256.1.1.1")
        assert not r.valid

    def test_negative(self):
        r = validate_ip("-1.0.0.0")
        assert not r.valid

    def test_whitespace_stripped(self):
        r = validate_ip("  8.8.8.8  ")
        assert r.valid
        assert r.normalized == "8.8.8.8"


class TestScannable:
    def test_public_scannable(self):
        r = validate_ip("8.8.8.8")
        assert is_scannable(r)

    def test_private_scannable(self):
        r = validate_ip("192.168.1.1")
        assert is_scannable(r)

    def test_loopback_scannable(self):
        r = validate_ip("127.0.0.1")
        assert is_scannable(r)

    def test_multicast_not_scannable(self):
        r = validate_ip("224.0.0.1")
        assert not is_scannable(r)

    def test_invalid_not_scannable(self):
        r = validate_ip("garbage")
        assert not is_scannable(r)
