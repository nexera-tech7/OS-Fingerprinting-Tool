import ipaddress
from dataclasses import dataclass
from enum import Enum


class AddressType(Enum):
    PUBLIC = "Public"
    PRIVATE = "Private"
    LOOPBACK = "Loopback"
    RESERVED = "Reserved"
    MULTICAST = "Multicast"
    LINK_LOCAL = "Link-Local"
    INVALID = "Invalid"


@dataclass
class ValidationResult:
    valid: bool
    address_type: AddressType
    ip_version: int | None = None
    normalized: str = ""
    message: str = ""


def validate_ip(raw: str) -> ValidationResult:
    raw = raw.strip()
    if not raw:
        return ValidationResult(False, AddressType.INVALID, message="Empty address")

    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return ValidationResult(False, AddressType.INVALID, message=f"Malformed IP address: {raw}")

    version = addr.version
    normalized = str(addr)

    if addr.is_loopback:
        return ValidationResult(True, AddressType.LOOPBACK, version, normalized, "Loopback address")

    if addr.is_multicast:
        return ValidationResult(True, AddressType.MULTICAST, version, normalized, "Multicast address")

    if addr.is_reserved:
        return ValidationResult(True, AddressType.RESERVED, version, normalized, "Reserved address")

    if addr.is_link_local:
        return ValidationResult(True, AddressType.LINK_LOCAL, version, normalized, "Link-local address")

    if addr.is_private:
        return ValidationResult(True, AddressType.PRIVATE, version, normalized, "Private address")

    if addr.is_global:
        return ValidationResult(True, AddressType.PUBLIC, version, normalized, "Public address")

    return ValidationResult(True, AddressType.RESERVED, version, normalized, "Address classification unclear")


def is_scannable(result: ValidationResult) -> bool:
    return result.valid and result.address_type not in (
        AddressType.INVALID,
        AddressType.MULTICAST,
        AddressType.RESERVED,
    )