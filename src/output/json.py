import json as json_lib
from typing import Any

from ..network.validation import ValidationResult
from ..scanner.ports import PortResult
from ..fingerprint.analyzer import AnalysisResult
from ..fingerprint.confidence import ConfidenceLevel


def build_json_output(
    validation: ValidationResult,
    reachable: bool,
    port_results: list[PortResult],
    analysis: AnalysisResult,
    confidence: ConfidenceLevel,
    elapsed: float | None = None,
    rdns: str | None = None,
    hops: int | None = None,
) -> dict[str, Any]:
    data: dict[str, Any] = {
        "target": validation.normalized,
        "ip_version": validation.ip_version,
        "address_type": validation.address_type.value.lower(),
        "rdns": rdns,
        "reachable": reachable,
        "hops": hops,
        "os": {
            "name": _format_os_name(analysis.likely_os),
            "confidence": confidence.value.lower(),
            "probability": analysis.probabilities.get(analysis.likely_os, 0),
        },
        "probabilities": {k: v for k, v in sorted(analysis.probabilities.items(), key=lambda x: x[1], reverse=True)},
        "ports": [
            {"port": p.port, "state": p.state, "service": p.service, "banner": p.banner}
            for p in port_results
        ],
        "open_ports":  [p.port for p in port_results if p.state == "open"],
        "services":    [p.service for p in port_results if p.state == "open"],
        "evidence":    [e.description for e in analysis.evidence if e.weight > 0],
        "warnings":    analysis.warnings,
    }
    if elapsed is not None:
        data["scan_time_seconds"] = round(elapsed, 3)
    return data


def render_json(data: dict[str, Any]) -> str:
    return json_lib.dumps(data, indent=2, ensure_ascii=False)


def _format_os_name(key: str) -> str:
    names = {"linux": "Linux", "windows": "Windows", "android": "Android", "ios": "iOS", "macos": "macOS", "bsd": "BSD", "unknown": "Unknown"}
    return names.get(key, key.capitalize())
