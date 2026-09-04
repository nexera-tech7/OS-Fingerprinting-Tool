import pytest
from src.fingerprint.confidence import calculate_confidence, ConfidenceLevel
from src.fingerprint.analyzer import AnalysisResult, Evidence
from src.config import OS_CATEGORIES


def _make_result(likely_os: str, top_prob: int, evidence: list[Evidence] | None = None) -> AnalysisResult:
    r = AnalysisResult()
    r.likely_os = likely_os
    r.probabilities = {k: 0 for k in OS_CATEGORIES}
    r.probabilities[likely_os] = top_prob
    remaining = 100 - top_prob
    others = [k for k in OS_CATEGORIES if k != likely_os]
    for o in others:
        r.probabilities[o] = remaining // len(others)
    diff = 100 - sum(r.probabilities.values())
    r.probabilities[others[0]] += diff
    r.evidence = evidence or []
    return r


class TestConfidence:
    def test_high_confidence(self):
        evidence = [
            Evidence("SSH detected", "linux", 20),
            Evidence("Banner match", "linux", 10),
            Evidence("TTL match", "linux", 15),
            Evidence("HTTP match", "linux", 18),
            Evidence("Port match", "linux", 12),
        ]
        result = _make_result("linux", 85, evidence)
        conf = calculate_confidence(result)
        assert conf in (ConfidenceLevel.HIGH, ConfidenceLevel.VERY_HIGH)

    def test_low_confidence_unknown(self):
        result = _make_result("unknown", 100)
        conf = calculate_confidence(result)
        assert conf == ConfidenceLevel.VERY_LOW

    def test_android_penalized(self):
        evidence = [Evidence("Some hint", "android", 10)]
        result = _make_result("android", 60, evidence)
        conf_android = calculate_confidence(result)

        evidence2 = [Evidence("Some hint", "linux", 10)]
        result2 = _make_result("linux", 60, evidence2)
        conf_linux = calculate_confidence(result2)

        assert conf_android.value <= conf_linux.value or conf_android == conf_linux

    def test_public_ip_reduces_confidence(self):
        evidence = [Evidence("Match", "linux", 15), Evidence("Match2", "linux", 15)]
        result = _make_result("linux", 70, evidence)
        conf_private = calculate_confidence(result, is_public=False)
        conf_public = calculate_confidence(result, is_public=True)
        assert conf_public.value <= conf_private.value or conf_public == conf_private

    def test_conflicting_evidence(self):
        evidence = [
            Evidence("SSH match", "linux", 20),
            Evidence("IIS match", "windows", 18),
            Evidence("BSD banner", "bsd", 10),
        ]
        result = _make_result("linux", 50, evidence)
        conf = calculate_confidence(result)
        assert conf in (ConfidenceLevel.VERY_LOW, ConfidenceLevel.LOW, ConfidenceLevel.MEDIUM)

    def test_json_output_format(self):
        from src.output.json import build_json_output
        from src.network.validation import validate_ip
        from src.scanner.ports import PortResult

        validation = validate_ip("203.0.113.10")
        ports = [PortResult(80, "open", "http")]
        result = _make_result("linux", 80)
        result.warnings = ["Test warning"]
        conf = ConfidenceLevel.HIGH

        data = build_json_output(validation, True, ports, result, conf)
        assert data["target"] == "203.0.113.10"
        assert data["os"]["name"] == "Linux"
        assert data["os"]["confidence"] == "high"
        assert isinstance(data["probabilities"], dict)
        assert isinstance(data["ports"], list)
        assert isinstance(data["warnings"], list)
