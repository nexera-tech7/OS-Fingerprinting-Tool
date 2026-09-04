from enum import Enum
from .analyzer import AnalysisResult


class ConfidenceLevel(Enum):
    VERY_LOW = "Very Low"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    VERY_HIGH = "Very High"


def calculate_confidence(result: AnalysisResult, is_public: bool = False) -> ConfidenceLevel:
    if result.likely_os == "unknown":
        return ConfidenceLevel.VERY_LOW

    top_prob = result.probabilities.get(result.likely_os, 0)
    evidence_count = len([e for e in result.evidence if e.weight > 0])
    unique_sources = len({e.description.split()[0] for e in result.evidence if e.weight > 0})
    has_conflicts = _has_conflicting_evidence(result)

    score = 0.0

    if top_prob >= 80:
        score += 3.0
    elif top_prob >= 60:
        score += 2.0
    elif top_prob >= 40:
        score += 1.0

    if evidence_count >= 5:
        score += 2.0
    elif evidence_count >= 3:
        score += 1.5
    elif evidence_count >= 1:
        score += 0.5

    if unique_sources >= 3:
        score += 1.5
    elif unique_sources >= 2:
        score += 1.0
    elif unique_sources >= 1:
        score += 0.5

    if has_conflicts:
        score -= 1.5

    if is_public:
        score -= 1.0

    ambiguous_os = result.likely_os in ("android", "ios")
    if ambiguous_os:
        score -= 1.0

    if score >= 5.5:
        return ConfidenceLevel.VERY_HIGH
    if score >= 4.0:
        return ConfidenceLevel.HIGH
    if score >= 2.5:
        return ConfidenceLevel.MEDIUM
    if score >= 1.0:
        return ConfidenceLevel.LOW
    return ConfidenceLevel.VERY_LOW


def _has_conflicting_evidence(result: AnalysisResult) -> bool:
    os_keys_with_evidence = {e.os_key for e in result.evidence if e.weight > 5 and e.os_key}
    return len(os_keys_with_evidence) >= 3
