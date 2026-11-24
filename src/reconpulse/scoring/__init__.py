"""Risk engine.

The score is transparent and reproducible -- there are no undocumented magic
numbers:

``points(finding) = severity_weight x evidence_weight x confidence_weight``

Weights
-------
severity   info 0.0, low 2.0, medium 5.0, high 9.0
evidence   static_indicator 1.0, observed_response 1.5, active_probe 2.0
confidence low 0.6, medium 1.0, high 1.4

So a vague static indicator (high severity, low confidence) counts 9 x 1.0 x 0.6
= 5.4, while the same issue confirmed by an active probe counts 9 x 2.0 x 1.4 =
25.2. The summed points are rounded and capped at 100.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..core.models import Confidence, EvidenceType, Finding, Severity

SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.INFO: 0.0,
    Severity.LOW: 2.0,
    Severity.MEDIUM: 5.0,
    Severity.HIGH: 9.0,
}

EVIDENCE_WEIGHTS: dict[EvidenceType, float] = {
    EvidenceType.STATIC_INDICATOR: 1.0,
    EvidenceType.OBSERVED_RESPONSE: 1.5,
    EvidenceType.ACTIVE_PROBE: 2.0,
}

CONFIDENCE_WEIGHTS: dict[Confidence, float] = {
    Confidence.LOW: 0.6,
    Confidence.MEDIUM: 1.0,
    Confidence.HIGH: 1.4,
}

MAX_SCORE = 100

LEVEL_THRESHOLDS = ((70, "high"), (40, "medium"), (15, "low"))

_LEVEL_ORDER = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2, Severity.INFO: 3}


def finding_points(finding: Finding) -> float:
    """Weighted points contributed by a single finding."""

    return (
        SEVERITY_WEIGHTS[finding.severity]
        * EVIDENCE_WEIGHTS[finding.evidence_type]
        * CONFIDENCE_WEIGHTS[finding.confidence]
    )


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Most severe first, then most confident, then by title."""

    return sorted(
        findings,
        key=lambda f: (
            _LEVEL_ORDER[f.severity],
            -CONFIDENCE_WEIGHTS[f.confidence],
            f.title.lower(),
        ),
    )


@dataclass
class RiskAssessment:
    raw_points: float
    score: int
    level: str
    counts: dict[str, int] = field(default_factory=dict)
    breakdown: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "level": self.level,
            "raw_points": round(self.raw_points, 2),
            "counts": dict(self.counts),
            "formula": (
                "points = severity_weight * evidence_weight * confidence_weight; score = min(100, round(sum(points)))"
            ),
            "weights": {
                "severity": {k.value: v for k, v in SEVERITY_WEIGHTS.items()},
                "evidence": {k.value: v for k, v in EVIDENCE_WEIGHTS.items()},
                "confidence": {k.value: v for k, v in CONFIDENCE_WEIGHTS.items()},
            },
            "breakdown": self.breakdown,
        }


def compute_risk(findings: list[Finding]) -> RiskAssessment:
    """Score a set of findings and explain every point awarded."""

    raw = 0.0
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    breakdown: list[dict[str, Any]] = []

    for finding in findings:
        points = finding_points(finding)
        raw += points
        counts[finding.severity.value] += 1
        breakdown.append(
            {
                "title": finding.title,
                "severity": finding.severity.value,
                "confidence": finding.confidence.value,
                "evidence_type": finding.evidence_type.value,
                "points": round(points, 2),
            }
        )
    breakdown.sort(key=lambda item: item["points"], reverse=True)

    score = min(MAX_SCORE, round(raw))
    level = "info"
    for threshold, name in LEVEL_THRESHOLDS:
        if score >= threshold:
            level = name
            break

    return RiskAssessment(raw_points=raw, score=int(score), level=level, counts=counts, breakdown=breakdown)


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        counts[finding.severity.value] += 1
    return counts


__all__ = [
    "CONFIDENCE_WEIGHTS",
    "EVIDENCE_WEIGHTS",
    "LEVEL_THRESHOLDS",
    "MAX_SCORE",
    "SEVERITY_WEIGHTS",
    "RiskAssessment",
    "compute_risk",
    "finding_points",
    "severity_counts",
    "sort_findings",
]
