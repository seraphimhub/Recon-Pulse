"""Data models shared by every ReconPulse layer.

The models are plain dataclasses so they can be produced by collectors,
consumed by analyzers, scored, and serialised by reporters without circular
imports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Impact if the finding is real."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    def __str__(self) -> str:  # pragma: no cover - convenience
        return self.value


class Confidence(str, Enum):
    """How strongly the evidence supports the finding."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    def __str__(self) -> str:  # pragma: no cover - convenience
        return self.value


class EvidenceType(str, Enum):
    """Where the evidence came from."""

    STATIC_INDICATOR = "static_indicator"
    OBSERVED_RESPONSE = "observed_response"
    ACTIVE_PROBE = "active_probe"

    def __str__(self) -> str:  # pragma: no cover - convenience
        return self.value


class ScanMode(str, Enum):
    """Scan mode. Passive is the only default."""

    PASSIVE = "passive"
    ACTIVE = "active"

    def __str__(self) -> str:  # pragma: no cover - convenience
        return self.value


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.astimezone(timezone.utc).isoformat()


@dataclass
class Finding:
    """A single observation.

    Static analysis findings are heuristics. Every finding carries an explicit
    confidence, evidence type, and remediation guidance so that nothing is ever
    presented as a confirmed vulnerability.
    """

    title: str
    severity: Severity
    confidence: Confidence
    evidence_type: EvidenceType
    explanation: str
    remediation: str = ""
    verification: str = ""
    category: str = "general"
    url: str | None = None
    parameter: str | None = None
    source: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "evidence_type": self.evidence_type.value,
            "category": self.category,
            "url": self.url,
            "parameter": self.parameter,
            "source": self.source,
            "explanation": self.explanation,
            "remediation": self.remediation,
            "verification": self.verification,
            "evidence": self.evidence,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        return cls(
            title=str(data.get("title", "Untitled")),
            severity=Severity(str(data.get("severity", "info"))),
            confidence=Confidence(str(data.get("confidence", "low"))),
            evidence_type=EvidenceType(str(data.get("evidence_type", "static_indicator"))),
            explanation=str(data.get("explanation", "")),
            remediation=str(data.get("remediation", "")),
            verification=str(data.get("verification", "")),
            category=str(data.get("category", "general")),
            url=data.get("url"),
            parameter=data.get("parameter"),
            source=data.get("source"),
            evidence=dict(data.get("evidence") or {}),
        )


@dataclass
class OutOfScopeDiscovery:
    """An asset discovered during recon that must not be contacted."""

    host: str
    discovered_by: str
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"host": self.host, "discovered_by": self.discovered_by, "detail": self.detail}


@dataclass
class AuthorizationSummary:
    """Non-sensitive snapshot of the authorization used for a scan."""

    engagement: str | None = None
    authorized_by: str | None = None
    valid_from: str | None = None
    valid_until: str | None = None
    scope_in: list[str] = field(default_factory=list)
    scope_out: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    contact_for_incident: str | None = None
    requests_budget: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "engagement": self.engagement,
            "authorized_by": self.authorized_by,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "scope_in": list(self.scope_in),
            "scope_out": list(self.scope_out),
            "techniques": list(self.techniques),
            "contact_for_incident": self.contact_for_incident,
            "requests_budget": self.requests_budget,
        }


@dataclass
class ScanMetadata:
    """Everything a reader needs to interpret a report."""

    tool_version: str
    mode: ScanMode
    target: str
    started_at: datetime
    finished_at: datetime | None = None
    scope: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    request_count: int = 0
    user_agent: str | None = None
    authorization: AuthorizationSummary | None = None
    config: dict[str, Any] = field(default_factory=dict)
    interrupted: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_version": self.tool_version,
            "mode": self.mode.value,
            "target": self.target,
            "started_at": _iso(self.started_at),
            "finished_at": _iso(self.finished_at),
            "duration_seconds": (
                round((self.finished_at - self.started_at).total_seconds(), 3) if self.finished_at else None
            ),
            "scope": list(self.scope),
            "techniques": list(self.techniques),
            "request_count": self.request_count,
            "user_agent": self.user_agent,
            "authorization": self.authorization.to_dict() if self.authorization else None,
            "config": self.config,
            "interrupted": self.interrupted,
        }


@dataclass
class ScanReport:
    """Result of scanning a single target."""

    metadata: ScanMetadata
    findings: list[Finding] = field(default_factory=list)
    risk: dict[str, Any] = field(default_factory=dict)
    out_of_scope: list[OutOfScopeDiscovery] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    passive_findings: int = 0
    active_findings: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "metadata": self.metadata.to_dict(),
            "risk": self.risk,
            "summary": {
                "total_findings": len(self.findings),
                "passive_findings": self.passive_findings,
                "active_findings": self.active_findings,
                "out_of_scope_discoveries": len(self.out_of_scope),
                "errors": len(self.errors),
            },
            "findings": [f.to_dict() for f in self.findings],
            "out_of_scope": [d.to_dict() for d in self.out_of_scope],
            "errors": list(self.errors),
            "notes": list(self.notes),
        }
