"""Shared contract for active modules.

Every module:

* declares a name, impact level, and one-line description
* implements :meth:`plan` so ``--dry-run`` can describe work without sending it
* implements :meth:`run` and returns :class:`~reconpulse.core.models.Finding`
  objects with ``evidence_type=ACTIVE_PROBE``
* goes through the shared :class:`~reconpulse.core.http_client.HTTPClient`
* never sends exploit payloads or state-changing requests
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol
from urllib.parse import urlparse

from ..analyzers.endpoints import Endpoint
from ..analyzers.params import ParamCandidate
from ..core.authorization import Authorization
from ..core.http_client import HTTPClient
from ..core.models import Confidence, EvidenceType, Finding, OutOfScopeDiscovery, Severity


@dataclass
class ActiveContext:
    client: HTTPClient
    base_url: str
    authorization: Authorization
    canary_domain: str | None = None
    out_of_scope: list[OutOfScopeDiscovery] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    parameters: list[ParamCandidate] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)

    @property
    def host(self) -> str:
        return (urlparse(self.base_url).hostname or "").lower()

    @property
    def origin(self) -> str:
        parsed = urlparse(self.base_url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def url_for(self, path: str) -> str:
        return self.origin + "/" + path.lstrip("/")


@dataclass
class PlanItem:
    technique: str
    description: str
    requests: int
    hosts: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "technique": self.technique,
            "description": self.description,
            "requests": self.requests,
            "hosts": self.hosts,
        }


class ActiveModule(Protocol):
    name: str
    level: int
    description: str

    def plan(self, ctx: ActiveContext) -> PlanItem: ...

    def run(self, ctx: ActiveContext) -> list[Finding]: ...


def active_finding(
    *,
    title: str,
    severity: Severity,
    confidence: Confidence,
    explanation: str,
    remediation: str,
    verification: str,
    category: str,
    url: str | None,
    source: str,
    evidence: dict[str, str] | None = None,
    parameter: str | None = None,
) -> Finding:
    """Build a finding that is always marked as active-probe evidence."""

    return Finding(
        title=title,
        severity=severity,
        confidence=confidence,
        evidence_type=EvidenceType.ACTIVE_PROBE,
        category=category,
        url=url,
        parameter=parameter,
        source=source,
        explanation=explanation,
        remediation=remediation,
        verification=verification,
        evidence=evidence or {},
    )
