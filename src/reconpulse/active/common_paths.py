"""Level 1: probe well-known, harmless paths and record metadata only."""

from __future__ import annotations

import hashlib

from ..core.errors import ReconPulseError
from ..core.models import Confidence, Finding, Severity
from .base import ActiveContext, PlanItem, active_finding

COMMON_PATHS = (
    "robots.txt",
    "sitemap.xml",
    ".well-known/security.txt",
    "security.txt",
    "swagger.json",
    "swagger-ui.html",
    "openapi.json",
    "api-docs",
    "actuator/health",
    "actuator/info",
    "humans.txt",
)

_INTERESTING = {
    "swagger.json": "API documentation exposed",
    "swagger-ui.html": "API documentation UI exposed",
    "openapi.json": "API documentation exposed",
    "api-docs": "API documentation exposed",
    "actuator/health": "Actuator health endpoint exposed",
    "actuator/info": "Actuator info endpoint exposed",
}


class CommonPathsModule:
    name = "common_paths"
    level = 1
    description = (
        "GET a fixed list of well-known documentation and health paths; only status, size, "
        "and content hash are recorded."
    )

    def plan(self, ctx: ActiveContext) -> PlanItem:
        return PlanItem(
            technique=self.name,
            description=f"GET {len(COMMON_PATHS)} well-known paths under {ctx.origin}",
            requests=len(COMMON_PATHS),
            hosts=[ctx.host],
        )

    def run(self, ctx: ActiveContext) -> list[Finding]:
        findings: list[Finding] = []
        for path in COMMON_PATHS:
            url = ctx.url_for(path)
            try:
                response = ctx.client.get(url, module=self.name)
            except ReconPulseError:
                continue
            if response.status >= 400 or not response.content:
                continue
            digest = hashlib.sha256(response.content).hexdigest()[:16]
            metadata = {
                "status": str(response.status),
                "bytes": str(len(response.content)),
                "sha256_16": digest,
            }
            title = _INTERESTING.get(path)
            if title:
                findings.append(
                    active_finding(
                        title=title,
                        severity=Severity.LOW,
                        confidence=Confidence.HIGH,
                        explanation=(
                            f"GET {url} returned HTTP {response.status} and {len(response.content)} bytes. "
                            "Documentation and actuator endpoints often reveal internal paths, "
                            "build metadata, or dependency versions."
                        ),
                        remediation=(
                            "Serve documentation only to authenticated staff, and disable or "
                            "restrict management endpoints such as /actuator."
                        ),
                        verification=(
                            "Open the URL in a browser as an anonymous user and confirm what is "
                            "exposed; do not download large dumps."
                        ),
                        category="common_paths",
                        url=url,
                        source=self.name,
                        evidence=metadata,
                    )
                )
        return findings


MODULE = CommonPathsModule()
