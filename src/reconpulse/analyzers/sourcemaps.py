"""Exposed source map detection (static: reads script comments only)."""

from __future__ import annotations

from ..collectors.js import ScriptAsset
from ..core.models import Confidence, EvidenceType, Finding, Severity


def analyze_source_maps(assets: list[ScriptAsset], url: str) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()

    for asset in assets:
        label = asset.url or "inline script"
        for map_reference in asset.source_maps:
            if map_reference in seen:
                continue
            seen.add(map_reference)
            findings.append(
                Finding(
                    title="Source map reference exposed",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    evidence_type=EvidenceType.STATIC_INDICATOR,
                    category="sourcemaps",
                    url=url,
                    source="sourcemaps",
                    explanation=(
                        f"{label} references a source map ({map_reference}). If the .map file is "
                        "published, it reconstructs original source code, comments, and sometimes "
                        "internal endpoint names."
                    ),
                    remediation=(
                        "Do not deploy .map files to production, or restrict them to authenticated "
                        "internal users. Strip sourceMappingURL comments from production builds."
                    ),
                    verification=(
                        "Request the .map URL once, as an anonymous user, inside the authorized "
                        "scope, and check only the status code."
                    ),
                    evidence={"script": label, "map": map_reference},
                )
            )
    return findings
