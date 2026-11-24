"""Passive CORS configuration review (response headers only)."""

from __future__ import annotations

from ..core.models import Confidence, EvidenceType, Finding, Severity


def analyze_cors(headers: dict[str, str], url: str) -> list[Finding]:
    """Review CORS headers already present in a normal response.

    A genuine origin-reflection test needs a request with a chosen Origin header,
    which belongs to active mode (``cors_probe``). This analyzer only reads what
    the site returned.
    """

    allow_origin = headers.get("access-control-allow-origin", "")
    allow_credentials = headers.get("access-control-allow-credentials", "")
    findings: list[Finding] = []

    if allow_origin == "*" and allow_credentials.lower() == "true":
        findings.append(
            Finding(
                title="CORS allows any origin with credentials",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                evidence_type=EvidenceType.OBSERVED_RESPONSE,
                category="cors",
                url=url,
                source="cors",
                explanation=(
                    "The response sets Access-Control-Allow-Origin: * together with "
                    "Access-Control-Allow-Credentials: true. Browsers reject that combination, but "
                    "its presence suggests a misconfigured CORS policy that may reflect arbitrary "
                    "origins when a specific Origin is sent."
                ),
                remediation=(
                    "Return an explicit allowlist of origins and never reflect the Origin header without validation."
                ),
                verification=(
                    "Use the active cors_probe technique (with authorization) to send a single GET "
                    "with a canary Origin and read the ACAO header."
                ),
                evidence={"acao": allow_origin, "acac": allow_credentials},
            )
        )
    elif allow_origin == "*":
        findings.append(
            Finding(
                title="CORS open to any origin (no credentials)",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                evidence_type=EvidenceType.OBSERVED_RESPONSE,
                category="cors",
                url=url,
                source="cors",
                explanation=(
                    "Access-Control-Allow-Origin is '*'. Any site can read these responses when the "
                    "request carries no credentials; this is only a risk if the endpoint returns "
                    "private data."
                ),
                remediation="Restrict ACAO to known origins for endpoints that return private data.",
                verification="Confirm what the endpoint returns and whether it requires authentication.",
                evidence={"acao": allow_origin},
            )
        )

    if allow_origin == "null":
        findings.append(
            Finding(
                title="CORS trusts the null origin",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                evidence_type=EvidenceType.OBSERVED_RESPONSE,
                category="cors",
                url=url,
                source="cors",
                explanation=(
                    "Access-Control-Allow-Origin: null can be reached from sandboxed iframes and "
                    "data: documents, which an attacker can host."
                ),
                remediation="Never allow the null origin; use an explicit allowlist.",
                verification="Re-check with an authorized cors_probe request using a canary origin.",
                evidence={"acao": allow_origin},
            )
        )

    return findings
