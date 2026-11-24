"""Level 1: CORS probe with a single GET carrying a test Origin header.

The Origin value is the configured canary domain (or a reserved example value).
No credentials are sent and no CORS bypass is attempted.
"""

from __future__ import annotations

from ..core.errors import ReconPulseError
from ..core.models import Confidence, Finding, Severity
from .base import ActiveContext, PlanItem, active_finding

DEFAULT_TEST_ORIGIN = "https://reconpulse-canary.example"


class CorsProbeModule:
    name = "cors_probe"
    level = 1
    description = "Send one GET with a test Origin header and read Access-Control-Allow-* headers."

    def test_origin(self, ctx: ActiveContext) -> str:
        if ctx.canary_domain:
            domain = ctx.canary_domain
            for prefix in ("https://", "http://"):
                if domain.startswith(prefix):
                    domain = domain[len(prefix) :]
            return f"https://{domain.split('/')[0]}"
        return DEFAULT_TEST_ORIGIN

    def plan(self, ctx: ActiveContext) -> PlanItem:
        return PlanItem(
            technique=self.name,
            description=f"GET {ctx.base_url} with Origin: {self.test_origin(ctx)}",
            requests=1,
            hosts=[ctx.host],
        )

    def run(self, ctx: ActiveContext) -> list[Finding]:
        origin = self.test_origin(ctx)
        try:
            response = ctx.client.get(
                ctx.base_url,
                module=self.name,
                headers={"Origin": origin},
                allow_redirects=False,
            )
        except ReconPulseError as exc:
            ctx.notes.append(f"cors_probe: {exc}")
            return []

        allow_origin = response.headers.get("Access-Control-Allow-Origin", "")
        allow_credentials = response.headers.get("Access-Control-Allow-Credentials", "")
        vary = response.headers.get("Vary", "")
        evidence = {
            "status": str(response.status),
            "acao": allow_origin or "(absent)",
            "acac": allow_credentials or "(absent)",
            "vary": vary or "(absent)",
        }

        if not allow_origin:
            return [
                active_finding(
                    title="No CORS headers for a cross-origin request",
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    explanation=(
                        f"GET {ctx.base_url} with Origin {origin} returned no "
                        "Access-Control-Allow-Origin header, so cross-origin reads are blocked by "
                        "the browser."
                    ),
                    remediation="No action needed if cross-origin access is not a requirement.",
                    verification="Re-check after any CORS configuration change.",
                    category="cors",
                    url=ctx.base_url,
                    source=self.name,
                    evidence=evidence,
                )
            ]

        if allow_origin.strip() == "*":
            severity = Severity.MEDIUM if allow_credentials.lower() == "true" else Severity.INFO
            return [
                active_finding(
                    title="CORS allows any origin",
                    severity=severity,
                    confidence=Confidence.HIGH,
                    explanation=(
                        f"The endpoint answered Origin {origin} with Access-Control-Allow-Origin: *"
                        + (
                            " and Access-Control-Allow-Credentials: true."
                            if allow_credentials.lower() == "true"
                            else "."
                        )
                    ),
                    remediation="Return an explicit allowlist of origins instead of *.",
                    verification="Re-send the same single GET after the fix and confirm ACAO names a specific host.",
                    category="cors",
                    url=ctx.base_url,
                    source=self.name,
                    evidence=evidence,
                )
            ]

        if allow_origin.strip() == origin:
            severity = Severity.MEDIUM if allow_credentials.lower() == "true" else Severity.LOW
            findings = [
                active_finding(
                    title="CORS reflects an arbitrary Origin",
                    severity=severity,
                    confidence=Confidence.HIGH,
                    explanation=(
                        f"Access-Control-Allow-Origin echoed the test origin {origin}"
                        + (
                            " while allowing credentials, so any site could read authenticated responses."
                            if allow_credentials.lower() == "true"
                            else "; with credentials disabled a malicious site can read public responses only."
                        )
                    ),
                    remediation=(
                        "Validate Origin against an allowlist and never echo it back blindly. Add "
                        "Vary: Origin so caches stay correct."
                    ),
                    verification="Send one GET with a different test origin and confirm it is not reflected.",
                    category="cors",
                    url=ctx.base_url,
                    source=self.name,
                    evidence=evidence,
                )
            ]
            if "origin" not in vary.lower():
                findings.append(
                    active_finding(
                        title="CORS response is missing Vary: Origin",
                        severity=Severity.LOW,
                        confidence=Confidence.MEDIUM,
                        explanation=(
                            "The response varies by Origin but does not say so, so shared caches may "
                            "serve one origin's CORS headers to another."
                        ),
                        remediation="Add Vary: Origin to responses that echo the Origin header.",
                        verification="Check the Vary header on the same response.",
                        category="cors",
                        url=ctx.base_url,
                        source=self.name,
                        evidence=evidence,
                    )
                )
            return findings

        return [
            active_finding(
                title="CORS allows a specific third-party origin",
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                explanation=(
                    f"Access-Control-Allow-Origin is {allow_origin}, which is not the test origin. "
                    "Confirm that this origin is intended and trusted."
                ),
                remediation="Keep the allowlist minimal and reviewed.",
                verification="Validate the listed origin against the application's documented integrations.",
                category="cors",
                url=ctx.base_url,
                source=self.name,
                evidence=evidence,
            )
        ]


MODULE = CorsProbeModule()
