"""Level 1: read the Allow header from a single OPTIONS request.

No PUT/PATCH/DELETE/POST request is ever sent to test methods.
"""

from __future__ import annotations

from ..core.errors import ReconPulseError
from ..core.models import Confidence, Finding, Severity
from .base import ActiveContext, PlanItem, active_finding

INTERESTING = {"PUT", "DELETE", "PATCH", "TRACE", "CONNECT"}


class HttpMethodsModule:
    name = "http_methods"
    level = 1
    description = "Send one OPTIONS request and read the Allow header; never tests a method."

    def plan(self, ctx: ActiveContext) -> PlanItem:
        return PlanItem(
            technique=self.name,
            description=f"OPTIONS {ctx.origin}/ and read Allow",
            requests=1,
            hosts=[ctx.host],
        )

    def run(self, ctx: ActiveContext) -> list[Finding]:
        try:
            response = ctx.client.options(ctx.base_url, module=self.name)
        except ReconPulseError as exc:
            ctx.notes.append(f"http_methods: {exc}")
            return []

        allow = response.headers.get("Allow", "")
        if not allow:
            ctx.notes.append("http_methods: no Allow header returned")
            return []

        advertised = sorted({method.strip().upper() for method in allow.split(",") if method.strip()})
        interesting = [method for method in advertised if method in INTERESTING]
        if not interesting:
            return [
                active_finding(
                    title="Advertised HTTP methods",
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    explanation=f"OPTIONS reports Allow: {', '.join(advertised)}.",
                    remediation="Advertise only the methods the route actually supports.",
                    verification="Compare the Allow header with the documented API contract.",
                    category="http_methods",
                    url=ctx.base_url,
                    source=self.name,
                    evidence={"allow": allow},
                )
            ]

        return [
            active_finding(
                title=f"Server advertises {', '.join(interesting)}",
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                explanation=(
                    f"OPTIONS reports Allow: {', '.join(advertised)}. Advertising write methods is "
                    "informational: they may still require authentication, and this tool did not "
                    "send them."
                ),
                remediation="Restrict methods at the edge and remove unused verbs from the header.",
                verification=(
                    "Review the route definition and its authorization checks; do not send write requests to verify."
                ),
                category="http_methods",
                url=ctx.base_url,
                source=self.name,
                evidence={"allow": allow},
            )
        ]


MODULE = HttpMethodsModule()
