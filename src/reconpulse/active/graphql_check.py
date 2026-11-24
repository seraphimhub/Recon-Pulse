"""Level 2: a single read-only GraphQL query over GET.

Only the introspection type name is requested (``{__typename}``). Introspection
of the full schema is *not* dumped, and no mutations or data queries are sent.
"""

from __future__ import annotations

import json
from urllib.parse import quote

from ..core.errors import ReconPulseError
from ..core.models import Confidence, Finding, Severity
from .base import ActiveContext, PlanItem, active_finding

CANDIDATE_PATHS = ("graphql", "api/graphql", "v1/graphql", "query")
QUERY = "{__typename}"


class GraphqlCheckModule:
    name = "graphql_check"
    level = 2
    description = "Send {__typename} over GET to common GraphQL paths and check for a data response."

    def plan(self, ctx: ActiveContext) -> PlanItem:
        return PlanItem(
            technique=self.name,
            description=f"GET {len(CANDIDATE_PATHS)} candidate paths with ?query={QUERY}",
            requests=len(CANDIDATE_PATHS),
            hosts=[ctx.host],
        )

    def run(self, ctx: ActiveContext) -> list[Finding]:
        findings: list[Finding] = []
        for path in CANDIDATE_PATHS:
            url = ctx.url_for(f"{path}?query={quote(QUERY)}")
            try:
                response = ctx.client.get(url, module=self.name, allow_redirects=False)
            except ReconPulseError:
                continue
            if response.status != 200:
                continue
            try:
                payload = json.loads(response.text)
            except (ValueError, TypeError):
                continue
            data = payload.get("data") if isinstance(payload, dict) else None
            if not isinstance(data, dict) or "__typename" not in data:
                continue
            findings.append(
                active_finding(
                    title=f"GraphQL endpoint responds at /{path}",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    explanation=(
                        f"GET {url} returned a JSON GraphQL response with __typename="
                        f"{data.get('__typename')!r}. The endpoint accepted a query without "
                        "authentication; whether it should is for the owner to confirm."
                    ),
                    remediation=(
                        "Require authentication where appropriate, disable production introspection "
                        "if not needed, and apply query depth and rate limits."
                    ),
                    verification=(
                        "Review the endpoint's authorization rules with the owner; do not send data "
                        "or mutation queries."
                    ),
                    category="graphql",
                    url=url,
                    source=self.name,
                    evidence={"typename": str(data.get("__typename"))},
                )
            )
        if not findings:
            ctx.notes.append("graphql_check: no GraphQL endpoint answered the test query")
        return findings


MODULE = GraphqlCheckModule()
