"""Level 3: open-redirect indicator using the engagement's canary domain.

The parameter is pointed at the canary domain configured in authorization.yaml.
Redirects are never followed: only the ``Location`` header is read, so the tool
cannot be turned into an open proxy.
"""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..core.errors import ReconPulseError
from ..core.models import Confidence, Finding, Severity
from .base import ActiveContext, PlanItem, active_finding

REDIRECT_PARAMS = {
    "redirect",
    "redirect_uri",
    "redirect_url",
    "redirecturl",
    "url",
    "uri",
    "next",
    "return",
    "return_to",
    "returnto",
    "dest",
    "destination",
    "target",
    "continue",
    "goto",
    "out",
    "back",
    "backurl",
    "callback",
    "callback_url",
    "link",
    "ref",
}
MAX_PROBES = 6


class RedirectCheckModule:
    name = "redirect_check"
    level = 3
    description = (
        f"Send up to {MAX_PROBES} GETs with a redirect parameter set to the canary domain and read "
        "the Location header without following it."
    )

    def _targets(self, ctx: ActiveContext) -> list[tuple[str, str]]:
        targets: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for candidate in ctx.parameters:
            if candidate.name.lower() not in REDIRECT_PARAMS:
                continue
            url = candidate.context_url or ctx.base_url
            key = (url, candidate.name)
            if key in seen:
                continue
            seen.add(key)
            targets.append((url, candidate.name))
            if len(targets) >= MAX_PROBES:
                break
        return targets

    def plan(self, ctx: ActiveContext) -> PlanItem:
        canary = ctx.canary_domain or "(canary_domain not configured; module will refuse to run)"
        return PlanItem(
            technique=self.name,
            description=f"Redirect-parameter checks pointing at {canary}",
            requests=len(self._targets(ctx)),
            hosts=[ctx.host],
        )

    @staticmethod
    def _with_value(url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        pairs = [
            (name, value if name == param else existing)
            for name, existing in parse_qsl(parsed.query, keep_blank_values=True)
        ]
        if not any(name == param for name, _ in pairs):
            pairs.append((param, value))
        return urlunparse(parsed._replace(query=urlencode(pairs)))

    def run(self, ctx: ActiveContext) -> list[Finding]:
        if not ctx.canary_domain:
            ctx.notes.append("redirect_check: skipped because canary_domain is not set in authorization.yaml")
            return []

        canary_host = ctx.canary_domain.lower()
        for prefix in ("https://", "http://"):
            if canary_host.startswith(prefix):
                canary_host = canary_host[len(prefix) :]
        canary_host = canary_host.split("/")[0]
        value = f"https://{canary_host}/"
        findings: list[Finding] = []

        for url, param in self._targets(ctx):
            request_url = self._with_value(url, param, value)
            try:
                response = ctx.client.get(request_url, module=self.name, allow_redirects=False)
            except ReconPulseError:
                continue
            location = response.headers.get("Location", "")
            if not location:
                continue
            location_host = (urlparse(location).hostname or "").lower()
            if location_host != canary_host:
                continue
            findings.append(
                active_finding(
                    title=f"Open redirect indicator: '{param}'",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    explanation=(
                        f"GET {request_url} answered HTTP {response.status} with Location: {location}. "
                        "The server redirected to a host supplied by the client."
                    ),
                    remediation=(
                        "Only redirect to relative paths or an allowlist of hosts, and reject values "
                        "that contain a scheme or host."
                    ),
                    verification=(
                        "Repeat the same single request with a different canary value and confirm the "
                        "behaviour. Do not point the parameter at third-party domains."
                    ),
                    category="redirects",
                    url=request_url,
                    parameter=param,
                    source=self.name,
                    evidence={"status": str(response.status), "location": location},
                )
            )

        if not findings:
            ctx.notes.append("redirect_check: no parameter redirected to the canary domain")
        return findings


MODULE = RedirectCheckModule()
