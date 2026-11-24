"""Level 3: mirrored-input check using a harmless marker.

A unique marker (``rp7f3a9c``) is placed in a discovered parameter. The response
is inspected for the marker and the context is described. No tags, quotes,
handlers, or payload syntax are ever sent, and no claim of XSS is made.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..core.errors import ReconPulseError
from ..core.models import Confidence, Finding, Severity
from .base import ActiveContext, PlanItem, active_finding

MARKER = "rp7f3a9c"
REFLECTABLE_PARAMS = {
    "q",
    "query",
    "search",
    "s",
    "keyword",
    "lang",
    "name",
    "title",
    "message",
    "comment",
    "text",
    "description",
    "error",
    "msg",
    "notice",
    "ref",
    "referrer",
    "callback",
}
MAX_PROBES = 8


class ReflectionCheckModule:
    name = "reflection_check"
    level = 3
    description = f"Insert the marker {MARKER} into up to {MAX_PROBES} parameters and inspect reflection context."

    def _targets(self, ctx: ActiveContext) -> list[tuple[str, str]]:
        targets: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for candidate in ctx.parameters:
            if candidate.name.lower() not in REFLECTABLE_PARAMS:
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
        targets = self._targets(ctx)
        return PlanItem(
            technique=self.name,
            description=(
                f"GET up to {len(targets) or MAX_PROBES} parameterised URLs with the marker {MARKER}; no payloads"
            ),
            requests=len(targets),
            hosts=[ctx.host],
        )

    def _url_with_marker(self, url: str, param: str) -> str:
        parsed = urlparse(url)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        replaced = False
        updated: list[tuple[str, str]] = []
        for name, value in pairs:
            if name == param:
                updated.append((name, MARKER))
                replaced = True
            else:
                updated.append((name, value))
        if not replaced:
            updated.append((param, MARKER))
        return urlunparse(parsed._replace(query=urlencode(updated)))

    @staticmethod
    def _context(response_text: str, response_headers: dict[str, str], marker: str) -> str | None:
        for header, value in response_headers.items():
            if marker in value:
                return f"response header '{header}'"
        if marker not in response_text:
            return None
        if re.search(rf"<script[^>]*>[^<]*{marker}", response_text, re.IGNORECASE):
            return "inside a script block"
        if re.search(rf'<[^>]*=["\'][^"\']*{marker}', response_text, re.IGNORECASE):
            return "inside an HTML attribute"
        if re.search(rf"<!--(?:(?!-->).)*{marker}", response_text, re.DOTALL):
            return "inside an HTML comment"
        return "in the HTML body"

    def run(self, ctx: ActiveContext) -> list[Finding]:
        findings: list[Finding] = []
        moved = 0
        for url, param in self._targets(ctx):
            request_url = self._url_with_marker(url, param)
            try:
                response = ctx.client.get(request_url, module=self.name, allow_redirects=False)
            except ReconPulseError:
                continue
            moved += 1
            location = self._context(response.text, dict(response.headers), MARKER)
            if location is None:
                continue
            findings.append(
                active_finding(
                    title=f"Input reflected ({location}): '{param}'",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    explanation=(
                        f"The marker {MARKER} sent in '{param}' was returned unmodified {location}. "
                        "Reflected input is a prerequisite for reflected cross-site scripting, but "
                        "this check does not prove a vulnerability: encoding, CSP, and browser "
                        "parsing all matter."
                    ),
                    remediation=(
                        "Apply context-aware output encoding and a restrictive Content-Security-Policy; "
                        "validate that input is not trusted anywhere it is echoed."
                    ),
                    verification=(
                        "In a browser you control, confirm how the marker is rendered. Do not send "
                        "tags or event handlers; report the reflection and let the owner test it."
                    ),
                    category="reflection",
                    url=request_url,
                    parameter=param,
                    source=self.name,
                    evidence={"context": location, "status": str(response.status)},
                )
            )
        if moved and not findings:
            ctx.notes.append("reflection_check: marker was not reflected in any response")
        return findings


MODULE = ReflectionCheckModule()
