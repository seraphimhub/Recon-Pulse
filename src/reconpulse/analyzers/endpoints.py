"""Endpoint discovery from HTML and JavaScript, with classification.

Only *static* extraction happens here: no endpoint found this way is contacted.
Each endpoint keeps the file and line it came from so a reviewer can check it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from ..collectors.page import PageData
from ..core.models import Confidence, EvidenceType, Finding, Severity

_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"""fetch\(\s*["'`]([^"'`\s]+)["'`]"""),
    re.compile(r"""axios\.(?:get|post|put|patch|delete|request)\(\s*["'`]([^"'`\s]+)["'`]"""),
    re.compile(r"""\$http\.(?:get|post|jsonp)\(\s*["'`]([^"'`\s]+)["'`]"""),
    re.compile(r"""XMLHttpRequest\(\)[\s\S]{0,80}?\.open\(\s*["'`]\w+["'`]\s*,\s*["'`]([^"'`\s]+)["'`]"""),
    re.compile(r"""\$\.ajax\(\s*\{[\s\S]{0,200}?url\s*:\s*["'`]([^"'`\s]+)["'`]"""),
    re.compile(r"""(?<![\w-])url\s*:\s*["'`]([^"'`\s]+)["'`]"""),
    re.compile(r"""(?:action|src|href)\s*=\s*["']([^"'#][^"']*)["']"""),
    re.compile(r"""["'`](/[A-Za-z0-9_\-./~%{}$:?=&+]{2,})["'`]"""),
    re.compile(r"""["'`](https?://[^"'`\s]+)["'`]"""),
]

_STATIC_EXTENSIONS = (
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".webp",
    ".ico",
    ".css",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".mp4",
    ".webm",
    ".mp3",
    ".map",
)

_AUTH_HINTS = (
    "login",
    "logout",
    "signin",
    "sign-in",
    "signup",
    "sign-up",
    "auth",
    "oauth",
    "token",
    "session",
    "password",
    "reset",
    "verify",
    "mfa",
    "otp",
)
_ADMIN_HINTS = ("admin", "dashboard", "manage", "internal", "console", "staff", "root", "superuser")
_UPLOAD_HINTS = ("upload", "attachment", "import", "file", "media", "avatar", "document")
_API_HINTS = ("/api", "/v1", "/v2", "/v3", "/rest", "/graphql", "/rpc", "/ajax")
_DEBUG_HINTS = ("debug", "actuator", "swagger", "openapi", "phpinfo", "test", "staging", "dev")


@dataclass
class Endpoint:
    value: str
    path: str
    url: str | None
    kind: str
    source_file: str
    line: int
    methods: list[str] = field(default_factory=list)

    @property
    def host(self) -> str:
        return (urlparse(self.url or self.value).hostname or "").lower()

    def to_dict(self) -> dict[str, object]:
        return {
            "value": self.value,
            "path": self.path,
            "url": self.url,
            "kind": self.kind,
            "source": self.source_file,
            "line": self.line,
        }


def classify_path(value: str) -> str:
    lowered = value.lower()
    if lowered.startswith(("ws://", "wss://")) or "socket.io" in lowered:
        return "websocket"
    if "graphql" in lowered:
        return "graphql"
    if any(hint in lowered for hint in _UPLOAD_HINTS):
        return "upload"
    if any(hint in lowered for hint in _ADMIN_HINTS):
        return "admin"
    if any(hint in lowered for hint in _AUTH_HINTS):
        return "auth"
    if any(hint in lowered for hint in _API_HINTS):
        return "api"
    if lowered.endswith(_STATIC_EXTENSIONS):
        return "static"
    return "other"


def _is_noise(value: str) -> bool:
    if not value or len(value) > 512:
        return True
    if value.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
        return True
    if value in ("/", "", "#", "//"):
        return True
    return any(token in value for token in ("${", "{{", "}}", "%s", "<%", "+="))


def discover_endpoints(text: str, base_url: str, source_file: str = "page") -> list[Endpoint]:
    """Extract and classify endpoint-like strings from a document."""

    found: dict[tuple[str, str], Endpoint] = {}
    if not text:
        return []

    for pattern in _PATTERNS:
        for match in pattern.finditer(text):
            raw = match.group(1).strip().strip("\"'`")
            if _is_noise(raw):
                continue
            if raw.startswith(("http://", "https://", "ws://", "wss://")):
                absolute: str | None = raw if raw.startswith(("http://", "https://")) else None
                path = urlparse(raw).path or "/"
            else:
                path = raw.split("?", 1)[0].split("#", 1)[0]
                if not path.startswith("/"):
                    path = "/" + path
                absolute = urljoin(base_url, raw)
            kind = classify_path(raw)
            key = (path, kind)
            if key in found:
                continue
            line = text.count("\n", 0, match.start()) + 1
            found[key] = Endpoint(
                value=raw,
                path=path,
                url=absolute,
                kind=kind,
                source_file=source_file,
                line=line,
            )
    return list(found.values())


def endpoints_from_page(page: PageData) -> list[Endpoint]:
    """Collect endpoints from markup and from links/forms."""

    endpoints = discover_endpoints(page.html, page.final_url, source_file=page.final_url)
    seen = {(endpoint.path, endpoint.kind) for endpoint in endpoints}

    for form in page.forms():
        path = urlparse(form.action).path or "/"
        kind = classify_path(form.action)
        if (path, kind) in seen:
            continue
        seen.add((path, kind))
        endpoints.append(
            Endpoint(
                value=form.action,
                path=path,
                url=form.action,
                kind=kind,
                source_file="form",
                line=0,
                methods=[form.method],
            )
        )

    for link in page.links():
        path = urlparse(link).path or "/"
        kind = classify_path(link)
        if (path, kind) in seen:
            continue
        seen.add((path, kind))
        endpoints.append(
            Endpoint(
                value=link,
                path=path,
                url=link,
                kind=kind,
                source_file="link",
                line=0,
            )
        )
    return endpoints


def endpoint_findings(endpoints: list[Endpoint], url: str) -> list[Finding]:
    """Report interesting endpoint classes without contacting them."""

    findings: list[Finding] = []
    interesting = [e for e in endpoints if e.kind in {"admin", "upload", "graphql", "websocket"}]
    for endpoint in interesting[:15]:
        severity = Severity.LOW if endpoint.kind in {"admin", "upload"} else Severity.INFO
        findings.append(
            Finding(
                title=f"{endpoint.kind.title()} endpoint referenced: {endpoint.path}",
                severity=severity,
                confidence=Confidence.LOW,
                evidence_type=EvidenceType.STATIC_INDICATOR,
                category="endpoints",
                url=endpoint.url or url,
                source=f"endpoint discovery ({endpoint.source_file}:{endpoint.line})",
                explanation=(
                    f"A {endpoint.kind} endpoint is referenced in {endpoint.source_file} "
                    f"(line {endpoint.line}). The reference alone does not prove the endpoint is "
                    "reachable or unauthenticated."
                ),
                remediation=(
                    "Confirm the endpoint enforces authentication and authorization server-side, "
                    "and remove unused references from shipped content."
                ),
                verification=(
                    "Only within the authorized scope: request the endpoint as an anonymous user "
                    "with a single GET and check whether a login or 403 is returned."
                ),
                evidence={"endpoint": endpoint.path, "kind": endpoint.kind},
            )
        )
    return findings
