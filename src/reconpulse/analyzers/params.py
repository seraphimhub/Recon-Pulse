"""Parameter discovery and context-aware vulnerability heuristics.

The prototype flagged a parameter only because of its name. This module adds
context: where the parameter appears (query string, form, API, auth flow), how
the endpoint classifies, and how much of the signal is name-based. Findings are
always indicators with an explicit confidence, never vulnerabilities.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qsl, urlparse

from ..collectors.page import FormInfo
from ..core.models import Confidence, EvidenceType, Finding, Severity
from .endpoints import Endpoint

_PARAM_RULES: list[tuple[str, set[str], Severity, str, str, str]] = [
    (
        "Open redirect / SSRF",
        {
            "url",
            "uri",
            "redirect",
            "redirect_uri",
            "redirect_url",
            "redirecturl",
            "next",
            "return",
            "return_to",
            "returnto",
            "returntourl",
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
            "webhook",
            "image",
            "imageurl",
            "avatar",
            "proxy",
            "feed",
            "src",
            "source",
            "site",
            "host",
        },
        Severity.MEDIUM,
        "The parameter name commonly carries a URL or host that the server later fetches or redirects to.",
        "Validate that the value is a relative path or an allowlisted host; never redirect to arbitrary input.",
        "As an anonymous user, set the parameter to a canary domain you control and check whether the "
        "Location header or server-side fetch uses it. Do not use third-party domains you do not own.",
    ),
    (
        "IDOR",
        {
            "id",
            "uid",
            "user",
            "user_id",
            "userid",
            "account",
            "account_id",
            "order",
            "order_id",
            "invoice",
            "invoice_id",
            "customer",
            "customer_id",
            "profile",
            "pid",
            "doc",
            "document",
            "member",
            "member_id",
            "tenant",
            "tenant_id",
            "project",
            "project_id",
        },
        Severity.MEDIUM,
        "The parameter looks like an object identifier, a classic horizontal authorization boundary.",
        "Resolve the object server-side and compare its owner with the authenticated principal on every request.",
        "Create two accounts you control in the program and request the same object id from each; "
        "a 200 with the other account's data is the indicator. Stop immediately if you see real user data.",
    ),
    (
        "Reflected XSS",
        {
            "q",
            "query",
            "search",
            "s",
            "keyword",
            "message",
            "comment",
            "name",
            "title",
            "content",
            "text",
            "description",
            "lang",
            "error",
            "msg",
            "notice",
        },
        Severity.LOW,
        "The parameter is likely echoed into the page, which is a prerequisite for reflected XSS.",
        "Context-aware output encoding and a restrictive Content-Security-Policy.",
        "Send a harmless unique marker (for example rp7f3a9c) and check whether it is reflected and in "
        "which context. Do not send tags or event handlers.",
    ),
    (
        "Path traversal / LFI",
        {
            "file",
            "filename",
            "path",
            "page",
            "template",
            "include",
            "dir",
            "folder",
            "download",
            "document",
            "view",
            "load",
            "resource",
        },
        Severity.MEDIUM,
        "The parameter name suggests a file or path is chosen by the client.",
        "Map the input to a server-side identifier; never concatenate user input into a filesystem path.",
        "Request a path that does not exist and compare the error text; a filesystem error hints at "
        "path handling. Do not attempt traversal payloads.",
    ),
    (
        "SQL injection",
        {
            "id",
            "sort",
            "order",
            "orderby",
            "filter",
            "where",
            "category",
            "cat",
            "type",
            "select",
            "column",
            "group",
            "limit",
            "offset",
        },
        Severity.LOW,
        "The parameter is frequently interpolated into database queries.",
        "Use parameterised queries and allowlist sort/column names.",
        "Outside this tool's scope. Only an authorized tester with a separate approval should run "
        "SQL injection verification; ReconPulse deliberately performs no such probing.",
    ),
    (
        "Mass assignment",
        {
            "role",
            "roles",
            "is_admin",
            "admin",
            "permission",
            "permissions",
            "verified",
            "active",
            "status",
            "plan",
            "price",
            "credits",
            "balance",
        },
        Severity.LOW,
        "The parameter maps to a privileged attribute that clients should not normally set.",
        "Bind request bodies to an explicit allowlist of user-editable fields.",
        "Compare the profile update request with the fields shown in the UI; extra accepted fields "
        "are the signal. Report rather than tamper with your own privilege level.",
    ),
]

_RULE_INDEX = {
    name: (keywords, severity, explanation, remediation, verification)
    for name, keywords, severity, explanation, remediation, verification in _PARAM_RULES
}


@dataclass
class ParamCandidate:
    name: str
    location: str  # "query" | "form"
    endpoint: Endpoint | None = None
    form: FormInfo | None = None

    @property
    def kind(self) -> str:
        return self.endpoint.kind if self.endpoint else "form"

    @property
    def context_url(self) -> str | None:
        return self.endpoint.url if self.endpoint else (self.form.action if self.form else None)


def extract_parameters(endpoints: list[Endpoint], forms: list[FormInfo] | None = None) -> list[ParamCandidate]:
    """Collect query-string and form parameters with their endpoint context."""

    candidates: list[ParamCandidate] = []
    seen: set[tuple[str, str, str | None]] = set()

    for endpoint in endpoints:
        if not endpoint.url:
            continue
        query = urlparse(endpoint.url).query
        if not query:
            continue
        for name, _value in parse_qsl(query, keep_blank_values=True):
            key = (name, "query", endpoint.url)
            if key in seen:
                continue
            seen.add(key)
            candidates.append(ParamCandidate(name=name, location="query", endpoint=endpoint))

    for form in forms or []:
        for name in form.inputs:
            key = (name, "form", form.action)
            if key in seen:
                continue
            seen.add(key)
            candidates.append(ParamCandidate(name=name, location="form", form=form))

    return candidates


def _confidence(candidate: ParamCandidate, rule_name: str) -> Confidence:
    """Raise confidence when the parameter sits in a meaningful context."""

    kind = candidate.kind
    strong_context = kind in {"api", "auth", "admin", "upload", "graphql"}
    if rule_name == "Open redirect / SSRF" and kind in {"auth", "api"}:
        return Confidence.HIGH
    if strong_context:
        return Confidence.MEDIUM
    if candidate.location == "form":
        return Confidence.MEDIUM
    return Confidence.LOW


def analyze_parameters(candidates: list[ParamCandidate], url: str) -> list[Finding]:
    """Turn parameter candidates into context-aware indicator findings."""

    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()

    for candidate in candidates:
        name = candidate.name.lower()
        for rule_name, (
            keywords,
            severity,
            explanation,
            remediation,
            verification,
        ) in _RULE_INDEX.items():
            if name not in keywords:
                continue
            key = (name, rule_name, candidate.context_url or "")
            if key in seen:
                continue
            seen.add(key)
            confidence = _confidence(candidate, rule_name)
            location = "query string" if candidate.location == "query" else "form field"
            context_desc = f"on a {candidate.kind} endpoint" if candidate.endpoint else "in a form submission"
            findings.append(
                Finding(
                    title=f"{rule_name} indicator: '{candidate.name}' parameter",
                    severity=severity,
                    confidence=confidence,
                    evidence_type=EvidenceType.STATIC_INDICATOR,
                    category="parameters",
                    url=candidate.context_url or url,
                    parameter=candidate.name,
                    source="params",
                    explanation=(
                        f"The {location} parameter '{candidate.name}' was found {context_desc}. "
                        f"{explanation} This is a name- and context-based indicator only; it does "
                        "not prove the parameter is vulnerable."
                    ),
                    remediation=remediation,
                    verification=verification,
                    evidence={"location": candidate.location, "endpoint_kind": candidate.kind},
                )
            )
            break
    return findings
