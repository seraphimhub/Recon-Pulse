"""Cookie flag analysis.

Cookie *values* are never stored, logged, or reported -- only names and flags.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from http.cookies import SimpleCookie

from ..core.models import Confidence, EvidenceType, Finding, Severity


@dataclass
class CookieInfo:
    name: str
    secure: bool = False
    http_only: bool = False
    same_site: str | None = None
    domain: str | None = None
    path: str | None = None
    max_age: str | None = None
    flags: list[str] = field(default_factory=list)


def parse_set_cookie(header_values: list[str], url: str) -> list[CookieInfo]:
    """Parse every Set-Cookie header line into :class:`CookieInfo` records."""

    cookies: list[CookieInfo] = []
    for raw in header_values:
        jar = SimpleCookie()
        try:
            jar.load(raw)
        except Exception:  # pragma: no cover - SimpleCookie is lenient
            continue
        for name, morsel in jar.items():
            lower = raw.lower()
            cookie = CookieInfo(
                name=name,
                secure=bool(morsel["secure"]) or "secure" in lower,
                http_only=bool(morsel["httponly"]) or "httponly" in lower,
                same_site=morsel["samesite"] or None,
                domain=morsel["domain"] or None,
                path=morsel["path"] or None,
                max_age=morsel["max-age"] or None,
            )
            cookie.flags = [
                name
                for name, present in (
                    ("secure", cookie.secure),
                    ("httponly", cookie.http_only),
                    ("samesite", bool(cookie.same_site)),
                )
                if present
            ]
            if cookie not in cookies:
                cookies.append(cookie)
    return cookies


def analyze_cookies(cookies: list[CookieInfo], url: str) -> list[Finding]:
    findings: list[Finding] = []
    is_https = url.lower().startswith("https://")

    for cookie in cookies:
        if is_https and not cookie.secure:
            findings.append(
                Finding(
                    title=f"Cookie '{cookie.name}' is not marked Secure",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    evidence_type=EvidenceType.OBSERVED_RESPONSE,
                    category="cookies",
                    url=url,
                    parameter=cookie.name,
                    source="cookies",
                    explanation=(
                        f"The cookie '{cookie.name}' lacks the Secure attribute, so the browser may "
                        "send it over plain HTTP where it can be intercepted."
                    ),
                    remediation=f"Set the Secure attribute on '{cookie.name}' and serve the site over HTTPS only.",
                    verification="Inspect the cookie in developer tools and confirm the Secure column is set.",
                    evidence={"cookie": cookie.name, "flags": ", ".join(cookie.flags) or "none"},
                )
            )

        if not cookie.http_only:
            findings.append(
                Finding(
                    title=f"Cookie '{cookie.name}' is readable from JavaScript",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    evidence_type=EvidenceType.OBSERVED_RESPONSE,
                    category="cookies",
                    url=url,
                    parameter=cookie.name,
                    source="cookies",
                    explanation=(
                        f"The cookie '{cookie.name}' has no HttpOnly attribute. If a script-injection "
                        "flaw exists anywhere on the origin, the cookie can be read by injected code."
                    ),
                    remediation=f"Add HttpOnly to '{cookie.name}' unless client-side code genuinely needs it.",
                    verification="Run document.cookie in the console and confirm the cookie is absent.",
                    evidence={"cookie": cookie.name},
                )
            )

        if not cookie.same_site:
            findings.append(
                Finding(
                    title=f"Cookie '{cookie.name}' has no SameSite attribute",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    evidence_type=EvidenceType.OBSERVED_RESPONSE,
                    category="cookies",
                    url=url,
                    parameter=cookie.name,
                    source="cookies",
                    explanation=(
                        f"The cookie '{cookie.name}' does not set SameSite, so browser defaults decide "
                        "whether it is attached to cross-site requests. That weakens CSRF protection."
                    ),
                    remediation=f"Set SameSite=Lax (or Strict) on '{cookie.name}'.",
                    verification="Check the cookie attributes in developer tools.",
                    evidence={"cookie": cookie.name},
                )
            )
        elif cookie.same_site.lower() == "none" and not cookie.secure:
            findings.append(
                Finding(
                    title=f"Cookie '{cookie.name}' uses SameSite=None without Secure",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    evidence_type=EvidenceType.OBSERVED_RESPONSE,
                    category="cookies",
                    url=url,
                    parameter=cookie.name,
                    source="cookies",
                    explanation=(
                        f"The cookie '{cookie.name}' is cross-site (SameSite=None) but not Secure; "
                        "modern browsers reject it and, where accepted, it travels over plain HTTP."
                    ),
                    remediation=f"Either add Secure to '{cookie.name}' or stop using SameSite=None.",
                    verification="Check the browser console for a cookie rejection warning.",
                    evidence={"cookie": cookie.name},
                )
            )

        if cookie.name.startswith("__Host-") and (cookie.domain or cookie.path not in (None, "/")):
            findings.append(
                Finding(
                    title=f"__Host- cookie '{cookie.name}' has an invalid Domain or Path",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    evidence_type=EvidenceType.OBSERVED_RESPONSE,
                    category="cookies",
                    url=url,
                    parameter=cookie.name,
                    source="cookies",
                    explanation=(
                        "The __Host- prefix requires Secure, Path=/, and no Domain attribute. A "
                        "browser rejects the cookie when those rules are broken."
                    ),
                    remediation=f"Remove Domain and set Path=/ on '{cookie.name}'.",
                    verification="Confirm the browser accepts the cookie without warnings.",
                    evidence={"cookie": cookie.name},
                )
            )

        if cookie.name.startswith(("__Secure-", "__Host-")) and not cookie.secure:
            findings.append(
                Finding(
                    title=f"Prefixed cookie '{cookie.name}' is not Secure",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    evidence_type=EvidenceType.OBSERVED_RESPONSE,
                    category="cookies",
                    url=url,
                    parameter=cookie.name,
                    source="cookies",
                    explanation="Cookie name prefixes are only honoured when the Secure attribute is set.",
                    remediation=f"Add Secure to '{cookie.name}'.",
                    verification="Confirm the prefix rules are satisfied in developer tools.",
                    evidence={"cookie": cookie.name},
                )
            )

    return findings
