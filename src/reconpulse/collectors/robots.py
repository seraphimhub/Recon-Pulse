"""Robots.txt, sitemap.xml and security.txt collection (passive GETs)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from ..core.errors import ReconPulseError
from ..core.http_client import HTTPClient
from ..core.models import Confidence, EvidenceType, Finding, Severity


@dataclass
class RobotsInfo:
    url: str
    status: int | None = None
    text: str = ""
    disallowed: list[str] = field(default_factory=list)
    allowed: list[str] = field(default_factory=list)
    sitemaps: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def present(self) -> bool:
        return self.status is not None and 200 <= self.status < 300


@dataclass
class SecurityTxtInfo:
    url: str
    status: int | None = None
    text: str = ""
    contacts: list[str] = field(default_factory=list)

    @property
    def present(self) -> bool:
        return self.status is not None and 200 <= self.status < 300


def _base(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def fetch_robots(client: HTTPClient, url: str, *, module: str = "passive") -> RobotsInfo:
    robots_url = urljoin(_base(url) + "/", "robots.txt")
    info = RobotsInfo(url=robots_url)
    try:
        response = client.get(robots_url, module=module)
    except ReconPulseError as exc:
        info.error = str(exc)
        return info

    info.status = response.status
    if not response.ok:
        return info
    info.text = response.text[:200_000]
    for line in info.text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.lower().startswith("disallow:"):
            path = stripped.split(":", 1)[1].strip()
            if path and path not in info.disallowed:
                info.disallowed.append(path)
        elif stripped.lower().startswith("allow:"):
            path = stripped.split(":", 1)[1].strip()
            if path and path not in info.allowed:
                info.allowed.append(path)
        elif stripped.lower().startswith("sitemap:"):
            sitemap = stripped.split(":", 1)[1].strip()
            if sitemap and sitemap not in info.sitemaps:
                info.sitemaps.append(sitemap)
    return info


def fetch_security_txt(client: HTTPClient, url: str, *, module: str = "passive") -> SecurityTxtInfo:
    """Check ``/.well-known/security.txt`` then ``/security.txt``."""

    base = _base(url)
    for path in ("/.well-known/security.txt", "/security.txt"):
        target = urljoin(base + "/", path.lstrip("/"))
        try:
            response = client.get(target, module=module)
        except ReconPulseError:
            continue
        if response.ok and response.text.strip():
            info = SecurityTxtInfo(url=target, status=response.status, text=response.text[:50_000])
            for line in info.text.splitlines():
                if line.lower().startswith("contact:"):
                    contact = line.split(":", 1)[1].strip()
                    if contact and contact not in info.contacts:
                        info.contacts.append(contact)
            return info
    return SecurityTxtInfo(url=urljoin(base + "/", ".well-known/security.txt"), status=None)


def analyze_robots(info: RobotsInfo) -> list[Finding]:
    """Report interesting but low-severity robots.txt signals."""

    findings: list[Finding] = []
    if info.present and info.disallowed:
        interesting = [
            path
            for path in info.disallowed
            if re.search(r"(admin|internal|private|backup|config|api|debug|staging)", path, re.I)
        ]
        if interesting:
            findings.append(
                Finding(
                    title="robots.txt advertises sensitive-looking paths",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    evidence_type=EvidenceType.OBSERVED_RESPONSE,
                    category="robots",
                    url=info.url,
                    source="robots",
                    explanation=(
                        "robots.txt lists Disallow entries that look sensitive "
                        f"({', '.join(interesting[:5])}). Disallow only asks well-behaved "
                        "crawlers to stay away; it does not protect the paths."
                    ),
                    remediation=(
                        "Do not rely on robots.txt for access control. Require authentication "
                        "on sensitive paths and remove hints you do not want published."
                    ),
                    verification=(
                        "Request the listed paths manually as an anonymous user and confirm "
                        "authorization is enforced; only within the engagement scope."
                    ),
                    evidence={
                        "count": str(len(info.disallowed)),
                        "examples": ", ".join(interesting[:5]),
                    },
                )
            )
    return findings


def analyze_security_txt(info: SecurityTxtInfo) -> list[Finding]:
    if info.present:
        return []
    return [
        Finding(
            title="No security.txt published",
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            evidence_type=EvidenceType.OBSERVED_RESPONSE,
            category="policy",
            url=info.url,
            source="security_txt",
            explanation=(
                "Neither /.well-known/security.txt nor /security.txt returned content, so "
                "researchers have no documented way to report vulnerabilities."
            ),
            remediation=("Publish /.well-known/security.txt (RFC 9116) with a Contact and Expires field."),
            verification="Open /.well-known/security.txt in a browser and confirm it renders.",
        )
    ]
