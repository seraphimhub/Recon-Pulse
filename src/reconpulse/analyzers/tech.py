"""Technology fingerprinting from headers, HTML, and asset paths.

Fingerprints are heuristics: they are reported as observations with a
confidence, never as confirmed versions.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..core.models import Confidence, EvidenceType, Finding, Severity


@dataclass
class TechHit:
    name: str
    category: str
    evidence: str
    confidence: Confidence


_HEADER_RULES: list[tuple[str, str, str, str]] = [
    # header, substring, name, category
    ("server", "nginx", "Nginx", "server"),
    ("server", "apache", "Apache HTTP Server", "server"),
    ("server", "iis", "Microsoft IIS", "server"),
    ("server", "cloudflare", "Cloudflare", "cdn"),
    ("server", "gunicorn", "Gunicorn", "server"),
    ("x-powered-by", "php", "PHP", "language"),
    ("x-powered-by", "asp.net", "ASP.NET", "framework"),
    ("x-powered-by", "express", "Express", "framework"),
    ("x-powered-by", "next.js", "Next.js", "framework"),
    ("x-generator", "wordpress", "WordPress", "cms"),
    ("x-drupal-cache", "", "Drupal", "cms"),
    ("x-aspnet-version", "", "ASP.NET", "framework"),
    ("x-amz-cf-id", "", "Amazon CloudFront", "cdn"),
    ("cf-ray", "", "Cloudflare", "waf"),
    ("x-akamai-transformed", "", "Akamai", "cdn"),
    ("x-sucuri-id", "", "Sucuri", "waf"),
    ("x-varnish", "", "Varnish", "cache"),
    ("x-shopify-stage", "", "Shopify", "commerce"),
]

_HTML_RULES: list[tuple[str, str, str]] = [
    ("wp-content", "WordPress", "cms"),
    ("wp-includes", "WordPress", "cms"),
    ("/_next/", "Next.js", "framework"),
    ("__NEXT_DATA__", "Next.js", "framework"),
    ("ng-version", "Angular", "framework"),
    ("data-reactroot", "React", "framework"),
    ("__VUE__", "Vue.js", "framework"),
    ("cdn.shopify.com", "Shopify", "commerce"),
    ("static.wixstatic.com", "Wix", "site-builder"),
    ("squarespace.com", "Squarespace", "site-builder"),
    ("drupal-settings-json", "Drupal", "cms"),
    ("laravel", "Laravel", "framework"),
]


def fingerprint_headers(headers: dict[str, str]) -> list[TechHit]:
    hits: list[TechHit] = []
    seen: set[str] = set()
    for header, needle, name, category in _HEADER_RULES:
        value = headers.get(header, "")
        if needle and needle not in value.lower():
            continue
        if not needle and header not in headers:
            continue
        if name in seen:
            continue
        seen.add(name)
        hits.append(
            TechHit(
                name=name,
                category=category,
                evidence=f"{header}: {value}" if value else header,
                confidence=Confidence.HIGH if needle else Confidence.MEDIUM,
            )
        )
    return hits


def fingerprint_html(html: str, generator: str = "") -> list[TechHit]:
    hits: list[TechHit] = []
    seen: set[str] = set()
    lowered = (html or "").lower()
    for needle, name, category in _HTML_RULES:
        if needle.lower() in lowered and name not in seen:
            seen.add(name)
            hits.append(
                TechHit(
                    name=name,
                    category=category,
                    evidence=f"markup contains '{needle}'",
                    confidence=Confidence.MEDIUM,
                )
            )
    if generator and "wordpress" in generator.lower() and "WordPress" not in seen:
        hits.append(
            TechHit(
                name="WordPress",
                category="cms",
                evidence=f"meta generator: {generator}",
                confidence=Confidence.HIGH,
            )
        )
    return hits


def technology_findings(hits: list[TechHit], url: str) -> list[Finding]:
    """Summarise fingerprints as a single informational finding."""

    if not hits:
        return []
    summary = ", ".join(f"{hit.name} ({hit.category})" for hit in hits)
    return [
        Finding(
            title="Technology fingerprint",
            severity=Severity.INFO,
            confidence=Confidence.MEDIUM,
            evidence_type=EvidenceType.OBSERVED_RESPONSE,
            category="technology",
            url=url,
            source="tech",
            explanation=(
                f"Passive fingerprinting suggests: {summary}. Fingerprints can be spoofed and do "
                "not prove a specific version is running."
            ),
            remediation=("Reduce unnecessary version disclosure and keep the identified components patched."),
            verification="Confirm component versions through an authenticated inventory, not headers alone.",
            evidence={hit.name: hit.evidence for hit in hits},
        )
    ]
