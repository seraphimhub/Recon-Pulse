"""Security header analysis with per-finding remediation guidance."""

from __future__ import annotations

import re

from ..core.models import Confidence, EvidenceType, Finding, Severity

_CSP_UNSAFE = re.compile(r"(unsafe-inline|unsafe-eval)", re.IGNORECASE)


def _finding(
    *,
    title: str,
    severity: Severity,
    confidence: Confidence,
    explanation: str,
    remediation: str,
    verification: str,
    url: str,
    evidence: dict[str, str] | None = None,
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        confidence=confidence,
        evidence_type=EvidenceType.OBSERVED_RESPONSE,
        category="headers",
        url=url,
        source="headers",
        explanation=explanation,
        remediation=remediation,
        verification=verification,
        evidence=evidence or {},
    )


def analyze_security_headers(headers: dict[str, str], url: str) -> list[Finding]:
    """Audit HTTP response headers. ``headers`` must be lower-cased."""

    findings: list[Finding] = []
    csp = headers.get("content-security-policy", "")
    hsts = headers.get("strict-transport-security", "")

    # -- Content Security Policy -------------------------------------------
    if not csp:
        findings.append(
            _finding(
                title="Content-Security-Policy header missing",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                explanation=(
                    "The response has no Content-Security-Policy. Without a policy the browser "
                    "may execute any injected inline or third-party script, which makes XSS "
                    "impact much larger."
                ),
                remediation=(
                    "Publish a CSP that starts in report-only mode, then enforce it. Prefer "
                    "nonce- or hash-based script-src over allowlists."
                ),
                verification=(
                    "Fetch the page with developer tools open and confirm the CSP header is "
                    "present, then check the browser console for violations."
                ),
                url=url,
            )
        )
    else:
        weaknesses = sorted({match.lower() for match in _CSP_UNSAFE.findall(csp)})
        if weaknesses:
            findings.append(
                _finding(
                    title="Content-Security-Policy allows unsafe script sources",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    explanation=(
                        f"The CSP contains {', '.join(weaknesses)}, which lets inline or eval-based "
                        "script run and largely defeats the policy's XSS protection."
                    ),
                    remediation=(
                        "Replace unsafe-inline/unsafe-eval with nonces or hashes, and migrate "
                        "string-evaluated code to static calls."
                    ),
                    verification="Review the CSP with a policy validator and confirm no unsafe keywords remain.",
                    url=url,
                    evidence={"weaknesses": ", ".join(weaknesses)},
                )
            )
        if re.search(r"(script-src|default-src)[^;]*\s\*", csp, re.IGNORECASE):
            findings.append(
                _finding(
                    title="Content-Security-Policy uses a wildcard source",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    explanation=(
                        "A wildcard (*) script source allows loading code from any origin, so an "
                        "attacker-controlled host can be used to serve payloads."
                    ),
                    remediation="List explicit origins instead of *, and keep the list short.",
                    verification="Inspect the directive and confirm no wildcard remains.",
                    url=url,
                )
            )

    # -- HSTS ---------------------------------------------------------------
    if not hsts:
        findings.append(
            _finding(
                title="Strict-Transport-Security header missing",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                explanation=(
                    "Without HSTS the browser may contact the site over plain HTTP first, which "
                    "allows a network attacker to downgrade or intercept the session."
                ),
                remediation=(
                    "Send Strict-Transport-Security: max-age=31536000; includeSubDomains (add "
                    "preload only once you are sure every subdomain supports HTTPS)."
                ),
                verification="Check the header over HTTPS with curl -sI and confirm max-age is present.",
                url=url,
            )
        )
    else:
        max_age = re.search(r"max-age=(\d+)", hsts)
        if max_age and int(max_age.group(1)) < 15_552_000:
            findings.append(
                _finding(
                    title="HSTS max-age is shorter than six months",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    explanation=(
                        f"max-age is {max_age.group(1)} seconds. Short lifetimes leave windows where "
                        "the downgrade protection lapses."
                    ),
                    remediation="Raise max-age to at least 15552000 and add includeSubDomains.",
                    verification="Read the header value and compare max-age.",
                    url=url,
                    evidence={"max_age": max_age.group(1)},
                )
            )

    # -- clickjacking / sniffing / referrer / permissions -------------------
    frame_options = headers.get("x-frame-options", "")
    if not frame_options and "frame-ancestors" not in csp.lower():
        findings.append(
            _finding(
                title="Framing protection missing",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                explanation=(
                    "Neither X-Frame-Options nor CSP frame-ancestors is set, so the page can be "
                    "embedded in an attacker frame and used for clickjacking."
                ),
                remediation="Send X-Frame-Options: DENY (or SAMEORIGIN), or add CSP frame-ancestors.",
                verification="Load the page inside an iframe on a local test page and confirm it is blocked.",
                url=url,
            )
        )

    content_type_options = headers.get("x-content-type-options", "")
    if content_type_options.lower() != "nosniff":
        findings.append(
            _finding(
                title="X-Content-Type-Options is not nosniff",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                explanation=(
                    "Browsers may sniff a response as a different content type, which can turn an "
                    "uploaded file into executable script."
                ),
                remediation="Send X-Content-Type-Options: nosniff on every response.",
                verification="Check the header with curl -sI.",
                url=url,
            )
        )

    if "referrer-policy" not in headers:
        findings.append(
            _finding(
                title="Referrer-Policy header missing",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                explanation=(
                    "Full URLs may leak to third parties through the Referer header, including "
                    "tokens placed in query strings."
                ),
                remediation="Send Referrer-Policy: strict-origin-when-cross-origin (or no-referrer).",
                verification="Inspect outgoing requests in developer tools after following an external link.",
                url=url,
            )
        )

    if "permissions-policy" not in headers and "feature-policy" not in headers:
        findings.append(
            _finding(
                title="Permissions-Policy header missing",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                explanation=(
                    "Browser features such as camera, geolocation, and microphone are enabled by "
                    "default for the page and any embedded frame."
                ),
                remediation="Send Permissions-Policy restricting features the application does not use.",
                verification="Confirm the header is present and lists only required features.",
                url=url,
            )
        )

    if "cross-origin-opener-policy" not in headers or "cross-origin-resource-policy" not in headers:
        findings.append(
            _finding(
                title="Cross-origin isolation headers incomplete",
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                explanation=(
                    "COOP and/or CORP are missing, so the page is not cross-origin isolated and "
                    "cross-window attacks such as XS-Leaks are easier."
                ),
                remediation=(
                    "Send Cross-Origin-Opener-Policy: same-origin and "
                    "Cross-Origin-Resource-Policy: same-origin where compatible."
                ),
                verification="Check both headers with curl -sI and confirm loaded resources still work.",
                url=url,
            )
        )

    # -- information disclosure --------------------------------------------
    server = headers.get("server", "")
    powered_by = headers.get("x-powered-by", "")
    if re.search(r"\d+\.\d+", server) or powered_by:
        detail = ", ".join(filter(None, [server, powered_by]))
        findings.append(
            _finding(
                title="Server software version disclosed",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                explanation=(
                    f"Response headers reveal implementation details ({detail}). That helps an "
                    "attacker pick exploits for known versions."
                ),
                remediation="Remove or genericise Server and X-Powered-By headers at the edge.",
                verification="Check the headers before and after the change.",
                url=url,
                evidence={"headers": detail},
            )
        )

    return findings
