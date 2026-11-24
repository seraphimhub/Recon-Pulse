"""Secret detection with false-positive filtering and mandatory masking.

The full secret value never leaves this module: findings carry only a masked
form (``AKIA****CDEF``) plus the location. That keeps reports, logs, and the UI
safe to share with a program owner.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

from ..core.models import Confidence, EvidenceType, Finding, Severity

_TOKEN_FORBIDDEN = re.compile(
    r"(?i)(xxxx|your[_-]?|example|sample|placeholder|changeme|change[_-]?me|dummy|lorem|"
    r"redacted|undefined|null|none|todo|fixme|abcdef|1234567|0000000|^test$)"
)

_PROVIDER_PATTERNS: list[tuple[str, re.Pattern[str], Severity, Confidence, str]] = [
    (
        "AWS access key id",
        re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
        Severity.HIGH,
        Confidence.HIGH,
        "An AWS access key identifier appears in shipped content.",
    ),
    (
        "Google API key",
        re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        Severity.HIGH,
        Confidence.HIGH,
        "A Google API key appears in shipped content.",
    ),
    (
        "Stripe live secret key",
        re.compile(r"\bsk_live_[0-9a-zA-Z]{16,}\b"),
        Severity.HIGH,
        Confidence.HIGH,
        "A Stripe live secret key appears in shipped content.",
    ),
    (
        "Stripe key",
        re.compile(r"\b(sk|pk|rk)_(test|live)_[0-9a-zA-Z]{16,}\b"),
        Severity.MEDIUM,
        Confidence.MEDIUM,
        "A Stripe API key appears in shipped content.",
    ),
    (
        "GitHub token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
        Severity.HIGH,
        Confidence.HIGH,
        "A GitHub access token appears in shipped content.",
    ),
    (
        "Slack token",
        re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"),
        Severity.HIGH,
        Confidence.HIGH,
        "A Slack token appears in shipped content.",
    ),
    (
        "JSON Web Token",
        re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),
        Severity.MEDIUM,
        Confidence.MEDIUM,
        "A JWT-shaped string appears in shipped content.",
    ),
    (
        "private key block",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
        Severity.HIGH,
        Confidence.HIGH,
        "A private key block appears in shipped content.",
    ),
]

_ASSIGNMENT = re.compile(
    r"""(?i)\b(api[_-]?key|apikey|secret[_-]?key|secret|access[_-]?token|auth[_-]?token|"""
    r"""client[_-]?secret|password|passwd|pwd)\b\s*[:=]\s*["'`]?([A-Za-z0-9_\-./+=]{16,})["'`]?"""
)

MAX_HITS_PER_FILE = 20


@dataclass
class SecretHit:
    name: str
    masked: str
    source: str
    line: int
    entropy: float
    severity: Severity
    confidence: Confidence
    description: str

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "masked": self.masked,
            "source": self.source,
            "line": self.line,
            "entropy": round(self.entropy, 2),
            "severity": self.severity.value,
        }


def mask_secret(value: str) -> str:
    """Return a shareable masked form of a secret."""

    value = value.strip()
    if len(value) <= 4:
        return "*" * len(value)
    if len(value) <= 10:
        return f"{value[0]}****{value[-1]}"
    return f"{value[:4]}****{value[-4:]}"


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for character in value:
        counts[character] = counts.get(character, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def is_placeholder(value: str) -> bool:
    if _TOKEN_FORBIDDEN.search(value):
        return True
    if len(set(value)) <= 3:
        return True
    # Repeating pattern such as abababab
    return bool(len(value) >= 8 and value[:4] * (len(value) // 4) == value[: len(value) // 4 * 4])


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def find_secrets(text: str, source: str = "inline") -> list[SecretHit]:
    """Scan a document for provider-shaped and high-entropy assignment secrets."""

    hits: list[SecretHit] = []
    seen: set[str] = set()
    if not text:
        return hits

    for name, pattern, severity, confidence, description in _PROVIDER_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(0)
            masked = mask_secret(value)
            if masked in seen or is_placeholder(value):
                continue
            seen.add(masked)
            hits.append(
                SecretHit(
                    name=name,
                    masked=masked,
                    source=source,
                    line=_line_of(text, match.start()),
                    entropy=shannon_entropy(value),
                    severity=severity,
                    confidence=confidence,
                    description=description,
                )
            )
            if len(hits) >= MAX_HITS_PER_FILE:
                return hits

    for match in _ASSIGNMENT.finditer(text):
        label, value = match.group(1), match.group(2)
        if is_placeholder(value):
            continue
        entropy = shannon_entropy(value)
        if len(value) < 20 or entropy < 3.4:
            continue
        masked = mask_secret(value)
        if masked in seen:
            continue
        seen.add(masked)
        hits.append(
            SecretHit(
                name=f"high-entropy value assigned to '{label}'",
                masked=masked,
                source=source,
                line=_line_of(text, match.start()),
                entropy=entropy,
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                description=(
                    "A high-entropy string is assigned to a secret-like variable. This may be a "
                    "build-time constant rather than a live credential."
                ),
            )
        )
        if len(hits) >= MAX_HITS_PER_FILE:
            break

    return hits


def secret_findings(hits: list[SecretHit], url: str) -> list[Finding]:
    """Convert hits into findings that only ever contain the masked value."""

    findings: list[Finding] = []
    for hit in hits:
        findings.append(
            Finding(
                title=f"Possible secret in {hit.source}: {hit.name}",
                severity=hit.severity,
                confidence=hit.confidence,
                evidence_type=EvidenceType.STATIC_INDICATOR,
                category="secrets",
                url=url,
                source="secrets",
                explanation=(
                    f"{hit.description} Found at {hit.source} line {hit.line} "
                    f"(masked value {hit.masked}, Shannon entropy {hit.entropy:.2f}). The value is "
                    "masked here and was never written in full to any log or report."
                ),
                remediation=(
                    "Rotate the credential if it is real, remove it from client-side bundles, and "
                    "serve secrets only from a backend. Add a pre-commit secret scanner."
                ),
                verification=(
                    "Check the provider console for the key's status and recent usage. Do not use "
                    "the key to make requests."
                ),
                evidence={
                    "masked": hit.masked,
                    "location": f"{hit.source}:{hit.line}",
                    "entropy": f"{hit.entropy:.2f}",
                },
            )
        )
    return findings
