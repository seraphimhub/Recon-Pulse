"""Level 2: existence check for common sensitive files.

Only the status code, size, and a content hash are recorded. Contents are never
stored, logged, or reported; a small in-memory signature test reduces false
positives and is discarded immediately.
"""

from __future__ import annotations

import hashlib

from ..core.errors import ReconPulseError
from ..core.models import Confidence, Finding, Severity
from .base import ActiveContext, PlanItem, active_finding

# path -> (signature prefix, description)
CANDIDATES: dict[str, tuple[bytes | None, str]] = {
    ".git/HEAD": (b"ref:", "Git metadata"),
    ".env": (None, "environment file"),
    ".env.local": (None, "environment file"),
    "config.php.bak": (None, "configuration backup"),
    "web.config": (b"<?xml", "IIS configuration"),
    "backup.zip": (b"PK\x03\x04", "archive"),
    "db.sql": (None, "database dump"),
    "app.js.map": (b'{"version"', "source map"),
    ".DS_Store": (b"\x00\x00\x00\x01Bud1", "macOS metadata"),
}


class SensitiveFileCheckModule:
    name = "sensitive_file_check"
    level = 2
    description = f"GET {len(CANDIDATES)} known-sensitive paths and record status, size, and hash only."

    def plan(self, ctx: ActiveContext) -> PlanItem:
        return PlanItem(
            technique=self.name,
            description=f"Existence check for {len(CANDIDATES)} sensitive paths under {ctx.origin}",
            requests=len(CANDIDATES),
            hosts=[ctx.host],
        )

    def run(self, ctx: ActiveContext) -> list[Finding]:
        findings: list[Finding] = []
        for path, (signature, description) in CANDIDATES.items():
            url = ctx.url_for(path)
            try:
                response = ctx.client.get(url, module=self.name, allow_redirects=False)
            except ReconPulseError:
                continue
            if response.status != 200 or not response.content:
                continue
            head = response.content[:32]
            if head.lstrip().lower().startswith((b"<!doctype", b"<html")):
                continue
            if signature is not None and not head.startswith(signature):
                continue
            digest = hashlib.sha256(response.content).hexdigest()[:16]
            findings.append(
                active_finding(
                    title=f"Sensitive file exposed: /{path}",
                    severity=Severity.HIGH if path in {".env", ".env.local", ".git/HEAD"} else Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    explanation=(
                        f"GET {url} returned HTTP 200 with {len(response.content)} bytes "
                        f"(sha256_16 {digest}), matching the {description} signature. The content "
                        "was inspected in memory for the signature and then discarded; nothing was "
                        "saved."
                    ),
                    remediation=(
                        "Remove the file from the web root, block dotfiles at the server, and rotate "
                        "any credential the file may have contained."
                    ),
                    verification=(
                        "Ask the owner to confirm the file should not be public; do not download or share its contents."
                    ),
                    category="sensitive_files",
                    url=url,
                    source=self.name,
                    evidence={
                        "status": str(response.status),
                        "bytes": str(len(response.content)),
                        "sha256_16": digest,
                        "content_type": response.headers.get("Content-Type", ""),
                    },
                )
            )
        if not findings:
            ctx.notes.append("sensitive_file_check: no candidate file was exposed")
        return findings


MODULE = SensitiveFileCheckModule()
