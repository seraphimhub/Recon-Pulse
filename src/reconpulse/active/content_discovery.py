"""Level 2: curated content discovery with soft-404 handling.

The wordlist is small and deliberately benign. Paths that would change state or
log the tester out are refused even if a user adds them to the list. Responses
that match the site's wildcard 404 signature are discarded.
"""

from __future__ import annotations

import hashlib
import random
import string

from ..core.errors import ReconPulseError
from ..core.models import Confidence, Finding, Severity
from .base import ActiveContext, PlanItem, active_finding

WORDLIST = (
    "admin",
    "administrator",
    "login",
    "dashboard",
    "api",
    "api/v1",
    "graphql",
    "upload",
    "uploads",
    "backup",
    "backups",
    "config",
    "config.json",
    "config.php",
    "db.sql",
    "dump.sql",
    "debug",
    "docs",
    "documentation",
    "internal",
    "logs",
    "monitoring",
    "old",
    "private",
    "readme",
    "server-status",
    "setup",
    "staging",
    "status",
    "test",
    "tmp",
    "vendor",
    ".git/HEAD",
    ".env",
    ".htaccess",
    "phpinfo.php",
    "web.config",
    "sitemap_index.xml",
)

# Never request these, whatever the user configuration says.
BLOCKED_PREFIXES = (
    "logout",
    "signout",
    "delete",
    "remove",
    "reset",
    "unsubscribe",
    "revoke",
    "disable",
    "deactivate",
    "admin/reset",
    "purchase",
    "checkout",
    "pay",
    "transfer",
)

MAX_REQUESTS_DEFAULT = 40


class ContentDiscoveryModule:
    name = "content_discovery"
    level = 2
    description = (
        f"GET {len(WORDLIST)} curated paths with soft-404 comparison; state-changing and "
        "logout paths are always skipped."
    )

    def __init__(self, wordlist: tuple[str, ...] = WORDLIST, max_requests: int = MAX_REQUESTS_DEFAULT) -> None:
        self.wordlist = wordlist
        self.max_requests = max_requests

    def plan(self, ctx: ActiveContext) -> PlanItem:
        allowed = [path for path in self.wordlist if not path.startswith(BLOCKED_PREFIXES)]
        planned = min(len(allowed), self.max_requests) + 1  # +1 soft-404 baseline
        return PlanItem(
            technique=self.name,
            description=f"GET up to {planned} curated paths under {ctx.origin} (soft-404 aware)",
            requests=planned,
            hosts=[ctx.host],
        )

    def _ignored(self, path: str) -> bool:
        lowered = path.lower().lstrip("/")
        return any(lowered.startswith(prefix) for prefix in BLOCKED_PREFIXES)

    def _baseline(self, ctx: ActiveContext) -> tuple[int, int]:
        token = "".join(random.choices(string.ascii_lowercase, k=12))
        url = ctx.url_for(f"reconpulse-{token}-does-not-exist")
        try:
            response = ctx.client.get(url, module=self.name)
        except ReconPulseError:
            return 404, 0
        return response.status, len(response.content)

    def run(self, ctx: ActiveContext) -> list[Finding]:
        findings: list[Finding] = []
        baseline_status, baseline_length = self._baseline(ctx)
        attempted = 0

        for path in self.wordlist:
            if attempted >= self.max_requests:
                break
            if self._ignored(path):
                ctx.notes.append(f"content_discovery: refused state-changing path '{path}'")
                continue
            attempted += 1
            url = ctx.url_for(path)
            try:
                response = ctx.client.get(url, module=self.name, allow_redirects=False)
            except ReconPulseError:
                continue

            length = len(response.content)
            looks_wildcard = response.status == baseline_status and abs(length - baseline_length) < 32
            if looks_wildcard:
                continue
            if response.status not in (200, 204, 301, 302, 401, 403):
                continue

            digest = hashlib.sha256(response.content).hexdigest()[:16]
            severity = Severity.MEDIUM if response.status in (200, 204) else Severity.LOW
            findings.append(
                active_finding(
                    title=f"Discoverable path: /{path.lstrip('/')} (HTTP {response.status})",
                    severity=severity,
                    confidence=Confidence.MEDIUM,
                    explanation=(
                        f"GET {url} returned HTTP {response.status} with {length} bytes "
                        f"(sha256_16 {digest}), which differs from the wildcard-404 baseline of "
                        f"{baseline_status}/{baseline_length} bytes. Content was not stored."
                    ),
                    remediation=(
                        "Require authentication on administrative and configuration paths, remove "
                        "unused files from production, and return a consistent 404 for everything else."
                    ),
                    verification=(
                        "Open the path in a browser as an anonymous user and confirm what is visible; "
                        "do not download backups or credential files."
                    ),
                    category="content_discovery",
                    url=url,
                    source=self.name,
                    evidence={
                        "status": str(response.status),
                        "bytes": str(length),
                        "sha256_16": digest,
                        "content_type": response.headers.get("Content-Type", ""),
                    },
                )
            )

        if not findings:
            ctx.notes.append("content_discovery: no distinct paths beyond the wildcard baseline")
        return findings


MODULE = ContentDiscoveryModule()
