"""Level 1: subdomain enumeration through DNS records only.

Uses ``dnspython`` for A/AAAA/CNAME resolution (plain ``socket`` cannot see
CNAMEs). Discovered hosts outside ``scope.in`` become out-of-scope discoveries and
are never contacted. Dangling CNAMEs are reported as an indicator that needs
manual verification; nothing is claimed about takeover.

Certificate-transparency lookups would send the target to a third-party service,
so they are intentionally not performed.
"""

from __future__ import annotations

import dns.exception
import dns.resolver

from ..core.models import Confidence, Finding, OutOfScopeDiscovery, Severity
from .base import ActiveContext, PlanItem, active_finding

WORDLIST = (
    "www",
    "api",
    "app",
    "admin",
    "auth",
    "blog",
    "cdn",
    "dev",
    "docs",
    "git",
    "internal",
    "mail",
    "mobile",
    "staging",
    "status",
    "test",
    "vpn",
)

CLOUD_SUFFIXES = (
    "s3.amazonaws.com",
    "herokuapp.com",
    "github.io",
    "azurewebsites.net",
    "cloudfront.net",
    "netlify.app",
    "vercel.app",
    "trafficmanager.net",
)


class DnsEnumModule:
    name = "dns_enum"
    level = 1
    description = (
        f"Resolve {len(WORDLIST)} common labels plus the apex with DNS A/AAAA/CNAME records; "
        "never contacts the discovered hosts."
    )

    def plan(self, ctx: ActiveContext) -> PlanItem:
        return PlanItem(
            technique=self.name,
            description=f"DNS lookups for {len(WORDLIST) + 1} names under {ctx.host}",
            requests=len(WORDLIST) + 1,
            hosts=[ctx.host],
        )

    # -- internals ---------------------------------------------------------

    def _resolve(self, name: str) -> tuple[list[str], list[str]]:
        addresses: list[str] = []
        cnames: list[str] = []
        for record_type in ("A", "AAAA"):
            try:
                answers = dns.resolver.resolve(name, record_type, lifetime=4)
            except (dns.exception.DNSException, OSError):
                continue
            for answer in answers:
                value = str(answer.address)
                if value not in addresses:
                    addresses.append(value)
        try:
            answers = dns.resolver.resolve(name, "CNAME", lifetime=4)
            for answer in answers:
                target = str(answer.target).rstrip(".")
                if target not in cnames:
                    cnames.append(target)
        except (dns.exception.DNSException, OSError):
            pass
        return addresses, cnames

    def _target_resolves(self, name: str) -> bool:
        for record_type in ("A", "AAAA"):
            try:
                dns.resolver.resolve(name, record_type, lifetime=4)
                return True
            except (dns.exception.DNSException, OSError):
                continue
        return False

    # -- module entry point -------------------------------------------------

    def run(self, ctx: ActiveContext) -> list[Finding]:
        findings: list[Finding] = []
        scope = ctx.authorization.scope
        root = ctx.host
        candidates = [root, *(f"{label}.{root}" for label in WORDLIST)]

        for candidate in candidates:
            addresses, cnames = self._resolve(candidate)
            if not addresses and not cnames:
                continue

            if candidate != root and not scope.is_allowed(candidate, addresses):
                ctx.out_of_scope.append(
                    OutOfScopeDiscovery(
                        host=candidate,
                        discovered_by=self.name,
                        detail="resolves to " + (", ".join(addresses[:3]) or ", ".join(cnames[:2])),
                    )
                )
                continue

            dangling = False
            if cnames:
                dangling = not any(self._target_resolves(target) for target in cnames)

            findings.append(
                active_finding(
                    title=f"Subdomain resolves: {candidate}",
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    explanation=(
                        f"{candidate} resolves to {', '.join(addresses[:3]) or '(no A/AAAA)'}"
                        + (f" via CNAME {', '.join(cnames[:2])}" if cnames else "")
                        + "."
                    ),
                    remediation=(
                        "Keep an inventory of published names, retire unused ones, and monitor "
                        "certificate transparency for new subdomains."
                    ),
                    verification="Confirm the host is intentionally published by the program owner.",
                    category="dns",
                    url=f"https://{candidate}/",
                    source=self.name,
                    evidence={"addresses": ", ".join(addresses[:3]), "cname": ", ".join(cnames[:2])},
                )
            )

            if dangling:
                suspicious = any(any(cname.endswith(suffix) for suffix in CLOUD_SUFFIXES) for cname in cnames)
                findings.append(
                    active_finding(
                        title=f"Possible dangling CNAME: {candidate}",
                        severity=Severity.LOW if suspicious else Severity.INFO,
                        confidence=Confidence.LOW,
                        explanation=(
                            f"{candidate} points at {', '.join(cnames[:2])}, which does not resolve. "
                            "If the target service can be claimed by anyone, the name could be "
                            "taken over. This is an indicator, not a confirmed takeover."
                        ),
                        remediation=(
                            "Remove the stale DNS record, or reclaim the upstream resource, then add "
                            "a CI check that every CNAME resolves."
                        ),
                        verification=(
                            "Check the upstream provider dashboard to see who controls the CNAME "
                            "target. Do not attempt to register the name."
                        ),
                        category="dns",
                        url=f"https://{candidate}/",
                        source=self.name,
                        evidence={"cname": ", ".join(cnames[:2])},
                    )
                )

        if not findings:
            ctx.notes.append("dns_enum: no additional names resolved")
        return findings


MODULE = DnsEnumModule()
