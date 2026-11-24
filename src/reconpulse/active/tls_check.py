"""Level 1: TLS configuration review (no HTTP request is made)."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any

from ..core.errors import SSRFGuardError
from ..core.models import Confidence, Finding, Severity
from ..core.netguard import is_blocked_address, resolve_host
from ..core.scope import ScopeError
from .base import ActiveContext, PlanItem, active_finding

WEAK_PROTOCOLS = {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}


class TlsCheckModule:
    name = "tls_check"
    level = 1
    description = "Inspect the certificate chain, expiry, hostname match, and negotiated protocol."
    port = 443

    def plan(self, ctx: ActiveContext) -> PlanItem:
        return PlanItem(
            technique=self.name,
            description=f"TCP/TLS handshake with {ctx.host}:{self.port}; no HTTP request",
            requests=1,
            hosts=[ctx.host],
        )

    def _guard(self, ctx: ActiveContext) -> list[str]:
        host = ctx.host
        ctx.authorization.ensure_host_in_scope(host)
        addresses = resolve_host(host, self.port)
        for address in addresses:
            if is_blocked_address(address) and not ctx.client.allow_private:
                raise SSRFGuardError(f"{host} resolves to a blocked address {address}")
            if is_blocked_address(address) and not ctx.authorization.scope.contains_ip(address):
                raise SSRFGuardError(f"{host} resolves to a private address outside scope")
        return addresses

    def run(self, ctx: ActiveContext) -> list[Finding]:
        findings: list[Finding] = []
        try:
            addresses = self._guard(ctx)
        except (ScopeError, SSRFGuardError) as exc:
            ctx.notes.append(f"tls_check skipped: {exc}")
            return findings

        host = ctx.host
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            with (
                socket.create_connection((addresses[0], self.port), timeout=8) as raw,
                context.wrap_socket(raw, server_hostname=host) as tls,
            ):
                certificate: dict[str, Any] = dict(tls.getpeercert() or {})
                protocol = tls.version() or "unknown"
                cipher_info = tls.cipher()
                cipher = cipher_info[0] if cipher_info else "unknown"
        except OSError as exc:
            ctx.notes.append(f"tls_check: connection failed ({exc})")
            return findings

        if protocol in WEAK_PROTOCOLS:
            findings.append(
                active_finding(
                    title=f"Obsolete TLS protocol negotiated ({protocol})",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    explanation=(
                        f"The handshake completed with {protocol} and cipher {cipher}. TLS 1.0/1.1 "
                        "are deprecated and lack modern mitigations."
                    ),
                    remediation="Require TLS 1.2 or newer and disable legacy protocol versions.",
                    verification="Re-run the handshake and confirm TLSv1.2 or TLSv1.3 is negotiated.",
                    category="tls",
                    url=f"https://{host}:{self.port}/",
                    source=self.name,
                    evidence={"protocol": protocol, "cipher": cipher},
                )
            )

        not_after = certificate.get("notAfter")
        if not_after:
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            except ValueError:
                expiry = None
            if expiry is not None:
                remaining = (expiry - datetime.now(timezone.utc)).days
                if remaining < 0:
                    findings.append(
                        active_finding(
                            title="TLS certificate has expired",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            explanation=f"The certificate expired {abs(remaining)} days ago ({not_after}).",
                            remediation="Renew the certificate and automate renewal.",
                            verification="Check the certificate dates in a browser.",
                            category="tls",
                            url=f"https://{host}/",
                            source=self.name,
                            evidence={"not_after": not_after},
                        )
                    )
                elif remaining < 30:
                    findings.append(
                        active_finding(
                            title=f"TLS certificate expires in {remaining} days",
                            severity=Severity.LOW,
                            confidence=Confidence.HIGH,
                            explanation=f"The certificate expires on {not_after}.",
                            remediation="Renew before expiry and automate the renewal process.",
                            verification="Check the certificate expiry date in a browser.",
                            category="tls",
                            url=f"https://{host}/",
                            source=self.name,
                            evidence={"not_after": not_after},
                        )
                    )

        try:
            verifying = ssl.create_default_context()
            with (
                socket.create_connection((addresses[0], self.port), timeout=8) as raw,
                verifying.wrap_socket(raw, server_hostname=host),
            ):
                pass
        except ssl.SSLCertVerificationError as exc:
            findings.append(
                active_finding(
                    title="TLS certificate fails verification",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    explanation=(
                        "A verifying handshake failed, which means the certificate is self-signed, "
                        f"expired, or issued for a different name: {exc.verify_message}"
                    ),
                    remediation="Install a certificate from a trusted CA that covers the hostname.",
                    verification="Open the site in a browser and read the certificate error.",
                    category="tls",
                    url=f"https://{host}/",
                    source=self.name,
                    evidence={"verify_message": str(exc.verify_message)},
                )
            )
        except OSError:
            pass

        if not findings:
            ctx.notes.append(f"tls_check: {protocol} with a valid certificate")
        return findings


MODULE = TlsCheckModule()
