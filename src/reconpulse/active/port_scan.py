"""Level 2: TCP connect scan over a short, configurable port list.

No raw SYN packets, no full 65535 sweep by default, low concurrency, and a short
timeout per port. A banner is read only if the service sends one immediately
(passive grab); nothing is sent to provoke a response.
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor

from ..core.errors import SSRFGuardError
from ..core.models import Confidence, Finding, Severity
from ..core.netguard import is_blocked_address, resolve_host
from ..core.scope import ScopeError
from .base import ActiveContext, PlanItem, active_finding

DEFAULT_PORTS = (21, 22, 25, 53, 80, 110, 143, 443, 445, 1433, 3000, 3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017)
SENSITIVE_PORTS = {
    21: "FTP",
    23: "Telnet",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    9200: "Elasticsearch",
    27017: "MongoDB",
}


class PortScanModule:
    name = "port_scan"
    level = 2
    description = f"TCP connect() to {len(DEFAULT_PORTS)} common ports with low concurrency and a passive banner read."

    def __init__(self, ports: tuple[int, ...] = DEFAULT_PORTS, timeout: float = 1.5) -> None:
        self.ports = ports
        self.timeout = timeout

    def plan(self, ctx: ActiveContext) -> PlanItem:
        return PlanItem(
            technique=self.name,
            description=(
                f"TCP connect scan of {len(self.ports)} ports on {ctx.host} (timeout {self.timeout}s, concurrency 4)"
            ),
            requests=len(self.ports),
            hosts=[ctx.host],
        )

    def _probe(self, address: str, port: int) -> tuple[int, str, bool]:
        try:
            with socket.create_connection((address, port), timeout=self.timeout) as sock:
                sock.settimeout(0.6)
                try:
                    banner = sock.recv(128)
                except (TimeoutError, OSError):
                    banner = b""
                text = banner.decode("utf-8", errors="replace").strip().splitlines()
                return port, (text[0][:120] if text else ""), True
        except OSError:
            return port, "", False

    def run(self, ctx: ActiveContext) -> list[Finding]:
        addresses: list[str] = []
        try:
            ctx.authorization.ensure_host_in_scope(ctx.host)
            addresses = resolve_host(ctx.host)
        except (ScopeError, SSRFGuardError) as exc:
            ctx.notes.append(f"port_scan skipped: {exc}")
            return []

        for address in addresses:
            if is_blocked_address(address) and not ctx.client.allow_private:
                ctx.notes.append(f"port_scan skipped: {address} is a blocked address")
                return []

        findings: list[Finding] = []
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda port: self._probe(addresses[0], port), self.ports))

        for port, banner, is_open in results:
            if not is_open:
                continue
            service = SENSITIVE_PORTS.get(port)
            what = service or "service"
            findings.append(
                active_finding(
                    title=f"Open TCP port {port} ({what})",
                    severity=Severity.LOW if service else Severity.INFO,
                    confidence=Confidence.HIGH,
                    explanation=(
                        f"A TCP connection to {ctx.host}:{port} succeeded"
                        + (f" and the service sent a banner: {banner!r}" if banner else "")
                        + ". The port is reachable from the internet; whether it should be is a "
                        "question for the owner."
                    ),
                    remediation=(
                        "Expect a standard web port to be public; for databases and remote "
                        "administration restrict access with a firewall or security group, require "
                        "strong authentication, and prefer private networking."
                    ),
                    verification=(
                        "Confirm with the owner whether the port is intentionally public; do not "
                        "attempt to authenticate against it."
                    ),
                    category="ports",
                    url=f"{ctx.host}:{port}",
                    source=self.name,
                    evidence={"port": str(port), "banner": banner or "(none)"},
                )
            )

        if not findings:
            ctx.notes.append("port_scan: no open ports in the configured list")
        return findings


MODULE = PortScanModule()
