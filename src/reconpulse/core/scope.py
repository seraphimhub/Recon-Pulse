"""Scope allowlist enforcement.

Scope entries may be:

* a domain -- ``example.com`` (matches the apex and every subdomain)
* a wildcard -- ``*.example.com`` (matches subdomains only)
* an IP address -- ``203.0.113.10``
* a CIDR block -- ``203.0.113.0/24``

``scope.out`` always wins over ``scope.in``.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlparse

from .errors import ScopeError

DomainEntry = str
CidrEntry = ipaddress.IPv4Network | ipaddress.IPv6Network


def normalize_host(host: str) -> str:
    """Lower-case a hostname, drop brackets, userinfo, and a trailing root dot."""

    h = host.strip()
    if "@" in h:
        h = h.rsplit("@", 1)[-1]
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    if ":" in h and h.count(":") != 1:  # IPv6 literal
        try:
            return str(ipaddress.ip_address(h))
        except ValueError:
            pass
    return h.rstrip(".").lower()


def normalize_entry(entry: str) -> str:
    """Turn ``https://Example.com/path`` into ``example.com``."""

    value = entry.strip()
    if not value:
        return ""
    if "://" in value:
        value = urlparse(value).hostname or value
    elif "/" not in value and not value.startswith("*."):
        parsed = urlparse(f"//{value}")
        if parsed.hostname:
            value = parsed.hostname
    value = value.rstrip("/")
    if value.startswith("*."):
        return "*." + normalize_host(value[2:])
    return normalize_host(value)


@dataclass(frozen=True)
class ScopeEntry:
    """A single parsed scope rule."""

    raw: str
    kind: str  # "domain" | "wildcard" | "ip" | "cidr"
    domain: str | None = None
    network: CidrEntry | None = None
    address: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None

    @classmethod
    def parse(cls, entry: str) -> ScopeEntry | None:
        normalized = normalize_entry(entry)
        if not normalized:
            return None
        if normalized.startswith("*."):
            return cls(raw=entry, kind="wildcard", domain=normalized[2:])
        try:
            network = ipaddress.ip_network(normalized, strict=False)
        except ValueError:
            network = None
        if network is not None:
            if network.num_addresses == 1:
                return cls(raw=entry, kind="ip", address=network.network_address)
            return cls(raw=entry, kind="cidr", network=network)
        return cls(raw=entry, kind="domain", domain=normalized)

    def matches_host(self, host: str) -> bool:
        host = normalize_host(host)
        if self.kind == "domain":
            return host == self.domain or host.endswith(f".{self.domain}")
        if self.kind == "wildcard":
            return host != self.domain and host.endswith(f".{self.domain}")
        return False

    def matches_ip(self, ip: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        try:
            addr = ip if isinstance(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)) else ipaddress.ip_address(ip)
        except ValueError:
            return False
        if self.kind == "ip":
            return addr == self.address
        if self.kind == "cidr":
            assert self.network is not None
            return addr in self.network
        return False

    def describe(self) -> str:
        return self.raw


class Scope:
    """An allowlist with an explicit denylist that takes precedence."""

    def __init__(
        self,
        in_entries: list[str] | str | None = None,
        out_entries: list[str] | str | None = None,
        *,
        default_deny: bool = False,
    ):
        self.allow: list[ScopeEntry] = self._parse_many(in_entries)
        self.deny: list[ScopeEntry] = self._parse_many(out_entries)
        # With no allowlist at all, passive scans may reach any public host.
        # Active scans pass default_deny=True so an empty list can never widen scope.
        self.default_deny = default_deny

    @staticmethod
    def _parse_many(entries: list[str] | str | None) -> list[ScopeEntry]:
        if entries is None:
            return []
        if isinstance(entries, str):
            entries = [entries]
        parsed: list[ScopeEntry] = []
        for entry in entries:
            parsed_entry = ScopeEntry.parse(str(entry))
            if parsed_entry is not None:
                parsed.append(parsed_entry)
        return parsed

    # -- classification -----------------------------------------------------

    def is_excluded(self, host: str, ips: list[str] | None = None) -> bool:
        if not self.deny:
            return False
        host = normalize_host(host)
        for entry in self.deny:
            if entry.matches_host(host) or self._literal_matches(entry, host):
                return True
            for ip in ips or ():
                if entry.matches_ip(ip):
                    return True
        return False

    def is_allowed(self, host: str, ips: list[str] | None = None) -> bool:
        """True only when the host is listed in scope and not denied."""

        if self.is_excluded(host, ips):
            return False
        if not self.allow:
            return not self.default_deny
        host = normalize_host(host)
        for entry in self.allow:
            if entry.matches_host(host):
                return True
            if self._literal_matches(entry, host):
                return True
            for ip in ips or ():
                if entry.matches_ip(ip):
                    return True
        return False

    def is_allowed_host(self, host: str) -> bool:
        """Scope check when only a hostname or IP literal is known (no resolution)."""

        if self.is_excluded(host):
            return False
        if not self.allow:
            return not self.default_deny
        normalized = normalize_host(host)
        return any(entry.matches_host(normalized) or self._literal_matches(entry, normalized) for entry in self.allow)

    @staticmethod
    def _literal_matches(entry: ScopeEntry, host: str) -> bool:
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            return False
        return entry.matches_ip(literal)

    def contains_ip(self, ip: str) -> bool:
        """Whether an IP literal is explicitly covered by the allowlist."""

        if not self.allow:
            return False
        return any(entry.matches_ip(ip) for entry in self.allow)

    def require(self, url: str, ips: list[str] | None = None) -> str:
        """Return the URL if it is in scope, otherwise raise :class:`ScopeError`."""

        host = normalize_host(urlparse(url).hostname or "")
        if self.is_excluded(host, ips):
            raise ScopeError(f"Host '{host}' is excluded by scope.out")
        if not self.is_allowed(host, ips):
            raise ScopeError(f"Host '{host}' is outside the authorized scope")
        return url

    def describe(self) -> dict[str, list[str]]:
        return {"in": [e.describe() for e in self.allow], "out": [e.describe() for e in self.deny]}
