"""SSRF guard: URL validation with DNS resolution and address classification.

The guard is deliberately strict:

* only ``http``/``https`` schemes are permitted
* URLs carrying userinfo (``user:pass@host``) are rejected outright
* the host is resolved and **every** resolved address must be public
* private, loopback, link-local, reserved, multicast and unspecified ranges are
  blocked -- including cloud metadata endpoints such as ``169.254.169.254``
* numeric host obfuscation (decimal, hex, octal, short IPv4 forms) is normalised
  before classification so ``2130706433`` and ``0x7f.0.0.1`` are still blocked
* ``allow_private`` only relaxes the check for addresses that are explicitly
  listed in the authorization scope

Residual risk: the address is validated before the connection is opened, so a
host that changes its DNS answer inside that window (classic rebinding) is not
fully defeated. Redirects are re-validated hop by hop, which closes the far more
common redirect-based bypass.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from .errors import SSRFGuardError
from .scope import Scope, normalize_host

ALLOWED_SCHEMES = ("http", "https")

# Ranges that are never reachable for a recon tool, on top of ipaddress flags.
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),  # carrier grade NAT
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),  # TEST-NET-1
    ipaddress.ip_network("198.18.0.0/15"),  # benchmarking
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
    ipaddress.ip_network("169.254.169.254/32"),  # cloud metadata
    ipaddress.ip_network("fd00:ec2::254/128"),  # AWS IPv6 metadata
]

# Never contacted, even with --allow-private and an explicit scope entry.
METADATA_ADDRESSES = frozenset({"169.254.169.254", "fd00:ec2::254"})

Resolver = Callable[[str], list[str]]


@dataclass(frozen=True)
class ValidatedURL:
    """A URL that passed scheme, scope, and SSRF checks."""

    url: str
    scheme: str
    host: str
    port: int
    ips: tuple[str, ...] = field(default_factory=tuple)


def parse_ip_literal(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse every common textual IPv4/IPv6 form, including obfuscated ones."""

    h = host.strip()
    if "@" in h:
        h = h.rsplit("@", 1)[-1]
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    h = h.rstrip(".")
    if not h:
        return None
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        pass

    # Single decimal integer, e.g. http://2130706433/
    if h.isdigit():
        try:
            value = int(h)
        except ValueError:  # pragma: no cover - defensive
            return None
        if 0 <= value <= 0xFFFFFFFF:
            return ipaddress.IPv4Address(value)
        return None

    parts = h.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    numbers: list[int] = []
    for part in parts:
        low = part.lower()
        try:
            if low.startswith("0x"):
                numbers.append(int(low, 16))
            elif len(part) > 1 and part.startswith("0") and part.isdigit():
                numbers.append(int(part, 8))
            elif part.isdigit():
                numbers.append(int(part, 10))
            else:
                return None
        except ValueError:
            return None
    if any(n < 0 for n in numbers):
        return None
    try:
        if len(numbers) == 1:
            return ipaddress.IPv4Address(numbers[0])
        if len(numbers) == 2:
            return ipaddress.IPv4Address((numbers[0] << 24) | numbers[1])
        if len(numbers) == 3:
            return ipaddress.IPv4Address((numbers[0] << 24) | (numbers[1] << 16) | numbers[2])
        return ipaddress.IPv4Address((numbers[0] << 24) | (numbers[1] << 16) | (numbers[2] << 8) | numbers[3])
    except ipaddress.AddressValueError:
        return None


def is_blocked_address(ip: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True when the address is private, loopback, link-local, or reserved."""

    try:
        addr = ip if isinstance(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)) else ipaddress.ip_address(ip)
    except ValueError:
        return True
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    if (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    ):
        return True
    return any(addr in network for network in _BLOCKED_NETWORKS if addr.version == network.version)


def resolve_host(host: str, port: int | None = None) -> list[str]:
    """Resolve a hostname to a de-duplicated list of string addresses."""

    try:
        infos = socket.getaddrinfo(host, port or 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SSRFGuardError(f"Cannot resolve host '{host}': {exc}") from exc
    seen: list[str] = []
    for info in infos:
        address = str(info[4][0])
        if address not in seen:
            seen.append(address)
    return seen


def validate_url(
    url: str,
    *,
    allow_private: bool = False,
    scope: Scope | None = None,
    resolver: Resolver | None = None,
) -> ValidatedURL:
    """Validate a URL and return the resolved, checked target."""

    parsed = urlparse(url)
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise SSRFGuardError(f"Scheme '{parsed.scheme or '(none)'}' is not allowed; only http and https are permitted")
    if parsed.username is not None or parsed.password is not None:
        raise SSRFGuardError("URLs containing userinfo (user:pass@host) are not accepted")
    host = normalize_host(parsed.hostname or "")
    if not host:
        raise SSRFGuardError("URL has no host")

    literal = parse_ip_literal(host)
    resolve = resolver or (lambda h: resolve_host(h, parsed.port))
    ips = [str(literal)] if literal is not None else list(resolve(host))
    if not ips:
        raise SSRFGuardError(f"Host '{host}' did not resolve to any address")

    metadata = [ip for ip in ips if ip.lower() in METADATA_ADDRESSES]
    if metadata:
        raise SSRFGuardError(
            f"Host '{host}' resolves to the cloud metadata address {metadata[0]}; "
            "metadata endpoints are never contacted"
        )

    blocked = [ip for ip in ips if is_blocked_address(ip)]
    if blocked:
        if not allow_private:
            raise SSRFGuardError(
                f"Host '{host}' resolves to a private/reserved address ({blocked[0]}); "
                "refusing to connect (use --allow-private only with explicit authorization)"
            )
        if scope is None or not all(scope.contains_ip(ip) for ip in blocked):
            raise SSRFGuardError(
                f"Host '{host}' resolves to a private/reserved address ({blocked[0]}) that is "
                "not listed in the authorized scope; refusing to connect"
            )

    if scope is not None:
        scope.require(url, ips)

    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    return ValidatedURL(url=url, scheme=parsed.scheme.lower(), host=host, port=port, ips=tuple(ips))


@contextmanager
def pinned_resolution(host: str, ips: list[str] | tuple[str, ...]) -> Iterator[None]:
    """Temporarily force DNS for ``host`` to the already-validated addresses.

    This narrows the DNS-rebinding window between validation and connection.
    Patching is process-global, so callers that need strict isolation should run
    requests sequentially while the pin is active.
    """

    if not ips:
        yield
        return
    try:
        import urllib3.util.connection as urllib3_connection
    except Exception:  # pragma: no cover - urllib3 always ships with requests
        yield
        return

    original = urllib3_connection.create_connection
    target_ip = str(ips[0])
    host_normalized = normalize_host(host)

    def patched(address: Any, *args: Any, **kwargs: Any) -> Any:
        try:
            candidate_host, candidate_port = address[0], address[1]
        except (TypeError, IndexError):  # pragma: no cover - defensive
            return original(address, *args, **kwargs)
        if normalize_host(str(candidate_host)) == host_normalized:
            return original((target_ip, candidate_port), *args, **kwargs)
        return original(address, *args, **kwargs)

    urllib3_connection.create_connection = patched
    try:
        yield
    finally:
        urllib3_connection.create_connection = original
