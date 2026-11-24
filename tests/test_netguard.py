"""SSRF guard tests: obfuscated literals, private ranges, scopes, and DNS."""

from __future__ import annotations

import ipaddress
import socket

import pytest

from reconpulse.core.errors import ScopeError, SSRFGuardError
from reconpulse.core.netguard import (
    is_blocked_address,
    parse_ip_literal,
    pinned_resolution,
    resolve_host,
    validate_url,
)
from reconpulse.core.scope import Scope


class TestParseIpLiteral:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("127.0.0.1", "127.0.0.1"),
            ("2130706433", "127.0.0.1"),
            ("0x7f000001", "127.0.0.1"),
            ("0x7f.0.0.1", "127.0.0.1"),
            ("0177.0.0.1", "127.0.0.1"),
            ("127.1", "127.0.0.1"),
            ("[::1]", "::1"),
            ("169.254.169.254", "169.254.169.254"),
        ],
    )
    def test_known_forms(self, value: str, expected: str) -> None:
        parsed = parse_ip_literal(value)
        assert parsed is not None
        assert str(parsed) == expected

    @pytest.mark.parametrize("value", ["example.com", "", "999.1.1.1", "not-an-ip"])
    def test_non_ip_values(self, value: str) -> None:
        assert parse_ip_literal(value) is None

    def test_too_large_decimal(self) -> None:
        assert parse_ip_literal("4294967296") is None


class TestBlockedAddresses:
    @pytest.mark.parametrize(
        "value",
        [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.1.1",
            "169.254.169.254",
            "0.0.0.0",
            "::1",
            "fe80::1",
            "fd00:ec2::254",
            "::ffff:127.0.0.1",
        ],
    )
    def test_blocked(self, value: str) -> None:
        assert is_blocked_address(value)

    @pytest.mark.parametrize("value", ["93.184.216.34", "1.1.1.1", "2606:4700:4700::1111"])
    def test_public(self, value: str) -> None:
        assert not is_blocked_address(value)

    def test_garbage_is_blocked(self) -> None:
        assert is_blocked_address("not-an-ip")


class TestValidateURL:
    def test_rejects_non_http_scheme(self) -> None:
        with pytest.raises(SSRFGuardError, match="Scheme"):
            validate_url("file:///etc/passwd")

    def test_rejects_userinfo(self) -> None:
        with pytest.raises(SSRFGuardError, match="userinfo"):
            validate_url("http://user:pass@example.com/")

    def test_rejects_missing_host(self) -> None:
        with pytest.raises(SSRFGuardError, match="no host"):
            validate_url("http:///path")

    def test_private_literal_requires_allow_private(self) -> None:
        with pytest.raises(SSRFGuardError, match="private/reserved"):
            validate_url("http://127.0.0.1/")

    def test_allow_private_without_scope_is_refused(self) -> None:
        with pytest.raises(SSRFGuardError, match="not listed in the authorized scope"):
            validate_url("http://127.0.0.1/", allow_private=True)

    def test_allow_private_with_scope_is_accepted(self) -> None:
        validated = validate_url("http://127.0.0.1:8080/x", allow_private=True, scope=Scope(["127.0.0.1"]))
        assert validated.host == "127.0.0.1"
        assert validated.port == 8080
        assert validated.ips == ("127.0.0.1",)

    def test_metadata_endpoint_is_blocked_even_with_allow_private(self) -> None:
        with pytest.raises(SSRFGuardError):
            validate_url("http://169.254.169.254/latest/", allow_private=True, scope=Scope(["169.254.169.254"]))

    def test_dns_result_is_classified(self) -> None:
        with pytest.raises(SSRFGuardError, match="private/reserved"):
            validate_url("http://rebind.example/", resolver=lambda host: ["10.0.0.5"])

    def test_any_private_answer_blocks_the_host(self) -> None:
        with pytest.raises(SSRFGuardError):
            validate_url(
                "http://mixed.example/",
                resolver=lambda host: ["93.184.216.34", "10.0.0.5"],
            )

    def test_public_resolution_with_default_port(self) -> None:
        validated = validate_url("https://example.com/", resolver=lambda host: ["93.184.216.34"])
        assert validated.port == 443
        assert validated.scheme == "https"
        assert validated.ips == ("93.184.216.34",)

    def test_scope_is_enforced_after_resolution(self) -> None:
        with pytest.raises(ScopeError):
            validate_url(
                "https://other.example/",
                scope=Scope(["example.com"]),
                resolver=lambda host: ["93.184.216.34"],
            )

    def test_empty_resolution_is_refused(self) -> None:
        with pytest.raises(SSRFGuardError, match="did not resolve"):
            validate_url("https://empty.example/", resolver=lambda host: [])

    def test_resolver_errors_are_wrapped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def boom(*args: object, **kwargs: object) -> None:
            raise socket.gaierror("no such host")

        monkeypatch.setattr(socket, "getaddrinfo", boom)
        with pytest.raises(SSRFGuardError, match="Cannot resolve"):
            resolve_host("nope.example")

    def test_pinned_resolution_follows_the_validated_address(self) -> None:
        import urllib3.util.connection as urllib3_connection

        original = urllib3_connection.create_connection
        with pinned_resolution("rebind.example", ["93.184.216.34"]):
            assert urllib3_connection.create_connection is not original
        assert urllib3_connection.create_connection is original

    def test_ipv6_literal(self) -> None:
        validated = validate_url("http://[::1]:9000/", allow_private=True, scope=Scope(["::1"]))
        assert validated.ips == ("::1",)
        assert isinstance(ipaddress.ip_address(validated.ips[0]), ipaddress.IPv6Address)
