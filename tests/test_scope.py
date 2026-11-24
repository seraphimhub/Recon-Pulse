"""Scope allowlist behaviour: domains, wildcards, IPs, CIDRs, and denials."""

from __future__ import annotations

import pytest

from reconpulse.core.errors import ScopeError
from reconpulse.core.scope import Scope, ScopeEntry, normalize_entry, normalize_host


class TestNormalization:
    def test_url_entry_becomes_hostname(self) -> None:
        assert normalize_entry("https://Example.com/some/path") == "example.com"

    def test_host_with_port(self) -> None:
        assert normalize_entry("example.com:8443") == "example.com"

    def test_wildcard_is_kept(self) -> None:
        assert normalize_entry("*.Example.com") == "*.example.com"

    def test_normalize_host_strips_userinfo_brackets_and_dot(self) -> None:
        assert normalize_host("user:pass@Example.com.") == "example.com"
        assert normalize_host("[::1]") == "::1"

    def test_empty_entry_parses_to_none(self) -> None:
        assert ScopeEntry.parse("   ") is None


class TestDomainMatching:
    def test_apex_and_subdomains_match(self) -> None:
        scope = Scope(["example.com"])
        assert scope.is_allowed("example.com")
        assert scope.is_allowed("api.example.com")
        assert scope.is_allowed("deep.api.example.com")

    def test_lookalike_domain_does_not_match(self) -> None:
        scope = Scope(["example.com"])
        assert not scope.is_allowed("notexample.com")
        assert not scope.is_allowed("example.com.evil.net")

    def test_wildcard_does_not_match_apex(self) -> None:
        scope = Scope(["*.example.com"])
        assert scope.is_allowed("api.example.com")
        assert not scope.is_allowed("example.com")

    def test_url_form_of_target_is_accepted(self) -> None:
        scope = Scope(["example.com"])
        assert scope.require("https://api.example.com/path") == "https://api.example.com/path"

    def test_denial_always_wins(self) -> None:
        scope = Scope(["example.com"], ["internal.example.com"])
        assert not scope.is_allowed("internal.example.com")
        assert scope.is_excluded("internal.example.com")
        assert scope.is_allowed("public.example.com")


class TestAddressMatching:
    def test_ip_literal_is_matched(self) -> None:
        scope = Scope(["127.0.0.1"])
        assert scope.is_allowed("127.0.0.1")
        assert scope.is_allowed_host("127.0.0.1")
        assert scope.contains_ip("127.0.0.1")

    def test_cidr_covers_members(self) -> None:
        scope = Scope(["10.0.0.0/24"])
        assert scope.is_allowed("10.0.0.5")
        assert not scope.is_allowed("10.0.1.5")
        assert scope.contains_ip("10.0.0.200")

    def test_ipv6_entry(self) -> None:
        scope = Scope(["::1"])
        assert scope.is_allowed("::1")
        assert not scope.is_allowed("::2")

    def test_ip_denial(self) -> None:
        scope = Scope(["10.0.0.0/24"], ["10.0.0.7"])
        assert not scope.is_allowed("10.0.0.7")
        assert scope.is_allowed("10.0.0.8")


class TestDefaults:
    def test_default_allow_without_allowlist(self) -> None:
        scope = Scope()
        assert scope.is_allowed("anything.example")

    def test_default_deny_without_allowlist(self) -> None:
        scope = Scope(default_deny=True)
        assert not scope.is_allowed("anything.example")


class TestRequire:
    def test_require_returns_url_in_scope(self) -> None:
        scope = Scope(["example.com"])
        assert scope.require("https://api.example.com/x") == "https://api.example.com/x"

    def test_require_raises_outside_scope(self) -> None:
        with pytest.raises(ScopeError):
            Scope(["example.com"]).require("https://other.example/x")

    def test_require_raises_for_excluded(self) -> None:
        scope = Scope(["example.com"], ["internal.example.com"])
        with pytest.raises(ScopeError):
            scope.require("https://internal.example.com/")

    def test_describe_lists_raw_entries(self) -> None:
        scope = Scope(["example.com"], ["out.example.com"])
        assert scope.describe() == {"in": ["example.com"], "out": ["out.example.com"]}
