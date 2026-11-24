"""Authorization gate: every way an active run must be refused."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from reconpulse.core.authorization import (
    EXAMPLE_AUTHORIZATION,
    Authorization,
    Limits,
    load_authorization,
    parse_datetime,
    validate_authorization_data,
    write_example_authorization,
)
from reconpulse.core.errors import AuthorizationError, ScopeError


def _now() -> datetime:
    return datetime.now(timezone.utc)


class TestValidateData:
    def test_valid_data_has_no_errors(self, authorization_raw: dict[str, Any]) -> None:
        assert validate_authorization_data(authorization_raw) == []

    def test_non_mapping_is_rejected(self) -> None:
        assert validate_authorization_data(["not", "a", "mapping"]) != []

    @pytest.mark.parametrize(
        "field",
        ["engagement", "authorized_by", "valid_from", "valid_until", "scope", "allowed_techniques"],
    )
    def test_missing_required_field(self, authorization_raw: dict[str, Any], field: str) -> None:
        raw = dict(authorization_raw)
        raw.pop(field)
        errors = validate_authorization_data(raw)
        assert any(field in error for error in errors)

    def test_missing_contact_is_required(self, authorization_raw: dict[str, Any]) -> None:
        raw = dict(authorization_raw)
        raw["contact_for_incident"] = ""
        assert any("contact_for_incident" in error for error in validate_authorization_data(raw))

    def test_expired_authorization(self, authorization_raw: dict[str, Any]) -> None:
        raw = dict(authorization_raw)
        raw["valid_from"] = (_now() - timedelta(days=10)).isoformat()
        raw["valid_until"] = (_now() - timedelta(days=1)).isoformat()
        errors = validate_authorization_data(raw)
        assert any("expired" in error for error in errors)

    def test_not_yet_valid_authorization(self, authorization_raw: dict[str, Any]) -> None:
        raw = dict(authorization_raw)
        raw["valid_from"] = (_now() + timedelta(days=1)).isoformat()
        raw["valid_until"] = (_now() + timedelta(days=2)).isoformat()
        errors = validate_authorization_data(raw)
        assert any("not valid yet" in error for error in errors)

    def test_valid_from_after_valid_until(self, authorization_raw: dict[str, Any]) -> None:
        raw = dict(authorization_raw)
        raw["valid_from"] = (_now() + timedelta(days=3)).isoformat()
        raw["valid_until"] = (_now() + timedelta(days=2)).isoformat()
        errors = validate_authorization_data(raw)
        assert any("earlier" in error for error in errors)

    def test_naive_datetime_is_rejected(self, authorization_raw: dict[str, Any]) -> None:
        raw = dict(authorization_raw)
        raw["valid_from"] = "2026-01-01T00:00:00"
        errors = validate_authorization_data(raw)
        assert any("timezone" in error for error in errors)

    def test_unparsable_datetime(self, authorization_raw: dict[str, Any]) -> None:
        raw = dict(authorization_raw)
        raw["valid_from"] = "not-a-date"
        assert validate_authorization_data(raw) != []

    def test_unknown_technique_is_rejected(self, authorization_raw: dict[str, Any]) -> None:
        raw = dict(authorization_raw)
        raw["allowed_techniques"] = ["common_paths", "sqlmap"]
        errors = validate_authorization_data(raw)
        assert any("unknown technique" in error for error in errors)

    @pytest.mark.parametrize("scope", [{"in": []}, "example.com", {"in": "example.com", "out": "x"}])
    def test_scope_shapes(self, authorization_raw: dict[str, Any], scope: object) -> None:
        raw = dict(authorization_raw)
        raw["scope"] = scope
        if scope == {"in": "example.com", "out": "x"}:
            raw["scope"] = {"in": "example.com", "out": "x"}
        errors = validate_authorization_data(raw)
        if scope == {"in": "example.com", "out": "x"}:
            # A string scope.out is tolerated and normalised; this is valid data.
            assert errors == []
        else:
            assert errors != []

    def test_invalid_limits(self, authorization_raw: dict[str, Any]) -> None:
        raw = dict(authorization_raw)
        raw["limits"] = {"max_requests_per_second": 0}
        assert any("positive" in error for error in validate_authorization_data(raw))

    def test_limits_must_be_mapping(self, authorization_raw: dict[str, Any]) -> None:
        raw = dict(authorization_raw)
        raw["limits"] = "fast"
        assert validate_authorization_data(raw) != []


class TestLoadAuthorization:
    def test_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(AuthorizationError, match="not found"):
            load_authorization(tmp_path / "absent.yaml")

    def test_invalid_yaml(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.yaml"
        path.write_text("engagement: [unclosed", encoding="utf-8")
        with pytest.raises(AuthorizationError, match="not valid YAML"):
            load_authorization(path)

    def test_non_mapping_yaml(self, tmp_path: Path) -> None:
        path = tmp_path / "list.yaml"
        path.write_text("- one\n- two\n", encoding="utf-8")
        with pytest.raises(AuthorizationError, match="mapping"):
            load_authorization(path)

    def test_rejected_file_lists_every_problem(self, make_auth_file: Any) -> None:
        path = make_auth_file(valid_until="2000-01-01T00:00:00Z", contact_for_incident="")
        with pytest.raises(AuthorizationError) as excinfo:
            load_authorization(path)
        message = str(excinfo.value)
        assert "expired" in message
        assert "contact_for_incident" in message

    def test_valid_file_round_trip(self, make_auth_file: Any) -> None:
        authorization = load_authorization(make_auth_file())
        assert authorization.engagement == "Mock engagement"
        assert authorization.scope.is_allowed("127.0.0.1")
        assert authorization.technique_allowed("common_paths")


class TestAuthorizationObject:
    def test_scope_is_default_deny(self, authorization_raw: dict[str, Any]) -> None:
        raw = dict(authorization_raw)
        raw["scope"] = {"in": [], "out": []}
        authorization = Authorization.from_mapping(raw)
        assert not authorization.scope.is_allowed("anything.example")

    def test_scope_out_wins(self, authorization_raw: dict[str, Any]) -> None:
        raw = dict(authorization_raw)
        raw["scope"] = {"in": ["example.com"], "out": ["secret.example.com"]}
        authorization = Authorization.from_mapping(raw)
        with pytest.raises(ScopeError, match="excluded"):
            authorization.ensure_host_in_scope("secret.example.com")

    def test_out_of_scope_host_is_refused(self, authorization: Authorization) -> None:
        with pytest.raises(ScopeError, match=r"outside scope\.in"):
            authorization.ensure_host_in_scope("evil.example")

    def test_technique_gate(self, authorization_raw: dict[str, Any]) -> None:
        raw = dict(authorization_raw)
        raw["allowed_techniques"] = ["common_paths"]
        authorization = Authorization.from_mapping(raw)
        authorization.ensure_technique_allowed("common_paths")
        with pytest.raises(AuthorizationError, match="not listed"):
            authorization.ensure_technique_allowed("port_scan")

    def test_levels(self, authorization: Authorization) -> None:
        assert authorization.technique_level("common_paths") == 1
        assert authorization.technique_level("port_scan") == 2
        assert authorization.technique_level("redirect_check") == 3
        assert authorization.technique_level("nope") == 99

    def test_validity_window(self, authorization: Authorization) -> None:
        assert authorization.is_currently_valid()
        assert not authorization.has_expired()
        assert not authorization.not_yet_valid()
        assert not authorization.expires_within(hours=0)

    def test_expiry_helpers_with_fixed_clock(self, authorization: Authorization) -> None:
        ahead = authorization.valid_until + timedelta(seconds=1)
        assert authorization.has_expired(ahead)
        assert not authorization.is_currently_valid(ahead)
        before = authorization.valid_from - timedelta(seconds=1)
        assert authorization.not_yet_valid(before)
        with pytest.raises(AuthorizationError, match="not yet valid"):
            authorization.ensure_valid_now(before)
        with pytest.raises(AuthorizationError, match="expired"):
            authorization.ensure_valid_now(ahead)

    def test_expiry_warning_window(self, authorization_raw: dict[str, Any]) -> None:
        raw = dict(authorization_raw)
        soon = _now() + timedelta(hours=2)
        raw["valid_until"] = soon.isoformat()
        authorization = Authorization.from_mapping(raw)
        assert authorization.expires_within(24)

    def test_summary_contains_no_raw_file(self, authorization: Authorization) -> None:
        summary = authorization.to_summary().to_dict()
        assert summary["engagement"] == "Mock engagement"
        assert "raw" not in summary

    def test_parse_datetime_accepts_z_suffix(self) -> None:
        parsed = parse_datetime("2026-01-01T00:00:00Z", "valid_from")
        assert parsed.tzinfo is not None
        assert parsed.year == 2026


class TestLimits:
    def test_defaults(self) -> None:
        limits = Limits.from_mapping({})
        assert limits.max_requests_per_second == 1.0
        assert limits.max_total_requests == 500

    def test_per_host_and_hours(self) -> None:
        limits = Limits.from_mapping({"per_host_requests": 10, "operational_hours": "09:00-17:00"})
        assert limits.per_host_requests == 10
        assert limits.operational_hours == "09:00-17:00"

    def test_zero_total_is_rejected(self) -> None:
        with pytest.raises(AuthorizationError):
            Limits.from_mapping({"max_total_requests": 0})

    def test_non_mapping_is_rejected(self) -> None:
        with pytest.raises(AuthorizationError):
            Limits.from_mapping([])  # type: ignore[arg-type]


def test_example_authorization_is_valid_right_now(tmp_path: Path) -> None:
    """The shipped example must load cleanly, so the docs never go stale."""

    path = write_example_authorization(tmp_path / "authorization.example.yaml")
    assert path.read_text(encoding="utf-8") == EXAMPLE_AUTHORIZATION
    authorization = load_authorization(path, now=datetime(2026, 6, 1, tzinfo=timezone.utc))
    assert authorization.canary_domain is not None
