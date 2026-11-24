"""Authorization file loading and strict validation for active mode.

Active mode is refused unless every one of these holds:

* the file exists and parses as a YAML mapping
* all required fields are present and non-empty
* ``valid_from``/``valid_until`` are timezone-aware and bracket "now"
* ``scope.in`` is non-empty and the target matches it
* the target is not excluded by ``scope.out``
* every requested technique appears in ``allowed_techniques``

The parsed object also exposes a :class:`~reconpulse.core.scope.Scope` built with
``default_deny=True`` so an empty or malformed scope can never widen access.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

from .errors import AuthorizationError, ScopeError
from .models import AuthorizationSummary
from .scope import Scope

REQUIRED_FIELDS = (
    "engagement",
    "authorized_by",
    "valid_from",
    "valid_until",
    "scope",
    "allowed_techniques",
)

# Impact tier of each technique. Tier 2 and 3 are never enabled implicitly.
TECHNIQUE_LEVELS: dict[str, int] = {
    "dns_enum": 1,
    "tls_check": 1,
    "http_methods": 1,
    "cors_probe": 1,
    "common_paths": 1,
    "port_scan": 2,
    "content_discovery": 2,
    "graphql_check": 2,
    "sensitive_file_check": 2,
    "reflection_check": 3,
    "redirect_check": 3,
}

DEFAULT_TIER1 = tuple(name for name, level in TECHNIQUE_LEVELS.items() if level == 1)

EXPIRY_WARNING_HOURS = 24


def parse_datetime(value: Any, field_name: str) -> datetime:
    """Parse an ISO-8601 datetime that must carry a timezone."""

    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise AuthorizationError(f"'{field_name}' is not a valid ISO-8601 datetime: {value!r}") from exc
    if parsed.tzinfo is None:
        raise AuthorizationError(f"'{field_name}' must include a timezone offset (e.g. 2026-01-01T00:00:00Z)")
    return parsed.astimezone(timezone.utc)


@dataclass
class Limits:
    """Operational limits taken from the authorization file."""

    max_requests_per_second: float = 1.0
    max_concurrency: int = 5
    max_total_requests: int | None = 500
    per_host_requests: int | None = None
    operational_hours: str | None = None

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> Limits:
        if not isinstance(data, dict):
            raise AuthorizationError("'limits' must be a mapping")
        rate = data.get("max_requests_per_second", 1.0)
        concurrency = data.get("max_concurrency", 5)
        total = data.get("max_total_requests", 500)
        per_host = data.get("per_host_requests")
        try:
            rate_value = float(rate)
            concurrency_value = int(concurrency)
        except (TypeError, ValueError) as exc:
            raise AuthorizationError("limits.max_requests_per_second/concurrency must be numeric") from exc
        if rate_value <= 0:
            raise AuthorizationError("limits.max_requests_per_second must be positive")
        if concurrency_value <= 0:
            raise AuthorizationError("limits.max_concurrency must be positive")
        total_value = None if total is None else int(total)
        if total_value is not None and total_value <= 0:
            raise AuthorizationError("limits.max_total_requests must be positive")
        return cls(
            max_requests_per_second=rate_value,
            max_concurrency=concurrency_value,
            max_total_requests=total_value,
            per_host_requests=None if per_host is None else int(per_host),
            operational_hours=data.get("operational_hours"),
        )


@dataclass
class Authorization:
    """Validated authorization for one engagement."""

    engagement: str
    authorized_by: str
    valid_from: datetime
    valid_until: datetime
    scope_in: list[str]
    allowed_techniques: list[str]
    scope_out: list[str] = field(default_factory=list)
    limits: Limits = field(default_factory=Limits)
    testing_window: str | None = None
    contact_for_incident: str = ""
    canary_domain: str | None = None
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_mapping(cls, raw: dict[str, Any]) -> Authorization:
        """Build an Authorization from already-validated mapping data."""

        scope = raw.get("scope") or {}
        scope_in = scope.get("in") or []
        if isinstance(scope_in, str):
            scope_in = [scope_in]
        scope_out = scope.get("out") or []
        if isinstance(scope_out, str):
            scope_out = [scope_out]
        scope_out = [str(entry) for entry in scope_out if str(entry).strip()]

        return cls(
            engagement=str(raw["engagement"]),
            authorized_by=str(raw["authorized_by"]),
            valid_from=parse_datetime(raw["valid_from"], "valid_from"),
            valid_until=parse_datetime(raw["valid_until"], "valid_until"),
            scope_in=[str(entry) for entry in scope_in],
            scope_out=scope_out,
            allowed_techniques=list(raw.get("allowed_techniques") or []),
            limits=Limits.from_mapping(raw.get("limits") or {}),
            testing_window=None if raw.get("testing_window") is None else str(raw["testing_window"]),
            contact_for_incident=str(raw.get("contact_for_incident", "")),
            canary_domain=None if raw.get("canary_domain") is None else str(raw["canary_domain"]),
            raw=raw,
        )

    # -- derived -----------------------------------------------------------

    @property
    def scope(self) -> Scope:
        return Scope(self.scope_in, self.scope_out, default_deny=True)

    def to_summary(self) -> AuthorizationSummary:
        return AuthorizationSummary(
            engagement=self.engagement,
            authorized_by=self.authorized_by,
            valid_from=self.valid_from.isoformat(),
            valid_until=self.valid_until.isoformat(),
            scope_in=list(self.scope_in),
            scope_out=list(self.scope_out),
            techniques=list(self.allowed_techniques),
            contact_for_incident=self.contact_for_incident,
            requests_budget=self.limits.max_total_requests,
        )

    # -- checks ------------------------------------------------------------

    def is_currently_valid(self, now: datetime | None = None) -> bool:
        moment = now or datetime.now(timezone.utc)
        return self.valid_from <= moment <= self.valid_until

    def has_expired(self, now: datetime | None = None) -> bool:
        return (now or datetime.now(timezone.utc)) > self.valid_until

    def not_yet_valid(self, now: datetime | None = None) -> bool:
        return (now or datetime.now(timezone.utc)) < self.valid_from

    def expires_within(self, hours: int = EXPIRY_WARNING_HOURS, now: datetime | None = None) -> bool:
        moment = now or datetime.now(timezone.utc)
        return timedelta(0) <= (self.valid_until - moment) < timedelta(hours=hours)

    def ensure_valid_now(self, now: datetime | None = None) -> None:
        moment = now or datetime.now(timezone.utc)
        if moment < self.valid_from:
            raise AuthorizationError(f"Authorization not yet valid: starts {self.valid_from.isoformat()}")
        if moment > self.valid_until:
            raise AuthorizationError(f"Authorization expired at {self.valid_until.isoformat()}")

    def is_in_scope(self, host: str) -> bool:
        return self.scope.is_allowed(host)

    def is_excluded(self, host: str) -> bool:
        return self.scope.is_excluded(host)

    def ensure_host_in_scope(self, host: str, *, ips: list[str] | None = None) -> None:
        scope = self.scope
        if scope.is_excluded(host, ips):
            raise ScopeError(f"Host '{host}' is excluded by scope.out")
        if not scope.is_allowed(host, ips):
            raise ScopeError(f"Host '{host}' is outside scope.in")

    def technique_allowed(self, technique: str) -> bool:
        return technique in self.allowed_techniques

    def ensure_technique_allowed(self, technique: str) -> None:
        if technique not in self.allowed_techniques:
            raise AuthorizationError(
                f"Technique '{technique}' is not listed in allowed_techniques "
                f"({', '.join(sorted(self.allowed_techniques)) or 'none'})"
            )

    def technique_level(self, technique: str) -> int:
        return TECHNIQUE_LEVELS.get(technique, 99)


def validate_authorization_data(data: Any, *, now: datetime | None = None) -> list[str]:
    """Return a list of problems; an empty list means the file is usable."""

    errors: list[str] = []
    if not isinstance(data, dict):
        return ["authorization file must contain a YAML mapping"]

    for name in REQUIRED_FIELDS:
        if data.get(name) in (None, "", [], {}):
            errors.append(f"missing or empty required field: '{name}'")

    scope = data.get("scope")
    if scope is not None:
        if not isinstance(scope, dict):
            errors.append("'scope' must be a mapping with at least 'in'")
        else:
            scope_in = scope.get("in")
            if isinstance(scope_in, str):
                scope_in = [scope_in]
            if not scope_in:
                errors.append("'scope.in' must list at least one domain, wildcard, IP or CIDR")
            elif not isinstance(scope_in, list):
                errors.append("'scope.in' must be a string or a list of strings")
            scope_out = scope.get("out", [])
            if isinstance(scope_out, str):
                scope_out = [scope_out]
            if not isinstance(scope_out, list):
                errors.append("'scope.out' must be a list of strings")

    techniques = data.get("allowed_techniques")
    if techniques is not None:
        if not isinstance(techniques, list) or not all(isinstance(t, str) for t in techniques):
            errors.append("'allowed_techniques' must be a list of technique names")
        else:
            for technique in techniques:
                if technique not in TECHNIQUE_LEVELS:
                    known = ", ".join(sorted(TECHNIQUE_LEVELS))
                    errors.append(f"unknown technique '{technique}' (known: {known})")

    parsed: dict[str, datetime] = {}
    for name in ("valid_from", "valid_until"):
        if not data.get(name):
            continue
        try:
            parsed[name] = parse_datetime(data[name], name)
        except AuthorizationError as exc:
            errors.append(str(exc))

    if "valid_from" in parsed and "valid_until" in parsed:
        if parsed["valid_from"] >= parsed["valid_until"]:
            errors.append("'valid_from' must be earlier than 'valid_until'")
        moment = now or datetime.now(timezone.utc)
        if parsed["valid_until"] < moment:
            errors.append(f"authorization expired at {parsed['valid_until'].isoformat()}")
        if parsed["valid_from"] > moment:
            errors.append(f"authorization is not valid yet (starts {parsed['valid_from'].isoformat()})")

    if data.get("contact_for_incident") in (None, ""):
        errors.append("missing required field: 'contact_for_incident'")

    limits = data.get("limits")
    if limits is not None:
        try:
            Limits.from_mapping(limits)
        except AuthorizationError as exc:
            errors.append(str(exc))

    return errors


def parse_authorization_file(path: str | Path) -> dict[str, Any]:
    file_path = Path(path)
    if not file_path.is_file():
        raise AuthorizationError(f"authorization file not found: {file_path}")
    try:
        raw = yaml.safe_load(file_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise AuthorizationError(f"authorization file is not valid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise AuthorizationError("authorization file must contain a YAML mapping")
    return raw


def load_authorization(path: str | Path, *, now: datetime | None = None) -> Authorization:
    """Load, validate, and parse an authorization file."""

    raw = parse_authorization_file(path)
    errors = validate_authorization_data(raw, now=now)
    if errors:
        raise AuthorizationError("authorization file rejected:\n" + "\n".join(f"  - {error}" for error in errors))

    return Authorization.from_mapping(raw)


EXAMPLE_AUTHORIZATION = """\
# ReconPulse authorization file -- REQUIRED for active mode.
# Copy to authorization.yaml (which is git-ignored) and fill in real values.
# Active mode refuses to run unless this file is valid and in date.
engagement: "Example Bug Bounty Program - https://example.com/program"
authorized_by: "Jane Doe <security@example.com>"
valid_from: "2026-01-01T00:00:00Z"
valid_until: "2026-12-31T23:59:59Z"
scope:
  in:
    - example.com
    - "*.example.com"
  out:
    - internal.example.com
allowed_techniques:
  - dns_enum
  - tls_check
  - http_methods
  - cors_probe
  - common_paths
limits:
  max_requests_per_second: 1.0
  max_concurrency: 3
  max_total_requests: 500
  per_host_requests: 200
  operational_hours: "09:00-18:00 Asia/Jakarta"
testing_window: "2026-01-01T00:00:00Z/2026-12-31T23:59:59Z"
contact_for_incident: "security@example.com"
# Optional: domain you control, used by the open-redirect check.
canary_domain: "canary.example.net"
"""


def write_example_authorization(path: str | Path = "authorization.example.yaml") -> Path:
    """Write the documented example authorization file."""

    destination = Path(path)
    destination.write_text(EXAMPLE_AUTHORIZATION, encoding="utf-8")
    return destination
