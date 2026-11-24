"""Core building blocks: HTTP client, guards, configuration, authorization."""

from __future__ import annotations

from .audit import AuditLog, AuditRecord, verify_chain
from .authorization import (
    DEFAULT_TIER1,
    EXAMPLE_AUTHORIZATION,
    TECHNIQUE_LEVELS,
    Authorization,
    Limits,
    load_authorization,
    validate_authorization_data,
    write_example_authorization,
)
from .budget import Budget
from .circuit import CircuitBreaker
from .config import DEFAULT_USER_AGENT, AppConfig
from .errors import (
    AuthorizationError,
    BudgetExhausted,
    CircuitOpen,
    ConfigError,
    KillSwitchTriggered,
    NetworkError,
    ReconPulseError,
    ResponseTooLarge,
    ScopeError,
    SSRFGuardError,
)
from .http_client import HTTPClient, HTTPResponse
from .killswitch import KillSwitch
from .models import (
    AuthorizationSummary,
    Confidence,
    EvidenceType,
    Finding,
    OutOfScopeDiscovery,
    ScanMetadata,
    ScanMode,
    ScanReport,
    Severity,
)
from .netguard import ValidatedURL, is_blocked_address, parse_ip_literal, validate_url
from .ratelimit import RateLimiter
from .scope import Scope

__all__ = [
    "DEFAULT_TIER1",
    "DEFAULT_USER_AGENT",
    "EXAMPLE_AUTHORIZATION",
    "TECHNIQUE_LEVELS",
    "AppConfig",
    "AuditLog",
    "AuditRecord",
    "Authorization",
    "AuthorizationError",
    "AuthorizationSummary",
    "Budget",
    "BudgetExhausted",
    "CircuitBreaker",
    "CircuitOpen",
    "Confidence",
    "ConfigError",
    "EvidenceType",
    "Finding",
    "HTTPClient",
    "HTTPResponse",
    "KillSwitch",
    "KillSwitchTriggered",
    "Limits",
    "NetworkError",
    "OutOfScopeDiscovery",
    "RateLimiter",
    "ReconPulseError",
    "ResponseTooLarge",
    "SSRFGuardError",
    "ScanMetadata",
    "ScanMode",
    "ScanReport",
    "Scope",
    "ScopeError",
    "Severity",
    "ValidatedURL",
    "is_blocked_address",
    "load_authorization",
    "parse_ip_literal",
    "validate_authorization_data",
    "validate_url",
    "verify_chain",
    "write_example_authorization",
]
