"""Exception hierarchy for ReconPulse.

All tool-specific failures derive from :class:`ReconPulseError` so callers can
distinguish expected, human-readable failures from unexpected bugs.
"""

from __future__ import annotations


class ReconPulseError(Exception):
    """Base class for every error raised deliberately by ReconPulse."""


class ConfigError(ReconPulseError):
    """Invalid configuration (file, environment variable, or CLI flag)."""


class AuthorizationError(ReconPulseError):
    """Authorization file missing, malformed, expired, or out of scope."""


class ScopeError(ReconPulseError):
    """A URL or host falls outside the authorized scope."""


class SSRFGuardError(ReconPulseError):
    """A URL would make the tool talk to a private/reserved address."""


class NetworkError(ReconPulseError):
    """A request failed after retries (DNS, connection, TLS, timeout)."""


class ResponseTooLarge(ReconPulseError):
    """A response exceeded the configured size limit."""


class BudgetExhausted(ReconPulseError):
    """The configured request budget has been consumed."""


class CircuitOpen(ReconPulseError):
    """A host is being blocked (429/5xx/timeouts) and the breaker is open."""


class KillSwitchTriggered(ReconPulseError):
    """The operator interrupted the run; workers must stop cleanly."""
