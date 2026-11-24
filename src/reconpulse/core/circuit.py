"""Per-host circuit breaker.

The breaker stops a host when it looks like we are being blocked: repeated 429
or 5xx responses, or a streak of timeouts. ReconPulse never tries to evade a
block (no IP or User-Agent rotation), it simply stops and reports.
"""

from __future__ import annotations

import threading

from .errors import CircuitOpen

DEFAULT_FAILURE_THRESHOLD = 5
DEFAULT_TIMEOUT_STREAK = 3


class CircuitBreaker:
    """Track failures per host and trip after a configured threshold."""

    def __init__(
        self,
        failure_threshold: int = DEFAULT_FAILURE_THRESHOLD,
        timeout_streak: int = DEFAULT_TIMEOUT_STREAK,
    ):
        self.failure_threshold = failure_threshold
        self.timeout_streak = timeout_streak
        self._failures: dict[str, int] = {}
        self._timeouts: dict[str, int] = {}
        self._open: dict[str, str] = {}
        self._lock = threading.Lock()

    def check(self, host: str) -> None:
        with self._lock:
            reason = self._open.get(host)
        if reason:
            raise CircuitOpen(f"Circuit open for {host}: {reason}")

    def is_open(self, host: str) -> bool:
        with self._lock:
            return host in self._open

    def record_success(self, host: str) -> None:
        with self._lock:
            self._failures.pop(host, None)
            self._timeouts.pop(host, None)

    def record_status(self, host: str, status: int | None) -> None:
        """Feed an HTTP status into the breaker."""

        if status is not None and 200 <= status < 400:
            self.record_success(host)
            return
        if status in (429, 403, 503) or (status is not None and 500 <= status < 600):
            with self._lock:
                count = self._failures.get(host, 0) + 1
                self._failures[host] = count
                if count >= self.failure_threshold:
                    self._open[host] = f"{count} blocking responses (last status {status})"

    def record_timeout(self, host: str) -> None:
        with self._lock:
            count = self._timeouts.get(host, 0) + 1
            self._timeouts[host] = count
            if count >= self.timeout_streak:
                self._open[host] = f"{count} consecutive timeouts"

    def trip(self, host: str, reason: str) -> None:
        with self._lock:
            self._open[host] = reason

    def open_hosts(self) -> dict[str, str]:
        with self._lock:
            return dict(self._open)

    def reset(self) -> None:
        with self._lock:
            self._failures.clear()
            self._timeouts.clear()
            self._open.clear()
