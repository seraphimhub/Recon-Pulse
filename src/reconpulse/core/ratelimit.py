"""Conservative rate limiting, global and per host."""

from __future__ import annotations

import threading
import time

DEFAULT_RATE_PER_SECOND = 1.0


class RateLimiter:
    """Minimum-interval limiter shared by all workers.

    A single instance is used by :class:`~reconpulse.core.http_client.HTTPClient`
    so the configured rate applies across threads and hosts. An optional
    per-host interval is enforced on top of the global one.
    """

    def __init__(self, rate_per_second: float = DEFAULT_RATE_PER_SECOND, per_host_rate: float | None = None):
        if rate_per_second <= 0:
            raise ValueError("rate_per_second must be positive")
        self.rate_per_second = rate_per_second
        self.interval = 1.0 / rate_per_second
        self.per_host_interval = (1.0 / per_host_rate) if per_host_rate and per_host_rate > 0 else None
        self._lock = threading.Lock()
        self._last_global = 0.0
        self._last_per_host: dict[str, float] = {}
        self._sleep = time.sleep

    def wait(self, host: str | None = None) -> float:
        """Block until the next request is allowed. Returns seconds slept."""

        slept = 0.0
        with self._lock:
            now = time.monotonic()
            earliest = self._last_global + self.interval
            if host and self.per_host_interval is not None:
                earliest = max(earliest, self._last_per_host.get(host, 0.0) + self.per_host_interval)
            if earliest > now:
                slept = earliest - now
                self._sleep(slept)
            stamp = time.monotonic()
            self._last_global = stamp
            if host and self.per_host_interval is not None:
                self._last_per_host[host] = stamp
        return slept

    def reset(self) -> None:
        with self._lock:
            self._last_global = 0.0
            self._last_per_host.clear()
