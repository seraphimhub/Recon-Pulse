"""Request budget accounting (global and per host)."""

from __future__ import annotations

import threading
from typing import Any

from .errors import BudgetExhausted


class Budget:
    """Counts requests and refuses more once a ceiling is reached.

    ``max_total`` is the global budget for the whole run; ``max_per_host`` caps
    a single host so one noisy target cannot consume the global budget.
    """

    def __init__(self, max_total: int | None = None, max_per_host: int | None = None):
        if max_total is not None and max_total < 0:
            raise ValueError("max_total must be >= 0")
        self.max_total = max_total
        self.max_per_host = max_per_host
        self._total = 0
        self._per_host: dict[str, int] = {}
        self._lock = threading.Lock()

    @property
    def used(self) -> int:
        return self._total

    @property
    def remaining(self) -> int | None:
        if self.max_total is None:
            return None
        return max(self.max_total - self._total, 0)

    def host_used(self, host: str) -> int:
        return self._per_host.get(host, 0)

    def would_exceed(self, host: str | None = None) -> bool:
        if self.max_total is not None and self._total >= self.max_total:
            return True
        return bool(host and self.max_per_host is not None and self._per_host.get(host, 0) >= self.max_per_host)

    def consume(self, host: str | None = None, amount: int = 1) -> None:
        """Reserve ``amount`` requests or raise :class:`BudgetExhausted`."""

        with self._lock:
            if self.max_total is not None and self._total + amount > self.max_total:
                raise BudgetExhausted(f"Request budget exhausted ({self._total}/{self.max_total} used)")
            if host and self.max_per_host is not None:
                used = self._per_host.get(host, 0)
                if used + amount > self.max_per_host:
                    raise BudgetExhausted(f"Per-host budget exhausted for {host} ({used}/{self.max_per_host} used)")
                self._per_host[host] = used + amount
            self._total += amount

    def snapshot(self) -> dict[str, Any]:
        return {
            "used": self._total,
            "max_total": self.max_total,
            "remaining": self.remaining,
            "per_host": dict(self._per_host),
        }
