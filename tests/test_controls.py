"""Operational controls: audit chain, budget, circuit breaker, rate limit, kill switch."""

from __future__ import annotations

from pathlib import Path

import pytest

from reconpulse.core.audit import AuditLog, verify_chain
from reconpulse.core.budget import Budget
from reconpulse.core.circuit import CircuitBreaker
from reconpulse.core.errors import BudgetExhausted, CircuitOpen, KillSwitchTriggered
from reconpulse.core.killswitch import KillSwitch
from reconpulse.core.ratelimit import RateLimiter


class TestAuditChain:
    def _write(self, path: Path, count: int) -> AuditLog:
        log = AuditLog(path)
        for index in range(count):
            log.append(module="test", method="GET", url=f"https://example.com/{index}", status=200)
        return log

    def test_chain_verifies(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        log = self._write(path, 3)
        assert len(log) == 3
        ok, message = verify_chain(path)
        assert ok
        assert "3 records" in message

    def test_records_link_to_previous_hash(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        log = self._write(path, 2)
        first, second = log.records()
        assert second.prev == first.hash
        assert first.hash != second.hash

    def test_tampering_is_detected(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        self._write(path, 3)
        lines = path.read_text(encoding="utf-8").splitlines()
        lines[1] = lines[1].replace('"status": 200', '"status": 201')
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        ok, message = verify_chain(path)
        assert not ok
        assert "hash mismatch" in message

    def test_deleted_record_breaks_the_chain(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        self._write(path, 3)
        lines = path.read_text(encoding="utf-8").splitlines()
        del lines[1]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        ok, message = verify_chain(path)
        assert not ok
        assert "broken chain" in message

    def test_invalid_json_is_reported(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        path.write_text("{not json}\n", encoding="utf-8")
        ok, message = verify_chain(path)
        assert not ok
        assert "not valid JSON" in message

    def test_empty_and_missing_file(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty.jsonl"
        empty.write_text("", encoding="utf-8")
        assert verify_chain(empty)[0] is False
        assert verify_chain(tmp_path / "absent.jsonl")[0] is False

    def test_reopening_continues_the_chain(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        self._write(path, 1)
        second = AuditLog(path)
        second.append(module="test", method="HEAD", url="https://example.com/again", status=200)
        assert verify_chain(path)[0]

    def test_note_and_duration_are_recorded(self, tmp_path: Path) -> None:
        log = AuditLog(tmp_path / "audit.jsonl")
        record = log.append(module="test", method="post", url="u", status=None, duration_ms=1.23456, note="timeout")
        assert record.method == "POST"
        assert record.to_dict()["duration_ms"] == 1.23
        assert record.to_dict()["note"] == "timeout"


class TestBudget:
    def test_unlimited(self) -> None:
        budget = Budget()
        for _ in range(5):
            budget.consume("example.com")
        assert budget.used == 5
        assert budget.remaining is None
        assert not budget.would_exceed("example.com")

    def test_global_limit(self) -> None:
        budget = Budget(max_total=2)
        budget.consume()
        budget.consume()
        assert budget.remaining == 0
        assert budget.would_exceed()
        with pytest.raises(BudgetExhausted, match="budget exhausted"):
            budget.consume()

    def test_per_host_limit(self) -> None:
        budget = Budget(max_total=10, max_per_host=2)
        budget.consume("a.example")
        budget.consume("a.example")
        assert budget.host_used("a.example") == 2
        assert budget.would_exceed("a.example")
        with pytest.raises(BudgetExhausted, match="Per-host"):
            budget.consume("a.example")
        budget.consume("b.example")
        assert budget.host_used("b.example") == 1

    def test_snapshot(self) -> None:
        budget = Budget(max_total=5)
        budget.consume("h")
        snapshot = budget.snapshot()
        assert snapshot["used"] == 1
        assert snapshot["remaining"] == 4
        assert snapshot["per_host"] == {}

    def test_negative_total(self) -> None:
        with pytest.raises(ValueError):
            Budget(max_total=-1)


class TestCircuitBreaker:
    def test_trips_on_blocking_statuses(self) -> None:
        breaker = CircuitBreaker(failure_threshold=2, timeout_streak=2)
        breaker.record_status("h", 403)
        breaker.check("h")
        breaker.record_status("h", 429)
        assert breaker.is_open("h")
        with pytest.raises(CircuitOpen, match="blocking responses"):
            breaker.check("h")

    def test_success_resets_failures(self) -> None:
        breaker = CircuitBreaker(failure_threshold=2, timeout_streak=2)
        breaker.record_status("h", 500)
        breaker.record_status("h", 200)
        breaker.record_status("h", 503)
        assert not breaker.is_open("h")

    def test_trips_on_timeout_streak(self) -> None:
        breaker = CircuitBreaker(failure_threshold=5, timeout_streak=2)
        breaker.record_timeout("h")
        breaker.record_timeout("h")
        assert breaker.is_open("h")
        # Once open, only an explicit reset closes it.
        breaker.record_success("h")
        assert breaker.is_open("h")
        breaker.reset()
        assert not breaker.is_open("h")

    def test_manual_trip_and_reset(self) -> None:
        breaker = CircuitBreaker()
        breaker.trip("h", "operator")
        assert breaker.open_hosts() == {"h": "operator"}
        breaker.reset()
        assert breaker.open_hosts() == {}


class TestRateLimiter:
    def test_minimum_interval_is_enforced(self) -> None:
        limiter = RateLimiter(rate_per_second=50)
        slept = limiter.wait("example.com")
        slept += limiter.wait("example.com")
        assert slept > 0

    def test_reset(self) -> None:
        limiter = RateLimiter(rate_per_second=1000)
        limiter.wait()
        limiter.reset()
        assert limiter.wait() == 0.0

    def test_invalid_rate(self) -> None:
        with pytest.raises(ValueError):
            RateLimiter(rate_per_second=0)

    def test_per_host_interval(self) -> None:
        limiter = RateLimiter(rate_per_second=1000, per_host_rate=1000)
        limiter.wait("a")
        assert limiter.wait("a") > 0
        assert limiter.wait("b") >= 0.0


class TestKillSwitch:
    def test_trip_and_reset(self) -> None:
        switch = KillSwitch()
        switch.check()
        switch.trip()
        assert switch.triggered
        with pytest.raises(KillSwitchTriggered):
            switch.check()
        switch.reset()
        assert not switch.triggered
        switch.check()
