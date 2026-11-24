"""Append-only, hash-chained audit log (JSONL).

Every HTTP request the tool makes is recorded with enough context to prove what
was sent to a client or bug bounty program. Each record stores the hash of the
previous record, so deleting or editing an entry breaks the chain and
:func:`verify_chain` detects it.

Records deliberately contain no response bodies and no secrets.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS = "GENESIS"

_SENSITIVE_KEYS = {"authorization", "cookie", "set-cookie", "x-api-key", "api-key", "token"}


def _canonical(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(record: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(record).encode("utf-8")).hexdigest()


@dataclass
class AuditRecord:
    """One audited HTTP interaction."""

    timestamp: str
    module: str
    method: str
    url: str
    status: int | None = None
    duration_ms: float | None = None
    bytes_received: int | None = None
    note: str | None = None
    prev: str = GENESIS
    hash: str = field(default="", compare=False)

    def payload(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "timestamp": self.timestamp,
            "module": self.module,
            "method": self.method,
            "url": self.url,
            "status": self.status,
            "duration_ms": None if self.duration_ms is None else round(self.duration_ms, 2),
            "bytes_received": self.bytes_received,
            "note": self.note,
            "prev": self.prev,
        }
        return data

    def to_dict(self) -> dict[str, Any]:
        data = self.payload()
        data["hash"] = self.hash
        return data


class AuditLog:
    """Thread-safe chained JSONL audit log."""

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self._lock = threading.Lock()
        self._records: list[AuditRecord] = []
        self._last_hash = GENESIS
        if self.path and self.path.exists():
            self._load_existing()

    def _load_existing(self) -> None:
        assert self.path is not None
        last_hash = GENESIS
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue
                last_hash = str(data.get("hash") or last_hash)
        self._last_hash = last_hash

    def append(
        self,
        *,
        module: str,
        method: str,
        url: str,
        status: int | None = None,
        duration_ms: float | None = None,
        bytes_received: int | None = None,
        note: str | None = None,
    ) -> AuditRecord:
        with self._lock:
            record = AuditRecord(
                timestamp=datetime.now(timezone.utc).isoformat(),
                module=module,
                method=method.upper(),
                url=url,
                status=status,
                duration_ms=duration_ms,
                bytes_received=bytes_received,
                note=note,
                prev=self._last_hash,
            )
            record.hash = _digest(record.payload())
            self._last_hash = record.hash
            self._records.append(record)
            if self.path:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(record.to_dict(), sort_keys=True) + "\n")
            return record

    @property
    def last_hash(self) -> str:
        return self._last_hash

    def records(self) -> list[AuditRecord]:
        with self._lock:
            return list(self._records)

    def __len__(self) -> int:
        return len(self._records)


def verify_chain(path: str | Path) -> tuple[bool, str]:
    """Verify a persisted audit log. Returns ``(valid, message)``."""

    log_path = Path(path)
    if not log_path.exists():
        return False, f"audit log not found: {log_path}"
    expected_prev = GENESIS
    count = 0
    with log_path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                return False, f"line {line_number}: not valid JSON"
            count += 1
            if data.get("prev") != expected_prev:
                return False, f"line {line_number}: broken chain (prev does not match)"
            stored_hash = data.pop("hash", None)
            if stored_hash != _digest(data):
                return False, f"line {line_number}: hash mismatch (record modified)"
            expected_prev = stored_hash
    if count == 0:
        return False, "audit log is empty"
    return True, f"audit log OK ({count} records)"
