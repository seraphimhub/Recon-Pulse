"""The one HTTP client every ReconPulse module must use.

Responsibilities:

* session reuse and a configurable, identifying User-Agent
* retry with exponential backoff, bounded timeout and bounded response size
* global and per-host rate limiting
* scope allowlist and SSRF guard on **every** request and every redirect hop
* request budget, per-host circuit breaker, and cooperative kill switch
* hash-chained audit logging of each request
* optional in-memory response cache

No module is allowed to call ``requests`` directly; that is what makes the
guarantees above enforceable.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from requests.structures import CaseInsensitiveDict

from .audit import AuditLog
from .budget import Budget
from .circuit import CircuitBreaker
from .config import AppConfig
from .errors import CircuitOpen, NetworkError, ScopeError, SSRFGuardError
from .killswitch import KillSwitch
from .netguard import Resolver, ValidatedURL, validate_url
from .ratelimit import RateLimiter
from .scope import Scope

REDIRECT_STATUSES = {301, 302, 303, 307, 308}


def _build_user_agent(template: str, version: str) -> str:
    return template.replace("{version}", version)


@dataclass
class HTTPResponse:
    """A response already read into memory (subject to the size cap)."""

    url: str
    status: int
    headers: CaseInsensitiveDict = field(default_factory=CaseInsensitiveDict)
    text: str = ""
    content: bytes = b""
    elapsed_ms: float = 0.0
    history: list[str] = field(default_factory=list)
    truncated: bool = False
    method: str = "GET"

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400

    @property
    def content_type(self) -> str:
        return self.headers.get("Content-Type", "")

    def json(self) -> Any:
        import json

        return json.loads(self.text)


class HTTPClient:
    """Guarded HTTP client shared by collectors and active modules."""

    def __init__(
        self,
        config: AppConfig | None = None,
        *,
        scope: Scope | None = None,
        allow_private: bool | None = None,
        user_agent: str | None = None,
        audit_log: AuditLog | None = None,
        budget: Budget | None = None,
        circuit: CircuitBreaker | None = None,
        kill_switch: KillSwitch | None = None,
        rate_limiter: RateLimiter | None = None,
        resolver: Resolver | None = None,
        version: str = "2.0.0",
    ) -> None:
        self.config = config or AppConfig()
        self.scope = scope
        self.allow_private = self.config.allow_private if allow_private is None else allow_private
        self.user_agent = _build_user_agent(user_agent or self.config.user_agent, version)
        self.audit_log = audit_log
        self.budget = budget
        self.circuit = circuit or CircuitBreaker(
            failure_threshold=self.config.circuit_failure_threshold,
            timeout_streak=self.config.circuit_timeout_streak,
        )
        self.kill_switch = kill_switch or KillSwitch()
        self.rate_limiter = rate_limiter or RateLimiter(
            rate_per_second=self.config.rate_per_second,
            per_host_rate=self.config.per_host_rate,
        )
        self.resolver = resolver
        self.max_redirects = self.config.max_redirects
        self.timeout = self.config.timeout
        self.max_bytes = self.config.max_response_bytes
        self.verify_tls = self.config.verify_tls
        self.cache_enabled = self.config.cache_enabled

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.user_agent, "Accept": "*/*"})
        self._cache: dict[tuple[str, str], HTTPResponse] = {}
        self._cache_lock = threading.Lock()
        self._request_count = 0
        self._count_lock = threading.Lock()
        self.errors: list[str] = []

    # -- introspection ------------------------------------------------------

    @property
    def request_count(self) -> int:
        return self._request_count

    def _bump_count(self) -> None:
        with self._count_lock:
            self._request_count += 1

    # -- public verbs -------------------------------------------------------

    def get(
        self,
        url: str,
        *,
        module: str = "passive",
        headers: Mapping[str, str] | None = None,
        allow_redirects: bool = True,
        cache: bool | None = None,
        use_auth: bool = True,
    ) -> HTTPResponse:
        return self.request(
            "GET",
            url,
            module=module,
            headers=headers,
            allow_redirects=allow_redirects,
            cache=cache,
            use_auth=use_auth,
        )

    def head(
        self,
        url: str,
        *,
        module: str = "passive",
        headers: Mapping[str, str] | None = None,
        allow_redirects: bool = True,
    ) -> HTTPResponse:
        return self.request("HEAD", url, module=module, headers=headers, allow_redirects=allow_redirects)

    def options(
        self,
        url: str,
        *,
        module: str = "passive",
        headers: Mapping[str, str] | None = None,
        allow_redirects: bool = False,
    ) -> HTTPResponse:
        return self.request("OPTIONS", url, module=module, headers=headers, allow_redirects=allow_redirects)

    # -- core request pipeline ---------------------------------------------

    def request(
        self,
        method: str,
        url: str,
        *,
        module: str = "passive",
        headers: Mapping[str, str] | None = None,
        allow_redirects: bool = True,
        cache: bool | None = None,
        use_auth: bool = True,
        _hop: int = 0,
        _history: list[str] | None = None,
    ) -> HTTPResponse:
        method = method.upper()
        if method not in {"GET", "HEAD", "OPTIONS"}:
            raise SSRFGuardError(f"HTTP method {method} is not permitted (read-only tool)")

        history = _history or []
        use_cache = self.cache_enabled if cache is None else cache
        cache_key = (method, url)
        if use_cache and method in {"GET", "HEAD"}:
            with self._cache_lock:
                cached = self._cache.get(cache_key)
            if cached is not None:
                return cached

        self.kill_switch.check()
        host = (urlparse(url).hostname or "").lower()
        self.circuit.check(host)
        if self.budget is not None:
            self.budget.consume(host)  # raises BudgetExhausted
        self.rate_limiter.wait(host)

        validated = validate_url(
            url,
            allow_private=self.allow_private,
            scope=self.scope,
            resolver=self.resolver,
        )
        response = self._send_with_retries(method, validated, module=module, headers=headers, use_auth=use_auth)
        response.history = list(history)
        self._bump_count()
        self.circuit.record_status(host, response.status)

        if allow_redirects and response.status in REDIRECT_STATUSES and _hop < self.max_redirects:
            location = response.headers.get("Location", "").strip()
            if location:
                target = urljoin(response.url, location)
                if urlparse(target).scheme.lower() in ("http", "https"):
                    history.append(response.url)
                    try:
                        redirected = self.request(
                            method,
                            target,
                            module=module,
                            headers=headers,
                            allow_redirects=True,
                            cache=cache,
                            use_auth=use_auth,
                            _hop=_hop + 1,
                            _history=history,
                        )
                    except (SSRFGuardError, ScopeError, NetworkError) as exc:
                        self.errors.append(f"blocked redirect {response.url} -> {target}: {exc}")
                        return response
                    self._audit(
                        module=module,
                        method=method,
                        url=response.url,
                        status=response.status,
                        duration_ms=response.elapsed_ms,
                        bytes_received=len(response.content),
                        note=f"redirect to {target}",
                    )
                    return redirected

        if use_cache and method in {"GET", "HEAD"}:
            with self._cache_lock:
                self._cache[cache_key] = response
        return response

    def _send_with_retries(
        self,
        method: str,
        validated: ValidatedURL,
        *,
        module: str,
        headers: Mapping[str, str] | None,
        use_auth: bool,
    ) -> HTTPResponse:
        attempts = 3
        last_error: Exception | None = None
        merged_headers = dict(headers or {})
        if use_auth and self._client_auth_header(validated.host):
            merged_headers.setdefault("Authorization", self._client_auth_header(validated.host) or "")

        for attempt in range(attempts):
            self.kill_switch.check()
            started = time.perf_counter()
            try:
                raw = self.session.request(
                    method,
                    validated.url,
                    timeout=self.timeout,
                    allow_redirects=False,
                    headers=merged_headers or None,
                    stream=True,
                    verify=self.verify_tls,
                )
                content, truncated = self._read_limited(raw)
                elapsed_ms = (time.perf_counter() - started) * 1000
                response = HTTPResponse(
                    url=validated.url,
                    status=raw.status_code,
                    headers=CaseInsensitiveDict(raw.headers),
                    content=content,
                    text=self._decode(content, raw.headers.get("Content-Type", "")),
                    elapsed_ms=elapsed_ms,
                    truncated=truncated,
                    method=method,
                )
                self._audit(
                    module=module,
                    method=method,
                    url=validated.url,
                    status=response.status,
                    duration_ms=elapsed_ms,
                    bytes_received=len(content),
                )
                raw.close()
                return response
            except requests.Timeout as exc:
                last_error = exc
                self.circuit.record_timeout(validated.host)
                self._audit(
                    module=module,
                    method=method,
                    url=validated.url,
                    status=None,
                    duration_ms=(time.perf_counter() - started) * 1000,
                    note="timeout",
                )
                if self.circuit.is_open(validated.host):
                    raise CircuitOpen(f"Circuit opened for {validated.host} after repeated timeouts") from exc
            except requests.RequestException as exc:
                last_error = exc
                self._audit(
                    module=module,
                    method=method,
                    url=validated.url,
                    status=None,
                    duration_ms=(time.perf_counter() - started) * 1000,
                    note=f"error: {type(exc).__name__}",
                )
            if attempt < attempts - 1:
                time.sleep(0.5 * (2**attempt))
        raise NetworkError(f"{method} {validated.url} failed after {attempts} attempts: {last_error}")

    def _read_limited(self, raw: requests.Response) -> tuple[bytes, bool]:
        chunks: list[bytes] = []
        total = 0
        truncated = False
        try:
            for chunk in raw.iter_content(chunk_size=16384):
                if not chunk:
                    continue
                total += len(chunk)
                if total > self.max_bytes:
                    keep = len(chunk) - (total - self.max_bytes)
                    if keep > 0:
                        chunks.append(chunk[:keep])
                    truncated = True
                    break
                chunks.append(chunk)
        except Exception:  # pragma: no cover - streaming errors are network errors
            pass
        return b"".join(chunks), truncated

    @staticmethod
    def _decode(content: bytes, content_type: str) -> str:
        if not content:
            return ""
        charset = "utf-8"
        if "charset=" in content_type.lower():
            charset = content_type.lower().split("charset=", 1)[1].split(";")[0].strip() or "utf-8"
        try:
            return content.decode(charset, errors="replace")
        except LookupError:
            return content.decode("utf-8", errors="replace")

    @staticmethod
    def _client_auth_header(host: str) -> str | None:
        """Reserved: engagement-supplied credentials are never stored by the tool."""

        return None

    def _audit(
        self,
        *,
        module: str,
        method: str,
        url: str,
        status: int | None,
        duration_ms: float | None,
        bytes_received: int | None = None,
        note: str | None = None,
    ) -> None:
        if self.audit_log is None:
            return
        self.audit_log.append(
            module=module,
            method=method,
            url=url,
            status=status,
            duration_ms=duration_ms,
            bytes_received=bytes_received,
            note=note,
        )

    def clear_cache(self) -> None:
        with self._cache_lock:
            self._cache.clear()

    def close(self) -> None:
        with suppress(Exception):
            self.session.close()

    def __enter__(self) -> HTTPClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


def check_scope(client: HTTPClient, url: str) -> str:
    """Convenience helper: validate a URL without sending a request."""

    return validate_url(
        url,
        allow_private=client.allow_private,
        scope=client.scope,
        resolver=client.resolver,
    ).url
