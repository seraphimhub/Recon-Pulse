"""Shared fixtures: a local mock site, a guarded client, and authorization files.

The tests never touch the network. Every HTTP request goes to a threaded
``ThreadingHTTPServer`` bound to 127.0.0.1 on an ephemeral port.
"""

from __future__ import annotations

import copy
import threading
from collections.abc import Callable, Iterator
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
import yaml

from reconpulse.core.authorization import TECHNIQUE_LEVELS, Authorization
from reconpulse.core.config import AppConfig
from reconpulse.core.http_client import HTTPClient
from reconpulse.core.scope import Scope

PAGE_HTML = """<!doctype html>
<html>
  <head>
    <title>Mock site</title>
    <meta name="generator" content="WordPress 6.2">
    <script src="/static/app.js"></script>
    <script src="https://cdn.other.example/ext.js"></script>
    <script>var apiKey = "AKIAZ3Q7KJ2MNPQRSTUV";</script>
  </head>
  <body>
    <h1>Welcome</h1>
    <a href="/admin">Admin</a>
    <a href="/search?q=hello">Search</a>
    <a href="/redirect?next=/home">Home</a>
    <form action="/login" method="post">
      <input name="username">
      <input name="password" type="password">
    </form>
  </body>
</html>
"""

APP_JS = """\
fetch("/api/v1/users?id=42&sort=asc");
fetch("/api/v1/orders?next=/home&id=7");
const stripe = "not-a-real-key";
//# sourceMappingURL=app.js.map
"""

SECURITY_TXT = "Contact: mailto:security@example.com\nExpires: 2030-01-01T00:00:00Z\n"

ROBOTS_TXT = "User-agent: *\nDisallow: /admin\nDisallow: /backup\n"


class MockHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "MockSite/1.0"

    def log_message(self, *args: object) -> None:  # keep the test output clean
        pass

    # -- helpers -----------------------------------------------------------

    def _send(
        self,
        status: int,
        body: bytes = b"",
        content_type: str = "text/html; charset=utf-8",
        headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        origin = self.headers.get("Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _record(self) -> None:
        self.server.requests.append(  # type: ignore[attr-defined]
            {"method": self.command, "path": self.path, "headers": dict(self.headers)}
        )

    def _route(self) -> None:
        self._record()
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if self.command == "OPTIONS":
            self._send(200, b"", "text/plain", {"Allow": "GET, HEAD, OPTIONS, PUT"})
            return

        if path == "/":
            self._send(200, PAGE_HTML.encode(), headers={"Set-Cookie": "sid=abc123; Path=/"})
        elif path == "/static/app.js":
            self._send(200, APP_JS.encode(), "application/javascript")
        elif path == "/app.js.map":
            self._send(200, b'{"version": 3}', "application/json")
        elif path == "/robots.txt":
            self._send(200, ROBOTS_TXT.encode(), "text/plain")
        elif path == "/.well-known/security.txt":
            self._send(200, SECURITY_TXT.encode(), "text/plain")
        elif path == "/search":
            value = query.get("q", [""])[0]
            body = f"<html><body><p>Results for {value}</p></body></html>"
            self._send(200, body.encode())
        elif path == "/redirect":
            target = query.get("next", ["/"])[0]
            self._send(302, b"", "text/plain", {"Location": target})
        elif path == "/loop":
            self._send(302, b"", "text/plain", {"Location": "/loop"})
        elif path == "/private":
            self._send(302, b"", "text/plain", {"Location": "http://169.254.169.254/latest/meta-data/"})
        elif path == "/blocked":
            self._send(403, b"forbidden", "text/plain")
        elif path == "/huge":
            self._send(200, b"A" * 100_000, "text/plain")
        elif path == "/graphql":
            if query.get("query") == ["{__typename}"]:
                self._send(200, b'{"data": {"__typename": "Query"}}', "application/json")
            else:
                self._send(400, b'{"errors": []}', "application/json")
        elif path == "/admin":
            self._send(200, b"<html><body>admin area</body></html>")
        elif path == "/api/v1":
            self._send(200, b'{"ok": true}', "application/json")
        elif path == "/api/v1/users":
            self._send(200, b'{"users": []}', "application/json")
        elif path == "/actuator/health":
            self._send(200, b'{"status": "UP"}', "application/json")
        elif path == "/login":
            self._send(200, b"<html><body>login</body></html>")
        else:
            self._send(404, b"not found", "text/plain")

    do_GET = _route
    do_HEAD = _route
    do_OPTIONS = _route

    def do_POST(self) -> None:  # pragma: no cover - the client never sends POST
        self._send(405, b"method not allowed", "text/plain")


class MockSite:
    def __init__(self, server: ThreadingHTTPServer, thread: threading.Thread) -> None:
        self._server = server
        self._thread = thread
        host, port = server.server_address[:2]
        self.base_url = f"http://{host}:{port}"
        self.requests: list[dict[str, Any]] = server.requests  # type: ignore[attr-defined]

    def paths(self) -> list[str]:
        return [request["path"] for request in self.requests]

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


@pytest.fixture
def site() -> Iterator[MockSite]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), MockHandler)
    server.daemon_threads = True
    server.requests = []  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    mock = MockSite(server, thread)
    try:
        yield mock
    finally:
        mock.close()


@pytest.fixture
def make_client(site: MockSite) -> Iterator[Callable[..., HTTPClient]]:
    """Factory for guarded clients pointed at the mock site."""

    created: list[HTTPClient] = []

    def _make(**kwargs: Any) -> HTTPClient:
        config_kwargs: dict[str, Any] = {
            "rate_per_second": 1000.0,
            "concurrency": 2,
            "timeout": 5,
            "allow_private": True,
            "cache_enabled": kwargs.pop("cache_enabled", True),
            "max_response_bytes": kwargs.pop("max_response_bytes", 2_000_000),
        }
        config = AppConfig(**config_kwargs)
        scope = kwargs.pop("scope", Scope(["127.0.0.1"]))
        client = HTTPClient(config, scope=scope, **kwargs)
        created.append(client)
        return client

    try:
        yield _make
    finally:
        for client in created:
            client.close()


@pytest.fixture
def authorization_raw() -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    return {
        "engagement": "Mock engagement",
        "authorized_by": "Tester <tester@example.com>",
        "valid_from": (now - timedelta(days=1)).isoformat(),
        "valid_until": (now + timedelta(days=1)).isoformat(),
        "scope": {"in": ["127.0.0.1"], "out": []},
        "allowed_techniques": sorted(TECHNIQUE_LEVELS),
        "limits": {
            "max_requests_per_second": 1000,
            "max_concurrency": 3,
            "max_total_requests": 500,
            "per_host_requests": 500,
        },
        "testing_window": "always",
        "contact_for_incident": "tester@example.com",
        "canary_domain": "canary.example.net",
    }


@pytest.fixture
def authorization(authorization_raw: dict[str, Any]) -> Authorization:
    return Authorization.from_mapping(authorization_raw)


@pytest.fixture
def make_auth_file(tmp_path: Path, authorization_raw: dict[str, Any]) -> Callable[..., Path]:
    counter = {"n": 0}

    def _make(**overrides: Any) -> Path:
        raw = copy.deepcopy(authorization_raw)
        raw.update(overrides)
        counter["n"] += 1
        path = tmp_path / f"authorization-{counter['n']}.yaml"
        path.write_text(yaml.safe_dump(raw), encoding="utf-8")
        return path

    return _make
