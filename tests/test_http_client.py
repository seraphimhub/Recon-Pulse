"""The guarded HTTP client is the only path to the network; test its guarantees."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from reconpulse.core.audit import verify_chain
from reconpulse.core.budget import Budget
from reconpulse.core.errors import (
    BudgetExhausted,
    CircuitOpen,
    KillSwitchTriggered,
    ScopeError,
    SSRFGuardError,
)
from reconpulse.core.http_client import HTTPClient, HTTPResponse, check_scope
from reconpulse.core.killswitch import KillSwitch
from reconpulse.core.scope import Scope

ClientFactory = Callable[..., HTTPClient]


class TestBasics:
    def test_get_ok(self, site: Any, make_client: ClientFactory) -> None:
        client = make_client()
        response = client.get(site.base_url + "/")
        assert isinstance(response, HTTPResponse)
        assert response.status == 200
        assert "Mock site" in response.text
        assert response.ok
        assert response.method == "GET"
        assert client.request_count == 1

    def test_user_agent_is_identified(self, site: Any, make_client: ClientFactory) -> None:
        client = make_client()
        client.get(site.base_url + "/")
        assert site.requests[0]["headers"]["User-Agent"].startswith("ReconPulse/")

    def test_head_has_no_body(self, site: Any, make_client: ClientFactory) -> None:
        response = make_client().head(site.base_url + "/")
        assert response.status == 200
        assert response.content == b""

    def test_options(self, site: Any, make_client: ClientFactory) -> None:
        response = make_client().options(site.base_url + "/")
        assert "PUT" in response.headers.get("Allow", "")

    def test_json_helper(self, site: Any, make_client: ClientFactory) -> None:
        response = make_client().get(site.base_url + "/api/v1")
        assert response.json() == {"ok": True}
        assert response.content_type.startswith("application/json")

    def test_404_is_returned_not_raised(self, site: Any, make_client: ClientFactory) -> None:
        response = make_client().get(site.base_url + "/missing")
        assert response.status == 404
        assert not response.ok

    def test_write_methods_are_refused_before_any_request(self, site: Any, make_client: ClientFactory) -> None:
        client = make_client()
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            with pytest.raises(SSRFGuardError, match="not permitted"):
                client.request(method, site.base_url + "/login")
        assert site.requests == []


class TestSafety:
    def test_private_host_without_flag(self, make_client: ClientFactory) -> None:
        client = make_client(allow_private=False)
        with pytest.raises(SSRFGuardError):
            client.get("http://127.0.0.1:1/")

    def test_out_of_scope_host(self, make_client: ClientFactory) -> None:
        client = make_client(scope=Scope(["example.com"]))
        with pytest.raises(SSRFGuardError):
            client.get("http://127.0.0.1:1/")

    def test_redirect_to_metadata_is_blocked(self, site: Any, make_client: ClientFactory) -> None:
        client = make_client()
        response = client.get(site.base_url + "/private")
        assert response.status == 302
        assert any("169.254.169.254" in error for error in client.errors)
        assert all("metadata" not in path for path in site.paths())

    def test_redirect_chain_is_recorded(self, site: Any, make_client: ClientFactory) -> None:
        client = make_client()
        response = client.get(site.base_url + "/redirect?next=/admin")
        assert response.status == 200
        assert "admin area" in response.text
        assert response.history
        assert len(site.requests) == 2

    def test_infinite_redirect_stops_at_the_limit(self, site: Any, make_client: ClientFactory) -> None:
        client = make_client()
        response = client.get(site.base_url + "/loop")
        assert response.status == 302
        assert client.request_count <= client.max_redirects + 1

    def test_response_size_is_capped(self, site: Any, make_client: ClientFactory) -> None:
        client = make_client(max_response_bytes=1000)
        response = client.get(site.base_url + "/huge", cache=False)
        assert response.truncated
        assert len(response.content) == 1000

    def test_budget_stops_requests(self, site: Any, make_client: ClientFactory) -> None:
        client = make_client(budget=Budget(max_total=1))
        client.get(site.base_url + "/admin", cache=False)
        with pytest.raises(BudgetExhausted):
            client.get(site.base_url + "/api/v1", cache=False)
        assert len(site.requests) == 1

    def test_circuit_opens_after_blocking_responses(self, site: Any, make_client: ClientFactory) -> None:
        client = make_client()
        client.circuit.failure_threshold = 2
        for index in range(2):
            response = client.get(f"{site.base_url}/blocked?i={index}")
            assert response.status == 403
        with pytest.raises(CircuitOpen):
            client.get(site.base_url + "/blocked?i=3")
        assert len(site.requests) == 2

    def test_kill_switch_stops_before_network(self, site: Any, make_client: ClientFactory) -> None:
        switch = KillSwitch()
        switch.trip()
        client = make_client(kill_switch=switch)
        with pytest.raises(KillSwitchTriggered):
            client.get(site.base_url + "/")
        assert site.requests == []


class TestCacheAndAudit:
    def test_get_is_cached(self, site: Any, make_client: ClientFactory) -> None:
        client = make_client()
        client.get(site.base_url + "/admin")
        client.get(site.base_url + "/admin")
        assert len(site.requests) == 1

    def test_cache_can_be_bypassed(self, site: Any, make_client: ClientFactory) -> None:
        client = make_client()
        client.get(site.base_url + "/admin", cache=False)
        client.get(site.base_url + "/admin", cache=False)
        assert len(site.requests) == 2
        client.clear_cache()

    def test_options_is_not_cached(self, site: Any, make_client: ClientFactory) -> None:
        client = make_client()
        client.options(site.base_url + "/")
        client.options(site.base_url + "/")
        assert len(site.requests) == 2

    def test_audit_log_is_chained_and_leaks_no_secrets(
        self, site: Any, make_client: ClientFactory, tmp_path: Path
    ) -> None:
        from reconpulse.core.audit import AuditLog

        path = tmp_path / "audit.jsonl"
        client = make_client(audit_log=AuditLog(path))
        client.get(site.base_url + "/")
        client.get(site.base_url + "/private")
        assert verify_chain(path)[0]
        text = path.read_text(encoding="utf-8")
        assert "/private" in text
        assert "sid=abc123" not in text


class TestHelpers:
    def test_check_scope_accepts_valid_url(self, site: Any, make_client: ClientFactory) -> None:
        client = make_client()
        assert check_scope(client, site.base_url + "/x") == site.base_url + "/x"

    def test_check_scope_rejects_other_host(self, make_client: ClientFactory) -> None:
        client = make_client(scope=Scope(["127.0.0.1"]), resolver=lambda host: ["93.184.216.34"])
        with pytest.raises(ScopeError):
            check_scope(client, "https://evil.example/")

    def test_context_manager(self, make_client: ClientFactory) -> None:
        with make_client() as client:
            assert client.session is not None
