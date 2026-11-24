"""End-to-end pipeline behaviour against the local mock site."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from reconpulse.core.authorization import DEFAULT_TIER1, load_authorization
from reconpulse.core.config import AppConfig
from reconpulse.core.errors import AuthorizationError
from reconpulse.core.models import Confidence, EvidenceType, ScanMode
from reconpulse.core.scope import Scope
from reconpulse.pipeline import ScanOptions, dry_run_plan, scan_target


def _config() -> AppConfig:
    return AppConfig(
        rate_per_second=1000,
        concurrency=3,
        timeout=5,
        allow_private=True,
        cache_enabled=False,
        max_response_bytes=2_000_000,
    )


def _passive(site: Any) -> Any:
    return scan_target(site.base_url, _config(), ScanOptions(scope=Scope(["127.0.0.1"])))


class TestPassiveScan:
    def test_scan_produces_findings(self, site: Any) -> None:
        report = _passive(site)
        assert report.metadata.mode is ScanMode.PASSIVE
        assert report.findings
        assert report.metadata.request_count > 0
        assert report.risk["score"] > 0
        assert report.risk["level"] in {"low", "medium", "high"}
        assert not report.errors

    def test_every_finding_has_confidence_and_evidence_type(self, site: Any) -> None:
        for finding in _passive(site).findings:
            assert isinstance(finding.confidence, Confidence)
            assert isinstance(finding.evidence_type, EvidenceType)
            assert finding.explanation
            assert finding.verification or finding.remediation

    def test_headers_cookies_and_secrets_are_found(self, site: Any) -> None:
        categories = {finding.category for finding in _passive(site).findings}
        assert {"headers", "cookies", "secrets"} <= categories

    def test_secret_values_are_masked_everywhere(self, site: Any) -> None:
        report = _passive(site)
        import json

        payload = json.dumps(report.to_dict())
        assert "AKIAZ3Q7KJ2MNPQRSTUV" not in payload
        assert "****" in payload

    def test_out_of_scope_script_is_recorded_not_fetched(self, site: Any) -> None:
        report = _passive(site)
        assert any(discovery.host == "cdn.other.example" for discovery in report.out_of_scope)
        assert all("other.example" not in path for path in site.paths())

    def test_metadata_records_the_scope(self, site: Any) -> None:
        report = _passive(site)
        assert report.metadata.scope == ["127.0.0.1"]
        assert report.metadata.user_agent.startswith("ReconPulse/")

    def test_endpoints_and_parameters_are_counted(self, site: Any) -> None:
        config = _passive(site).metadata.config
        assert config["endpoints_discovered"] > 0
        assert config["parameters_discovered"] > 0
        assert config["scripts_analysed"] >= 2

    def test_out_of_scope_target_is_refused(self, site: Any) -> None:
        report = scan_target(
            "https://not-in-scope.example/",
            _config(),
            ScanOptions(scope=Scope(["127.0.0.1"])),
        )
        assert report.errors
        assert not report.findings

    def test_cache_never_leaks_between_targets(self, site: Any) -> None:
        first = _passive(site)
        second = _passive(site)
        assert first.metadata.request_count == second.metadata.request_count


class TestActiveGate:
    def test_active_without_authorization_is_refused(self, site: Any) -> None:
        with pytest.raises(AuthorizationError, match="requires a validated authorization"):
            scan_target(site.base_url, _config(), ScanOptions(mode=ScanMode.ACTIVE))

    def test_active_with_authorization_runs(self, site: Any, authorization: Any) -> None:
        report = scan_target(
            site.base_url,
            _config(),
            ScanOptions(mode=ScanMode.ACTIVE, authorization=authorization, techniques=["common_paths"]),
        )
        assert report.metadata.mode is ScanMode.ACTIVE
        assert report.active_findings > 0
        assert any(finding.evidence_type is EvidenceType.ACTIVE_PROBE for finding in report.findings)
        assert report.metadata.authorization is not None
        assert report.metadata.authorization.engagement == "Mock engagement"

    def test_active_refuses_out_of_scope_target(self, site: Any, authorization: Any) -> None:
        authorization.scope_in = ["example.com"]
        report = scan_target(
            site.base_url,
            _config(),
            ScanOptions(mode=ScanMode.ACTIVE, authorization=authorization, techniques=["common_paths"]),
        )
        assert any("refused" in error for error in report.errors)

    def test_level_two_and_three_techniques(self, site: Any, authorization: Any) -> None:
        report = scan_target(
            site.base_url,
            _config(),
            ScanOptions(
                mode=ScanMode.ACTIVE,
                authorization=authorization,
                techniques=["cors_probe", "http_methods", "graphql_check", "redirect_check", "reflection_check"],
            ),
        )
        titles = {finding.title for finding in report.findings}
        assert "CORS reflects an arbitrary Origin" in titles
        assert "GraphQL endpoint responds at /graphql" in titles
        assert any("Open redirect indicator" in title for title in titles)
        assert any("Input reflected" in title for title in titles)
        assert any("advertises" in title for title in titles)

    def test_disallowed_technique_is_refused(self, site: Any, authorization: Any) -> None:
        authorization.allowed_techniques = ["common_paths"]
        report = scan_target(
            site.base_url,
            _config(),
            ScanOptions(mode=ScanMode.ACTIVE, authorization=authorization, techniques=["port_scan"]),
        )
        assert any("refused" in error for error in report.errors)


class TestDryRun:
    def test_plan_sends_no_requests(self, site: Any, authorization: Any) -> None:
        plan = dry_run_plan(site.base_url, authorization, ["common_paths", "http_methods"])
        assert site.requests == []
        assert plan["estimated_requests"] > 0
        assert {item["technique"] for item in plan["techniques"]} == {"common_paths", "http_methods"}

    def test_plan_defaults_to_tier_one(self, site: Any, authorization: Any) -> None:
        plan = dry_run_plan(site.base_url, authorization, [])
        assert len(plan["techniques"]) == 5
        assert {item["technique"] for item in plan["techniques"]} == set(DEFAULT_TIER1)

    def test_plan_does_not_touch_the_network_for_dns(self, site: Any, authorization: Any) -> None:
        plan = dry_run_plan(site.base_url, authorization, ["dns_enum", "tls_check", "port_scan"])
        assert len(plan["techniques"]) == 3
        assert site.requests == []


class TestAuthorizationFileIntegration:
    def test_authorization_file_drives_the_scan(self, site: Any, make_auth_file: Any) -> None:
        path: Path = make_auth_file()
        authorization = load_authorization(path)
        report = scan_target(
            site.base_url,
            _config(),
            ScanOptions(mode=ScanMode.ACTIVE, authorization=authorization, techniques=["common_paths"]),
        )
        assert not report.errors
        assert report.active_findings > 0
