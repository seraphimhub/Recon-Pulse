"""Static analyzers: secrets, headers, cookies, CORS, endpoints, parameters."""

from __future__ import annotations

import json

from reconpulse.analyzers.cookies import analyze_cookies, parse_set_cookie
from reconpulse.analyzers.cors import analyze_cors
from reconpulse.analyzers.endpoints import (
    classify_path,
    discover_endpoints,
    endpoint_findings,
)
from reconpulse.analyzers.headers_audit import analyze_security_headers
from reconpulse.analyzers.params import analyze_parameters, extract_parameters
from reconpulse.analyzers.secrets import find_secrets, is_placeholder, mask_secret, secret_findings
from reconpulse.analyzers.tech import fingerprint_headers, fingerprint_html, technology_findings
from reconpulse.core.models import Confidence, EvidenceType

AWS_KEY = "AKIAZ3Q7KJ2MNPQRSTUV"
URL = "https://example.com/"


class TestSecrets:
    def test_masking_never_reveals_the_value(self) -> None:
        masked = mask_secret(AWS_KEY)
        assert masked == "AKIA****STUV"
        assert AWS_KEY not in masked

    def test_short_values_are_fully_masked(self) -> None:
        assert mask_secret("abcd") == "****"
        assert mask_secret("abcdef") == "a****f"

    def test_placeholder_detection(self) -> None:
        assert is_placeholder("your_key_here")
        assert is_placeholder("aaaaaaaa")
        assert not is_placeholder(AWS_KEY)

    def test_aws_key_is_found_and_masked(self) -> None:
        hits = find_secrets(f'const key = "{AWS_KEY}";', "app.js")
        assert hits
        hit = hits[0]
        assert hit.name == "AWS access key id"
        assert hit.confidence is Confidence.HIGH
        assert AWS_KEY not in hit.masked
        assert hit.line == 1

    def test_placeholder_keys_are_ignored(self) -> None:
        assert find_secrets('const key = "AKIAABCDEFGHIJKLMNOP";') == []

    def test_findings_contain_no_plaintext_secret(self) -> None:
        findings = secret_findings(find_secrets(AWS_KEY, "inline"), URL)
        assert findings
        payload = json.dumps([finding.to_dict() for finding in findings])
        assert AWS_KEY not in payload
        assert findings[0].category == "secrets"
        assert findings[0].evidence_type is EvidenceType.STATIC_INDICATOR

    def test_high_entropy_assignment(self) -> None:
        text = 'var apiKey = "q8Zr2LmX4vT0pKc9Wb3Ns7Yd";'
        hits = find_secrets(text)
        assert hits
        assert "apiKey" in hits[0].name

    def test_empty_document(self) -> None:
        assert find_secrets("") == []


class TestHeaders:
    def test_missing_headers_produce_findings(self) -> None:
        findings = analyze_security_headers({}, URL)
        titles = {finding.title for finding in findings}
        assert "Content-Security-Policy header missing" in titles
        assert "Strict-Transport-Security header missing" in titles
        for finding in findings:
            assert finding.confidence in {Confidence.MEDIUM, Confidence.HIGH}
            assert finding.explanation
            assert finding.verification

    def test_unsafe_csp_is_flagged(self) -> None:
        headers = {
            "content-security-policy": "default-src 'self'; script-src 'unsafe-inline' *",
            "strict-transport-security": "max-age=31536000",
        }
        titles = {finding.title for finding in analyze_security_headers(headers, URL)}
        assert "Content-Security-Policy allows unsafe script sources" in titles
        assert "Content-Security-Policy uses a wildcard source" in titles

    def test_good_headers_are_quiet(self) -> None:
        headers = {
            "content-security-policy": "default-src 'self'",
            "strict-transport-security": "max-age=31536000",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "referrer-policy": "no-referrer",
            "permissions-policy": "geolocation=()",
            "cross-origin-opener-policy": "same-origin",
            "cross-origin-resource-policy": "same-origin",
        }
        assert analyze_security_headers(headers, URL) == []


class TestCookies:
    def test_parse_flags(self) -> None:
        cookies = parse_set_cookie(["sid=abc; Secure; HttpOnly; SameSite=Lax; Path=/"], URL)
        assert len(cookies) == 1
        cookie = cookies[0]
        assert cookie.name == "sid"
        assert cookie.secure and cookie.http_only
        assert cookie.same_site == "Lax"
        assert "secure" in cookie.flags

    def test_insecure_cookie_findings(self) -> None:
        cookies = parse_set_cookie(["sid=abc; Path=/", "token=xyz"], URL)
        findings = analyze_cookies(cookies, URL)
        titles = " ".join(finding.title for finding in findings)
        assert "readable from JavaScript" in titles
        assert "SameSite" in titles
        assert all(finding.category == "cookies" for finding in findings)

    def test_cookie_value_is_not_reported(self) -> None:
        cookies = parse_set_cookie(["sid=super-secret-value"], URL)
        payload = json.dumps([cookie.__dict__ for cookie in cookies])
        assert "super-secret-value" not in payload


class TestCors:
    def test_wildcard_with_credentials(self) -> None:
        findings = analyze_cors({"access-control-allow-origin": "*", "access-control-allow-credentials": "true"}, URL)
        assert findings[0].severity.value == "medium"
        assert findings[0].evidence_type is EvidenceType.OBSERVED_RESPONSE

    def test_wildcard_without_credentials(self) -> None:
        findings = analyze_cors({"access-control-allow-origin": "*"}, URL)
        assert findings[0].severity.value == "info"

    def test_null_origin(self) -> None:
        titles = {finding.title for finding in analyze_cors({"access-control-allow-origin": "null"}, URL)}
        assert "CORS trusts the null origin" in titles

    def test_absent_headers_are_quiet(self) -> None:
        assert analyze_cors({}, URL) == []


class TestEndpoints:
    JS = 'fetch("/api/v1/users?id=42");\n// navigate\nlocation = "/admin";\n'

    def test_classification(self) -> None:
        assert classify_path("/admin/login") == "admin"
        assert classify_path("/api/v1/users") == "api"
        assert classify_path("/graphql") == "graphql"
        assert classify_path("/upload") == "upload"
        assert classify_path("/app.css") == "static"

    def test_discovery_keeps_provenance(self) -> None:
        endpoints = discover_endpoints(self.JS, URL, "app.js")
        paths = {endpoint.path for endpoint in endpoints}
        assert "/api/v1/users" in paths
        assert "/admin" in paths
        for endpoint in endpoints:
            assert endpoint.source_file == "app.js"
            assert endpoint.line >= 1

    def test_url_is_resolved(self) -> None:
        endpoint = next(e for e in discover_endpoints(self.JS, URL) if e.path == "/api/v1/users")
        assert endpoint.url == "https://example.com/api/v1/users?id=42"

    def test_noise_is_skipped(self) -> None:
        assert discover_endpoints('location = "javascript:void(0)";', URL) == []

    def test_endpoint_findings(self) -> None:
        endpoints = discover_endpoints(self.JS, URL)
        findings = endpoint_findings(endpoints, URL)
        assert any("Admin endpoint referenced" in finding.title for finding in findings)
        assert all(finding.evidence_type is EvidenceType.STATIC_INDICATOR for finding in findings)


class TestParameters:
    def _candidates(self) -> list:
        endpoints = discover_endpoints(
            'fetch("/api/v1/users?id=42&sort=asc&next=/home");',
            URL,
        )
        return extract_parameters(endpoints)

    def test_extraction(self) -> None:
        names = {candidate.name for candidate in self._candidates()}
        assert {"id", "sort", "next"} <= names

    def test_findings_carry_confidence(self) -> None:
        findings = analyze_parameters(self._candidates(), URL)
        assert findings
        for finding in findings:
            assert finding.parameter
            assert finding.confidence in {Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH}
            assert "indicator" in finding.title

    def test_form_parameters(self) -> None:
        from reconpulse.collectors.page import FormInfo

        form = FormInfo(action="https://example.com/login", method="post", inputs=["username", "password"])
        candidates = extract_parameters([], [form])
        assert {candidate.location for candidate in candidates} == {"form"}
        assert {candidate.name for candidate in candidates} == {"username", "password"}
        assert candidates[0].context_url == "https://example.com/login"


class TestTechnology:
    def test_header_fingerprint(self) -> None:
        hits = fingerprint_headers({"server": "nginx/1.18.0", "x-powered-by": "PHP/8.1.2"})
        assert hits
        findings = technology_findings(hits, URL)
        assert findings

    def test_generator_fingerprint(self) -> None:
        html = '<meta name="generator" content="WordPress 6.2">'
        hits = fingerprint_html(html, "WordPress 6.2")
        assert hits
        assert all(
            finding.evidence_type is EvidenceType.OBSERVED_RESPONSE for finding in technology_findings(hits, URL)
        )

    def test_no_fingerprint(self) -> None:
        assert fingerprint_headers({}) == []
