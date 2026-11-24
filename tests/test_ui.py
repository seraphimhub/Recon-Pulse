"""Streamlit layer: the UI must call the same pipeline and refuse the same things."""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("streamlit")

from streamlit.testing.v1 import AppTest

from reconpulse.core.config import AppConfig
from reconpulse.core.scope import Scope
from reconpulse.pipeline import ScanOptions, scan_target
from reconpulse.ui.app import _authorization_from_upload

APP = Path(__file__).resolve().parents[1] / "src" / "reconpulse" / "ui" / "app.py"


def _app() -> AppTest:
    app = AppTest.from_file(str(APP), default_timeout=120)
    app.run()
    return app


class _Upload:
    def __init__(self, payload: str) -> None:
        self._payload = payload

    def getvalue(self) -> bytes:
        return self._payload.encode()


class TestRender:
    def test_initial_page(self) -> None:
        app = _app()
        assert not app.exception
        assert app.title[0].value == "ReconPulse"
        assert [button.label for button in app.button] == ["Run scan"]
        assert any("read-only" in info.value for info in app.info)

    def test_passive_scan_matches_the_pipeline(self, site: Any) -> None:
        app = _app()
        app.text_input[0].set_value(site.base_url)
        app.text_input[1].set_value("127.0.0.1")
        app.checkbox[0].check()
        app.button[0].click()
        app.run()

        assert not app.exception
        metrics = {metric.label: metric.value for metric in app.metric}
        expected = scan_target(
            site.base_url,
            AppConfig(rate_per_second=1000, concurrency=3, allow_private=True, cache_enabled=False),
            ScanOptions(scope=Scope(["127.0.0.1"])),
        )
        assert metrics["Findings"] == str(len(expected.findings))
        assert metrics["Risk score"] == f"{expected.risk['score']}/100"
        assert app.subheader[0].value == f"Results for {site.base_url}"
        assert len(app.download_button) == 5
        assert any("Technology fingerprint" in item.label for item in app.expander)

    def test_missing_target_shows_an_error(self) -> None:
        app = _app()
        app.button[0].click()
        app.run()
        assert any("Enter a target URL" in error.value for error in app.error)

    def test_active_without_authorization_is_refused(self) -> None:
        app = _app()
        app.text_input[0].set_value("https://example.com")
        app.radio[0].set_value("active")
        app.run()
        app.button[0].click()
        app.run()
        assert not app.exception
        assert any("requires an authorization.yaml" in error.value for error in app.error)


class TestAuthorizationUpload:
    def _payload(self) -> str:
        from datetime import datetime, timedelta, timezone

        now = datetime.now(timezone.utc)
        return (
            "engagement: UI test\n"
            "authorized_by: Tester\n"
            f"valid_from: '{(now - timedelta(days=1)).isoformat()}'\n"
            f"valid_until: '{(now + timedelta(days=1)).isoformat()}'\n"
            "scope:\n  in: ['127.0.0.1']\n"
            "allowed_techniques: [common_paths, cors_probe]\n"
            "contact_for_incident: tester@example.com\n"
            "canary_domain: canary.example.net\n"
        )

    def test_valid_upload(self) -> None:
        authorization, errors = _authorization_from_upload(_Upload(self._payload()))
        assert errors == []
        assert authorization is not None
        assert authorization.engagement == "UI test"
        assert authorization.canary_domain == "canary.example.net"

    def test_invalid_upload_reports_every_problem(self) -> None:
        authorization, errors = _authorization_from_upload(_Upload("engagement: only\n"))
        assert authorization is None
        assert len(errors) > 1

    def test_broken_yaml(self) -> None:
        authorization, errors = _authorization_from_upload(_Upload("scope: ["))
        assert authorization is None
        assert "cannot parse" in errors[0]

    def test_nothing_uploaded(self) -> None:
        assert _authorization_from_upload(None) == (None, [])

    def test_upload_is_not_kept(self) -> None:
        buffer = io.StringIO(self._payload())
        authorization, _ = _authorization_from_upload(_Upload(buffer.getvalue()))
        assert authorization is not None
        assert "raw" not in authorization.to_summary().to_dict()
