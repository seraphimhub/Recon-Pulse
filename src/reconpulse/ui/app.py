"""Streamlit presentation layer.

The UI is deliberately thin: it collects options, calls
:func:`reconpulse.pipeline.scan_target`, and renders the returned
:class:`~reconpulse.core.models.ScanReport`. All behaviour, including the
authorization gate, lives in the core so the CLI and the UI cannot drift apart.

Run with::

    streamlit run src/reconpulse/ui/app.py
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import streamlit as st
import yaml

from reconpulse._version import __version__
from reconpulse.active import available_techniques
from reconpulse.core.authorization import Authorization, validate_authorization_data
from reconpulse.core.config import AppConfig
from reconpulse.core.errors import AuthorizationError, ReconPulseError
from reconpulse.core.models import ScanMode, ScanReport
from reconpulse.core.scope import Scope
from reconpulse.pipeline import ScanOptions, dry_run_plan, scan_target
from reconpulse.reporting import render

CONFIRMATION_PHRASE = "I have authorization"
UI_FORMATS = ("json", "csv", "md", "html", "sarif")


def _authorization_from_upload(upload: Any) -> tuple[Authorization | None, list[str]]:
    if upload is None:
        return None, []
    try:
        raw = yaml.safe_load(upload.getvalue().decode("utf-8"))
    except (yaml.YAMLError, UnicodeDecodeError) as exc:
        return None, [f"cannot parse uploaded file: {exc}"]
    errors = validate_authorization_data(raw)
    if errors:
        return None, errors
    return Authorization.from_mapping(raw), []


def _extension(fmt: str) -> str:
    return "md" if fmt == "markdown" else fmt


def _render_report(report: ScanReport) -> None:
    meta = report.metadata
    risk = report.risk or {}
    st.subheader(f"Results for {meta.target}")
    left, middle, right, fourth = st.columns(4)
    left.metric("Risk score", f"{risk.get('score', 0)}/100")
    middle.metric("Risk level", str(risk.get("level", "info")).upper())
    right.metric("Findings", len(report.findings))
    fourth.metric("Requests", meta.request_count)

    if meta.interrupted:
        st.warning("Scan was interrupted; the report contains partial results.")
    for error in report.errors:
        st.error(error)

    st.caption(
        f"Mode: {meta.mode.value} · version {meta.tool_version} · "
        f"techniques: {', '.join(meta.techniques) or 'passive'} · "
        f"scope: {', '.join(meta.scope) or 'not restricted'}"
    )
    if meta.authorization:
        auth = meta.authorization
        st.info(
            f"Authorized under '{auth.engagement}' by {auth.authorized_by}, "
            f"valid {auth.valid_from} → {auth.valid_until}."
        )

    for finding in report.findings:
        label = f"[{finding.severity.value.upper()}] {finding.title} ({finding.confidence.value} confidence)"
        with st.expander(label):
            st.write(finding.explanation)
            details = {
                "Evidence type": finding.evidence_type.value,
                "Category": finding.category,
                "URL": finding.url or "-",
                "Parameter": finding.parameter or "-",
                "Detected by": finding.source or "-",
            }
            st.table({"field": list(details), "value": list(details.values())})
            if finding.remediation:
                st.write(f"**Remediation:** {finding.remediation}")
            if finding.verification:
                st.write(f"**Safe manual verification:** {finding.verification}")
            if finding.evidence:
                st.json(finding.evidence)

    if report.out_of_scope:
        st.warning("Out-of-scope assets were discovered and deliberately not contacted.")
        st.table([item.to_dict() for item in report.out_of_scope])
    if report.notes:
        with st.expander("Runner notes"):
            for note in report.notes:
                st.write(f"- {note}")

    st.markdown("#### Download")
    columns = st.columns(len(UI_FORMATS))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    for column, fmt in zip(columns, UI_FORMATS, strict=True):
        payload = render(report, fmt)
        mime = "application/json" if fmt in {"json", "sarif"} else "text/plain"
        column.download_button(
            label=fmt.upper(),
            data=payload,
            file_name=f"reconpulse_{stamp}.{_extension(fmt)}",
            mime=mime,
        )


def main() -> None:
    st.set_page_config(page_title="ReconPulse", page_icon="🛰️", layout="wide")
    st.title("ReconPulse")
    st.caption(
        f"Authorized web reconnaissance · v{__version__} · "
        "only scan systems you own or have written permission to test."
    )

    with st.sidebar:
        st.header("Scan")
        target = st.text_input("Target URL", placeholder="https://example.com")
        scope_text = st.text_input("Scope allowlist (comma separated, optional)", placeholder="example.com")
        mode = str(st.radio("Mode", ["passive", "active"], index=0, help="Active mode needs authorization."))
        rate = st.slider("Requests per second", 0.2, 5.0, 1.0, 0.2)
        concurrency = st.slider("Concurrency", 1, 10, 3)
        allow_private = st.checkbox("Allow private addresses (must be in scope)", value=False)

        upload: Any = None
        techniques: list[str] = []
        confirmed = False
        if mode == "active":
            st.warning("Active mode sends probes. Only use it with written authorization.")
            upload = st.file_uploader("authorization.yaml", type=["yaml", "yml"])
            available = available_techniques()
            techniques = st.multiselect(
                "Techniques (default: tier 1)",
                options=list(available),
                format_func=lambda name: f"{name} (level {available[name]['level']})",
            )
            confirmed = st.checkbox(f"I confirm I can type: {CONFIRMATION_PHRASE}")

        run = st.button("Run scan", type="primary", use_container_width=True)

    st.info(
        "ReconPulse only performs read-only requests. Static findings are indicators for manual "
        "verification, not confirmed vulnerabilities. See docs/ACTIVE_MODE.md before enabling active mode."
    )

    if not run:
        return
    if not target:
        st.error("Enter a target URL.")
        return

    authorization: Authorization | None = None
    if mode == "active":
        if upload is None:
            st.error("Active mode requires an authorization.yaml upload.")
            return
        authorization, errors = _authorization_from_upload(upload)
        if errors:
            st.error("Authorization refused:\n" + "\n".join(f"- {error}" for error in errors))
            return
        assert authorization is not None
        try:
            authorization.ensure_valid_now()
            authorization.ensure_host_in_scope(urlparse(target).hostname or "")
        except (AuthorizationError, ReconPulseError) as exc:
            st.error(f"Authorization refused: {exc}")
            return
        if not confirmed:
            st.error(f'Type the confirmation phrase "{CONFIRMATION_PHRASE}" in the sidebar to continue.')
            return

    config = AppConfig(rate_per_second=rate, concurrency=concurrency, allow_private=allow_private)
    scope_entries = [item.strip() for item in scope_text.split(",") if item.strip()]

    if mode == "active" and authorization is not None:
        plan = dry_run_plan(target, authorization, techniques)
        with st.expander("Planned requests (dry run)", expanded=False):
            st.json(plan)

    with st.spinner("Scanning ..."):
        try:
            report = scan_target(
                target,
                config,
                ScanOptions(
                    mode=ScanMode.ACTIVE if mode == "active" else ScanMode.PASSIVE,
                    scope=Scope(scope_entries) if scope_entries else None,
                    authorization=authorization,
                    techniques=techniques or None,
                ),
            )
        except ReconPulseError as exc:
            st.error(f"Scan failed: {exc}")
            return

    _render_report(report)

    with st.expander("Raw JSON"):
        st.code(render(report, "json"), language="json")


if __name__ == "__main__":
    main()
