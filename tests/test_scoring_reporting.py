"""Risk scoring is deterministic, and every export renders valid, complete output."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from reconpulse.core.models import (
    Confidence,
    EvidenceType,
    Finding,
    ScanMetadata,
    ScanMode,
    ScanReport,
    Severity,
)
from reconpulse.reporting import (
    SUPPORTED_FORMATS,
    build_sarif,
    export_report,
    export_reports,
    normalize_format,
    render,
    render_json_multi,
)
from reconpulse.scoring import compute_risk, finding_points, severity_counts, sort_findings


def make_finding(
    title: str = "Test finding",
    *,
    severity: Severity = Severity.MEDIUM,
    confidence: Confidence = Confidence.MEDIUM,
    evidence_type: EvidenceType = EvidenceType.STATIC_INDICATOR,
    parameter: str | None = None,
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        confidence=confidence,
        evidence_type=evidence_type,
        explanation='An explanation with \u00e9\u00e0 and "quotes", commas.',
        remediation="Fix it.",
        verification="Check it.",
        category="headers",
        url="https://example.com/?a=1,2",
        parameter=parameter,
        source="test",
        evidence={"masked": "AKIA****STUV"},
    )


def make_report(count: int = 2) -> ScanReport:
    findings = [make_finding(f"Finding {index}") for index in range(count)]
    metadata = ScanMetadata(
        tool_version="2.0.0",
        mode=ScanMode.PASSIVE,
        target="https://example.com",
        started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        finished_at=datetime(2026, 1, 1, 0, 1, tzinfo=timezone.utc),
    )
    report = ScanReport(metadata=metadata, findings=findings)
    report.risk = compute_risk(findings).to_dict()
    report.passive_findings = count
    return report


class TestScoring:
    def test_points_formula(self) -> None:
        finding = make_finding(
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            evidence_type=EvidenceType.ACTIVE_PROBE,
        )
        assert finding_points(finding) == pytest.approx(9 * 2.0 * 1.4)

    def test_info_finding_scores_zero(self) -> None:
        assert finding_points(make_finding(severity=Severity.INFO)) == 0

    def test_score_is_capped(self) -> None:
        findings = [
            make_finding(
                str(index), severity=Severity.HIGH, confidence=Confidence.HIGH, evidence_type=EvidenceType.ACTIVE_PROBE
            )
            for index in range(20)
        ]
        risk = compute_risk(findings)
        assert risk.score == 100
        assert risk.level == "high"

    @pytest.mark.parametrize(
        ("count", "expected"),
        [(0, "info"), (1, "info"), (3, "low"), (8, "medium"), (15, "high")],
    )
    def test_levels(self, count: int, expected: str) -> None:
        findings = [make_finding(str(index)) for index in range(count)]
        assert compute_risk(findings).level == expected

    def test_counts_and_breakdown(self) -> None:
        findings = [
            make_finding("a", severity=Severity.HIGH),
            make_finding("b", severity=Severity.LOW),
            make_finding("c", severity=Severity.INFO),
        ]
        risk = compute_risk(findings)
        assert risk.counts == {"high": 1, "medium": 0, "low": 1, "info": 1}
        assert risk.breakdown[0]["title"] == "a"
        payload = risk.to_dict()
        assert payload["formula"]
        assert payload["weights"]["severity"]["high"] == 9.0

    def test_severity_counts(self) -> None:
        assert severity_counts([])["info"] == 0

    def test_sort_order(self) -> None:
        low = make_finding("z-low", severity=Severity.LOW)
        high_low_conf = make_finding("b-high", severity=Severity.HIGH, confidence=Confidence.LOW)
        high_high_conf = make_finding("a-high", severity=Severity.HIGH, confidence=Confidence.HIGH)
        ordered = sort_findings([low, high_low_conf, high_high_conf])
        assert [finding.title for finding in ordered] == ["a-high", "b-high", "z-low"]


class TestRendering:
    @pytest.mark.parametrize("fmt", SUPPORTED_FORMATS)
    def test_every_format_renders(self, fmt: str) -> None:
        output = render(make_report(), fmt)
        assert isinstance(output, str)
        assert output.strip()
        assert "Finding 0" in output or fmt in {"sarif", "json"}

    def test_json_structure(self) -> None:
        payload = json.loads(render(make_report(), "json"))
        assert payload["metadata"]["mode"] == "passive"
        assert payload["summary"]["total_findings"] == 2
        assert payload["risk"]["score"] >= 0
        assert payload["findings"][0]["confidence"] in {"low", "medium", "high"}

    def test_csv_has_one_row_per_finding(self) -> None:
        output = render(make_report(3), "csv")
        lines = output.strip().splitlines()
        assert len(lines) == 4
        assert "severity" in lines[0]

    def test_markdown_and_html_contain_context(self) -> None:
        markdown = render(make_report(), "md")
        assert "# ReconPulse" in markdown or "ReconPulse" in markdown
        assert "Finding 0" in markdown
        html = render(make_report(), "html")
        assert html.lstrip().startswith("<!DOCTYPE html>")
        assert "Finding 0" in html

    def test_sarif_shape(self) -> None:
        sarif = build_sarif(make_report())
        assert sarif["version"] == "2.1.0"
        run = sarif["runs"][0]
        assert run["results"]
        assert run["tool"]["driver"]["rules"]
        assert run["results"][0]["locations"]

    def test_html_escapes_markup(self) -> None:
        report = make_report()
        report.findings[0].explanation = "<script>alert(1)</script>"
        assert "<script>alert(1)</script>" not in render(report, "html")

    def test_parameter_is_included_when_present(self) -> None:
        report = ScanReport(
            metadata=make_report().metadata,
            findings=[make_finding(parameter="next")],
        )
        assert "next" in render(report, "md")
        assert "next" in render(report, "sarif")

    def test_normalize_format_aliases(self) -> None:
        assert normalize_format("MARKDOWN") == "markdown"
        assert normalize_format(".json") == "json"
        with pytest.raises(ValueError, match="unsupported"):
            normalize_format("pdf")

    def test_export_report_and_reports(self, tmp_path: Path) -> None:
        path = export_report(make_report(), "json", tmp_path / "one.json")
        assert path.is_file()
        written = export_reports(make_report(), ["json", "md", "csv"], output_dir=tmp_path)
        assert set(written) == {"json", "md", "csv"}
        assert all(item.is_file() for item in written.values())

    def test_multi_report_json(self) -> None:
        payload = json.loads(render_json_multi([make_report(1), make_report(2)]))
        assert len(payload["scans"]) == 2
        assert payload["totals"]["findings"] == 3
        assert payload["scans"][0]["summary"]["total_findings"] == 1
