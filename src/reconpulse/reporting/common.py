"""Shared helpers for report renderers."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from ..core.models import Finding, ScanReport

FORMAT_EXTENSIONS = {
    "json": ".json",
    "csv": ".csv",
    "md": ".md",
    "markdown": ".md",
    "html": ".html",
    "sarif": ".sarif",
}

SEVERITY_LABEL = {"high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO"}


def slugify_target(target: str) -> str:
    """Turn a URL into a safe file name fragment."""

    slug = re.sub(r"^[a-z]+://", "", target, flags=re.IGNORECASE)
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", slug).strip("._-")
    return slug[:80] or "target"


def default_filename(report: ScanReport, fmt: str) -> str:
    stamp = (report.metadata.finished_at or datetime.now(timezone.utc)).strftime("%Y%m%d-%H%M%S")
    extension = FORMAT_EXTENSIONS.get(fmt.lower(), f".{fmt.lower()}")
    return f"reconpulse_{slugify_target(report.metadata.target)}_{stamp}{extension}"


def split_findings(findings: list[Finding]) -> tuple[list[Finding], list[Finding]]:
    """Return (passive, active) findings, keeping their original order."""

    passive = [f for f in findings if f.evidence_type.value != "active_probe"]
    active = [f for f in findings if f.evidence_type.value == "active_probe"]
    return passive, active


def summary_lines(report: ScanReport) -> list[str]:
    risk = report.risk or {}
    counts = risk.get("counts", {})
    return [
        f"Risk score: {risk.get('score', 0)}/100 ({risk.get('level', 'info')})",
        f"Findings: {len(report.findings)} "
        f"(high {counts.get('high', 0)}, medium {counts.get('medium', 0)}, "
        f"low {counts.get('low', 0)}, info {counts.get('info', 0)})",
        f"Out-of-scope discoveries (not contacted): {len(report.out_of_scope)}",
        f"Errors: {len(report.errors)}",
    ]


def write_text(destination: str | Path, content: str) -> Path:
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path
