"""CSV report renderer (one row per finding)."""

from __future__ import annotations

import csv
import io
from typing import Any

from ..core.models import ScanReport

COLUMNS = [
    "target",
    "severity",
    "confidence",
    "evidence_type",
    "category",
    "title",
    "parameter",
    "url",
    "source",
    "explanation",
    "remediation",
    "verification",
]


def render_csv(report: ScanReport) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=COLUMNS, lineterminator="\n")
    writer.writeheader()
    for finding in report.findings:
        row: dict[str, Any] = finding.to_dict()
        row["target"] = report.metadata.target
        writer.writerow({column: _cell(row.get(column)) for column in COLUMNS})
    return buffer.getvalue()


def _cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.replace("\r", " ").replace("\n", " ")
    return str(value)
