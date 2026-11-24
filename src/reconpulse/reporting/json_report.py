"""JSON report renderer (machine-readable, one object per scan)."""

from __future__ import annotations

import json

from ..core.models import ScanReport


def render_json(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False, sort_keys=False)


def render_json_multi(reports: list[ScanReport]) -> str:
    """Render several scans (multi-target runs) as one JSON document."""

    payload = {
        "tool": "reconpulse",
        "scans": [report.to_dict() for report in reports],
        "totals": {
            "targets": len(reports),
            "findings": sum(len(report.findings) for report in reports),
            "out_of_scope": sum(len(report.out_of_scope) for report in reports),
            "errors": sum(len(report.errors) for report in reports),
        },
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)
