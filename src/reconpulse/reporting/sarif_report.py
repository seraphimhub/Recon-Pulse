"""SARIF 2.1.0 report renderer (for CI and GitHub code scanning)."""

from __future__ import annotations

import json
import re
from typing import Any

from ..core.models import ScanReport

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

LEVEL_MAP = {"high": "error", "medium": "warning", "low": "note", "info": "note"}


def _rule_id(report: ScanReport, category: str, title: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:60]
    return f"RP/{category}/{slug}" if slug else f"RP/{category}"


def build_sarif(report: ScanReport) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in report.findings:
        rule_id = _rule_id(report, finding.category, finding.title)
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.explanation},
                "help": {"text": finding.remediation or finding.verification or finding.explanation},
                "defaultConfiguration": {"level": LEVEL_MAP[finding.severity.value]},
                "properties": {
                    "category": finding.category,
                    "confidence": finding.confidence.value,
                    "evidenceType": finding.evidence_type.value,
                },
            },
        )
        message_parts = [finding.explanation]
        if finding.parameter:
            message_parts.append(f"Parameter: {finding.parameter}")
        if finding.verification:
            message_parts.append(f"Verify manually: {finding.verification}")
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": LEVEL_MAP[finding.severity.value],
            "message": {"text": " ".join(part for part in message_parts if part)},
            "properties": {
                "severity": finding.severity.value,
                "confidence": finding.confidence.value,
                "evidenceType": finding.evidence_type.value,
                "source": finding.source,
            },
        }
        location_uri = finding.url or report.metadata.target
        result["locations"] = [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": location_uri},
                    "region": {"startLine": 1},
                }
            }
        ]
        results.append(result)

    invocation: dict[str, Any] = {
        "executionSuccessful": not report.metadata.interrupted,
        "startTimeUtc": report.metadata.started_at.isoformat(),
        "endTimeUtc": report.metadata.finished_at.isoformat() if report.metadata.finished_at else None,
        "properties": {
            "mode": report.metadata.mode.value,
            "requests": report.metadata.request_count,
            "riskScore": report.risk.get("score"),
            "riskLevel": report.risk.get("level"),
        },
    }

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ReconPulse",
                        "informationUri": "https://github.com/your-org/reconpulse",
                        "version": report.metadata.tool_version,
                        "rules": list(rules.values()),
                    }
                },
                "invocations": [invocation],
                "results": results,
                "properties": {
                    "target": report.metadata.target,
                    "scope": list(report.metadata.scope),
                    "outOfScopeDiscoveries": [d.to_dict() for d in report.out_of_scope],
                },
            }
        ],
    }


def render_sarif(report: ScanReport) -> str:
    return json.dumps(build_sarif(report), indent=2, ensure_ascii=False)
