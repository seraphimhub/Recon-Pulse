"""Report rendering and export.

Supported formats: ``json``, ``csv``, ``md`` (markdown), ``html`` and ``sarif``.
"""

from __future__ import annotations

from pathlib import Path

from ..core.models import ScanReport
from .common import FORMAT_EXTENSIONS, default_filename, write_text
from .csv_report import render_csv
from .html_report import render_html
from .json_report import render_json, render_json_multi
from .markdown_report import render_markdown
from .sarif_report import build_sarif, render_sarif

RENDERERS = {
    "json": render_json,
    "csv": render_csv,
    "md": render_markdown,
    "markdown": render_markdown,
    "html": render_html,
    "sarif": render_sarif,
}

SUPPORTED_FORMATS = tuple(RENDERERS)


def normalize_format(fmt: str) -> str:
    name = fmt.strip().lower().lstrip(".")
    if name not in RENDERERS:
        raise ValueError(f"unsupported report format '{fmt}' (choose from {', '.join(SUPPORTED_FORMATS)})")
    return name


def render(report: ScanReport, fmt: str) -> str:
    """Render a single scan report to a string."""

    return RENDERERS[normalize_format(fmt)](report)


def export_report(
    report: ScanReport,
    fmt: str,
    destination: str | Path | None = None,
    *,
    output_dir: str | Path = "reconpulse-output",
) -> Path:
    """Render and write a report, returning the path written."""

    name = normalize_format(fmt)
    if destination is None:
        destination = Path(output_dir) / default_filename(report, name)
    return write_text(destination, RENDERERS[name](report))


def export_reports(
    report: ScanReport,
    formats: list[str],
    *,
    output_dir: str | Path = "reconpulse-output",
) -> dict[str, Path]:
    """Export the same report in several formats."""

    written: dict[str, Path] = {}
    for fmt in formats:
        name = normalize_format(fmt)
        written[name] = export_report(report, name, output_dir=output_dir)
    return written


__all__ = [
    "FORMAT_EXTENSIONS",
    "RENDERERS",
    "SUPPORTED_FORMATS",
    "build_sarif",
    "export_report",
    "export_reports",
    "normalize_format",
    "render",
    "render_csv",
    "render_html",
    "render_json",
    "render_json_multi",
    "render_markdown",
    "render_sarif",
]
