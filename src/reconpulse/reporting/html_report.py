"""Standalone HTML report renderer (no external assets)."""

from __future__ import annotations

from html import escape

from ..core.models import Finding, ScanReport
from .common import SEVERITY_LABEL, split_findings, summary_lines

_STYLE = """
:root { color-scheme: light dark; --fg:#16181d; --muted:#5a6270; --bg:#ffffff;
        --panel:#f5f6f8; --border:#dfe3e9; --high:#b42318; --medium:#b54708;
        --low:#175cd3; --info:#475467; }
@media (prefers-color-scheme: dark) {
  :root { --fg:#e8eaee; --muted:#9aa3b2; --bg:#111318; --panel:#181b21;
          --border:#2a2f38; }
}
* { box-sizing: border-box; }
body { margin:0; padding:2rem 1.25rem 4rem; font:16px/1.6 -apple-system,
       BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
       color:var(--fg); background:var(--bg); }
main { max-width: 980px; margin: 0 auto; }
h1 { font-size: 1.7rem; margin: 0 0 .25rem; }
h2 { font-size: 1.15rem; margin: 2.2rem 0 .75rem; }
h3 { font-size: 1rem; margin: 1.6rem 0 .4rem; }
p.lede { color: var(--muted); margin-top:0; }
table { border-collapse: collapse; width:100%; font-size:.92rem; }
th, td { text-align:left; padding:.45rem .6rem; border-bottom:1px solid var(--border);
         vertical-align: top; }
th { color: var(--muted); font-weight:600; }
.card { background:var(--panel); border:1px solid var(--border); border-radius:10px;
        padding:1rem 1.15rem; margin:.85rem 0; }
.card dl { display:grid; grid-template-columns: 8.5rem 1fr; gap:.2rem .8rem;
           margin:.5rem 0 0; font-size:.9rem; }
.card dt { color:var(--muted); }
.card dd { margin:0; overflow-wrap:anywhere; }
.badge { display:inline-block; font-size:.72rem; font-weight:700; letter-spacing:.04em;
         padding:.12rem .45rem; border-radius:999px; color:#fff; margin-right:.4rem; }
.high { background:var(--high); } .medium { background:var(--medium); }
.low { background:var(--low); } .info { background:var(--info); }
.score { font-size:2rem; font-weight:700; }
.muted { color:var(--muted); }
code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size:.88em; }
ul { padding-left: 1.15rem; }
"""


def _badge(finding: Finding) -> str:
    level = finding.severity.value
    return f'<span class="badge {level}">{SEVERITY_LABEL[level]}</span>'


def _card(finding: Finding) -> str:
    rows = [
        ("Confidence", finding.confidence.value),
        ("Evidence type", finding.evidence_type.value),
        ("Category", finding.category),
    ]
    if finding.url:
        rows.append(("URL", f"<code>{escape(finding.url)}</code>"))
    if finding.parameter:
        rows.append(("Parameter", f"<code>{escape(finding.parameter)}</code>"))
    if finding.source:
        rows.append(("Detected by", escape(finding.source)))
    if finding.evidence:
        rendered = ", ".join(f"{escape(str(k))}={escape(str(v))}" for k, v in finding.evidence.items())
        rows.append(("Evidence", f"<code>{rendered}</code>"))

    definitions = "".join(f"<dt>{name}</dt><dd>{value}</dd>" for name, value in rows)
    parts = [
        '<div class="card">',
        f"<h3>{_badge(finding)} {escape(finding.title)}</h3>",
        f"<p>{escape(finding.explanation)}</p>",
        f"<dl>{definitions}</dl>",
    ]
    if finding.remediation:
        parts.append(f"<p><strong>Remediation:</strong> {escape(finding.remediation)}</p>")
    if finding.verification:
        parts.append(f"<p><strong>Safe manual verification:</strong> {escape(finding.verification)}</p>")
    parts.append("</div>")
    return "".join(parts)


def render_html(report: ScanReport) -> str:
    meta = report.metadata
    passive, active = split_findings(report.findings)
    risk = report.risk or {}
    counts = risk.get("counts", {})

    meta_rows = [
        ("Mode", meta.mode.value),
        ("Tool version", meta.tool_version),
        ("Started", meta.started_at.isoformat()),
        ("Finished", meta.finished_at.isoformat() if meta.finished_at else "-"),
        ("Scope", ", ".join(meta.scope) or "(not restricted)"),
        ("Techniques", ", ".join(meta.techniques) or "passive"),
        ("Requests sent", str(meta.request_count)),
        ("Interrupted", "yes" if meta.interrupted else "no"),
    ]
    if meta.authorization:
        meta_rows.extend(
            [
                ("Engagement", meta.authorization.engagement or "-"),
                ("Authorized by", meta.authorization.authorized_by or "-"),
                (
                    "Authorization valid",
                    f"{meta.authorization.valid_from} to {meta.authorization.valid_until}",
                ),
                ("Incident contact", meta.authorization.contact_for_incident or "-"),
            ]
        )

    sections: list[str] = []
    sections.append("<h2>Scan metadata</h2><table>")
    sections.extend(f"<tr><th>{escape(name)}</th><td>{escape(str(value))}</td></tr>" for name, value in meta_rows)
    sections.append("</table>")

    sections.append("<h2>Executive summary</h2>")
    sections.append(f'<p class="score">{risk.get("score", 0)}/100</p>')
    sections.append(
        f'<p class="muted">Risk level: {escape(str(risk.get("level", "info")))}. '
        f"High {counts.get('high', 0)}, medium {counts.get('medium', 0)}, "
        f"low {counts.get('low', 0)}, info {counts.get('info', 0)}.</p>"
    )
    sections.append("<ul>")
    sections.extend(f"<li>{escape(line)}</li>" for line in summary_lines(report))
    sections.append("</ul>")

    sections.append(f"<h2>Passive findings ({len(passive)})</h2>")
    sections.extend(_card(finding) for finding in passive)
    if not passive:
        sections.append('<p class="muted">No passive findings.</p>')

    if meta.mode.value == "active" or active:
        sections.append(f"<h2>Active findings ({len(active)})</h2>")
        sections.extend(_card(finding) for finding in active)
        if not active:
            sections.append('<p class="muted">No active findings.</p>')

    if report.out_of_scope:
        sections.append("<h2>Out-of-scope discoveries (not contacted)</h2><ul>")
        for discovery in report.out_of_scope:
            detail = f" - {escape(discovery.detail)}" if discovery.detail else ""
            sections.append(
                f"<li><code>{escape(discovery.host)}</code> (found by {escape(discovery.discovered_by)}){detail}</li>"
            )
        sections.append("</ul>")

    if report.errors:
        sections.append("<h2>Errors</h2><ul>")
        sections.extend(f"<li>{escape(error)}</li>" for error in report.errors)
        sections.append("</ul>")

    body = "\n".join(sections)
    title = escape(f"ReconPulse report - {meta.target}")
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{title}</title>\n<style>{_STYLE}</style>\n</head>\n<body>\n<main>\n"
        f"<h1>{title}</h1>\n"
        '<p class="lede">Generated by ReconPulse for authorized security testing only. '
        "Static findings are indicators, not confirmed vulnerabilities.</p>\n"
        f"{body}\n</main>\n</body>\n</html>\n"
    )
