"""Scan orchestration: passive pipeline first, then optional authorized active modules.

This module is the only place that wires collectors, analyzers, scoring, and
active modules together. It is import-safe for the CLI, the library, and the
Streamlit layer, which all call :func:`scan_target`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ._version import __version__
from .active import ActiveContext, available_techniques, plan_scan, run_modules, select_techniques
from .analyzers import (
    analyze_cookies,
    analyze_cors,
    analyze_parameters,
    analyze_security_headers,
    analyze_source_maps,
    discover_endpoints,
    endpoint_findings,
    endpoints_from_page,
    extract_parameters,
    find_secrets,
    fingerprint_headers,
    fingerprint_html,
    parse_set_cookie,
    secret_findings,
    technology_findings,
)
from .collectors import (
    analyze_robots,
    analyze_security_txt,
    collect_scripts,
    fetch_page,
    fetch_robots,
    fetch_security_txt,
)
from .core.audit import AuditLog
from .core.authorization import Authorization
from .core.budget import Budget
from .core.circuit import CircuitBreaker
from .core.config import AppConfig
from .core.errors import (
    AuthorizationError,
    BudgetExhausted,
    CircuitOpen,
    NetworkError,
    ReconPulseError,
    ScopeError,
    SSRFGuardError,
)
from .core.http_client import HTTPClient
from .core.killswitch import KillSwitch
from .core.models import (
    Finding,
    OutOfScopeDiscovery,
    ScanMetadata,
    ScanMode,
    ScanReport,
)
from .core.ratelimit import RateLimiter
from .core.scope import Scope
from .scoring import compute_risk, sort_findings


@dataclass
class ScanOptions:
    """Everything that changes how a single target is scanned."""

    mode: ScanMode = ScanMode.PASSIVE
    scope: Scope | None = None
    authorization: Authorization | None = None
    techniques: list[str] | None = None
    audit_log: AuditLog | None = None
    kill_switch: KillSwitch | None = None
    extra_config: dict[str, Any] = field(default_factory=dict)


def _scope_for(options: ScanOptions) -> Scope:
    if options.authorization is not None:
        return options.authorization.scope
    if options.scope is not None:
        return options.scope
    # Passive mode without --scope: no allowlist, but the SSRF guard still applies.
    return Scope([], [], default_deny=False)


def build_client(config: AppConfig, options: ScanOptions) -> HTTPClient:
    scope = _scope_for(options)
    budget = None
    breaker = None
    if options.authorization is not None:
        limits = options.authorization.limits
        budget = Budget(limits.max_total_requests, limits.per_host_requests)
        config = AppConfig.from_mapping(
            {
                **config.to_dict(),
                "rate_per_second": min(config.rate_per_second, limits.max_requests_per_second),
                "concurrency": min(config.concurrency, limits.max_concurrency),
            }
        )
    budget = budget or (
        Budget(config.budget_total, config.budget_per_host) if (config.budget_total or config.budget_per_host) else None
    )
    if config.circuit_failure_threshold or config.circuit_timeout_streak:
        breaker = CircuitBreaker(config.circuit_failure_threshold, config.circuit_timeout_streak)
    return HTTPClient(
        config,
        scope=scope,
        allow_private=config.allow_private,
        audit_log=options.audit_log,
        budget=budget,
        circuit=breaker,
        kill_switch=options.kill_switch,
        rate_limiter=RateLimiter(config.rate_per_second, config.per_host_rate),
        version=__version__,
    )


# ---------------------------------------------------------------------------
# Passive pipeline
# ---------------------------------------------------------------------------


def _passive_findings(
    client: HTTPClient,
    target: str,
    config: AppConfig,
    report: ScanReport,
    options: ScanOptions,
) -> tuple[list[Finding], Scope]:
    findings: list[Finding] = []
    scope = client.scope or Scope([], [], default_deny=False)

    page = fetch_page(client, target, module="passive")
    url = page.final_url

    findings.extend(analyze_security_headers(page.headers, url))
    set_cookie_headers = [value for key, value in page.headers.items() if key == "set-cookie"]
    if set_cookie_headers:
        cookies = parse_set_cookie(set_cookie_headers, url)
        findings.extend(analyze_cookies(cookies, url))
    findings.extend(analyze_cors(page.headers, url))

    generator = ""
    generator_tag = page.soup.find("meta", attrs={"name": "generator"})
    if generator_tag and generator_tag.get("content"):
        generator = str(generator_tag["content"])
    tech_hits = fingerprint_headers(page.headers) + fingerprint_html(page.html, generator)
    findings.extend(technology_findings(tech_hits, url))

    scripts = collect_scripts(
        client,
        page.html,
        url,
        max_files=config.js_max_files,
        concurrency=config.concurrency,
        module="passive",
    )
    for script in scripts.assets:
        if script.error and not script.inline:
            report.notes.append(f"script skipped: {script.url} ({script.error})")
        else:
            findings.extend(secret_findings(find_secrets(script.content, script.label), url))
    for script_url in scripts.out_of_scope:
        report.out_of_scope.append(
            OutOfScopeDiscovery(
                host=(urlparse(script_url).hostname or script_url),
                discovered_by="js",
                detail="script referenced by the page but outside scope; not fetched",
            )
        )
    findings.extend(analyze_source_maps(scripts.assets, url))

    endpoints = endpoints_from_page(page)
    for script in scripts.assets:
        if not script.content:
            continue
        endpoints.extend(discover_endpoints(script.content, url, script.label))
    deduped: dict[tuple[str, str], Any] = {}
    for endpoint in endpoints:
        deduped.setdefault((endpoint.path, endpoint.kind), endpoint)
    unique_endpoints = list(deduped.values())
    findings.extend(endpoint_findings(unique_endpoints, url))

    parameters = extract_parameters(unique_endpoints, page.forms())
    findings.extend(analyze_parameters(parameters, url))

    robots = fetch_robots(client, target, module="passive")
    findings.extend(analyze_robots(robots))
    security_txt = fetch_security_txt(client, target, module="passive")
    findings.extend(analyze_security_txt(security_txt))

    report.metadata.config["endpoints_discovered"] = len(unique_endpoints)
    report.metadata.config["parameters_discovered"] = len(parameters)
    report.metadata.config["scripts_analysed"] = len(scripts.assets)
    report.metadata.config["scripts_out_of_scope"] = len(scripts.out_of_scope)

    # Stash for active mode without polluting the report model.
    options.extra_config["endpoints"] = unique_endpoints
    options.extra_config["parameters"] = parameters
    return findings, scope


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def scan_target(
    target: str,
    config: AppConfig | None = None,
    options: ScanOptions | None = None,
) -> ScanReport:
    """Scan one target. Passive unless ``options.mode`` is active with authorization."""

    config = config or AppConfig()
    options = options or ScanOptions()

    if options.mode is ScanMode.ACTIVE and options.authorization is None:
        raise AuthorizationError("active mode requires a validated authorization file")

    started = datetime.now(timezone.utc)
    client = build_client(config, options)
    metadata = ScanMetadata(
        tool_version=__version__,
        mode=options.mode,
        target=target,
        started_at=started,
        scope=[entry.raw for entry in (client.scope.allow if client.scope else [])],
        techniques=list(options.techniques or []) if options.mode is ScanMode.ACTIVE else [],
        user_agent=client.user_agent,
        authorization=options.authorization.to_summary() if options.authorization else None,
        config=config.to_dict(),
    )
    report = ScanReport(metadata=metadata)

    findings: list[Finding] = []
    try:
        passive, _scope = _passive_findings(client, target, config, report, options)
        findings.extend(passive)
        report.passive_findings = len(passive)
    except (SSRFGuardError, ScopeError) as exc:
        report.errors.append(f"blocked before scanning: {exc}")
    except (NetworkError, BudgetExhausted, CircuitOpen) as exc:
        report.errors.append(f"passive collection stopped: {exc}")
    except ReconPulseError as exc:
        report.errors.append(f"passive collection failed: {exc}")

    if options.mode is ScanMode.ACTIVE and options.authorization is not None:
        authorization = options.authorization
        try:
            authorization.ensure_valid_now()
            authorization.ensure_host_in_scope(urlparse(target).hostname or "")
            techniques = select_techniques(options.techniques, authorization)
            metadata.techniques = techniques
            ctx = ActiveContext(
                client=client,
                base_url=target,
                authorization=authorization,
                canary_domain=authorization.canary_domain,
                parameters=options.extra_config.get("parameters", []),
                endpoints=options.extra_config.get("endpoints", []),
            )
            active_findings, notes = run_modules(ctx, techniques)
            findings.extend(active_findings)
            report.active_findings = len(active_findings)
            report.notes.extend(notes)
            report.out_of_scope.extend(ctx.out_of_scope)
        except (AuthorizationError, ScopeError) as exc:
            report.errors.append(f"active mode refused: {exc}")
        except (BudgetExhausted, CircuitOpen) as exc:
            report.errors.append(f"active mode stopped by safety limit: {exc}")

    try:
        if client.errors:
            report.notes.extend(client.errors)
    finally:
        client.close()

    unique: dict[tuple[str, str | None, str], Finding] = {}
    for finding in findings:
        unique.setdefault((finding.title, finding.url, finding.category), finding)
    ordered = sort_findings(list(unique.values()))

    report.findings = ordered
    report.risk = compute_risk(ordered).to_dict()
    report.metadata.request_count = client.request_count
    report.metadata.finished_at = datetime.now(timezone.utc)
    return report


def dry_run_plan(target: str, authorization: Authorization, techniques: list[str]) -> dict[str, Any]:
    """Describe an active run without sending any request."""

    selected = select_techniques(techniques, authorization)
    ctx = ActiveContext(
        client=None,  # type: ignore[arg-type]
        base_url=target,
        authorization=authorization,
        canary_domain=authorization.canary_domain,
    )
    items = plan_scan(ctx, selected)
    return {
        "target": target,
        "engagement": authorization.engagement,
        "scope_in": authorization.scope_in,
        "scope_out": authorization.scope_out,
        "valid_from": authorization.valid_from.isoformat(),
        "valid_until": authorization.valid_until.isoformat(),
        "rate_per_second": min(authorization.limits.max_requests_per_second, 1.0)
        if authorization.limits.max_requests_per_second
        else None,
        "max_concurrency": authorization.limits.max_concurrency,
        "budget": authorization.limits.max_total_requests,
        "canary_domain": authorization.canary_domain,
        "contact_for_incident": authorization.contact_for_incident,
        "techniques": [item.to_dict() for item in items],
        "estimated_requests": sum(item.requests for item in items),
    }


def write_audit_log(path: str | Path) -> AuditLog:
    return AuditLog(path)


__all__ = [
    "ScanOptions",
    "available_techniques",
    "build_client",
    "dry_run_plan",
    "scan_target",
    "write_audit_log",
]
