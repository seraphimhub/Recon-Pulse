"""Active reconnaissance registry (authorized engagements only).

Modules are opt-in per name through ``allowed_techniques`` in
``authorization.yaml``. Tier 1 modules run when active mode is enabled; tier 2
and tier 3 must be requested explicitly and listed by the engagement owner.
"""

from __future__ import annotations

from ..core.authorization import TECHNIQUE_LEVELS, Authorization
from ..core.errors import AuthorizationError
from ..core.models import Finding
from . import (
    common_paths,
    content_discovery,
    cors_probe,
    dns_enum,
    graphql_check,
    http_methods,
    port_scan,
    redirect_check,
    reflection_check,
    sensitive_file_check,
    tls_check,
)
from .base import ActiveContext, PlanItem

_MODULES = {
    module.MODULE.name: module.MODULE
    for module in (
        common_paths,
        dns_enum,
        tls_check,
        http_methods,
        cors_probe,
        port_scan,
        content_discovery,
        graphql_check,
        sensitive_file_check,
        reflection_check,
        redirect_check,
    )
}

# Convenience alias so callers can look up a module by technique name.
MODULES = _MODULES


def available_techniques() -> dict[str, dict[str, object]]:
    """Describe every module: level, description, and default selection."""

    return {
        name: {
            "level": module.level,
            "description": module.description,
            "default": module.level == 1 and name in _MODULES,
        }
        for name, module in sorted(_MODULES.items())
    }


def select_techniques(
    requested: list[str] | None,
    authorization: Authorization,
) -> list[str]:
    """Resolve the technique list, enforcing the authorization whitelist."""

    allowed = [name for name in authorization.allowed_techniques if name in _MODULES]
    unknown = [name for name in authorization.allowed_techniques if name not in _MODULES]
    if unknown:
        raise AuthorizationError(
            f"allowed_techniques contains modules this build does not provide: {', '.join(unknown)}"
        )

    if requested:
        cleaned: list[str] = []
        for name in requested:
            technique = name.strip().lower()
            if not technique:
                continue
            if technique not in _MODULES:
                raise AuthorizationError(f"unknown technique '{technique}' (available: {', '.join(sorted(_MODULES))})")
            if technique not in authorization.allowed_techniques:
                raise AuthorizationError(f"technique '{technique}' is not listed in allowed_techniques")
            if technique not in cleaned:
                cleaned.append(technique)
        if not cleaned:
            raise AuthorizationError("no usable technique was requested")
        return cleaned

    tier1 = [name for name in allowed if TECHNIQUE_LEVELS.get(name, 99) == 1]
    if not tier1:
        raise AuthorizationError(
            "active mode was requested but allowed_techniques lists no tier-1 module; "
            "add one explicitly (for example cors_probe)"
        )
    return tier1


def plan_scan(ctx: ActiveContext, techniques: list[str]) -> list[PlanItem]:
    return [_MODULES[name].plan(ctx) for name in techniques if name in _MODULES]


def run_modules(ctx: ActiveContext, techniques: list[str]) -> tuple[list[Finding], list[str]]:
    """Run each selected module and collect findings plus per-module notes."""

    findings: list[Finding] = []
    notes: list[str] = []
    for name in techniques:
        module = _MODULES.get(name)
        if module is None:
            notes.append(f"{name}: module unavailable")
            continue
        try:
            findings.extend(module.run(ctx))
        except Exception as exc:  # one module must never abort the whole scan
            notes.append(f"{name}: aborted ({type(exc).__name__}: {exc})")
    notes.extend(ctx.notes)
    return findings, notes


__all__ = [
    "MODULES",
    "ActiveContext",
    "PlanItem",
    "available_techniques",
    "plan_scan",
    "run_modules",
    "select_techniques",
]
