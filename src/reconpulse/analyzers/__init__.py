"""Static analysis: headers, cookies, technology, endpoints, parameters, secrets.

Every analyzer returns :class:`~reconpulse.core.models.Finding` objects with an
explicit confidence and evidence type. Analyzers never send requests; that is the
collectors' job, and everything they send goes through the guarded HTTP client.
"""

from __future__ import annotations

from .cookies import CookieInfo, analyze_cookies, parse_set_cookie
from .cors import analyze_cors
from .endpoints import (
    Endpoint,
    classify_path,
    discover_endpoints,
    endpoint_findings,
    endpoints_from_page,
)
from .headers_audit import analyze_security_headers
from .params import ParamCandidate, analyze_parameters, extract_parameters
from .secrets import SecretHit, find_secrets, mask_secret, secret_findings, shannon_entropy
from .sourcemaps import analyze_source_maps
from .tech import TechHit, fingerprint_headers, fingerprint_html, technology_findings

__all__ = [
    "CookieInfo",
    "Endpoint",
    "ParamCandidate",
    "SecretHit",
    "TechHit",
    "analyze_cookies",
    "analyze_cors",
    "analyze_parameters",
    "analyze_security_headers",
    "analyze_source_maps",
    "classify_path",
    "discover_endpoints",
    "endpoint_findings",
    "endpoints_from_page",
    "extract_parameters",
    "find_secrets",
    "fingerprint_headers",
    "fingerprint_html",
    "mask_secret",
    "parse_set_cookie",
    "secret_findings",
    "shannon_entropy",
    "technology_findings",
]
