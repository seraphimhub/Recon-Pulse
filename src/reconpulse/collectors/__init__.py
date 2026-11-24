"""Passive collectors: page, scripts, and policy files.

Collectors only perform normal GET requests through
:class:`~reconpulse.core.http_client.HTTPClient`; they never probe, fuzz, or
follow links outside scope.
"""

from __future__ import annotations

from .js import ScriptAsset, ScriptCollection, collect_scripts, extract_scripts, find_source_maps
from .page import FormInfo, PageData, fetch_page, page_from_response, parse_html
from .robots import (
    RobotsInfo,
    SecurityTxtInfo,
    analyze_robots,
    analyze_security_txt,
    fetch_robots,
    fetch_security_txt,
)

__all__ = [
    "FormInfo",
    "PageData",
    "RobotsInfo",
    "ScriptAsset",
    "ScriptCollection",
    "SecurityTxtInfo",
    "analyze_robots",
    "analyze_security_txt",
    "collect_scripts",
    "extract_scripts",
    "fetch_page",
    "fetch_robots",
    "fetch_security_txt",
    "find_source_maps",
    "page_from_response",
    "parse_html",
]
