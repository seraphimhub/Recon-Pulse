"""JavaScript collection: external files and inline blocks, fetched in parallel.

External scripts are only fetched when they are inside the authorized scope; any
other script URL is reported as an out-of-scope discovery and never contacted.
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from ..core.errors import ReconPulseError
from ..core.http_client import HTTPClient

SOURCE_MAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=([^\s'\"]+)")
MAX_INLINE_BYTES = 500_000


@dataclass
class ScriptAsset:
    """A piece of JavaScript that was analysed."""

    content: str
    url: str | None = None
    inline: bool = False
    error: str | None = None
    source_maps: list[str] = field(default_factory=list)
    truncated: bool = False

    @property
    def label(self) -> str:
        if self.inline:
            return "inline script"
        return self.url or "unknown script"


@dataclass
class ScriptCollection:
    assets: list[ScriptAsset] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    skipped: int = 0

    @property
    def external_count(self) -> int:
        return sum(1 for asset in self.assets if not asset.inline)

    @property
    def inline_count(self) -> int:
        return sum(1 for asset in self.assets if asset.inline)


def extract_scripts(html: str, base_url: str) -> tuple[list[str], list[str]]:
    """Return (external script URLs, inline script bodies), de-duplicated."""

    soup = BeautifulSoup(html or "", "html.parser")
    external: list[str] = []
    inline: list[str] = []

    for tag in soup.find_all("script"):
        src = tag.get("src")
        if src:
            absolute = urljoin(base_url, str(src).strip())
            if absolute.startswith(("http://", "https://")) and absolute not in external:
                external.append(absolute)
            continue
        if tag.string and tag.string.strip():
            body = tag.string
            if len(body) > MAX_INLINE_BYTES:
                body = body[:MAX_INLINE_BYTES]
            if body not in inline:
                inline.append(body)

    return external, inline


def find_source_maps(content: str, script_url: str | None) -> list[str]:
    """Locate ``sourceMappingURL`` comments and resolve them to absolute URLs."""

    maps: list[str] = []
    for match in SOURCE_MAP_RE.finditer(content or ""):
        target = match.group(1).strip()
        if target.startswith("data:"):
            maps.append(f"{script_url or 'inline'} (inline data URI)")
            continue
        absolute = urljoin(script_url, target) if script_url else target
        if absolute not in maps:
            maps.append(absolute)
    return maps


def _fetch_one(client: HTTPClient, url: str, *, module: str) -> ScriptAsset:
    try:
        response = client.get(url, module=module, cache=True)
    except ReconPulseError as exc:
        return ScriptAsset(content="", url=url, error=str(exc))
    return ScriptAsset(
        content=response.text,
        url=url,
        error=None if response.ok else f"HTTP {response.status}",
        source_maps=find_source_maps(response.text, url),
        truncated=response.truncated,
    )


def collect_scripts(
    client: HTTPClient,
    html: str,
    base_url: str,
    *,
    max_files: int = 50,
    concurrency: int = 5,
    module: str = "passive",
) -> ScriptCollection:
    """Collect inline scripts and fetch in-scope external scripts in parallel."""

    external, inline = extract_scripts(html, base_url)
    collection = ScriptCollection()

    for body in inline:
        collection.assets.append(
            ScriptAsset(
                content=body,
                inline=True,
                source_maps=find_source_maps(body, None),
            )
        )

    fetchable: list[str] = []
    for url in external:
        host = (urlparse(url).hostname or "").lower()
        scope = client.scope
        if scope is not None and not scope.is_allowed(host):
            collection.out_of_scope.append(url)
            continue
        if len(fetchable) >= max_files:
            collection.skipped += 1
            continue
        fetchable.append(url)

    if fetchable:
        workers = max(1, min(concurrency, len(fetchable)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(lambda url: _fetch_one(client, url, module=module), fetchable))
        collection.assets.extend(results)

    return collection
