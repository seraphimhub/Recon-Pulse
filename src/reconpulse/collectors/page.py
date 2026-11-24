"""Fetch and parse the target page (passive: GET only)."""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from ..core.http_client import HTTPClient, HTTPResponse


@dataclass
class FormInfo:
    action: str
    method: str
    inputs: list[str] = field(default_factory=list)


@dataclass
class PageData:
    url: str
    final_url: str
    status: int
    headers: dict[str, str]
    html: str
    soup: BeautifulSoup
    elapsed_ms: float = 0.0

    @property
    def title(self) -> str:
        if self.soup.title and self.soup.title.string:
            return self.soup.title.string.strip()
        return ""

    def forms(self) -> list[FormInfo]:
        found: list[FormInfo] = []
        for form in self.soup.find_all("form"):
            action = urljoin(self.final_url, str(form.get("action") or self.final_url))
            method = str(form.get("method") or "get").upper()
            inputs: list[str] = []
            for element in form.find_all(["input", "select", "textarea"]):
                name = str(element.get("name") or "")
                if name and name not in inputs:
                    inputs.append(name)
            found.append(FormInfo(action=action, method=method, inputs=inputs))
        return found

    def links(self) -> list[str]:
        links: list[str] = []
        for anchor in self.soup.find_all("a", href=True):
            href = str(anchor["href"]).strip()
            if href.startswith(("javascript:", "mailto:", "tel:", "#")):
                continue
            absolute = urljoin(self.final_url, href)
            if absolute not in links:
                links.append(absolute)
        return links


def parse_html(html: str) -> BeautifulSoup:
    return BeautifulSoup(html or "", "html.parser")


def page_from_response(response: HTTPResponse) -> PageData:
    headers = {key.lower(): value for key, value in response.headers.items()}
    return PageData(
        url=response.url,
        final_url=response.url,
        status=response.status,
        headers=headers,
        html=response.text,
        soup=parse_html(response.text),
        elapsed_ms=response.elapsed_ms,
    )


def fetch_page(client: HTTPClient, url: str, *, module: str = "passive") -> PageData:
    """Fetch the target page through the guarded client."""

    response = client.get(url, module=module)
    return page_from_response(response)
