"""ReconPulse - authorized web reconnaissance for bug bounty and pentest work.

Library usage::

    from reconpulse import AppConfig, ScanOptions, scan_target

    report = scan_target("https://example.com", AppConfig())
    print(report.risk["score"])

Command line usage::

    reconpulse scan https://example.com --format json,md,html

Active mode is opt-in and refuses to run without a validated authorization file.
"""

from __future__ import annotations

from ._version import __version__
from .core.authorization import Authorization, load_authorization
from .core.config import AppConfig
from .core.models import Finding, ScanMode, ScanReport
from .pipeline import ScanOptions, scan_target

__all__ = [
    "AppConfig",
    "Authorization",
    "Finding",
    "ScanMode",
    "ScanOptions",
    "ScanReport",
    "__version__",
    "load_authorization",
    "scan_target",
]
