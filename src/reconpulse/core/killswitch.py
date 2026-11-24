"""Cooperative kill switch.

Workers check :meth:`KillSwitch.check` before every request. Ctrl+C and the
Streamlit stop button both trip the switch, which lets in-flight work unwind and
a partial report be written instead of losing results.
"""

from __future__ import annotations

import threading

from .errors import KillSwitchTriggered


class KillSwitch:
    def __init__(self) -> None:
        self._event = threading.Event()

    def trip(self) -> None:
        self._event.set()

    def reset(self) -> None:
        self._event.clear()

    @property
    def triggered(self) -> bool:
        return self._event.is_set()

    def check(self) -> None:
        if self._event.is_set():
            raise KillSwitchTriggered("scan interrupted by operator")
