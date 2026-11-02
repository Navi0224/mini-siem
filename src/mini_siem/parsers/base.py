"""Common parser interface and small helpers shared by all parsers."""

from __future__ import annotations

import ipaddress
from abc import ABC, abstractmethod

from mini_siem.schema import Event


class Parser(ABC):
    """Turns one raw log line into a normalised :class:`Event` (or None).

    Returning None (rather than raising) for lines we don't understand is a
    deliberate choice: real log files are full of lines that are irrelevant
    to security (cron sessions, systemd noise). The ingester counts them as
    "skipped" so you can see how much was ignored.
    """

    #: Short name stored in Event.source and used on the CLI (--type).
    source_type: str = ""

    def __init__(self, default_host: str | None = None) -> None:
        self.default_host = default_host

    @abstractmethod
    def parse(self, line: str) -> Event | None:
        """Parse a single line (without trailing newline)."""


def clean_ip(value: str | None) -> str | None:
    """Return a normalised IP string, or None if ``value`` is not a valid IP.

    Validating the IP matters: log content is attacker-influenced, and we
    later compare IPs against a deny-list. Garbage such as "1.2.3.4; DROP" is
    rejected rather than stored as if it were an address.
    """
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def clean_user(value: str | None) -> str | None:
    """Normalise empty / placeholder user names ("-", "") to None."""
    if value is None:
        return None
    value = value.strip()
    if value in ("", "-"):
        return None
    return value[:128]
