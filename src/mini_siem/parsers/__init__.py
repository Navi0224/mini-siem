"""Log parsers. Each one turns a raw line into a normalised Event."""

from __future__ import annotations

from mini_siem.parsers.auth_log import AuthLogParser
from mini_siem.parsers.base import Parser
from mini_siem.parsers.json_log import JsonLogParser
from mini_siem.parsers.web_access import WebAccessParser

#: CLI ``--type`` value -> parser class
PARSERS: dict[str, type[Parser]] = {
    "auth": AuthLogParser,
    "web": WebAccessParser,
    "json": JsonLogParser,
}


def get_parser(log_type: str, host: str | None = None, year: int | None = None) -> Parser:
    """Build the parser for ``log_type`` ("auth", "web" or "json")."""
    if log_type not in PARSERS:
        raise ValueError(f"unknown log type {log_type!r}; choose from {sorted(PARSERS)}")
    if log_type == "auth":
        return AuthLogParser(default_host=host, year=year)
    return PARSERS[log_type](default_host=host)


__all__ = ["PARSERS", "Parser", "AuthLogParser", "WebAccessParser", "JsonLogParser", "get_parser"]
