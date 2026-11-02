"""Parser for generic JSON logs, one JSON object per line ("JSON Lines").

Different applications name the same thing differently (``src_ip`` vs
``client_ip`` vs ``source.ip``). The ``FIELD_ALIASES`` table maps the common
variants onto our schema -- this is normalisation in its simplest form.
Any keys we don't recognise are kept in ``details`` so nothing is lost.

Example::

    {"time": "2026-10-14T03:00:00Z", "client_ip": "198.51.100.30",
     "username": "erin", "action": "app_login", "result": "success"}
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from mini_siem.parsers.base import Parser, clean_ip, clean_user
from mini_siem.schema import OUTCOME_FAILURE, OUTCOME_SUCCESS, OUTCOME_UNKNOWN, Event

# schema field -> accepted JSON keys, in priority order.
# Dotted keys ("source.ip") are looked up in nested objects (ECS style).
FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "timestamp": ("timestamp", "@timestamp", "time", "ts", "datetime"),
    "source_ip": ("source_ip", "src_ip", "client_ip", "remote_addr", "ip", "source.ip"),
    "user": ("user", "username", "user_name", "account", "user.name"),
    "host": ("host", "hostname", "host.name"),
    "event_type": ("event_type", "event", "action", "type", "event.action"),
    "outcome": ("outcome", "result", "status", "event.outcome"),
}

# Map assorted outcome words onto success / failure.
_SUCCESS_WORDS = {"success", "succeeded", "ok", "allowed", "allow", "accepted", "true", "pass"}
_FAILURE_WORDS = {"failure", "failed", "fail", "denied", "deny", "rejected", "error", "false"}

_MAX_LINE = 65536


class JsonLogParser(Parser):
    """Parse one JSON object per line into an Event."""

    source_type = "json"

    def parse(self, line: str) -> Event | None:
        line = line.strip()
        if not line or len(line) > _MAX_LINE:
            return None
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            return None
        if not isinstance(obj, dict):
            return None

        raw_ts, ts_key = _first(obj, FIELD_ALIASES["timestamp"])
        ts = parse_timestamp(raw_ts)
        if ts is None:
            return None  # an event without a usable time cannot be correlated

        used_keys = {ts_key}
        values: dict[str, Any] = {}
        for schema_field in ("source_ip", "user", "host", "event_type", "outcome"):
            value, key = _first(obj, FIELD_ALIASES[schema_field])
            values[schema_field] = value
            used_keys.add(key)

        # Keep every top-level key we did not map, so analysts can still see it.
        details = {k: v for k, v in obj.items() if k not in used_keys}

        return Event(
            timestamp=ts,
            source=self.source_type,
            event_type=_as_str(values["event_type"]) or "generic",
            outcome=normalise_outcome(values["outcome"]),
            source_ip=clean_ip(_as_str(values["source_ip"])),
            user=clean_user(_as_str(values["user"])),
            host=_as_str(values["host"]) or self.default_host,
            raw=line,
            details=details,
        )


def _first(obj: dict[str, Any], keys: tuple[str, ...]) -> tuple[Any, str | None]:
    """Return (value, key) for the first alias present in ``obj``."""
    for key in keys:
        value: Any = obj
        for part in key.split("."):
            if not isinstance(value, dict) or part not in value:
                value = None
                break
            value = value[part]
        # Skip nested objects: {"user": {"name": "x"}} should fall through to
        # the "user.name" alias rather than return the whole dict.
        if value is not None and not isinstance(value, (dict, list)):
            return value, key.split(".")[0]
    return None, None


def _as_str(value: Any) -> str | None:
    if value is None or isinstance(value, (dict, list)):
        return None
    return str(value)[:256]


def normalise_outcome(value: Any) -> str:
    """Map "ok"/"denied"/True/HTTP-like codes to success/failure/unknown."""
    if isinstance(value, bool):
        return OUTCOME_SUCCESS if value else OUTCOME_FAILURE
    if isinstance(value, int):
        return OUTCOME_FAILURE if value >= 400 else OUTCOME_SUCCESS
    word = str(value).strip().lower() if value is not None else ""
    if word in _SUCCESS_WORDS:
        return OUTCOME_SUCCESS
    if word in _FAILURE_WORDS:
        return OUTCOME_FAILURE
    return OUTCOME_UNKNOWN


def parse_timestamp(value: Any) -> datetime | None:
    """Accept ISO 8601 strings (with or without 'Z') or Unix epoch seconds."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str):
        try:
            # Python 3.10's fromisoformat does not accept "Z", so swap it.
            return datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    return None
