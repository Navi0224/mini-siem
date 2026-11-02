"""The normalised event schema shared by every parser, the database and the rules.

Every log format (Linux auth.log, Apache/Nginx access logs, JSON application
logs) is converted into this ONE shape. That is "normalisation": once events
look the same, a single detection rule such as "many failed logins from one
IP" works regardless of which log the events came from.

The field names are loosely inspired by the Elastic Common Schema (ECS) --
e.g. ECS uses ``source.ip``, ``user.name``, ``host.name``, ``event.outcome``.
We flatten them to keep the code simple; this is NOT an ECS implementation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

# Allowed values for Event.outcome (ECS uses the same three words).
OUTCOME_SUCCESS = "success"
OUTCOME_FAILURE = "failure"
OUTCOME_UNKNOWN = "unknown"
VALID_OUTCOMES = (OUTCOME_SUCCESS, OUTCOME_FAILURE, OUTCOME_UNKNOWN)

# Store timestamps as fixed-width UTC strings. Because the format is fixed,
# sorting the strings alphabetically also sorts them chronologically, which
# lets SQLite ORDER BY / range queries work on a plain TEXT column.
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

# Attackers control log content. Cap the size we keep per line so one giant
# line cannot bloat the database or the dashboard.
MAX_RAW_LENGTH = 8192


@dataclass
class Event:
    """One normalised log event.

    Attributes:
        timestamp: When the event happened, timezone-aware, converted to UTC.
        source: Which parser produced it ("auth", "web" or "json").
        event_type: What happened, e.g. "ssh_login", "sudo", "http_request".
        outcome: "success", "failure" or "unknown".
        source_ip: The remote IP address that caused the event, if known.
        user: The account involved, if known.
        host: The machine that wrote the log, if known.
        raw: The original log line, kept for investigation/evidence.
        details: Format-specific extras (URL, HTTP status, sudo command ...).
        id: Database row id, set once the event has been stored.
    """

    timestamp: datetime
    source: str
    event_type: str
    outcome: str = OUTCOME_UNKNOWN
    source_ip: str | None = None
    user: str | None = None
    host: str | None = None
    raw: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    id: int | None = None

    def __post_init__(self) -> None:
        if self.timestamp.tzinfo is None:
            # Naive datetimes are ambiguous; we decide they are UTC.
            self.timestamp = self.timestamp.replace(tzinfo=timezone.utc)
        else:
            self.timestamp = self.timestamp.astimezone(timezone.utc)
        if self.outcome not in VALID_OUTCOMES:
            self.outcome = OUTCOME_UNKNOWN
        self.raw = self.raw[:MAX_RAW_LENGTH]

    @property
    def timestamp_str(self) -> str:
        """The timestamp in the canonical storage format."""
        return format_timestamp(self.timestamp)

    def get(self, field_path: str) -> Any:
        """Look up a field by name, with dotted access into ``details``.

        ``event.get("source_ip")`` returns the attribute, and
        ``event.get("details.status")`` returns ``event.details["status"]``.
        Unknown fields return None instead of raising, so a rule that refers to
        a field missing from some log type simply does not match.
        """
        if field_path.startswith("details."):
            return self.details.get(field_path[len("details."):])
        if field_path in _TOP_LEVEL_FIELDS:
            return getattr(self, field_path)
        return None


_TOP_LEVEL_FIELDS = {
    "timestamp", "source", "event_type", "outcome", "source_ip",
    "user", "host", "raw", "id",
}


def format_timestamp(value: datetime) -> str:
    """Format an aware datetime as the canonical UTC storage string."""
    return value.astimezone(timezone.utc).strftime(TIMESTAMP_FORMAT)


def parse_stored_timestamp(value: str) -> datetime:
    """Inverse of :func:`format_timestamp`."""
    return datetime.strptime(value, TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)
