"""SQLite storage for events and alerts.

Why SQLite? It is a single file, needs no server, ships with Python, and
works the same on Windows and Linux. Real SIEMs use search-optimised stores
(Splunk indexes, Elasticsearch, QRadar's Ariel DB) because they handle
billions of events; SQLite is plenty for a learning project.

SECURITY: every query uses parameter placeholders (``?``). Values that came
from logs -- which attackers control -- are never concatenated into SQL, so
a log line containing ``' OR 1=1 --`` is stored and searched as plain text.
The only dynamic SQL is the WHERE clause *structure* built from a fixed
whitelist of column names in :meth:`Storage.search_events`.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mini_siem.schema import Event, format_timestamp, parse_stored_timestamp

SEVERITIES = ("low", "medium", "high", "critical")
ALERT_STATUSES = ("open", "acknowledged", "closed")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,              -- UTC, 'YYYY-MM-DDTHH:MM:SSZ'
    source      TEXT NOT NULL,              -- parser: auth / web / json
    event_type  TEXT NOT NULL,
    outcome     TEXT NOT NULL,
    source_ip   TEXT,
    user        TEXT,
    host        TEXT,
    details     TEXT NOT NULL DEFAULT '{}', -- JSON object
    raw         TEXT NOT NULL,
    fingerprint TEXT NOT NULL UNIQUE,       -- makes re-ingesting a file idempotent
    ingested_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts   ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_ip   ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_user ON events(user);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);

CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id     TEXT NOT NULL,
    rule_name   TEXT NOT NULL,
    severity    TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
    status      TEXT NOT NULL DEFAULT 'open'
                CHECK (status IN ('open','acknowledged','closed')),
    message     TEXT NOT NULL,
    group_key   TEXT,                       -- e.g. the attacking IP
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    event_ids   TEXT NOT NULL DEFAULT '[]', -- JSON list of events.id (evidence)
    mitre       TEXT NOT NULL DEFAULT '[]', -- JSON list of ATT&CK techniques
    dedup_key   TEXT NOT NULL UNIQUE,       -- re-running detection never duplicates
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
"""


@dataclass
class Alert:
    """A detection produced by a rule, linking back to its evidence events."""

    rule_id: str
    rule_name: str
    severity: str
    message: str
    first_seen: datetime
    last_seen: datetime
    dedup_key: str
    group_key: str | None = None
    event_ids: list[int] = field(default_factory=list)
    mitre: list[dict[str, str]] = field(default_factory=list)
    status: str = "open"
    id: int | None = None


def _now() -> str:
    return format_timestamp(datetime.now(timezone.utc))


def event_fingerprint(source: str, origin: str, offset: int, raw: str) -> str:
    """Stable ID for "this line at this position in this file".

    Ingesting the same file twice produces the same fingerprints, and the
    UNIQUE constraint silently drops the duplicates.
    """
    data = f"{source}|{origin}|{offset}|{raw}".encode("utf-8", "replace")
    return hashlib.sha256(data).hexdigest()


class Storage:
    """Thin wrapper around a SQLite connection. Open one per thread/request."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = str(db_path)
        self.conn = sqlite3.connect(self.db_path, timeout=10)
        self.conn.row_factory = sqlite3.Row
        if self.db_path != ":memory:":
            # WAL lets the dashboard read while `follow` is writing.
            self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(_SCHEMA)

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> Storage:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------ events

    def insert_event(self, event: Event, fingerprint: str) -> int | None:
        """Insert one event; return its new id, or None if it was a duplicate."""
        cur = self.conn.execute(
            "INSERT OR IGNORE INTO events (timestamp, source, event_type, outcome,"
            " source_ip, user, host, details, raw, fingerprint, ingested_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            self._event_params(event, fingerprint),
        )
        self.conn.commit()
        if cur.rowcount == 0:
            return None
        event.id = cur.lastrowid
        return event.id

    def insert_events(self, items: Iterable[tuple[Event, str]]) -> int:
        """Bulk insert (event, fingerprint) pairs in one transaction.

        Returns how many rows were actually inserted (duplicates excluded).
        """
        before = self.conn.total_changes
        with self.conn:  # one transaction = much faster than commit-per-row
            self.conn.executemany(
                "INSERT OR IGNORE INTO events (timestamp, source, event_type, outcome,"
                " source_ip, user, host, details, raw, fingerprint, ingested_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (self._event_params(e, fp) for e, fp in items),
            )
        return self.conn.total_changes - before

    @staticmethod
    def _event_params(event: Event, fingerprint: str) -> tuple[Any, ...]:
        return (
            event.timestamp_str, event.source, event.event_type, event.outcome,
            event.source_ip, event.user, event.host,
            json.dumps(event.details, default=str), event.raw, fingerprint, _now(),
        )

    def iter_events(self) -> Iterator[Event]:
        """Yield every event in time order (used by the detection engine)."""
        cur = self.conn.execute("SELECT * FROM events ORDER BY timestamp, id")
        for row in cur:
            yield row_to_event(row)

    def get_events(self, ids: list[int]) -> list[Event]:
        """Fetch specific events, e.g. the evidence behind an alert."""
        if not ids:
            return []
        ids = [int(i) for i in ids][:500]
        placeholders = ",".join("?" for _ in ids)  # only "?" characters, no data
        rows = self.conn.execute(
            f"SELECT * FROM events WHERE id IN ({placeholders}) ORDER BY timestamp, id",
            ids,
        ).fetchall()
        return [row_to_event(r) for r in rows]

    def search_events(
        self,
        source_ip: str | None = None,
        user: str | None = None,
        event_type: str | None = None,
        text: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[Event], int]:
        """Search events by exact IP / user / type and free text in the raw line.

        Returns (page of events, total number of matches).
        """
        clauses: list[str] = []
        params: list[Any] = []
        # Column names come from this fixed list -- never from user input.
        for column, value in (("source_ip", source_ip), ("user", user),
                              ("event_type", event_type)):
            if value:
                clauses.append(f"{column} = ?")
                params.append(value)
        if text:
            # Escape LIKE wildcards so a search for "100%" means the literal text.
            escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            clauses.append("raw LIKE ? ESCAPE '\\'")
            params.append(f"%{escaped}%")
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

        total = self.conn.execute(f"SELECT COUNT(*) FROM events {where}", params).fetchone()[0]
        rows = self.conn.execute(
            f"SELECT * FROM events {where} ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?",
            [*params, int(limit), int(offset)],
        ).fetchall()
        return [row_to_event(r) for r in rows], total

    def distinct_event_types(self) -> list[str]:
        rows = self.conn.execute("SELECT DISTINCT event_type FROM events ORDER BY 1")
        return [r[0] for r in rows]

    # ------------------------------------------------------------------ alerts

    def save_alert(self, alert: Alert) -> bool:
        """Insert a new alert, or update the existing one with the same dedup_key.

        Returns True if the alert is new. On update we refresh the message,
        last_seen and evidence but deliberately leave ``status`` alone, so an
        analyst's decision is never overwritten by the engine.
        """
        if alert.severity not in SEVERITIES:
            raise ValueError(f"invalid severity {alert.severity!r}")
        now = _now()
        existing = self.conn.execute(
            "SELECT id FROM alerts WHERE dedup_key = ?", (alert.dedup_key,)
        ).fetchone()
        if existing is not None:
            alert.id = existing["id"]
            self.conn.execute(
                "UPDATE alerts SET message = ?, last_seen = MAX(last_seen, ?),"
                " event_ids = ?, updated_at = ? WHERE id = ?",
                (alert.message, format_timestamp(alert.last_seen),
                 json.dumps(alert.event_ids), now, alert.id),
            )
            self.conn.commit()
            return False

        cur = self.conn.execute(
            "INSERT INTO alerts (rule_id, rule_name, severity, status, message,"
            " group_key, first_seen, last_seen, event_ids, mitre, dedup_key,"
            " created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (alert.rule_id, alert.rule_name, alert.severity, alert.status, alert.message,
             alert.group_key, format_timestamp(alert.first_seen),
             format_timestamp(alert.last_seen), json.dumps(alert.event_ids),
             json.dumps(alert.mitre), alert.dedup_key, now, now),
        )
        self.conn.commit()
        alert.id = cur.lastrowid
        return True

    def list_alerts(
        self,
        status: str | None = None,
        severity: str | None = None,
        rule_id: str | None = None,
        limit: int = 500,
    ) -> list[sqlite3.Row]:
        clauses: list[str] = []
        params: list[Any] = []
        for column, value in (("status", status), ("severity", severity),
                              ("rule_id", rule_id)):
            if value:
                clauses.append(f"{column} = ?")
                params.append(value)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        # Most severe first, then newest.
        order = ("CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1"
                 " WHEN 'medium' THEN 2 ELSE 3 END, first_seen DESC")
        return self.conn.execute(
            f"SELECT * FROM alerts {where} ORDER BY {order} LIMIT ?", [*params, int(limit)]
        ).fetchall()

    def get_alert(self, alert_id: int) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()

    def update_alert_status(self, alert_id: int, status: str) -> bool:
        """Change an alert's workflow status. Returns False if no such alert."""
        if status not in ALERT_STATUSES:
            raise ValueError(f"invalid status {status!r}")
        cur = self.conn.execute(
            "UPDATE alerts SET status = ?, updated_at = ? WHERE id = ?",
            (status, _now(), alert_id),
        )
        self.conn.commit()
        return cur.rowcount == 1

    def alert_rule_ids(self) -> list[str]:
        rows = self.conn.execute("SELECT DISTINCT rule_id FROM alerts ORDER BY 1")
        return [r[0] for r in rows]

    # ------------------------------------------------------------------- stats

    def stats(self) -> dict[str, Any]:
        """Headline numbers for the dashboard overview."""
        c = self.conn
        return {
            "events_total": c.execute("SELECT COUNT(*) FROM events").fetchone()[0],
            "alerts_total": c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
            "alerts_open": c.execute(
                "SELECT COUNT(*) FROM alerts WHERE status = 'open'").fetchone()[0],
            "failures": c.execute(
                "SELECT COUNT(*) FROM events WHERE outcome = 'failure'").fetchone()[0],
            "alerts_by_severity": {
                r[0]: r[1] for r in c.execute(
                    "SELECT severity, COUNT(*) FROM alerts WHERE status != 'closed'"
                    " GROUP BY severity")
            },
            "events_by_type": c.execute(
                "SELECT event_type, COUNT(*) AS n FROM events GROUP BY event_type"
                " ORDER BY n DESC").fetchall(),
            "top_source_ips": c.execute(
                "SELECT source_ip, COUNT(*) AS n,"
                " SUM(CASE WHEN outcome = 'failure' THEN 1 ELSE 0 END) AS failures"
                " FROM events WHERE source_ip IS NOT NULL GROUP BY source_ip"
                " ORDER BY failures DESC, n DESC LIMIT 10").fetchall(),
        }

    def events_per_hour(self, max_buckets: int = 48) -> list[tuple[str, int]]:
        """Event counts per hour for the most recent ``max_buckets`` hours with data.

        ``substr(timestamp, 1, 13)`` turns '2026-10-14T09:15:02Z' into
        '2026-10-14T09' -- the fixed-width timestamp format makes this trivial.
        """
        rows = self.conn.execute(
            "SELECT substr(timestamp, 1, 13) AS hour, COUNT(*) FROM events"
            " GROUP BY hour ORDER BY hour DESC LIMIT ?", (int(max_buckets),)
        ).fetchall()
        return [(r[0], r[1]) for r in reversed(rows)]


def row_to_event(row: sqlite3.Row) -> Event:
    """Convert a database row back into an Event."""
    return Event(
        id=row["id"],
        timestamp=parse_stored_timestamp(row["timestamp"]),
        source=row["source"],
        event_type=row["event_type"],
        outcome=row["outcome"],
        source_ip=row["source_ip"],
        user=row["user"],
        host=row["host"],
        raw=row["raw"],
        details=json.loads(row["details"] or "{}"),
    )
