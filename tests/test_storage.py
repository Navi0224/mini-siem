"""Storage tests: round-trips, de-duplication, search and SQL-injection safety."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from conftest import make_event
from mini_siem.storage import Alert, Storage


def _alert(key: str = "k1", **kw: object) -> Alert:
    t = datetime(2026, 10, 14, 3, 0, tzinfo=timezone.utc)
    data = dict(rule_id="r1", rule_name="Rule 1", severity="high", message="m",
                first_seen=t, last_seen=t, dedup_key=key, group_key="203.0.113.5",
                event_ids=[1, 2], mitre=[{"id": "T1110"}])
    data.update(kw)
    return Alert(**data)  # type: ignore[arg-type]


def test_event_round_trip(storage: Storage) -> None:
    event = make_event(details={"port": 22, "nested": {"a": 1}})
    event_id = storage.insert_event(event, "fp1")
    assert event_id is not None
    [loaded] = storage.get_events([event_id])
    assert loaded.timestamp == event.timestamp
    assert (loaded.source_ip, loaded.user, loaded.details) == (
        "203.0.113.5", "root", {"port": 22, "nested": {"a": 1}})


def test_duplicate_fingerprints_are_ignored(storage: Storage) -> None:
    assert storage.insert_event(make_event(), "same") is not None
    assert storage.insert_event(make_event(), "same") is None
    assert storage.insert_events([(make_event(), "same"), (make_event(), "new")]) == 1


def test_events_iterate_in_time_order(storage: Storage) -> None:
    storage.insert_events([(make_event(30), "b"), (make_event(0), "a"), (make_event(10), "c")])
    seconds = [e.timestamp.second for e in storage.iter_events()]
    assert seconds == [0, 10, 30]


def test_search_filters_and_pagination(storage: Storage) -> None:
    storage.insert_events([
        (make_event(i, source_ip="203.0.113.5" if i % 2 else "198.51.100.1",
                    raw=f"line {i}"), f"fp{i}")
        for i in range(10)
    ])
    rows, total = storage.search_events(source_ip="203.0.113.5", limit=3)
    assert total == 5 and len(rows) == 3
    rows, total = storage.search_events(source_ip="203.0.113.5", limit=3, offset=3)
    assert total == 5 and len(rows) == 2
    assert storage.search_events(text="line 7")[1] == 1


def test_search_is_safe_against_sql_injection(storage: Storage) -> None:
    storage.insert_event(make_event(user="alice"), "fp")
    # If this string were concatenated into SQL it would match every row.
    rows, total = storage.search_events(user="x' OR '1'='1")
    assert (rows, total) == ([], 0)
    # And an attacker-named user is stored and found literally.
    storage.insert_event(make_event(user="'; DROP TABLE events; --"), "fp2")
    assert storage.search_events(user="'; DROP TABLE events; --")[1] == 1
    assert storage.stats()["events_total"] == 2  # table still there


def test_like_wildcards_are_escaped(storage: Storage) -> None:
    storage.insert_event(make_event(raw="100% done"), "a")
    storage.insert_event(make_event(raw="1000 done"), "b")
    assert storage.search_events(text="100%")[1] == 1
    assert storage.search_events(text="_")[1] == 0


def test_alert_save_update_and_status(storage: Storage) -> None:
    alert = _alert()
    assert storage.save_alert(alert) is True
    assert alert.id == 1
    assert storage.update_alert_status(1, "closed") is True

    # Same dedup_key again: updated in place, status preserved.
    later = _alert(message="m2", event_ids=[1, 2, 3],
                   last_seen=datetime(2026, 10, 14, 3, 5, tzinfo=timezone.utc))
    assert storage.save_alert(later) is False
    row = storage.get_alert(1)
    assert row is not None
    assert (row["status"], row["message"], row["last_seen"]) == (
        "closed", "m2", "2026-10-14T03:05:00Z")
    assert len(storage.list_alerts()) == 1


def test_invalid_status_and_severity_rejected(storage: Storage) -> None:
    storage.save_alert(_alert())
    with pytest.raises(ValueError):
        storage.update_alert_status(1, "deleted")
    with pytest.raises(ValueError):
        storage.save_alert(_alert("k2", severity="urgent"))
    assert storage.update_alert_status(999, "closed") is False


def test_list_alerts_filters_and_orders_by_severity(storage: Storage) -> None:
    storage.save_alert(_alert("a", severity="low"))
    storage.save_alert(_alert("b", severity="critical"))
    storage.save_alert(_alert("c", severity="medium", rule_id="r2"))
    assert [r["severity"] for r in storage.list_alerts()] == ["critical", "medium", "low"]
    assert len(storage.list_alerts(rule_id="r2")) == 1
    assert len(storage.list_alerts(status="open", severity="low")) == 1


def test_stats_and_events_per_hour(storage: Storage) -> None:
    storage.insert_events([(make_event(0), "a"), (make_event(3600, outcome="success"), "b"),
                           (make_event(3700), "c")])
    stats = storage.stats()
    assert stats["events_total"] == 3 and stats["failures"] == 2
    assert storage.events_per_hour() == [("2026-10-14T03", 1), ("2026-10-14T04", 2)]
