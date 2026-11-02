"""The correlation / detection engine.

Events are fed in **time order**, one at a time. Each rule has a small
"detector" that keeps whatever state it needs:

* ``MatchDetector``     -- one suspicious event is enough
                           (SQL injection in a URL, sudo by an unexpected user).
* ``ThresholdDetector`` -- counts matching events per group (e.g. per IP) in a
                           sliding time window: "5 failed logins in 60s".
                           With ``distinct: user`` it counts *different* users
                           instead (password spraying).
* ``SequenceDetector``  -- "A happened N times, then B" from the same group:
                           many failures followed by a success = the brute
                           force probably worked.

Correlation = combining several events (possibly from different logs) to
reach one conclusion that no single event shows on its own.

Alert-flood control ("incidents"): once a group (say, an attacking IP) has
triggered a rule, further matching events from that group within
``suppress_seconds`` are folded into the SAME alert -- its count, last_seen
and evidence grow -- instead of creating hundreds of near-identical alerts.
Each new event extends the quiet period, so one long attack = one alert.

Every alert gets a deterministic ``dedup_key`` (rule + group + first event
time), so re-running detection over the same database updates existing
alerts instead of duplicating them.
"""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from mini_siem.rules import Rule
from mini_siem.schema import Event, format_timestamp
from mini_siem.storage import Alert, Storage

MAX_MESSAGE_LENGTH = 300
MAX_EVIDENCE_EVENTS = 100  # cap evidence per alert; the count stays exact


@dataclass
class _Hit:
    """One event remembered inside a sliding window."""

    ts: datetime
    event_id: int | None
    value: Any = None  # the `distinct` field value, if the rule uses one


@dataclass
class _Incident:
    """An alert that is still "live" and absorbing follow-up events."""

    dedup_key: str
    first_seen: datetime
    until: datetime
    count: int = 0
    distinct_values: set[Any] = field(default_factory=set)
    event_ids: deque[int] = field(default_factory=lambda: deque(maxlen=MAX_EVIDENCE_EVENTS))

    def add(self, hit: _Hit) -> None:
        self.count += 1
        if hit.value is not None:
            self.distinct_values.add(hit.value)
        if hit.event_id is not None:
            self.event_ids.append(hit.event_id)


class _Detector:
    """Base class: one detector instance per rule."""

    def __init__(self, rule: Rule) -> None:
        self.rule = rule
        self._incidents: dict[str, _Incident] = {}

    def process(self, event: Event) -> Alert | None:  # pragma: no cover - abstract
        raise NotImplementedError

    def _group(self, event: Event) -> str | None:
        if not self.rule.group_by:
            return None
        value = event.get(self.rule.group_by)
        return None if value in (None, "") else str(value)

    def _continue_incident(self, group: str, event: Event, hit: _Hit) -> Alert | None:
        """If ``group`` already has a live alert, fold this event into it."""
        incident = self._incidents.get(group)
        if incident is None or event.timestamp >= incident.until:
            return None
        incident.add(hit)
        incident.until = event.timestamp + timedelta(seconds=self.rule.suppress_seconds or 0)
        return self._make_alert(event, group, incident)

    def _open_incident(self, group: str | None, event: Event, hits: list[_Hit],
                       count: int | None = None) -> Alert:
        """Create a new alert from the hits that crossed the rule's condition."""
        first_seen = hits[0].ts
        anchor = group if group is not None else f"event-{event.id}"
        incident = _Incident(
            dedup_key=f"{self.rule.id}|{anchor}|{format_timestamp(first_seen)}",
            first_seen=first_seen,
            until=event.timestamp + timedelta(seconds=self.rule.suppress_seconds or 0),
        )
        for hit in hits:
            incident.add(hit)
        if group is not None and self.rule.suppress_seconds:
            self._incidents[group] = incident
        return self._make_alert(event, group, incident, count)

    def _make_alert(self, event: Event, group: str | None, incident: _Incident,
                    count: int | None = None) -> Alert:
        rule = self.rule
        if count is None:
            count = len(incident.distinct_values) if rule.distinct else incident.count
        context = _message_context(event, group, count, rule)
        message = rule.message.format_map(_SafeDict(context))[:MAX_MESSAGE_LENGTH]
        return Alert(
            rule_id=rule.id, rule_name=rule.name, severity=rule.severity,
            message=message, group_key=group,
            first_seen=incident.first_seen, last_seen=event.timestamp,
            event_ids=list(incident.event_ids), mitre=rule.mitre,
            dedup_key=incident.dedup_key,
        )


class MatchDetector(_Detector):
    """Alert on a single matching event (optionally grouped + suppressed)."""

    def process(self, event: Event) -> Alert | None:
        if not self.rule.matches(event):
            return None
        group = self._group(event)
        hit = _Hit(event.timestamp, event.id)
        if group is not None:
            alert = self._continue_incident(group, event, hit)
            if alert is not None:
                return alert
        return self._open_incident(group, event, [hit])


class ThresholdDetector(_Detector):
    """Alert when a group reaches ``threshold`` matching events in the window."""

    def __init__(self, rule: Rule) -> None:
        super().__init__(rule)
        self._windows: dict[str, deque[_Hit]] = defaultdict(deque)

    def process(self, event: Event) -> Alert | None:
        if not self.rule.matches(event):
            return None
        group = self._group(event)
        if group is None:
            return None  # can't count "per IP" for an event with no IP
        value = event.get(self.rule.distinct) if self.rule.distinct else None
        hit = _Hit(event.timestamp, event.id, value)

        alert = self._continue_incident(group, event, hit)
        if alert is not None:
            return alert

        window = self._windows[group]
        window.append(hit)
        _expire(window, event.timestamp, self.rule.window_seconds)
        count = (len({h.value for h in window if h.value is not None})
                 if self.rule.distinct else len(window))
        if count < self.rule.threshold:
            return None
        hits = list(window)
        window.clear()  # these events now belong to the alert
        return self._open_incident(group, event, hits)


class SequenceDetector(_Detector):
    """Alert when ``first`` happened >= N times, then ``then`` happens."""

    def __init__(self, rule: Rule) -> None:
        super().__init__(rule)
        self._firsts: dict[str, deque[_Hit]] = defaultdict(deque)

    def process(self, event: Event) -> Alert | None:
        is_first = self.rule.first_matches(event)
        is_then = self.rule.then_matches(event)
        if not (is_first or is_then):
            return None
        group = self._group(event)
        if group is None:
            return None

        window = self._firsts[group]
        _expire(window, event.timestamp, self.rule.window_seconds)
        if is_first:
            window.append(_Hit(event.timestamp, event.id))
            return None

        # The "then" event (e.g. a successful login) arrived.
        failures = len(window)
        hits = [*window, _Hit(event.timestamp, event.id)]
        window.clear()  # a success resets the story for this group
        if failures < self.rule.first_count:
            return None
        return self._open_incident(group, event, hits, count=failures)


_DETECTORS: dict[str, type[_Detector]] = {
    "match": MatchDetector,
    "threshold": ThresholdDetector,
    "sequence": SequenceDetector,
}


class DetectionEngine:
    """Runs every rule against a stream of time-ordered events."""

    def __init__(self, rules: Iterable[Rule]) -> None:
        self.detectors = [_DETECTORS[r.type](r) for r in rules]

    def process(self, event: Event) -> list[Alert]:
        """Feed one event; return alerts it created or updated."""
        alerts = []
        for detector in self.detectors:
            alert = detector.process(event)
            if alert is not None:
                alerts.append(alert)
        return alerts


def run_detection(storage: Storage, rules: list[Rule]) -> int:
    """Re-scan every stored event with a fresh engine; return # of NEW alerts.

    Alerts already in the database (same dedup_key) are updated but keep
    their status -- an analyst's "closed" is never silently reopened.
    """
    engine = DetectionEngine(rules)
    new = 0
    for event in storage.iter_events():
        for alert in engine.process(event):
            if storage.save_alert(alert):
                new += 1
    return new


def _expire(window: deque[_Hit], now: datetime, window_seconds: int) -> None:
    """Drop hits older than the window (the left of the deque is the oldest)."""
    limit = timedelta(seconds=window_seconds)
    while window and now - window[0].ts > limit:
        window.popleft()


def _message_context(event: Event, group: str | None, count: int,
                     rule: Rule) -> dict[str, Any]:
    """Values available to ``message`` templates in rule files."""
    context: dict[str, Any] = {k: v for k, v in event.details.items()
                               if isinstance(v, (str, int, float))}
    context.update({
        "group": group or "", "count": count,
        "threshold": rule.threshold, "window_seconds": rule.window_seconds,
        "source_ip": event.source_ip or "-", "user": event.user or "-",
        "host": event.host or "-", "event_type": event.event_type,
    })
    return context


class _SafeDict(dict):  # type: ignore[type-arg]
    """Leave unknown ``{placeholders}`` visible instead of raising KeyError.

    The template string comes from the (trusted) rule file; attacker-supplied
    values are only ever *arguments*, so ``str.format_map`` is safe here.
    """

    def __missing__(self, key: str) -> str:
        return "{" + key + "}"
