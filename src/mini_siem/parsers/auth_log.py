"""Parser for Linux ``/var/log/auth.log`` (Debian/Ubuntu) style syslog lines.

Two timestamp styles are supported:

* classic syslog:   ``Oct 14 01:02:03 web01 sshd[1234]: ...``
  (no year and no timezone -- we take the year from a parameter and assume
  the server logs in UTC; see the README "Limitations" section)
* RFC 3339 (newer rsyslog / Ubuntu 23.10+ default):
  ``2026-10-14T01:02:03.123456+08:00 web01 sshd[1234]: ...``

Recognised messages:

* sshd ``Failed password for [invalid user] NAME from IP``  -> ssh_login / failure
* sshd ``Accepted password|publickey for NAME from IP``     -> ssh_login / success
* sshd ``Invalid user NAME from IP``                        -> ssh_invalid_user / failure
* sudo ``NAME : TTY=... ; USER=root ; COMMAND=...``          -> sudo / success
* sudo ``NAME : N incorrect password attempts ; ...`` or
  ``NAME : user NOT in sudoers ; ...``                      -> sudo / failure
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from mini_siem.parsers.base import Parser, clean_ip, clean_user
from mini_siem.schema import OUTCOME_FAILURE, OUTCOME_SUCCESS, Event

# "Oct 14 01:02:03 host program[pid]: message"  (day may be space-padded)
_SYSLOG_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<program>[\w\-./]+)(?:\[\d+\])?:\s+(?P<message>.*)$"
)
# "2026-10-14T01:02:03.123+08:00 host program[pid]: message"
_RFC3339_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s+"
    r"(?P<host>\S+)\s+(?P<program>[\w\-./]+)(?:\[\d+\])?:\s+(?P<message>.*)$"
)

# The user-name group is non-greedy and stops at " from " so that names
# containing spaces (attackers try those too) don't break the parse.
_SSH_FAILED_RE = re.compile(
    r"^Failed (?P<method>password|publickey) for (?P<invalid>invalid user )?"
    r"(?P<user>.*?) from (?P<ip>\S+) port (?P<port>\d+)"
)
_SSH_ACCEPTED_RE = re.compile(
    r"^Accepted (?P<method>password|publickey|keyboard-interactive/pam) for "
    r"(?P<user>.*?) from (?P<ip>\S+) port (?P<port>\d+)"
)
_SSH_INVALID_USER_RE = re.compile(
    r"^Invalid user (?P<user>.*?) from (?P<ip>\S+)(?: port (?P<port>\d+))?"
)
_SUDO_RE = re.compile(r"^\s*(?P<user>\S+)\s*:\s*(?P<rest>.*)$")
_SUDO_FIELD_RE = re.compile(r"(?P<key>TTY|PWD|USER|COMMAND)=(?P<value>[^;]*)")

_MONTHS = {
    m: i for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)
}


class AuthLogParser(Parser):
    """Parse sshd and sudo messages from a Linux auth.log."""

    source_type = "auth"

    def __init__(self, default_host: str | None = None, year: int | None = None) -> None:
        super().__init__(default_host)
        # Classic syslog lines have no year, so the caller must tell us.
        self.year = year or datetime.now(timezone.utc).year

    def parse(self, line: str) -> Event | None:
        header = self._parse_header(line)
        if header is None:
            return None
        timestamp, host, program, message = header

        if program == "sshd":
            event = self._parse_sshd(message, timestamp, host)
        elif program == "sudo":
            event = self._parse_sudo(message, timestamp, host)
        else:
            event = None  # cron, systemd-logind, etc. -- not security relevant here
        if event is not None:
            event.raw = line
        return event

    # -- header -----------------------------------------------------------

    def _parse_header(self, line: str) -> tuple[datetime, str, str, str] | None:
        """Split a syslog line into (timestamp, host, program, message)."""
        match = _RFC3339_RE.match(line)
        if match:
            ts = _parse_iso(match.group("ts"))
            if ts is None:
                return None
            return ts, match.group("host"), match.group("program"), match.group("message")

        match = _SYSLOG_RE.match(line)
        if not match:
            return None
        month = _MONTHS.get(match.group("month"))
        if month is None:
            return None
        try:
            hour, minute, second = (int(x) for x in match.group("time").split(":"))
            ts = datetime(self.year, month, int(match.group("day")),
                          hour, minute, second, tzinfo=timezone.utc)
        except ValueError:
            return None  # e.g. "Feb 30"
        return ts, match.group("host"), match.group("program"), match.group("message")

    # -- sshd -------------------------------------------------------------

    def _parse_sshd(self, message: str, ts: datetime, host: str) -> Event | None:
        if m := _SSH_FAILED_RE.match(message):
            return Event(
                timestamp=ts, source=self.source_type, event_type="ssh_login",
                outcome=OUTCOME_FAILURE, source_ip=clean_ip(m.group("ip")),
                user=clean_user(m.group("user")), host=host,
                details={"method": m.group("method"),
                         "invalid_user": bool(m.group("invalid")),
                         "port": int(m.group("port"))},
            )
        if m := _SSH_ACCEPTED_RE.match(message):
            return Event(
                timestamp=ts, source=self.source_type, event_type="ssh_login",
                outcome=OUTCOME_SUCCESS, source_ip=clean_ip(m.group("ip")),
                user=clean_user(m.group("user")), host=host,
                details={"method": m.group("method"), "port": int(m.group("port"))},
            )
        if m := _SSH_INVALID_USER_RE.match(message):
            return Event(
                timestamp=ts, source=self.source_type, event_type="ssh_invalid_user",
                outcome=OUTCOME_FAILURE, source_ip=clean_ip(m.group("ip")),
                user=clean_user(m.group("user")), host=host,
            )
        return None

    # -- sudo -------------------------------------------------------------

    def _parse_sudo(self, message: str, ts: datetime, host: str) -> Event | None:
        m = _SUDO_RE.match(message)
        if not m or "pam_unix" in message:
            return None  # "pam_unix(sudo:session): session opened ..." is noise
        rest = m.group("rest")
        fields = {f.group("key"): f.group("value").strip()
                  for f in _SUDO_FIELD_RE.finditer(rest)}
        if "COMMAND" not in fields:
            return None

        failed = "incorrect password" in rest or "NOT in sudoers" in rest
        return Event(
            timestamp=ts, source=self.source_type, event_type="sudo",
            outcome=OUTCOME_FAILURE if failed else OUTCOME_SUCCESS,
            user=clean_user(m.group("user")), host=host,
            details={"target_user": fields.get("USER", "root"),
                     "command": fields["COMMAND"][:1024],
                     "tty": fields.get("TTY"), "cwd": fields.get("PWD")},
        )


def _parse_iso(value: str) -> datetime | None:
    """Parse an ISO 8601 timestamp; accepts a trailing 'Z' on Python 3.10."""
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
