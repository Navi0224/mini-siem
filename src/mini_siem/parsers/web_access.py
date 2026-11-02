"""Parser for Apache / Nginx access logs in the "combined" format.

Example line::

    203.0.113.9 - - [14/Oct/2026:09:15:02 +0800] "GET /index.html HTTP/1.1" 200 512 "-" "Mozilla/5.0"

The "common" format (without referrer and user agent) is accepted too.

Security note: the URL is attacker-controlled. Attackers URL-encode
payloads (``%27%20OR%201%3D1``) so naive string matching misses them. We
therefore store both the raw URL and a *decoded* copy (decoded up to twice,
to catch double-encoding like ``%252e%252e%252f``). Detection rules match on
``details.url_decoded``.
"""

from __future__ import annotations

import re
from datetime import datetime
from urllib.parse import unquote_plus

from mini_siem.parsers.base import Parser, clean_ip, clean_user
from mini_siem.schema import OUTCOME_FAILURE, OUTCOME_SUCCESS, Event

_COMBINED_RE = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?P<request>[^"]*)" (?P<status>\d{3}) (?P<size>\d+|-)'
    r'(?: "(?P<referrer>[^"]*)" "(?P<agent>[^"]*)")?\s*$'
)
_TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"  # 14/Oct/2026:09:15:02 +0800
MAX_URL_LENGTH = 2048


class WebAccessParser(Parser):
    """Parse Apache/Nginx combined (or common) access log lines."""

    source_type = "web"

    def parse(self, line: str) -> Event | None:
        m = _COMBINED_RE.match(line)
        if not m:
            return None
        try:
            # %z understands "+0800", so this converts the server's local
            # time into an aware datetime; Event then normalises it to UTC.
            ts = datetime.strptime(m.group("time"), _TIME_FORMAT)
        except ValueError:
            return None

        method, url, protocol = _split_request(m.group("request"))
        status = int(m.group("status"))
        size = m.group("size")
        url = url[:MAX_URL_LENGTH]

        return Event(
            timestamp=ts,
            source=self.source_type,
            event_type="http_request",
            # 4xx/5xx = the request did not succeed. This is a simplification:
            # a 200 response to an SQL injection is a *successful* attack.
            outcome=OUTCOME_FAILURE if status >= 400 else OUTCOME_SUCCESS,
            source_ip=clean_ip(m.group("ip")),
            user=clean_user(m.group("user")),
            host=self.default_host,
            raw=line,
            details={
                "method": method,
                "url": url,
                "url_decoded": decode_url(url),
                "protocol": protocol,
                "status": status,
                "bytes": 0 if size == "-" else int(size),
                "referrer": m.group("referrer"),
                "user_agent": m.group("agent"),
            },
        )


def _split_request(request: str) -> tuple[str, str, str]:
    """Split ``"GET /path HTTP/1.1"`` into its three parts, tolerating junk.

    Scanners often send malformed request lines; we keep whatever we can
    instead of dropping the line, because malformed requests are themselves
    a useful signal.
    """
    parts = request.split(" ")
    if len(parts) == 3:
        return parts[0][:16], parts[1], parts[2][:16]
    return "", request, ""


def decode_url(url: str, rounds: int = 2) -> str:
    """URL-decode ``url`` up to ``rounds`` times (stops early when stable)."""
    decoded = url
    for _ in range(rounds):
        nxt = unquote_plus(decoded)
        if nxt == decoded:
            break
        decoded = nxt
    return decoded
