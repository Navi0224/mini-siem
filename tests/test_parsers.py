"""Parser tests: each log format normalises into the same Event schema."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from mini_siem.parsers import AuthLogParser, JsonLogParser, WebAccessParser, get_parser
from mini_siem.parsers.web_access import decode_url


# ------------------------------------------------------------------ auth.log

@pytest.fixture
def auth() -> AuthLogParser:
    return AuthLogParser(year=2026)


def test_auth_failed_password(auth: AuthLogParser) -> None:
    e = auth.parse("Oct 14 03:15:00 web01 sshd[123]: Failed password for root "
                   "from 203.0.113.45 port 41000 ssh2")
    assert e is not None
    assert (e.event_type, e.outcome, e.user, e.source_ip, e.host) == (
        "ssh_login", "failure", "root", "203.0.113.45", "web01")
    assert e.timestamp == datetime(2026, 10, 14, 3, 15, tzinfo=timezone.utc)
    assert e.details["invalid_user"] is False
    assert e.raw.startswith("Oct 14")


def test_auth_failed_password_invalid_user(auth: AuthLogParser) -> None:
    e = auth.parse("Oct 14 03:15:05 web01 sshd[124]: Failed password for invalid user "
                   "admin from 203.0.113.45 port 41001 ssh2")
    assert e is not None and e.user == "admin" and e.details["invalid_user"] is True


def test_auth_accepted_publickey_single_digit_day(auth: AuthLogParser) -> None:
    e = auth.parse("Oct  4 01:10:12 web01 sshd[9]: Accepted publickey for alice from "
                   "198.51.100.20 port 50122 ssh2: ED25519 SHA256:abc")
    assert e is not None
    assert (e.outcome, e.user, e.details["method"]) == ("success", "alice", "publickey")
    assert e.timestamp.day == 4


def test_auth_invalid_user_line(auth: AuthLogParser) -> None:
    e = auth.parse("Oct 14 05:00:00 web01 sshd[5]: Invalid user oracle from 203.0.113.88 port 60000")
    assert e is not None
    assert (e.event_type, e.outcome, e.user) == ("ssh_invalid_user", "failure", "oracle")


def test_auth_sudo_success(auth: AuthLogParser) -> None:
    e = auth.parse("Oct 14 06:31:15 web01 sudo:     dave : TTY=pts/2 ; PWD=/var/www ; "
                   "USER=root ; COMMAND=/bin/cat /etc/shadow")
    assert e is not None
    assert (e.event_type, e.outcome, e.user) == ("sudo", "success", "dave")
    assert e.details["target_user"] == "root"
    assert e.details["command"] == "/bin/cat /etc/shadow"
    assert e.source_ip is None


def test_auth_sudo_failures(auth: AuthLogParser) -> None:
    not_sudoer = auth.parse("Oct 14 06:33:02 web01 sudo: www-data : user NOT in sudoers ; "
                            "TTY=pts/3 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash")
    bad_pw = auth.parse("Oct 14 06:34:00 web01 sudo: bob : 3 incorrect password attempts ; "
                        "TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/ls")
    assert not_sudoer is not None and not_sudoer.outcome == "failure"
    assert bad_pw is not None and bad_pw.outcome == "failure"


def test_auth_rfc3339_timestamp_converted_to_utc(auth: AuthLogParser) -> None:
    e = auth.parse("2026-10-14T11:15:00.123456+08:00 web01 sshd[1]: Failed password for root "
                   "from 203.0.113.45 port 1 ssh2")
    assert e is not None
    assert e.timestamp == datetime(2026, 10, 14, 3, 15, 0, 123456, tzinfo=timezone.utc)


@pytest.mark.parametrize("line", [
    "Oct 14 00:05:01 web01 CRON[1]: pam_unix(cron:session): session opened for user root",
    "Oct 14 01:12:40 web01 sudo: pam_unix(sudo:session): session opened for user root",
    "Oct 14 03:00:00 web01 systemd-logind[1]: New session 42 of user carol.",
    "Feb 30 03:00:00 web01 sshd[1]: Failed password for root from 203.0.113.1 port 1 ssh2",
    "complete garbage",
    "",
])
def test_auth_irrelevant_or_invalid_lines_are_skipped(auth: AuthLogParser, line: str) -> None:
    assert auth.parse(line) is None


def test_auth_bad_ip_is_not_stored_as_ip(auth: AuthLogParser) -> None:
    e = auth.parse("Oct 14 03:15:00 web01 sshd[1]: Failed password for root from "
                   "not-an-ip port 22 ssh2")
    assert e is not None and e.source_ip is None


# ------------------------------------------------------------------ access log

WEB_LINE = ('203.0.113.150 - - [14/Oct/2026:12:10:00 +0800] '
            '"GET /products.php?id=1%27%20OR%20%271%27%3D%271 HTTP/1.1" 200 9120 '
            '"-" "Mozilla/5.0"')


def test_web_combined_line_and_timezone_normalisation() -> None:
    e = WebAccessParser(default_host="web01").parse(WEB_LINE)
    assert e is not None
    assert (e.event_type, e.source_ip, e.host, e.outcome) == (
        "http_request", "203.0.113.150", "web01", "success")
    # 12:10 in +08:00 (Malaysia time) is 04:10 UTC
    assert e.timestamp == datetime(2026, 10, 14, 4, 10, tzinfo=timezone.utc)
    assert e.details["status"] == 200
    assert e.details["method"] == "GET"
    assert e.details["url_decoded"] == "/products.php?id=1' OR '1'='1"
    assert e.details["user_agent"] == "Mozilla/5.0"


def test_web_error_status_is_failure_and_common_format_works() -> None:
    e = WebAccessParser().parse(
        '198.51.100.30 - bob [14/Oct/2026:09:00:00 +0000] "GET /missing HTTP/1.1" 404 -')
    assert e is not None
    assert (e.outcome, e.user, e.details["bytes"], e.details["user_agent"]) == (
        "failure", "bob", 0, None)


def test_web_malformed_request_line_is_kept() -> None:
    e = WebAccessParser().parse(
        '203.0.113.9 - - [14/Oct/2026:09:00:00 +0000] "\\x16\\x03\\x01" 400 0 "-" "-"')
    assert e is not None and e.details["method"] == ""


def test_web_garbage_is_skipped() -> None:
    assert WebAccessParser().parse("this is not an access log line") is None


def test_decode_url_handles_double_encoding() -> None:
    assert decode_url("/a/..%252f..%252fetc") == "/a/../../etc"
    assert decode_url("/search?q=blue+shoes") == "/search?q=blue shoes"


# ------------------------------------------------------------------ JSON

def test_json_field_aliases_are_mapped() -> None:
    e = JsonLogParser().parse(
        '{"time": "2026-10-14T07:40:00Z", "host": "app01", "client_ip": "192.0.2.10",'
        ' "username": "grace", "action": "app_login", "result": "success", "session_id": "s1"}')
    assert e is not None
    assert (e.event_type, e.outcome, e.user, e.source_ip, e.host) == (
        "app_login", "success", "grace", "192.0.2.10", "app01")
    assert e.details == {"session_id": "s1"}  # unmapped keys are preserved


def test_json_nested_ecs_style_and_offset() -> None:
    e = JsonLogParser().parse(
        '{"@timestamp": "2026-10-14T17:30:00+08:00", "source": {"ip": "198.51.100.42"},'
        ' "user": {"name": "heidi"}, "event": {"action": "logout", "outcome": "failure"}}')
    assert e is not None
    assert e.timestamp == datetime(2026, 10, 14, 9, 30, tzinfo=timezone.utc)
    assert (e.source_ip, e.user, e.event_type, e.outcome) == (
        "198.51.100.42", "heidi", "logout", "failure")


def test_json_epoch_timestamp_and_defaults() -> None:
    e = JsonLogParser(default_host="h1").parse('{"ts": 1792040400, "msg": "hello"}')
    assert e is not None
    assert (e.event_type, e.outcome, e.host) == ("generic", "unknown", "h1")


@pytest.mark.parametrize("line", [
    '{"time": "2026-10-14T07:00:00Z", "action": "app_lo',  # truncated
    '["not", "an", "object"]',
    '{"action": "login"}',                                  # no timestamp
    '{"time": "yesterday"}',
])
def test_json_invalid_lines_are_skipped(line: str) -> None:
    assert JsonLogParser().parse(line) is None


def test_get_parser_rejects_unknown_type() -> None:
    with pytest.raises(ValueError):
        get_parser("windows-evtx")
