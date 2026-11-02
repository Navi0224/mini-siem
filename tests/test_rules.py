"""Detection rule tests: every shipped rule fires on attack traffic and
stays quiet on similar benign traffic (to keep false positives in check)."""

from __future__ import annotations

from pathlib import Path

import pytest

from conftest import RULES_DIR, SAMPLES_DIR, make_event
from mini_siem.detection import DetectionEngine, run_detection
from mini_siem.ingest import ingest_file
from mini_siem.parsers import get_parser
from mini_siem.rules import Rule, RuleError, build_rule, load_rules
from mini_siem.schema import Event
from mini_siem.storage import Alert, Storage


@pytest.fixture(scope="module")
def rules() -> dict[str, Rule]:
    return {r.id: r for r in load_rules(RULES_DIR)}


def run(rule: Rule, events: list[Event]) -> list[Alert]:
    """Feed events (in order) to an engine with one rule; return alerts.

    Repeated alerts with the same dedup_key are updates of one alert, so we
    keep only the latest version of each.
    """
    engine = DetectionEngine([rule])
    latest: dict[str, Alert] = {}
    for i, event in enumerate(events, start=1):
        event.id = i
        for alert in engine.process(event):
            latest[alert.dedup_key] = alert
    return list(latest.values())


def web(seconds: float, url: str, status: int = 200, ip: str = "203.0.113.150") -> Event:
    from mini_siem.parsers.web_access import decode_url
    return make_event(seconds, source="web", event_type="http_request", user=None,
                      outcome="failure" if status >= 400 else "success", source_ip=ip,
                      details={"method": "GET", "url": url, "url_decoded": decode_url(url),
                               "status": status})


# ------------------------------------------------------------------ loading

def test_all_shipped_rules_load_with_mitre_mapping(rules: dict[str, Rule]) -> None:
    assert set(rules) == {
        "ssh_bruteforce", "ssh_bruteforce_success", "password_spraying", "web_scanning",
        "web_sqli", "web_path_traversal", "web_xss", "sudo_unusual_user", "denylist_login",
    }
    for rule in rules.values():
        assert rule.mitre, f"{rule.id} has no ATT&CK mapping"
        assert all(t["id"].startswith("T") for t in rule.mitre)


@pytest.mark.parametrize("data, error", [
    ({"name": "x", "severity": "high", "type": "match"}, "missing required key 'id'"),
    ({"id": "x", "name": "x", "severity": "urgent", "type": "match"}, "severity"),
    ({"id": "x", "name": "x", "severity": "low", "type": "magic"}, "type"),
    ({"id": "x", "name": "x", "severity": "low", "type": "threshold"}, "group_by"),
    ({"id": "x", "name": "x", "severity": "low", "type": "match",
      "filter": {"user": {"regex": "("}}}, "bad regex"),
    ({"id": "x", "name": "x", "severity": "low", "type": "match",
      "filter": {"user": {"startswith": "a"}}}, "unknown operator"),
    ({"id": "x", "name": "x", "severity": "low", "type": "threshold", "group_by": "user",
      "threshold": "five"}, "threshold"),
])
def test_invalid_rules_are_rejected(data: dict, error: str, tmp_path: Path) -> None:
    with pytest.raises(RuleError, match=error):
        build_rule(data, base_dir=tmp_path)


def test_unsafe_yaml_tags_are_rejected(tmp_path: Path) -> None:
    # yaml.safe_load refuses to build Python objects from tags like this.
    (tmp_path / "evil.yml").write_text("id: !!python/object/apply:os.system ['echo hi']\n")
    with pytest.raises(RuleError, match="invalid YAML"):
        load_rules(tmp_path)


def test_duplicate_rule_ids_rejected(tmp_path: Path) -> None:
    body = "id: same\nname: n\nseverity: low\ntype: match\n"
    (tmp_path / "a.yml").write_text(body)
    (tmp_path / "b.yml").write_text(body)
    with pytest.raises(RuleError, match="duplicate"):
        load_rules(tmp_path)


# ------------------------------------------------------------------ SSH brute force

def test_ssh_bruteforce_fires_and_aggregates(rules: dict[str, Rule]) -> None:
    events = [make_event(i * 5) for i in range(8)]  # 8 failures in 35 s
    alerts = run(rules["ssh_bruteforce"], events)
    assert len(alerts) == 1  # one incident, not four alerts
    assert alerts[0].group_key == "203.0.113.5"
    assert alerts[0].message.startswith("8 failed SSH logins")
    assert alerts[0].event_ids == list(range(1, 9))


def test_ssh_bruteforce_below_threshold_or_too_slow(rules: dict[str, Rule]) -> None:
    assert run(rules["ssh_bruteforce"], [make_event(i) for i in range(4)]) == []
    # 6 failures but 30 s apart: never 5 inside one 60 s window
    assert run(rules["ssh_bruteforce"], [make_event(i * 30) for i in range(6)]) == []


def test_ssh_bruteforce_counts_each_ip_separately(rules: dict[str, Rule]) -> None:
    events = [make_event(i, source_ip=f"203.0.113.{i}") for i in range(10)]
    assert run(rules["ssh_bruteforce"], events) == []


# ------------------------------------------------------------------ brute force -> success

def test_bruteforce_then_success(rules: dict[str, Rule]) -> None:
    events = [make_event(i * 10, user="deploy") for i in range(6)]
    events.append(make_event(65, user="deploy", outcome="success"))
    alerts = run(rules["ssh_bruteforce_success"], events)
    assert len(alerts) == 1
    assert "after 6 failed attempts" in alerts[0].message
    assert alerts[0].severity == "critical"


def test_typo_then_success_is_not_an_alert(rules: dict[str, Rule]) -> None:
    events = [make_event(0, user="carol"), make_event(9, user="carol", outcome="success")]
    assert run(rules["ssh_bruteforce_success"], events) == []


def test_success_from_different_ip_is_not_correlated(rules: dict[str, Rule]) -> None:
    events = [make_event(i) for i in range(6)]
    events.append(make_event(30, outcome="success", source_ip="198.51.100.20"))
    assert run(rules["ssh_bruteforce_success"], events) == []


# ------------------------------------------------------------------ password spraying

def test_password_spraying_counts_distinct_users(rules: dict[str, Rule]) -> None:
    users = ["admin", "test", "oracle", "postgres", "ubuntu", "guest"]
    events = [make_event(i * 45, user=u) for i, u in enumerate(users)]
    alerts = run(rules["password_spraying"], events)
    assert len(alerts) == 1
    assert "6 different users" in alerts[0].message


def test_many_failures_for_one_user_is_not_spraying(rules: dict[str, Rule]) -> None:
    events = [make_event(i * 45, user="root") for i in range(10)]
    assert run(rules["password_spraying"], events) == []


def test_spraying_also_covers_app_logins(rules: dict[str, Rule]) -> None:
    events = [make_event(i * 10, source="json", event_type="app_login", user=f"u{i}")
              for i in range(5)]
    assert len(run(rules["password_spraying"], events)) == 1


# ------------------------------------------------------------------ web scanning

def test_web_scanning(rules: dict[str, Rule]) -> None:
    events = [web(i * 2, f"/path{i}", 404, ip="203.0.113.99") for i in range(12)]
    alerts = run(rules["web_scanning"], events)
    assert len(alerts) == 1 and alerts[0].group_key == "203.0.113.99"


def test_a_few_404s_are_normal(rules: dict[str, Rule]) -> None:
    events = [web(i, "/favicon.ico", 404) for i in range(3)] + [web(10 + i, "/") for i in range(20)]
    assert run(rules["web_scanning"], events) == []


# ------------------------------------------------------------------ web payload patterns

@pytest.mark.parametrize("url", [
    "/products.php?id=1%27%20OR%20%271%27%3D%271",
    "/products.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users--",
    "/item?id=1;%20DROP%20TABLE%20users",
    "/item?id=1%20AND%20SLEEP(5)",
])
def test_sqli_detected(rules: dict[str, Rule], url: str) -> None:
    assert len(run(rules["web_sqli"], [web(0, url)])) == 1


@pytest.mark.parametrize("url", [
    "/download?file=../../../../etc/passwd",
    "/download?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/static/..%252f..%252f..%252fwindows/win.ini",
])
def test_path_traversal_detected(rules: dict[str, Rule], url: str) -> None:
    assert len(run(rules["web_path_traversal"], [web(0, url)])) == 1


@pytest.mark.parametrize("url", [
    "/search?q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E",
    "/search?q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
    "/go?next=javascript:alert(1)",
])
def test_xss_detected(rules: dict[str, Rule], url: str) -> None:
    assert len(run(rules["web_xss"], [web(0, url)])) == 1


@pytest.mark.parametrize("url", [
    "/search?q=blue+shoes", "/products.php?id=3", "/about", "/static/css/site.css",
    "/blog/union-station-review", "/search?q=O%27Reilly+books",
])
def test_benign_urls_do_not_trigger_web_rules(rules: dict[str, Rule], url: str) -> None:
    for rule_id in ("web_sqli", "web_path_traversal", "web_xss"):
        assert run(rules[rule_id], [web(0, url)]) == [], (rule_id, url)


def test_web_pattern_alerts_are_grouped_per_ip(rules: dict[str, Rule]) -> None:
    events = [web(i * 20, "/x?id=1%20OR%201=1") for i in range(3)]
    alerts = run(rules["web_sqli"], events)
    assert len(alerts) == 1 and "(3 requests)" in alerts[0].message


# ------------------------------------------------------------------ sudo

def sudo(user: str, target: str = "root", outcome: str = "success") -> Event:
    return make_event(0, event_type="sudo", user=user, source_ip=None, outcome=outcome,
                      details={"target_user": target, "command": "/bin/bash"})


def test_sudo_by_unusual_user(rules: dict[str, Rule]) -> None:
    alerts = run(rules["sudo_unusual_user"], [sudo("dave")])
    assert len(alerts) == 1 and "'dave' ran a command as root" in alerts[0].message


@pytest.mark.parametrize("event", [
    sudo("alice"),                        # on the admin allow-list
    sudo("dave", target="www-data"),      # not to root
    sudo("www-data", outcome="failure"),  # denied by sudo itself
])
def test_sudo_expected_cases_do_not_alert(rules: dict[str, Rule], event: Event) -> None:
    assert run(rules["sudo_unusual_user"], [event]) == []


# ------------------------------------------------------------------ deny-list

@pytest.mark.parametrize("ip, expected", [
    ("192.0.2.10", 1),     # exact entry
    ("192.0.2.70", 1),     # inside 192.0.2.64/28
    ("192.0.2.80", 0),     # just outside the /28
    ("198.51.100.20", 0),
])
def test_denylist_login(rules: dict[str, Rule], ip: str, expected: int) -> None:
    event = make_event(0, outcome="success", source_ip=ip)
    assert len(run(rules["denylist_login"], [event])) == expected


def test_denylist_ignores_failed_logins(rules: dict[str, Rule]) -> None:
    assert run(rules["denylist_login"], [make_event(0, source_ip="192.0.2.10")]) == []


# ------------------------------------------------------------------ end to end

def test_samples_trigger_every_rule_exactly_as_expected(storage: Storage) -> None:
    for name, log_type in (("auth.log", "auth"), ("access.log", "web"), ("app.jsonl", "json")):
        ingest_file(SAMPLES_DIR / name, get_parser(log_type, year=2026), storage)
    rules = load_rules(RULES_DIR)
    assert run_detection(storage, rules) == 11
    fired = [row["rule_id"] for row in storage.list_alerts()]
    assert set(fired) == {r.id for r in rules}  # every rule fires at least once
    assert fired.count("ssh_bruteforce") == 2
    assert fired.count("denylist_login") == 2

    # Re-running detection must not create duplicates.
    assert run_detection(storage, rules) == 0
    assert len(storage.list_alerts()) == 11
