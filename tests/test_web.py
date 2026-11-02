"""Flask route tests using the built-in test client (no real server needed)."""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

import pytest
from flask.testing import FlaskClient

from conftest import RULES_DIR, SAMPLES_DIR
from mini_siem.detection import run_detection
from mini_siem.ingest import ingest_file
from mini_siem.parsers import get_parser
from mini_siem.rules import load_rules
from mini_siem.storage import Storage
from mini_siem.web.app import create_app
from mini_siem.web.charts import build_time_chart, fill_hours


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "web.db"
    with Storage(path) as storage:
        for name, log_type in (("auth.log", "auth"), ("access.log", "web"),
                               ("app.jsonl", "json")):
            ingest_file(SAMPLES_DIR / name, get_parser(log_type, year=2026), storage)
        run_detection(storage, load_rules(RULES_DIR))
    return path


@pytest.fixture
def client(db_path: Path) -> Iterator[FlaskClient]:
    app = create_app(db_path, RULES_DIR, secret_key="test-secret")
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def _csrf(client: FlaskClient, url: str = "/alerts") -> str:
    html = client.get(url).get_data(as_text=True)
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match, "CSRF token missing from form"
    return match.group(1)


@pytest.mark.parametrize("url", [
    "/", "/alerts", "/alerts?status=open&severity=high", "/alerts/1",
    "/events", "/events?ip=203.0.113.45", "/events?type=sudo&user=dave",
    "/events?q=etc/passwd&page=1", "/rules", "/static/style.css",
])
def test_pages_render(client: FlaskClient, url: str) -> None:
    assert client.get(url).status_code == 200


def test_overview_shows_counts_and_svg_chart(client: FlaskClient) -> None:
    html = client.get("/").get_data(as_text=True)
    assert "Events stored" in html and "115" in html
    assert '<svg class="chart"' in html
    assert "<script" not in html  # dashboard ships no JavaScript at all


def test_unknown_alert_is_404(client: FlaskClient) -> None:
    assert client.get("/alerts/99999").status_code == 404


def test_bad_filter_values_are_ignored(client: FlaskClient) -> None:
    resp = client.get("/alerts?status=<script>&severity=nope")
    assert resp.status_code == 200
    assert "<script>" not in resp.get_data(as_text=True)


def test_attacker_controlled_strings_are_escaped(client: FlaskClient) -> None:
    """The XSS payloads in the sample logs must render as text, never as HTML."""
    for url in ("/events?ip=203.0.113.152", "/alerts", "/alerts/8"):
        html = client.get(url).get_data(as_text=True)
        assert "<script>alert" not in html, url
        assert "<img src=x" not in html, url
    html = client.get("/events?ip=203.0.113.152").get_data(as_text=True)
    assert "&lt;script&gt;alert(document.cookie)&lt;/script&gt;" in html


def test_security_headers(client: FlaskClient) -> None:
    resp = client.get("/")
    csp = resp.headers["Content-Security-Policy"]
    assert "default-src 'none'" in csp and "script-src" not in csp
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"


def test_status_change_with_csrf_token(client: FlaskClient, db_path: Path) -> None:
    token = _csrf(client)
    resp = client.post("/alerts/1/status", data={"status": "acknowledged", "csrf_token": token})
    assert resp.status_code == 302 and resp.headers["Location"].endswith("/alerts")
    with Storage(db_path) as storage:
        assert storage.get_alert(1)["status"] == "acknowledged"
    resp = client.post("/alerts/1/status",
                       data={"status": "closed", "csrf_token": token, "return_to": "detail"})
    assert resp.headers["Location"].endswith("/alerts/1")
    assert "closed" in client.get("/alerts?status=closed").get_data(as_text=True)


def test_status_change_without_csrf_token_is_rejected(client: FlaskClient, db_path: Path) -> None:
    client.get("/alerts")  # session exists, but the forged form has no token
    assert client.post("/alerts/1/status", data={"status": "closed"}).status_code == 400
    assert client.post("/alerts/1/status",
                       data={"status": "closed", "csrf_token": "guess"}).status_code == 400
    with Storage(db_path) as storage:
        assert storage.get_alert(1)["status"] == "open"


def test_status_change_validation(client: FlaskClient) -> None:
    token = _csrf(client)
    assert client.post("/alerts/1/status",
                       data={"status": "deleted", "csrf_token": token}).status_code == 400
    assert client.post("/alerts/9999/status",
                       data={"status": "closed", "csrf_token": token}).status_code == 404
    assert client.get("/alerts/1/status").status_code == 405  # GET must never change state


def test_event_search_by_ip_user_type(client: FlaskClient) -> None:
    html = client.get("/events?ip=203.0.113.45").get_data(as_text=True)
    assert "11 matching events" in html
    html = client.get("/events?user=dave&type=sudo").get_data(as_text=True)
    assert "1 matching event" in html and "/etc/shadow" in html


def test_rules_page_lists_mitre(client: FlaskClient) -> None:
    html = client.get("/rules").get_data(as_text=True)
    assert "T1110.003" in html and "https://attack.mitre.org/techniques/T1110/003/" in html


def test_empty_database_renders(tmp_path: Path) -> None:
    app = create_app(tmp_path / "empty.db", RULES_DIR, secret_key="x")
    with app.test_client() as c:
        assert "No events yet" in c.get("/").get_data(as_text=True)
        assert c.get("/alerts").status_code == 200


# ------------------------------------------------------------------ chart maths

def test_fill_hours_adds_empty_buckets() -> None:
    series = fill_hours([("2026-10-14T01", 3), ("2026-10-14T04", 1)])
    assert [n for _, n in series] == [3, 0, 0, 1]


def test_chart_geometry_stays_inside_plot() -> None:
    chart = build_time_chart([("2026-10-14T01", 30), ("2026-10-14T02", 7)])
    assert chart is not None and len(chart.bars) == 2
    tallest = max(chart.bars, key=lambda b: b.height)
    assert tallest.y >= 0 and tallest.y + tallest.height == pytest.approx(chart.baseline)
    assert build_time_chart([]) is None
