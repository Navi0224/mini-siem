"""The Flask dashboard.

Security design (the dashboard displays attacker-controlled strings -- URLs,
user names, user agents -- so treat it like any internet-facing app):

* **XSS**: Jinja2 autoescaping is ON for .html templates, so ``<script>`` in a
  log line is rendered as the text ``&lt;script&gt;``. We never use the
  ``|safe`` filter or ``Markup()`` on log data. As a second layer, a strict
  Content-Security-Policy forbids inline and external scripts entirely.
* **CSRF**: the only state-changing action (alert status) is a POST that
  must carry a per-session random token. Without it, any website you visit
  could make your browser POST to http://127.0.0.1:5000 and close alerts.
* **SQL injection**: all queries are parameterised (see storage.py).
* **Exposure**: binds to 127.0.0.1 by default; there is no login, so it
  must not be exposed to a network as-is.
"""

from __future__ import annotations

import hmac
import json
import os
import secrets
from pathlib import Path
from typing import Any

from flask import (Flask, abort, current_app, g, redirect, render_template, request,
                   session, url_for)
from werkzeug.wrappers import Response

from mini_siem.rules import RuleError, load_rules
from mini_siem.storage import ALERT_STATUSES, SEVERITIES, Storage
from mini_siem.web.charts import build_time_chart

PAGE_SIZE = 50

SECURITY_HEADERS = {
    # No scripts at all, styles only from our own /static, no framing.
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'self'; img-src 'self'; "
        "form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}


def create_app(db_path: str | Path, rules_dir: str | Path | None = None,
               secret_key: str | None = None) -> Flask:
    """Application factory (makes testing with a temporary database easy)."""
    app = Flask(__name__)
    app.config.update(
        DB_PATH=str(db_path),
        RULES_DIR=str(rules_dir) if rules_dir else None,
        # A random key per run is fine for a local tool: it only signs the
        # session cookie that holds the CSRF token.
        SECRET_KEY=secret_key or os.environ.get("MINI_SIEM_SECRET_KEY") or secrets.token_hex(32),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
    )
    Storage(app.config["DB_PATH"]).close()  # create tables up front

    _register_hooks(app)
    _register_routes(app)
    return app


# ---------------------------------------------------------------- plumbing

def _db() -> Storage:
    """One SQLite connection per request (sqlite3 objects aren't thread-safe)."""
    if "storage" not in g:
        g.storage = Storage(current_app.config["DB_PATH"])
    return g.storage


def csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


def _check_csrf() -> None:
    sent = request.form.get("csrf_token", "")
    expected = session.get("csrf_token", "")
    # compare_digest avoids leaking the token through timing differences.
    if not expected or not hmac.compare_digest(sent, expected):
        abort(400, description="Missing or invalid CSRF token.")


def _register_hooks(app: Flask) -> None:
    @app.teardown_appcontext
    def close_db(_exc: BaseException | None) -> None:
        storage = g.pop("storage", None)
        if storage is not None:
            storage.close()

    @app.after_request
    def add_security_headers(response: Response) -> Response:
        for header, value in SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        return response

    @app.context_processor
    def inject_globals() -> dict[str, Any]:
        return {"csrf_token": csrf_token, "statuses": ALERT_STATUSES,
                "severities": SEVERITIES}

    @app.template_filter("from_json")
    def from_json(value: str) -> Any:
        return json.loads(value or "null")

    @app.errorhandler(400)
    @app.errorhandler(404)
    def error_page(err: Any) -> tuple[str, int]:
        return render_template("error.html", error=err), err.code


def _arg(name: str, allowed: tuple[str, ...] | None = None) -> str | None:
    """Read a query parameter; drop values outside an allowed set."""
    value = (request.args.get(name) or "").strip()[:200]
    if not value or (allowed is not None and value not in allowed):
        return None
    return value


# ---------------------------------------------------------------- routes

def _register_routes(app: Flask) -> None:
    @app.get("/")
    def overview() -> str:
        db = _db()
        return render_template(
            "overview.html",
            stats=db.stats(),
            chart=build_time_chart(db.events_per_hour()),
            recent_alerts=db.list_alerts(status="open", limit=5),
        )

    @app.get("/alerts")
    def alerts() -> str:
        filters = {
            "status": _arg("status", ALERT_STATUSES),
            "severity": _arg("severity", SEVERITIES),
            "rule_id": _arg("rule_id"),
        }
        db = _db()
        return render_template("alerts.html", alerts=db.list_alerts(**filters),
                               filters=filters, rule_ids=db.alert_rule_ids())

    @app.get("/alerts/<int:alert_id>")
    def alert_detail(alert_id: int) -> str:
        db = _db()
        alert = db.get_alert(alert_id)
        if alert is None:
            abort(404)
        events = db.get_events(json.loads(alert["event_ids"]))
        return render_template("alert_detail.html", alert=alert, events=events,
                               mitre=json.loads(alert["mitre"]))

    @app.post("/alerts/<int:alert_id>/status")
    def update_status(alert_id: int) -> Response:
        _check_csrf()
        status = request.form.get("status", "")
        if status not in ALERT_STATUSES:
            abort(400, description="Invalid status.")
        if not _db().update_alert_status(alert_id, status):
            abort(404)
        # Only two fixed destinations -> no open-redirect risk.
        if request.form.get("return_to") == "detail":
            return redirect(url_for("alert_detail", alert_id=alert_id))
        return redirect(url_for("alerts"))

    @app.get("/events")
    def events() -> str:
        db = _db()
        query = {"source_ip": _arg("ip"), "user": _arg("user"),
                 "event_type": _arg("type"), "text": _arg("q")}
        try:
            page = max(1, int(request.args.get("page", "1")))
        except ValueError:
            page = 1
        rows, total = db.search_events(**query, limit=PAGE_SIZE,
                                       offset=(page - 1) * PAGE_SIZE)
        return render_template(
            "events.html", events=rows, total=total, page=page,
            pages=max(1, -(-total // PAGE_SIZE)), query=query,
            event_types=db.distinct_event_types(),
        )

    @app.get("/rules")
    def rules() -> str:
        rules_dir = app.config["RULES_DIR"]
        loaded, error = [], None
        if rules_dir:
            try:
                loaded = load_rules(Path(rules_dir))
            except RuleError as exc:
                error = str(exc)
        return render_template("rules.html", rules=loaded, error=error)
