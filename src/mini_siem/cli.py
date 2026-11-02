"""Command-line interface: ``mini-siem <command> [options]``.

Commands:
    ingest  FILE --type auth|web|json   parse a file, store events, run detection
    follow  FILE --type ...             tail a growing file, alert live
    detect                              re-run all rules over stored events
    alerts  [--status open]             print alerts in the terminal
    rules                               list loaded rules and ATT&CK mappings
    serve                               start the web dashboard
    demo                                fresh DB + sample logs + dashboard
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path

from mini_siem.detection import DetectionEngine, run_detection
from mini_siem.ingest import follow_file, ingest_file
from mini_siem.parsers import PARSERS, get_parser
from mini_siem.rules import RuleError, load_rules
from mini_siem.storage import ALERT_STATUSES, Storage

DEFAULT_DB = "mini_siem.db"
DEMO_DB = "mini_siem_demo.db"
# Which sample file is parsed with which parser in `demo`.
DEMO_SAMPLES = (("auth.log", "auth"), ("access.log", "web"), ("app.jsonl", "json"))
DEMO_YEAR = 2026  # the sample auth.log has no year in its timestamps


def project_dir(name: str) -> Path:
    """Find a top-level project folder (``rules`` or ``samples``).

    Looks in the current directory first, then next to the source checkout
    (works for ``pip install -e .``). Uses pathlib only, so it behaves the
    same on Windows and Linux.
    """
    cwd_candidate = Path.cwd() / name
    if cwd_candidate.is_dir():
        return cwd_candidate
    # src/mini_siem/cli.py -> parents[2] is the repository root
    return Path(__file__).resolve().parents[2] / name


def _db_path(args: argparse.Namespace) -> Path:
    return Path(args.db or os.environ.get("MINI_SIEM_DB", DEFAULT_DB))


def _rules_dir(args: argparse.Namespace) -> Path:
    return Path(args.rules or os.environ.get("MINI_SIEM_RULES") or project_dir("rules"))


# ------------------------------------------------------------------ commands

def cmd_ingest(args: argparse.Namespace) -> int:
    path = Path(args.file)
    if not path.is_file():
        print(f"error: file not found: {path}", file=sys.stderr)
        return 2
    rules = load_rules(_rules_dir(args))
    parser = get_parser(args.type, host=args.host, year=args.year)
    with Storage(_db_path(args)) as storage:
        result = ingest_file(path, parser, storage)
        print(f"{path.name}: {result.lines} lines, {result.parsed} parsed, "
              f"{result.inserted} new, {result.duplicates} duplicates, "
              f"{result.skipped} skipped (unrecognised)")
        if not args.no_detect:
            new = run_detection(storage, rules)
            print(f"detection: {len(rules)} rules, {new} new alerts")
    return 0


def cmd_follow(args: argparse.Namespace) -> int:
    path = Path(args.file)
    rules = load_rules(_rules_dir(args))
    parser = get_parser(args.type, host=args.host, year=args.year)
    print(f"Following {path} (type={args.type}). Press Ctrl+C to stop.")
    with Storage(_db_path(args)) as storage:
        result = follow_file(path, parser, storage, DetectionEngine(rules),
                             from_start=args.from_start, poll_interval=args.interval)
    print(f"\nStopped. {result.inserted} new events stored.")
    return 0


def cmd_detect(args: argparse.Namespace) -> int:
    rules = load_rules(_rules_dir(args))
    with Storage(_db_path(args)) as storage:
        new = run_detection(storage, rules)
    print(f"detection: {len(rules)} rules, {new} new alerts")
    return 0


def cmd_alerts(args: argparse.Namespace) -> int:
    with Storage(_db_path(args)) as storage:
        rows = storage.list_alerts(status=args.status)
    if not rows:
        print("no alerts")
        return 0
    print(f"{'ID':>3}  {'SEVERITY':8}  {'STATUS':12}  {'FIRST SEEN (UTC)':20}  {'RULE':24}  MESSAGE")
    for r in rows:
        print(f"{r['id']:>3}  {r['severity']:8}  {r['status']:12}  {r['first_seen']:20}  "
              f"{r['rule_id']:24}  {r['message'][:90]}")
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    rules = load_rules(_rules_dir(args))
    for rule in rules:
        techniques = ", ".join(m.get("id", "?") for m in rule.mitre)
        print(f"{rule.id:24} {rule.type:9} {rule.severity:8} {techniques:18} {rule.name}")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    from mini_siem.web.app import create_app  # imported lazily: Flask is slow to import

    if args.bind not in ("127.0.0.1", "localhost", "::1"):
        # The dashboard has no login. Exposing it on the network would let
        # anyone read your security events.
        print("WARNING: binding to a non-loopback address exposes the dashboard "
              "(which has NO authentication) to your network.", file=sys.stderr)
    app = create_app(db_path=_db_path(args), rules_dir=_rules_dir(args))
    print(f"Dashboard: http://{args.bind}:{args.port}/  (Ctrl+C to stop)")
    # debug=False: the Werkzeug debugger allows code execution if exposed.
    app.run(host=args.bind, port=args.port, debug=False, use_reloader=False)
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    samples = Path(args.samples) if args.samples else project_dir("samples")
    db = Path(args.db or DEMO_DB)
    for suffix in ("", "-wal", "-shm"):  # start from a clean demo database
        Path(str(db) + suffix).unlink(missing_ok=True)

    rules = load_rules(_rules_dir(args))
    with Storage(db) as storage:
        for filename, log_type in DEMO_SAMPLES:
            path = samples / filename
            if not path.is_file():
                print(f"error: sample not found: {path}", file=sys.stderr)
                return 2
            parser = get_parser(log_type, host="web01" if log_type == "web" else None,
                                year=DEMO_YEAR)
            result = ingest_file(path, parser, storage)
            print(f"loaded {filename:11} {result.inserted:3} events "
                  f"({result.skipped} lines skipped)")
        new = run_detection(storage, rules)
        print(f"detection: {len(rules)} rules -> {new} alerts\n")
    args.db = str(db)
    cmd_alerts(argparse.Namespace(db=str(db), status=None))
    if args.no_serve:
        return 0
    print()
    return cmd_serve(args)


# ------------------------------------------------------------------ argparse

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mini-siem", description="A small learning SIEM.")
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--db", help=f"SQLite file (default: $MINI_SIEM_DB or {DEFAULT_DB})")
        sp.add_argument("--rules", help="rules folder (default: ./rules)")

    def log_opts(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("file", help="log file to read")
        sp.add_argument("--type", required=True, choices=sorted(PARSERS),
                        help="log format: auth (Linux auth.log), web (Apache/Nginx "
                             "combined), json (JSON Lines)")
        sp.add_argument("--host", help="host name to record when the log has none")
        sp.add_argument("--year", type=int, default=datetime.now(timezone.utc).year,
                        help="year for syslog timestamps, which omit it (default: this year)")

    sp = sub.add_parser("ingest", help="ingest a log file")
    log_opts(sp)
    common(sp)
    sp.add_argument("--no-detect", action="store_true", help="store only, skip rules")
    sp.set_defaults(func=cmd_ingest)

    sp = sub.add_parser("follow", help="follow a growing log file (like tail -f)")
    log_opts(sp)
    common(sp)
    sp.add_argument("--from-start", action="store_true",
                    help="read existing content first instead of only new lines")
    sp.add_argument("--interval", type=float, default=1.0, help="poll interval in seconds")
    sp.set_defaults(func=cmd_follow)

    sp = sub.add_parser("detect", help="re-run detection rules over stored events")
    common(sp)
    sp.set_defaults(func=cmd_detect)

    sp = sub.add_parser("alerts", help="list alerts")
    common(sp)
    sp.add_argument("--status", choices=ALERT_STATUSES)
    sp.set_defaults(func=cmd_alerts)

    sp = sub.add_parser("rules", help="list detection rules")
    common(sp)
    sp.set_defaults(func=cmd_rules)

    def serve_opts(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--bind", default="127.0.0.1",
                        help="address to listen on (default 127.0.0.1 = this machine only)")
        sp.add_argument("--port", type=int, default=5000)

    sp = sub.add_parser("serve", help="start the web dashboard")
    common(sp)
    serve_opts(sp)
    sp.set_defaults(func=cmd_serve)

    sp = sub.add_parser("demo", help="load the sample logs into a fresh DB and start the dashboard")
    common(sp)
    serve_opts(sp)
    sp.add_argument("--samples", help="folder with sample logs (default: ./samples)")
    sp.add_argument("--no-serve", action="store_true", help="load samples but don't start the server")
    sp.set_defaults(func=cmd_demo)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except RuleError as exc:
        print(f"rule error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
