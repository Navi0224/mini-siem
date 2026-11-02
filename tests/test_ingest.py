"""Ingestion tests: whole-file, idempotency, follow mode and the CLI."""

from __future__ import annotations

import threading
import time
from pathlib import Path

from conftest import RULES_DIR, SAMPLES_DIR
from mini_siem.cli import main
from mini_siem.detection import DetectionEngine
from mini_siem.ingest import follow_file, follow_lines, ingest_file, read_lines
from mini_siem.parsers import get_parser
from mini_siem.rules import load_rules
from mini_siem.storage import Storage

FAIL = ("Oct 14 03:15:{s:02d} web01 sshd[1]: Failed password for root "
        "from 203.0.113.45 port {s} ssh2\n")


def test_ingest_counts_and_is_idempotent(storage: Storage) -> None:
    parser = get_parser("auth", year=2026)
    first = ingest_file(SAMPLES_DIR / "auth.log", parser, storage)
    assert (first.lines, first.parsed, first.inserted, first.skipped) == (50, 44, 44, 6)
    second = ingest_file(SAMPLES_DIR / "auth.log", parser, storage)
    assert (second.inserted, second.duplicates) == (0, 44)


def test_read_lines_survives_invalid_utf8_and_crlf(tmp_path: Path) -> None:
    path = tmp_path / "x.log"
    path.write_bytes(b"first \xff\xfe line\r\n\r\nsecond\n")
    lines = [line for _, line in read_lines(path)]
    assert lines == ["first �� line", "second"]


def test_follow_lines_sees_appended_and_partial_lines(tmp_path: Path) -> None:
    path = tmp_path / "grow.log"
    path.write_text("old line\n")
    stop = threading.Event()
    seen: list[str] = []

    def reader() -> None:
        for _, line in follow_lines(path, from_start=False, poll_interval=0.05, stop=stop):
            seen.append(line)

    t = threading.Thread(target=reader)
    t.start()
    time.sleep(0.2)
    with path.open("a") as f:
        f.write("new 1\nnew ")   # second line is only half written...
        f.flush()
        time.sleep(0.2)
        f.write("2\n")           # ...and completed later
    time.sleep(0.3)
    stop.set()
    t.join(timeout=2)
    assert seen == ["new 1", "new 2"]  # "old line" skipped: we started at the end


def test_follow_handles_truncation(tmp_path: Path) -> None:
    path = tmp_path / "rot.log"
    path.write_text("aaaaaaaaaa\nbbbbbbbbbb\n")
    stop = threading.Event()
    seen: list[str] = []

    def reader() -> None:
        for _, line in follow_lines(path, from_start=True, poll_interval=0.05, stop=stop):
            seen.append(line)

    t = threading.Thread(target=reader)
    t.start()
    time.sleep(0.2)
    path.write_text("c\n")  # file rotated/truncated: smaller than before
    time.sleep(0.3)
    stop.set()
    t.join(timeout=2)
    assert seen == ["aaaaaaaaaa", "bbbbbbbbbb", "c"]


def test_follow_file_stores_events_and_alerts_live(tmp_path: Path, storage: Storage) -> None:
    path = tmp_path / "auth.log"
    path.write_text("")
    stop = threading.Event()
    printed: list[str] = []
    engine = DetectionEngine(load_rules(RULES_DIR))

    def worker() -> None:
        # SQLite connections belong to the thread that opened them.
        with Storage(storage.db_path) as own_storage:
            follow_file(path, get_parser("auth", year=2026), own_storage, engine,
                        poll_interval=0.05, stop=stop, on_alert=printed.append)

    t = threading.Thread(target=worker)
    t.start()
    time.sleep(0.2)
    with path.open("a") as f:
        for s in range(6):
            f.write(FAIL.format(s=s))
    time.sleep(0.5)
    stop.set()
    t.join(timeout=2)
    assert storage.stats()["events_total"] == 6
    assert any("SSH brute force" in p for p in printed)
    assert [r["rule_id"] for r in storage.list_alerts()] == ["ssh_bruteforce"]


def test_cli_ingest_alerts_and_rules(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    db = str(tmp_path / "cli.db")
    rules = str(RULES_DIR)
    assert main(["ingest", str(SAMPLES_DIR / "access.log"), "--type", "web",
                 "--db", db, "--rules", rules]) == 0
    out = capsys.readouterr().out
    assert "62 parsed" in out and "4 new alerts" in out

    assert main(["alerts", "--db", db]) == 0
    assert "web_scanning" in capsys.readouterr().out
    assert main(["rules", "--rules", rules]) == 0
    assert "T1110.003" in capsys.readouterr().out
    assert main(["ingest", str(tmp_path / "missing.log"), "--type", "web", "--db", db,
                 "--rules", rules]) == 2


def test_cli_demo_without_server(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    db = str(tmp_path / "demo.db")
    assert main(["demo", "--no-serve", "--db", db, "--rules", str(RULES_DIR),
                 "--samples", str(SAMPLES_DIR)]) == 0
    out = capsys.readouterr().out
    assert "9 rules -> 11 alerts" in out
