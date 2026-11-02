"""Read log files (whole-file or "tail -f" style) and store parsed events.

Files are read in **binary** mode and each line is decoded as UTF-8 with
``errors="replace"``. Two reasons:

1. Logs often contain invalid bytes (attackers send them on purpose); we
   never want one bad byte to crash ingestion.
2. In binary mode ``file.tell()`` gives a real byte offset on every OS
   (text-mode offsets are opaque on Windows), which we use both to resume
   following a file and to fingerprint lines for de-duplication.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

from mini_siem.detection import DetectionEngine
from mini_siem.parsers import Parser
from mini_siem.storage import Storage, event_fingerprint

MAX_LINE_BYTES = 64 * 1024  # longer lines are truncated (defensive limit)


@dataclass
class IngestResult:
    """Counters reported after ingesting a file."""

    lines: int = 0
    parsed: int = 0
    inserted: int = 0

    @property
    def skipped(self) -> int:
        """Lines the parser did not recognise (noise, or malformed)."""
        return self.lines - self.parsed

    @property
    def duplicates(self) -> int:
        """Parsed events already in the database (file ingested before)."""
        return self.parsed - self.inserted


def read_lines(path: Path) -> Iterator[tuple[int, str]]:
    """Yield (byte_offset, decoded_line) for every non-empty line in a file."""
    with path.open("rb") as handle:
        while True:
            offset = handle.tell()
            data = handle.readline(MAX_LINE_BYTES)
            if not data:
                return
            line = data.decode("utf-8", errors="replace").rstrip("\r\n")
            if line.strip():
                yield offset, line


def ingest_file(path: Path, parser: Parser, storage: Storage) -> IngestResult:
    """Parse a whole file and bulk-insert its events."""
    result = IngestResult()
    batch = []
    for offset, line in read_lines(path):
        result.lines += 1
        event = parser.parse(line)
        if event is None:
            continue
        result.parsed += 1
        batch.append((event, event_fingerprint(parser.source_type, path.name, offset, line)))
    result.inserted = storage.insert_events(batch)
    return result


def follow_lines(
    path: Path,
    from_start: bool = False,
    poll_interval: float = 1.0,
    stop: threading.Event | None = None,
) -> Iterator[tuple[int, str]]:
    """Yield (offset, line) as lines are appended to ``path`` -- like ``tail -f``.

    Pure-Python polling, so it works the same on Windows and Linux without
    inotify or any shell command. Handles:

    * partial lines (a writer flushed half a line): buffered until the newline;
    * truncation / rotation (file got smaller): start again from offset 0.

    Stops when ``stop`` is set (used by tests) or on KeyboardInterrupt.
    """
    stop = stop or threading.Event()
    position = 0 if from_start else (path.stat().st_size if path.exists() else 0)
    pending = b""
    pending_offset = position

    while not stop.is_set():
        try:
            size = path.stat().st_size
        except FileNotFoundError:
            size = 0
        if size < position:  # truncated or rotated
            position, pending, pending_offset = 0, b"", 0

        if size > position:
            with path.open("rb") as handle:
                handle.seek(position)
                chunk = handle.read(size - position)
            position += len(chunk)
            data = pending + chunk
            lines = data.split(b"\n")
            pending = lines.pop()  # last element is an unfinished line (or b"")
            offset = pending_offset
            for raw in lines:
                line = raw[:MAX_LINE_BYTES].decode("utf-8", errors="replace").rstrip("\r")
                if line.strip():
                    yield offset, line
                offset += len(raw) + 1
            pending_offset = offset
        else:
            stop.wait(poll_interval)


def follow_file(
    path: Path,
    parser: Parser,
    storage: Storage,
    engine: DetectionEngine,
    from_start: bool = False,
    poll_interval: float = 1.0,
    stop: threading.Event | None = None,
    on_alert: Callable[[str], None] = print,
) -> IngestResult:
    """Follow a growing file: store each new event and run detection on it live."""
    result = IngestResult()
    try:
        for offset, line in follow_lines(path, from_start, poll_interval, stop):
            result.lines += 1
            event = parser.parse(line)
            if event is None:
                continue
            result.parsed += 1
            fp = event_fingerprint(parser.source_type, path.name, offset, line)
            if storage.insert_event(event, fp) is None:
                continue  # already stored earlier
            result.inserted += 1
            for alert in engine.process(event):
                if storage.save_alert(alert):
                    on_alert(f"[ALERT] {alert.severity.upper():8} {alert.rule_name}: "
                             f"{alert.message}")
    except KeyboardInterrupt:
        pass
    return result
