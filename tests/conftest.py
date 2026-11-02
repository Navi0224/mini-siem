"""Shared pytest fixtures."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from mini_siem.schema import Event
from mini_siem.storage import Storage

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = PROJECT_ROOT / "rules"
SAMPLES_DIR = PROJECT_ROOT / "samples"
T0 = datetime(2026, 10, 14, 3, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def storage(tmp_path: Path) -> Iterator[Storage]:
    db = Storage(tmp_path / "test.db")
    yield db
    db.close()


def make_event(seconds: float = 0, **kwargs: Any) -> Event:
    """Build an Event at T0 + seconds with sensible defaults."""
    defaults: dict[str, Any] = {
        "timestamp": T0 + timedelta(seconds=seconds),
        "source": "auth",
        "event_type": "ssh_login",
        "outcome": "failure",
        "source_ip": "203.0.113.5",
        "user": "root",
        "host": "web01",
        "raw": "test",
    }
    defaults.update(kwargs)
    return Event(**defaults)
