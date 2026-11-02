"""Server-side geometry for the "events over time" bar chart.

The chart is plain inline SVG produced by a Jinja template -- no JavaScript
and no CDN. It therefore works offline and fits a strict Content Security
Policy. This module only does the maths (where each bar goes); the template
draws it, and Jinja escapes every text label.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

WIDTH = 720
HEIGHT = 220
PAD_LEFT = 44   # room for y-axis labels
PAD_RIGHT = 8
PAD_TOP = 12
PAD_BOTTOM = 28  # room for x-axis labels
BAR_GAP = 2      # px of empty space between neighbouring bars


@dataclass
class Bar:
    x: float
    y: float
    width: float
    height: float
    label: str   # e.g. "2026-10-14 09:00 UTC"
    count: int


@dataclass
class TimeChart:
    bars: list[Bar]
    y_ticks: list[tuple[float, int]]  # (y position, value)
    x_labels: list[tuple[float, str]]  # (x position, text)
    width: int = WIDTH
    height: int = HEIGHT
    baseline: float = HEIGHT - PAD_BOTTOM
    left: float = PAD_LEFT


def fill_hours(buckets: list[tuple[str, int]], max_buckets: int = 48) -> list[tuple[datetime, int]]:
    """Turn sparse ("2026-10-14T09", n) rows into a continuous hourly series.

    Hours without events are added with a count of 0 so gaps are visible.
    """
    if not buckets:
        return []
    counts = {datetime.strptime(h, "%Y-%m-%dT%H").replace(tzinfo=timezone.utc): n
              for h, n in buckets}
    end = max(counts)
    start = max(min(counts), end - timedelta(hours=max_buckets - 1))
    series = []
    current = start
    while current <= end:
        series.append((current, counts.get(current, 0)))
        current += timedelta(hours=1)
    return series


def _nice_max(value: int) -> int:
    """Round the y-axis maximum up to a friendly number (1, 2, 5 x 10^n)."""
    if value <= 5:
        return 5
    magnitude = 10 ** (len(str(value)) - 1)
    for step in (1, 2, 5, 10):
        if value <= step * magnitude:
            return step * magnitude
    return 10 * magnitude  # pragma: no cover


def build_time_chart(buckets: list[tuple[str, int]]) -> TimeChart | None:
    """Compute bar positions for the hourly event counts (None if no data)."""
    series = fill_hours(buckets)
    if not series:
        return None
    plot_w = WIDTH - PAD_LEFT - PAD_RIGHT
    plot_h = HEIGHT - PAD_TOP - PAD_BOTTOM
    y_max = _nice_max(max(n for _, n in series))
    slot = plot_w / len(series)
    bar_w = max(slot - BAR_GAP, 1)
    baseline = HEIGHT - PAD_BOTTOM

    bars = []
    for i, (hour, count) in enumerate(series):
        h = plot_h * count / y_max
        bars.append(Bar(
            x=round(PAD_LEFT + i * slot + BAR_GAP / 2, 2), y=round(baseline - h, 2),
            width=round(bar_w, 2), height=round(h, 2),
            label=hour.strftime("%Y-%m-%d %H:00 UTC"), count=count,
        ))

    y_ticks = [(round(baseline - plot_h * f, 2), int(y_max * f)) for f in (0, 0.5, 1)]
    every = max(1, len(series) // 6)  # at most ~6 x labels so they never collide
    x_labels = [(round(PAD_LEFT + i * slot + slot / 2, 2), hour.strftime("%H:00"))
                for i, (hour, _) in enumerate(series) if i % every == 0]
    return TimeChart(bars=bars, y_ticks=y_ticks, x_labels=x_labels)
