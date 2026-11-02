"""mini-siem: a small, self-contained SIEM for learning and demonstration.

Pipeline: log file -> parser -> normalised Event -> SQLite -> detection rules
-> alerts -> Flask dashboard.
"""

__version__ = "0.1.0"
