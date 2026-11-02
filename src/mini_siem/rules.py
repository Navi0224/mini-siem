"""Load and validate YAML detection rules.

A rule file looks like this (see the ``rules/`` folder for the real ones)::

    id: ssh_bruteforce
    name: SSH brute force
    severity: high
    type: threshold            # match | threshold | sequence
    filter:                    # which events the rule looks at
      event_type: ssh_login
      outcome: failure
    group_by: source_ip        # count separately per attacker IP
    threshold: 5
    window_seconds: 60
    message: "{count} failed SSH logins from {group} within {window_seconds}s"
    mitre:
      - {id: T1110.001, name: "Brute Force: Password Guessing", tactic: Credential Access}

Filters are a mapping of ``field -> condition``. A condition is either a plain
value (equality) or one operator:

* ``{in: [a, b]}`` / ``{not_in: [a, b]}``
* ``{regex: "pattern"}``          -- case-insensitive search
* ``{in_ip_list: deny_list.txt}`` -- IP is in a local file of IPs / CIDR ranges

All conditions in a filter must be true (logical AND).

Rules are loaded with ``yaml.safe_load`` -- never ``yaml.load`` -- because the
full loader can construct arbitrary Python objects from a crafted file.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from mini_siem.schema import Event
from mini_siem.storage import SEVERITIES

RULE_TYPES = ("match", "threshold", "sequence")

Predicate = Callable[[Event], bool]


class RuleError(ValueError):
    """Raised when a rule file is invalid. The message names the file."""


@dataclass
class Rule:
    """A validated detection rule."""

    id: str
    name: str
    severity: str
    type: str
    description: str = ""
    message: str = ""
    mitre: list[dict[str, str]] = field(default_factory=list)
    enabled: bool = True
    # match / threshold
    filter: dict[str, Any] = field(default_factory=dict)
    matches: Predicate = lambda e: True  # noqa: E731 - compiled from `filter`
    group_by: str | None = None
    threshold: int = 1
    distinct: str | None = None
    window_seconds: int = 60
    suppress_seconds: int | None = None
    # sequence
    first_matches: Predicate = lambda e: False  # noqa: E731
    first_count: int = 1
    then_matches: Predicate = lambda e: False  # noqa: E731
    source_file: str = ""


# --------------------------------------------------------------- conditions

def compile_filter(spec: dict[str, Any], base_dir: Path) -> Predicate:
    """Turn a YAML filter mapping into a single ``Event -> bool`` function."""
    if not isinstance(spec, dict):
        raise RuleError("filter must be a mapping of field: condition")
    checks = [(fld, _compile_condition(cond, base_dir)) for fld, cond in spec.items()]

    def predicate(event: Event) -> bool:
        return all(check(event.get(fld)) for fld, check in checks)

    return predicate


def _compile_condition(cond: Any, base_dir: Path) -> Callable[[Any], bool]:
    """Compile one condition into a ``value -> bool`` function."""
    if not isinstance(cond, dict):
        expected = _norm(cond)
        return lambda value: value is not None and _norm(value) == expected

    if len(cond) != 1:
        raise RuleError(f"condition must have exactly one operator, got {sorted(cond)}")
    op, arg = next(iter(cond.items()))

    if op in ("in", "not_in"):
        if not isinstance(arg, list):
            raise RuleError(f"'{op}' needs a list")
        allowed = {_norm(v) for v in arg}
        if op == "in":
            return lambda value: value is not None and _norm(value) in allowed
        return lambda value: value is not None and _norm(value) not in allowed

    if op == "regex":
        try:
            pattern = re.compile(str(arg), re.IGNORECASE)
        except re.error as exc:
            raise RuleError(f"bad regex {arg!r}: {exc}") from exc
        return lambda value: value is not None and pattern.search(str(value)) is not None

    if op == "in_ip_list":
        networks = load_ip_list(base_dir / str(arg))
        return lambda value: ip_in_networks(value, networks)

    raise RuleError(f"unknown operator {op!r}")


def _norm(value: Any) -> str:
    """Compare as lowercase strings so YAML `404` equals the int 404 in details."""
    return str(value).strip().lower()


def load_ip_list(path: Path) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Read a local deny-list: one IP or CIDR per line, '#' starts a comment.

    This is a *local file only* -- no threat-intel feed is downloaded. In a
    real SOC this list would be fed by threat intelligence (e.g. MISP).
    """
    if not path.is_file():
        raise RuleError(f"IP list not found: {path}")
    networks = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        entry = line.split("#", 1)[0].strip()
        if not entry:
            continue
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError as exc:
            raise RuleError(f"{path.name}:{lineno}: invalid IP/CIDR {entry!r}") from exc
    return networks


def ip_in_networks(value: Any, networks: list[Any]) -> bool:
    if not value:
        return False
    try:
        ip = ipaddress.ip_address(str(value))
    except ValueError:
        return False
    return any(ip.version == net.version and ip in net for net in networks)


# --------------------------------------------------------------- loading

def load_rule(path: Path) -> Rule:
    """Load and validate one rule file."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise RuleError(f"{path.name}: invalid YAML: {exc}") from exc
    try:
        return build_rule(data, base_dir=path.parent, source_file=path.name)
    except RuleError as exc:
        raise RuleError(f"{path.name}: {exc}") from exc


def build_rule(data: Any, base_dir: Path, source_file: str = "") -> Rule:
    """Validate a parsed YAML mapping and build a :class:`Rule`."""
    if not isinstance(data, dict):
        raise RuleError("rule must be a YAML mapping")
    for key in ("id", "name", "severity", "type"):
        if not data.get(key):
            raise RuleError(f"missing required key '{key}'")
    if data["severity"] not in SEVERITIES:
        raise RuleError(f"severity must be one of {SEVERITIES}")
    if data["type"] not in RULE_TYPES:
        raise RuleError(f"type must be one of {RULE_TYPES}")

    rule = Rule(
        id=str(data["id"]), name=str(data["name"]), severity=data["severity"],
        type=data["type"], description=str(data.get("description", "")).strip(),
        message=str(data.get("message", data["name"])),
        mitre=list(data.get("mitre") or []), enabled=bool(data.get("enabled", True)),
        group_by=data.get("group_by"), source_file=source_file,
    )

    if rule.type in ("match", "threshold"):
        rule.filter = data.get("filter") or {}
        rule.matches = compile_filter(rule.filter, base_dir)
        rule.suppress_seconds = _int(data, "suppress_seconds", 0)

    if rule.type == "threshold":
        if not rule.group_by:
            raise RuleError("threshold rules need 'group_by'")
        rule.threshold = _int(data, "threshold", 1, minimum=1)
        rule.window_seconds = _int(data, "window_seconds", 60, minimum=1)
        rule.distinct = data.get("distinct")
        # By default, after alerting, stay quiet for one window per group.
        rule.suppress_seconds = _int(data, "suppress_seconds", rule.window_seconds)

    if rule.type == "sequence":
        if not rule.group_by:
            raise RuleError("sequence rules need 'group_by'")
        first, then = data.get("first"), data.get("then")
        if not isinstance(first, dict) or not isinstance(then, dict):
            raise RuleError("sequence rules need 'first' and 'then' sections")
        rule.first_matches = compile_filter(first.get("filter") or {}, base_dir)
        rule.first_count = _int(first, "min_count", 1, minimum=1)
        rule.then_matches = compile_filter(then.get("filter") or {}, base_dir)
        rule.window_seconds = _int(data, "window_seconds", 300, minimum=1)

    return rule


def _int(data: dict[str, Any], key: str, default: int, minimum: int = 0) -> int:
    value = data.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise RuleError(f"'{key}' must be an integer >= {minimum}")
    return value


def load_rules(rules_dir: Path) -> list[Rule]:
    """Load every ``*.yml`` / ``*.yaml`` rule in a folder (sorted by filename)."""
    if not rules_dir.is_dir():
        raise RuleError(f"rules directory not found: {rules_dir}")
    paths = sorted([*rules_dir.glob("*.yml"), *rules_dir.glob("*.yaml")])
    rules = [load_rule(p) for p in paths]
    seen: set[str] = set()
    for rule in rules:
        if rule.id in seen:
            raise RuleError(f"duplicate rule id {rule.id!r}")
        seen.add(rule.id)
    return [r for r in rules if r.enabled]
