"""Noise allowlist and known-bad rules loaded from YAML."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import yaml

from .events import SEVERITY_ORDER, Event, Finding

__all__ = ["Finding", "RuleSet"]

MAX_SUBJECT_CHARS = 100
MAX_SAMPLES = 2
_PLACEHOLDER = re.compile(r"\{(count|subject|source)\}")

Matcher = Callable[[Event], bool]


def _matcher(raw: Any, rule: str) -> Matcher:
    if not isinstance(raw, dict):
        raise ValueError(f"rule '{rule}': each matcher must be a mapping")
    if "status_class" in raw:
        digit = str(raw["status_class"])[:1]
        if digit not in "12345" or not digit:
            raise ValueError(f"rule '{rule}': bad status_class {raw['status_class']!r}")
        return lambda e: e.fields.get("status", "")[:1] == digit and len(e.fields.get("status", "")) == 3
    field = raw.get("field")
    if "equals" in raw:
        if not field:
            raise ValueError(f"rule '{rule}': 'equals' needs 'field'")
        want = str(raw["equals"])
        return lambda e: e.fields.get(field) == want
    if "regex" in raw:
        try:
            rx = re.compile(str(raw["regex"]))
        except re.error as err:
            raise ValueError(f"rule '{rule}': bad regex: {err}") from err
        if field:
            return lambda e: field in e.fields and rx.search(e.fields[field]) is not None
        return lambda e: rx.search(e.text) is not None
    raise ValueError(f"rule '{rule}': matcher needs regex, equals, or status_class")


@dataclass(frozen=True)
class _Rule:
    name: str
    severity: str
    source: str | None
    matchers: tuple[Matcher, ...]
    group_by: str
    threshold: int
    summary: str

    def matches(self, e: Event) -> bool:
        if self.source is not None and e.source != self.source:
            return False
        return any(m(e) for m in self.matchers)

    def subject(self, e: Event) -> str:
        value = e.source if self.group_by == "source" else e.fields.get(self.group_by, "-")
        return str(value)[:MAX_SUBJECT_CHARS]


class RuleSet:
    def __init__(self, noise: list[tuple[str | None, re.Pattern]], rules: list[_Rule]):
        self._noise = noise
        self._rules = rules

    @classmethod
    def load(cls, path: Path) -> "RuleSet":
        data = yaml.safe_load(Path(path).read_text()) or {}
        if not isinstance(data, dict):
            raise ValueError(f"{path}: rules file must be a mapping")
        noise = []
        for i, n in enumerate(data.get("noise") or []):
            try:
                noise.append((n.get("source"), re.compile(str(n["regex"]))))
            except (re.error, KeyError, AttributeError, TypeError) as err:
                raise ValueError(f"noise entry {i}: {err}") from err
        rules = []
        for r in data.get("rules") or []:
            name = str(r.get("name", "?")) if isinstance(r, dict) else "?"
            if not isinstance(r, dict):
                raise ValueError("rule '?': each rule must be a mapping")
            if r.get("severity") not in SEVERITY_ORDER:
                raise ValueError(f"rule '{name}': severity must be low, medium, or high")
            raw_match = r.get("match")
            raw_list = raw_match if isinstance(raw_match, list) else [raw_match]
            threshold = r.get("threshold", 1)
            if not isinstance(threshold, int) or threshold < 1:
                raise ValueError(f"rule '{name}': threshold must be a positive integer")
            rules.append(
                _Rule(
                    name=name,
                    severity=r["severity"],
                    source=r.get("source"),
                    matchers=tuple(_matcher(m, name) for m in raw_list),
                    group_by=str(r.get("group_by", "source")),
                    threshold=threshold,
                    summary=str(r.get("summary", name)),
                )
            )
        return cls(noise, rules)

    def _is_noise(self, e: Event) -> bool:
        return any((src is None or src == e.source) and rx.search(e.text) for src, rx in self._noise)

    def apply(self, events: list[Event]) -> tuple[list[Finding], list[Event]]:
        """Return (findings, remainder). First matching rule claims an event."""
        groups: dict[tuple[int, str, str], list[Event]] = {}
        remainder: list[Event] = []
        for e in events:
            if self._is_noise(e):
                continue
            for i, rule in enumerate(self._rules):
                if rule.matches(e):
                    groups.setdefault((i, e.source, rule.subject(e)), []).append(e)
                    break
            else:
                remainder.append(e)

        findings = []
        for (i, source, subject), matched in groups.items():
            rule = self._rules[i]
            if len(matched) < rule.threshold:
                continue
            values = {"count": str(len(matched)), "subject": subject, "source": source}
            samples = tuple(dict.fromkeys(e.text for e in matched))[:MAX_SAMPLES]
            findings.append(
                Finding(
                    rule=rule.name,
                    severity=rule.severity,  # type: ignore[arg-type]
                    source=source,
                    subject=subject,
                    count=len(matched),
                    summary=_PLACEHOLDER.sub(lambda m: values[m.group(1)], rule.summary),
                    samples=samples,
                )
            )
        findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], -f.count, f.rule, f.subject))
        return findings, remainder
