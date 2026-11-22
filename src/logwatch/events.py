"""Plain data types shared across modules."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal, Mapping

Severity = Literal["low", "medium", "high"]
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


@dataclass(frozen=True)
class Event:
    source: str
    file: str
    ts: datetime | None
    text: str  # always already redacted
    fields: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: Severity
    source: str
    subject: str
    count: int
    summary: str
    samples: tuple[str, ...] = ()
