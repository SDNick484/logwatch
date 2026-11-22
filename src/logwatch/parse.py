"""Turn one raw log line into an Event. Never raises; text is always redacted."""
from __future__ import annotations

import json
import re
from datetime import datetime

from .events import Event
from .redact import redact

_COMBINED = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<target>\S+)(?: [^"]*)?" '
    r'(?P<status>\d{3}) \S+(?: "[^"]*" "(?P<ua>[^"]*)")?'
)


def _combined(line: str) -> tuple[datetime | None, dict[str, str]]:
    m = _COMBINED.match(line)
    if not m:
        return None, {}
    try:
        ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        ts = None
    fields = {
        "ip": m["ip"],
        "method": m["method"],
        "path": m["target"].split("?", 1)[0],
        "status": m["status"],
    }
    if m["ua"] is not None:
        fields["ua"] = m["ua"]
    return ts, {k: redact(v) for k, v in fields.items()}


def _json(line: str) -> dict[str, str]:
    try:
        data = json.loads(line)
    except ValueError:
        return {}
    if not isinstance(data, dict):
        return {}
    return {
        str(k): redact(str(v))
        for k, v in data.items()
        if isinstance(v, (str, int, float)) and not isinstance(v, bool)
    }


def parse_line(source: str, file: str, fmt: str, line: str) -> Event:
    ts: datetime | None = None
    fields: dict[str, str] = {}
    if fmt == "combined":
        ts, fields = _combined(line)
    elif fmt == "json":
        fields = _json(line)
    return Event(source=source, file=file, ts=ts, text=redact(line), fields=fields)
