"""Group leftover lines by shape so the model sees templates and counts, not raw volume."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from .events import Event

MAX_SAMPLES = 2
_MASKS = [
    re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),  # uuid
    re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"),  # ipv4
    re.compile(r'"[^"]*"|\'[^\']*\''),  # quoted strings
    re.compile(r"\b(?=[0-9a-fA-F]*\d)[0-9a-fA-F]{8,}\b"),  # hex ids
    re.compile(r"\d+"),  # digit runs
]
_WS = re.compile(r"\s+")


@dataclass(frozen=True)
class Cluster:
    id: str
    source: str
    template: str
    count: int
    samples: tuple[str, ...]


def template_of(text: str) -> str:
    for rx in _MASKS:
        text = rx.sub("<*>", text)
    return _WS.sub(" ", text).strip()


def _id(source: str, template: str) -> str:
    return "c" + hashlib.sha1(f"{source}\x00{template}".encode("utf-8", "replace")).hexdigest()[:8]


def cluster(events: list[Event], max_clusters: int = 50) -> list[Cluster]:
    counts: dict[tuple[str, str], int] = {}
    samples: dict[tuple[str, str], list[str]] = {}
    for e in events:
        key = (e.source, template_of(e.text))
        counts[key] = counts.get(key, 0) + 1
        kept = samples.setdefault(key, [])
        if len(kept) < MAX_SAMPLES and e.text not in kept:
            kept.append(e.text)

    clusters = [
        Cluster(id=_id(src, tpl), source=src, template=tpl, count=n, samples=tuple(samples[(src, tpl)]))
        for (src, tpl), n in counts.items()
    ]
    clusters.sort(key=lambda c: (-c.count, c.id))
    if len(clusters) > max_clusters:
        tail = clusters[max_clusters:]
        clusters = clusters[:max_clusters] + [
            Cluster(id="cother", source="*", template="<other>", count=sum(c.count for c in tail), samples=())
        ]
    return clusters
