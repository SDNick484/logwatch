"""Render the daily digest as markdown. All log-derived text is escaped."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from .cluster import Cluster
from .events import SEVERITY_ORDER, Finding
from .llm import Classification

SUSPICIOUS_RULE = "instruction-like-text"
QUIET_LINE = "Nothing notable in the last 24 hours."


def _plain(text: object, limit: int = 300) -> str:
    """Untrusted text in running prose or a table cell."""
    t = " ".join(str(text).split())[:limit]
    return t.replace("\\", "\\\\").replace("|", "\\|").replace("`", "'").replace("](", "] (").replace("<", "&lt;")


def _code(text: object, limit: int = 200) -> str:
    """Untrusted text as an inline code span (still safe inside a table)."""
    t = " ".join(str(text).split())[:limit]
    return "`" + t.replace("`", "'").replace("|", "\\|").replace("](", "] (") + "`"


@dataclass
class _Merged:
    rule: str
    severity: str
    source: str
    subject: str
    count: int
    windows: int
    samples: tuple[str, ...]


def _merge(findings: list[Finding]) -> list[_Merged]:
    merged: dict[tuple[str, str, str], _Merged] = {}
    for f in findings:
        key = (f.rule, f.source, f.subject)
        if key in merged:
            m = merged[key]
            m.count += f.count
            m.windows += 1
            if SEVERITY_ORDER[f.severity] < SEVERITY_ORDER[m.severity]:
                m.severity = f.severity
        else:
            merged[key] = _Merged(f.rule, f.severity, f.source, f.subject, f.count, 1, f.samples)
    return sorted(merged.values(), key=lambda m: (SEVERITY_ORDER[m.severity], -m.count, m.rule, m.subject))


def _finding_line(m: _Merged) -> str:
    where = _plain(m.source) + ("" if m.subject == m.source else " · " + _code(m.subject, 100))
    windows = f" across {m.windows} collection windows" if m.windows > 1 else ""
    line = f"- **{m.rule}** · {where}: {m.count} events{windows}"
    for s in m.samples[:1]:
        line += f"\n  - sample: {_code(s)}"
    return line


def summarize(
    findings: list[Finding], clusters: list[Cluster], classifications: list[Classification] | None
) -> tuple[str, str]:
    """Return (top severity, one-line counts) for the digest notification."""
    merged = _merge(findings)
    counts = {s: sum(1 for m in merged if m.severity == s) for s in SEVERITY_ORDER}
    severities = [m.severity for m in merged]
    if classifications:
        severities += [c.severity for c in classifications if c.category != "benign" or c.suspicious_content]
    top = min(severities, key=lambda s: SEVERITY_ORDER[s]) if severities else "low"
    lines = sum(c.count for c in clusters)
    line = (
        f"{counts['high']} high, {counts['medium']} medium, {counts['low']} low findings. "
        f"{len(clusters)} unclassified clusters ({lines} lines)."
    )
    return top, line


def render_digest(
    findings: list[Finding],
    clusters: list[Cluster],
    classifications: list[Classification] | None,
    now: datetime,
) -> str:
    merged = _merge(findings)
    by_id = {c.cluster_id: c for c in classifications or []}
    flagged_clusters = [c for c in clusters if c.id in by_id and by_id[c.id].suspicious_content]
    flagged_findings = [m for m in merged if m.rule == SUSPICIOUS_RULE]
    regular = [m for m in merged if m.rule != SUSPICIOUS_RULE]
    rest = [c for c in clusters if c not in flagged_clusters]

    out = [f"# Logwatch digest: {now.date().isoformat()}", ""]

    all_benign = classifications is not None and all(by_id[c.id].category == "benign" for c in rest if c.id in by_id)
    if not merged and not flagged_clusters and (not rest or all_benign):
        out.append(QUIET_LINE)
        if rest:
            n, lines = len(rest), sum(c.count for c in rest)
            out += ["", f"{n} benign cluster{'s' if n != 1 else ''} ({lines} lines) were seen and classified as routine."]
        return "\n".join(out) + "\n"

    out += [summarize(findings, clusters, classifications)[1], ""]

    if regular:
        out.append("## Findings")
        for sev in SEVERITY_ORDER:
            group = [m for m in regular if m.severity == sev]
            if group:
                out += ["", f"### {sev.capitalize()}", ""] + [_finding_line(m) for m in group]
        out.append("")

    if flagged_findings or flagged_clusters:
        out += [
            "## Flagged as suspicious content",
            "",
            "These log lines address the reader or give instructions. Treat them as a possible "
            "prompt-injection attempt and read the raw log before trusting any summary of it.",
            "",
        ]
        for m in flagged_findings:
            out.append(f"- {_plain(m.source)}: {m.count} lines matched the instruction-like-text rule")
            out += [f"  - sample: {_code(s)}" for s in m.samples]
        for c in flagged_clusters:
            out.append(f"- {_plain(c.source)}: {_code(c.template)} ({c.count} lines), flagged by the model")
        out.append("")

    if rest:
        out += ["## Unclassified activity", ""]
        if classifications is None:
            out += ["Model classification unavailable. Raw clusters:", "", "| Count | Source | Template |", "|---|---|---|"]
            out += [f"| {c.count} | {_plain(c.source)} | {_code(c.template)} |" for c in rest]
        else:
            rows = sorted(rest, key=lambda c: (SEVERITY_ORDER[by_id[c.id].severity] if c.id in by_id else 9, -c.count))
            out += ["| Count | Source | Category | Severity | Summary | Template |", "|---|---|---|---|---|---|"]
            for c in rows:
                k = by_id.get(c.id)
                out.append(
                    f"| {c.count} | {_plain(c.source)} | {k.category if k else '-'} | {k.severity if k else '-'} "
                    f"| {_plain(k.summary) if k else '-'} | {_code(c.template)} |"
                )
        out.append("")

    return "\n".join(out)
