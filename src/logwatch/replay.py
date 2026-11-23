"""Replay a synthetic incident through the real cycles and compare with what was expected.

A fixture is a directory with one `fixture.json`:

  sources   list of {name, service?, docker?, quiet_minutes?, logs: [{file, format}]}
  llm       null (no model), "garbage" (model returns junk), or a list of
            {match, category, severity, summary, suspicious_content}: the scripted
            model applies the first entry whose `match` text appears in a cluster;
            unmatched clusters are answered as benign.
  advance_s seconds between steps (default 120)
  steps     list of {probe?, append?, rotate?, append_after?, access?}
            append / append_after: [{file, repeat, line}]
            rotate: [file]  (renamed to file.1, new empty file created)
            access: [{repeat, item}]  Cloudflare Access API result items
            probe: one ScriptedProbe cycle
  expected  {alerts?, open_alerts?, findings?, digest_contains?, digest_absent?, digest_severity?}
"""
from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

from .cloudflare import fetch_access_events
from .config import Config, LLMConfig, LogFile, NotifyConfig, Source
from .notify import MemoryNotifier, flush
from .rules import RuleSet
from .runner import collect_cycle, digest_cycle
from .services import ScriptedProbe, tier1_cycle
from .state import State

T0 = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
_ACCOUNT = "0" * 32


class ScriptedLLM:
    def __init__(self, script):
        self._script = script

    def complete(self, system: str, user: str) -> str:
        if self._script == "garbage":
            return "I cannot help with that."
        clusters = json.loads(user.split("<log_data>")[1].split("</log_data>")[0])
        out = []
        for c in clusters:
            haystack = " ".join([c["template"], *c["samples"]])
            hit = next((r for r in self._script if r["match"] in haystack), None)
            out.append(
                {
                    "cluster_id": c["id"],
                    "category": hit["category"] if hit else "benign",
                    "severity": hit["severity"] if hit else "low",
                    "summary": hit["summary"] if hit else "Routine",
                    "suspicious_content": bool(hit and hit.get("suspicious_content")),
                }
            )
        return json.dumps(out)


def _write(paths: dict[str, Path], ops: list[dict] | None) -> None:
    for op in ops or []:
        with open(paths[op["file"]], "a", encoding="utf-8") as f:
            f.write((op["line"] + "\n") * int(op.get("repeat", 1)))


def _access_fetch(spec: list[dict]):
    items = [entry["item"] for entry in spec for _ in range(int(entry.get("repeat", 1)))]
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"success": True, "result": items})))
    return lambda since: fetch_access_events(_ACCOUNT, "fixture-token", since, client)


def replay(fixture_dir: Path, rules_path: Path) -> list[str]:
    """Run the fixture. Returns a list of mismatches; empty means it behaved as expected."""
    spec = json.loads((Path(fixture_dir) / "fixture.json").read_text())
    expected = spec.get("expected", {})
    step_s = int(spec.get("advance_s", 120))

    with tempfile.TemporaryDirectory(prefix="logwatch-replay-") as tmp:
        root = Path(tmp)
        paths: dict[str, Path] = {}
        sources = []
        for s in spec["sources"]:
            logs = []
            for lf in s.get("logs", []):
                p = root / "logs" / s["name"] / lf["file"]
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text("")
                paths.setdefault(lf["file"], p)
                logs.append(LogFile(str(p), lf.get("format", "plain")))
            sources.append(Source(s["name"], s.get("service"), s.get("docker"), tuple(logs), s.get("quiet_minutes")))
        config = Config(
            sources=tuple(sources),
            state_dir=str(root / "state"),
            report_dir=str(root / "reports"),
            rules_path=str(rules_path),
            llm=LLMConfig(spec.get("llm") is not None, "http://fixture.invalid", "fixture-model", "UNUSED"),
            notify=NotifyConfig("http://fixture.invalid", "UNUSED", "fixture"),
        )
        state = State(root / "state" / "replay.db")
        rules = RuleSet.load(Path(rules_path))
        steps = spec.get("steps", [])
        probe = ScriptedProbe([s.get("probe", {}) for s in steps])

        now = T0
        collect_cycle(config, state, rules, now)  # first sight of every file
        for step in steps:
            now += timedelta(seconds=step_s)
            _write(paths, step.get("append"))
            for name in step.get("rotate", []):
                os.rename(paths[name], str(paths[name]) + ".1")
                paths[name].write_text("")
            _write(paths, step.get("append_after"))
            tier1_cycle(config, state, probe, now)
            collect_cycle(config, state, rules, now, cf_fetch=_access_fetch(step["access"]) if "access" in step else None)
            probe.advance()

        now += timedelta(seconds=step_s)
        client = ScriptedLLM(spec["llm"]) if spec.get("llm") is not None else None
        digest = digest_cycle(config, state, client, now).read_text()
        notifier = MemoryNotifier()
        flush(state, notifier)

        problems: list[str] = []
        alerts = [[t, sev] for t, _, sev in notifier.sent if t != "Daily digest"]
        if "alerts" in expected and alerts != expected["alerts"]:
            problems.append(f"alerts: expected {expected['alerts']}, got {alerts}")
        open_alerts = [list(a) for a in state.open_alerts()]
        if "open_alerts" in expected and open_alerts != expected["open_alerts"]:
            problems.append(f"open_alerts: expected {expected['open_alerts']}, got {open_alerts}")
        findings = [{"rule": f.rule, "severity": f.severity, "count": f.count} for f in state.findings_since(T0)]
        if "findings" in expected and findings != expected["findings"]:
            problems.append(f"findings: expected {expected['findings']}, got {findings}")
        for text in expected.get("digest_contains", []):
            if text not in digest:
                problems.append(f"digest_contains: {text!r} is missing from the digest")
        for text in expected.get("digest_absent", []):
            if text in digest:
                problems.append(f"digest_absent: {text!r} appears in the digest")
        if "digest_severity" in expected:
            got = next((sev for t, _, sev in notifier.sent if t == "Daily digest"), None)
            if got != expected["digest_severity"]:
                problems.append(f"digest_severity: expected {expected['digest_severity']}, got {got}")
        state.close()
        return problems
