import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

from logwatch.config import Config, LLMConfig, LogFile, NotifyConfig, Source
from logwatch.events import Event
from logwatch.rules import RuleSet
from logwatch.runner import collect_cycle, digest_cycle, digest_due
from logwatch.state import State

RULES = RuleSet.load(Path(__file__).resolve().parent.parent / "rules" / "default.yaml")
NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def setup(tmp_path, *names):
    sources = []
    for n in names:
        (tmp_path / n).mkdir()
        (tmp_path / n / "access.log").write_text("")
        sources.append(Source(n, None, None, (LogFile(str(tmp_path / n / "access.log"), "combined"),), None))
    config = Config(
        sources=tuple(sources), state_dir=str(tmp_path / "state"), report_dir=str(tmp_path / "reports"), rules_path="x",
        llm=LLMConfig(True, "http://x", "m", "K"), notify=NotifyConfig("http://x", "T", "svc"),
    )
    state = State(tmp_path / "state" / "s.db")
    collect_cycle(config, state, RULES, NOW)  # first sight: cursors at end of file
    return config, state


def write(tmp_path, name, path, status, n, ip="203.0.113.9"):
    with open(tmp_path / name / "access.log", "a") as f:
        for _ in range(n):
            f.write(f'{ip} - - [01/Jan/2026:12:00:00 +0000] "GET {path} HTTP/1.1" {status} 10 "-" "ua"\n')


def titles(state):
    return [t for _, t, _, _ in state.outbox_pending()]


def test_collect_advances_cursors(tmp_path):
    config, state = setup(tmp_path, "app")
    write(tmp_path, "app", "/.env", 404, 25)
    collect_cycle(config, state, RULES, NOW)
    assert [(f.rule, f.count) for f in state.findings_since(NOW)] == [("path-scanning", 25)]
    collect_cycle(config, state, RULES, NOW + timedelta(hours=1))
    assert len(state.findings_since(NOW)) == 1  # nothing new, nothing recounted


def test_missing_file_alert_others_continue(tmp_path):
    config, state = setup(tmp_path, "bad", "good")
    (tmp_path / "bad" / "access.log").unlink()
    write(tmp_path, "good", "/.env", 404, 25)
    collect_cycle(config, state, RULES, NOW)
    collect_cycle(config, state, RULES, NOW + timedelta(hours=1))
    assert titles(state) == ["Cannot read log: bad"]
    assert [f.source for f in state.findings_since(NOW)] == ["good"]


def test_unreadable_clears_when_fixed(tmp_path):
    config, state = setup(tmp_path, "bad")
    (tmp_path / "bad" / "access.log").unlink()
    collect_cycle(config, state, RULES, NOW)
    assert len(state.open_alerts()) == 1
    (tmp_path / "bad" / "access.log").write_text("")
    collect_cycle(config, state, RULES, NOW)
    assert state.open_alerts() == []


def denied(n, app="dinner.example.com"):
    return [Event("cloudflare-access", "api", NOW, f"access denied app={app}", {"app": app, "action": "denied", "ip": "198.51.100.7"})] * n


def test_high_finding_escalates_immediately(tmp_path):
    config, state = setup(tmp_path, "app")
    collect_cycle(config, state, RULES, NOW, cf_fetch=lambda since: denied(40))
    assert titles(state) == ["access-denied: dinner.example.com"]
    assert state.outbox_pending()[0][3] == "high"


def test_medium_finding_waits_for_digest(tmp_path):
    config, state = setup(tmp_path, "app")
    write(tmp_path, "app", "/.env", 404, 300)
    collect_cycle(config, state, RULES, NOW)
    assert titles(state) == []
    digest_cycle(config, state, None, NOW)
    assert titles(state) == ["Daily digest"]


def test_cf_http_error_returns_empty_and_alerts(tmp_path):
    config, state = setup(tmp_path, "app")

    def boom(since):
        raise httpx.ConnectError("unreachable")

    write(tmp_path, "app", "/.env", 404, 25)
    collect_cycle(config, state, RULES, NOW, cf_fetch=boom)
    collect_cycle(config, state, RULES, NOW, cf_fetch=boom)
    assert titles(state) == ["Cannot read Cloudflare Access logs"]
    assert len(state.findings_since(NOW)) == 1


def test_cf_since_moves_forward(tmp_path):
    config, state = setup(tmp_path, "app")
    asked = []

    def fetch(since):
        asked.append(since)
        return [Event("cloudflare-access", "api", NOW + timedelta(minutes=5), "x", {"app": "a", "action": "allowed"})]

    collect_cycle(config, state, RULES, NOW, cf_fetch=fetch)
    collect_cycle(config, state, RULES, NOW + timedelta(hours=1), cf_fetch=fetch)
    assert asked[0] == NOW - timedelta(seconds=3600)
    assert asked[1] > NOW + timedelta(minutes=5)


def test_remainder_survives_restart(tmp_path):
    config, state = setup(tmp_path, "app")
    write(tmp_path, "app", "/odd/endpoint", 200, 3)
    collect_cycle(config, state, RULES, NOW)
    state.close()
    state = State(tmp_path / "state" / "s.db")
    path = digest_cycle(config, state, None, NOW)
    assert "/odd/endpoint" in path.read_text()
    assert state.take_remainder() == []


class FakeLLM:
    def __init__(self, text):
        self.text, self.calls = text, 0

    def complete(self, system, user):
        self.calls += 1
        if callable(self.text):
            return self.text(user)
        return self.text


def test_digest_uses_llm_and_writes_audit(tmp_path):
    config, state = setup(tmp_path, "app")
    write(tmp_path, "app", "/odd/endpoint", 200, 3)
    collect_cycle(config, state, RULES, NOW)

    def answer(user):
        cid = json.loads(user.split("<log_data>")[1].split("</log_data>")[0])[0]["id"]
        return json.dumps([{"cluster_id": cid, "category": "security", "severity": "high", "summary": "Odd endpoint probing", "suspicious_content": False}])

    path = digest_cycle(config, state, FakeLLM(answer), NOW)
    text = path.read_text()
    assert "Odd endpoint probing" in text
    assert path.parent == tmp_path / "reports" and path.name == "digest-2026-01-01.md"
    assert len(list((tmp_path / "state" / "audit").iterdir())) == 1
    assert state.outbox_pending()[-1][3] == "high"


def test_digest_with_garbage_llm_still_ships(tmp_path):
    config, state = setup(tmp_path, "app")
    write(tmp_path, "app", "/odd/endpoint", 200, 3)
    collect_cycle(config, state, RULES, NOW)
    text = digest_cycle(config, state, FakeLLM("no json here"), NOW).read_text()
    assert "Model classification unavailable" in text


def test_digest_quiet_day_skips_llm(tmp_path):
    config, state = setup(tmp_path, "app")
    llm = FakeLLM("[]")
    text = digest_cycle(config, state, llm, NOW).read_text()
    assert "Nothing notable in the last 24 hours." in text
    assert llm.calls == 0


def test_digest_only_covers_findings_since_last_digest(tmp_path):
    config, state = setup(tmp_path, "app")
    write(tmp_path, "app", "/.env", 404, 300)
    collect_cycle(config, state, RULES, NOW)
    digest_cycle(config, state, None, NOW + timedelta(minutes=1))
    text = digest_cycle(config, state, None, NOW + timedelta(days=1)).read_text()
    assert "path-scanning" not in text


def test_digest_due():
    at = lambda h, m=0, d=2: datetime(2026, 1, d, h, m).astimezone()
    assert digest_due(at(6, 59), None, "07:00") is False
    assert digest_due(at(7, 0), None, "07:00") is True
    assert digest_due(at(9), at(7, 1), "07:00") is False
    assert digest_due(at(9), at(7, 1, d=1), "07:00") is True
    assert digest_due(at(6), at(7, 1, d=1), "07:00") is False
