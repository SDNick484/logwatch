from datetime import datetime, timedelta, timezone

from logwatch.config import Config, LLMConfig, LogFile, NotifyConfig, Source
from logwatch.services import OpenRCProbe, ScriptedProbe, parse_rc_status, tier1_cycle
from logwatch.state import State

T0 = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def cfg(*sources):
    return Config(
        sources=tuple(sources), state_dir="/x", report_dir="/x", rules_path="/x",
        llm=LLMConfig(False, "http://x", "m", "K"), notify=NotifyConfig("http://x", "T", "svc"),
    )


APP = Source("app", "app-svc", None, (), None)


def run(tmp_path, config, script, step_s=120, mtime=None):
    state = State(tmp_path / "s.db")
    probe = ScriptedProbe(script)
    for i in range(len(script)):
        kwargs = {"mtime": mtime} if mtime else {}
        tier1_cycle(config, state, probe, T0 + timedelta(seconds=step_s * i), **kwargs)
        probe.advance()
    return state, [(t, sev) for _, t, _, sev in state.outbox_pending()]


def svc(state, pid=None):
    return {"services": {"app-svc": [state, pid]}}


def test_healthy_is_silent(tmp_path):
    _, sent = run(tmp_path, cfg(APP), [svc("started", 10)] * 3)
    assert sent == []


def test_crash_alerts_once(tmp_path):
    state, sent = run(tmp_path, cfg(APP), [svc("started", 10)] + [svc("crashed")] * 3)
    assert sent == [("Service down: app", "high")]
    assert state.open_alerts() == [("svc:app:down", "high")]


def test_stopped_counts_as_down(tmp_path):
    _, sent = run(tmp_path, cfg(APP), [svc("stopped")])
    assert sent == [("Service down: app", "high")]


def test_recovery_note(tmp_path):
    state, sent = run(tmp_path, cfg(APP), [svc("crashed"), svc("started", 11)])
    assert sent == [("Service down: app", "high"), ("Recovered: app", "low")]
    assert state.open_alerts() == []


def test_restart_loop(tmp_path):
    script = [svc("started", 10 + i) for i in range(7)]  # 6 pid changes
    state, sent = run(tmp_path, cfg(APP), script, step_s=100)
    assert sent == [("Restart loop: app", "high")]
    assert state.open_alerts() == [("svc:app:loop", "high")]


def test_two_respawns_no_loop(tmp_path):
    _, sent = run(tmp_path, cfg(APP), [svc("started", 1), svc("started", 2), svc("started", 3)])
    assert sent == []


def test_old_respawns_fall_out_of_window(tmp_path):
    script = [svc("started", i) for i in range(1, 5)]  # 3 changes, but 15 min apart
    _, sent = run(tmp_path, cfg(APP), script, step_s=900)
    assert sent == []


def test_loop_clears_when_stable(tmp_path):
    script = [svc("started", 10 + i) for i in range(4)] + [svc("started", 13)] * 6
    state, sent = run(tmp_path, cfg(APP), script, step_s=120)
    assert sent == [("Restart loop: app", "high"), ("Stable again: app", "low")]
    assert state.open_alerts() == []


def test_crash_and_restart_is_one_event_not_two(tmp_path):
    script = [svc("started", 1), svc("crashed"), svc("started", 2), svc("crashed"), svc("started", 3)]
    _, sent = run(tmp_path, cfg(APP), script)
    assert "Restart loop: app" not in [t for t, _ in sent]


def test_oom_names_source(tmp_path):
    _, sent = run(tmp_path, cfg(APP), [{"oom": ["app-svc"]}, {}])
    assert sent == [("OOM kill: app", "high")]


def test_oom_unknown_victim(tmp_path):
    _, sent = run(tmp_path, cfg(APP), [{"oom": ["*"]}, {"oom": ["*"]}, {}])
    assert sent == [("OOM kill in container", "high"), ("OOM kill in container", "high")]


def test_container_down_and_recovered(tmp_path):
    c = Source("cloudflared", None, "cloudflared", (), None)
    script = [{"containers": {"cloudflared": False}}] * 2 + [{"containers": {"cloudflared": True}}]
    _, sent = run(tmp_path, cfg(c), script)
    assert sent == [("Container down: cloudflared", "high"), ("Recovered: cloudflared", "low")]


def test_container_unknown_is_silent(tmp_path):
    c = Source("cloudflared", None, "cloudflared", (), None)
    _, sent = run(tmp_path, cfg(c), [{"containers": {"cloudflared": None}}])
    assert sent == []


def test_unknown_state_low_once(tmp_path):
    state, sent = run(tmp_path, cfg(APP), [svc("unknown")] * 3 + [svc("started", 5)])
    assert sent == [("Cannot read service state: app", "low")]
    assert state.open_alerts() == []


def test_source_without_service_skipped(tmp_path):
    logs_only = Source("files", None, None, (LogFile("/var/log/x.log", "plain"),), None)
    _, sent = run(tmp_path, cfg(logs_only), [svc("crashed")])
    assert sent == []


def test_quiet_file_alert(tmp_path):
    quiet = Source("app", None, None, (LogFile("/var/log/app/app.log", "plain"),), 30)
    last_write = T0 - timedelta(minutes=10)
    state, sent = run(tmp_path, cfg(quiet), [{}] * 4, step_s=600, mtime=lambda p: last_write.timestamp())
    # cycles at +0, +10, +20, +30 min: silent for 10, 20, 30, 40 min -> alert once, on the last cycle
    assert sent == [("Log gone quiet: app", "medium")]


def test_quiet_file_missing_is_not_tier1s_problem(tmp_path):
    quiet = Source("app", None, None, (LogFile("/nonexistent/app.log", "plain"),), 30)
    _, sent = run(tmp_path, cfg(quiet), [{}])
    assert sent == []


def test_parse_rc_status():
    assert parse_rc_status(0, " * status: started\n") == "started"
    assert parse_rc_status(3, " * status: stopped\n") == "stopped"
    assert parse_rc_status(32, " * status: crashed\n") == "crashed"
    assert parse_rc_status(1, " * status: crashed\n") == "crashed"
    assert parse_rc_status(1, "rc-service: service `x' does not exist\n") == "unknown"
    assert parse_rc_status(127, "") == "unknown"


def test_openrc_probe_rejects_unsafe_names():
    calls = []
    probe = OpenRCProbe(run=lambda argv: calls.append(argv) or (0, " * status: started\n"))
    assert probe.status("x; rm -rf /").state == "unknown"
    assert calls == []
    assert probe.status("dinner-app").state == "started"
    assert calls == [["rc-service", "dinner-app", "status"]]


def test_openrc_probe_missing_binary_is_unknown():
    def run(argv):
        raise FileNotFoundError("rc-service")

    assert OpenRCProbe(run=run).status("app").state == "unknown"


def test_openrc_probe_oom_counter(tmp_path):
    events = tmp_path / "memory.events"
    events.write_text("low 0\nhigh 0\nmax 3\noom 1\noom_kill 1\n")
    probe = OpenRCProbe(run=lambda argv: (0, ""), memory_events_path=str(events))
    assert probe.oom_victims(T0) == []  # first read is the baseline
    assert probe.oom_victims(T0) == []
    events.write_text("low 0\nhigh 0\nmax 9\noom 3\noom_kill 3\n")
    assert probe.oom_victims(T0) == ["*"]
    assert probe.oom_victims(T0) == []


def test_openrc_probe_oom_file_missing(tmp_path):
    probe = OpenRCProbe(run=lambda argv: (0, ""), memory_events_path=str(tmp_path / "nope"))
    assert probe.oom_victims(T0) == []
