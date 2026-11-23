from datetime import datetime, timedelta, timezone

from logwatch.config import Config, LLMConfig, LogFile, NotifyConfig, Source
from logwatch.services import OpenRCProbe, ScriptedProbe, tier1_cycle
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


def tree(tmp_path, started=("matinee",), initd=("matinee",), pidfile_pid=100,
         procs={100: ("supervise-daemon", 1, [101]), 101: ("gunicorn", 100, [])}, children_file=True, daemon_entry=True):
    """A fake /run/openrc, /etc/init.d and /proc, shaped like an Alpine box running supervise-daemon."""
    run, initd_dir, proc = tmp_path / "run" / "openrc", tmp_path / "init.d", tmp_path / "proc"
    (run / "started").mkdir(parents=True)
    initd_dir.mkdir()
    proc.mkdir()
    for name in initd:
        (initd_dir / name).write_text("#!/sbin/openrc-run\n")
    for name in started:
        (run / "started" / name).symlink_to(initd_dir / name)
        if daemon_entry:
            pidfile = tmp_path / "run" / f"supervise-{name}.pid"
            if pidfile_pid is not None:
                pidfile.write_text(f"{pidfile_pid}\n")
            (run / "daemons" / name).mkdir(parents=True)
            (run / "daemons" / name / "001").write_text(f"exec=/usr/bin/gunicorn\nargv_0=/usr/bin/gunicorn\npidfile={pidfile}\n")
    for pid, (comm, ppid, kids) in procs.items():
        d = proc / str(pid)
        (d / "task" / str(pid)).mkdir(parents=True)
        (d / "comm").write_text(comm + "\n")
        (d / "stat").write_text(f"{pid} ({comm}) S {ppid} {pid} {pid} 0 -1 4194560\n")
        if children_file:
            (d / "task" / str(pid) / "children").write_text(" ".join(map(str, kids)) + (" " if kids else ""))
    return OpenRCProbe(openrc_run_dir=str(run), initd_dir=str(initd_dir), proc_dir=str(proc))


def test_probe_started_under_supervise_daemon_reports_child_pid(tmp_path):
    st = tree(tmp_path).status("matinee")
    assert (st.state, st.pid) == ("started", 101)


def test_probe_needs_no_subprocess_and_no_conf_d(tmp_path):
    def run(argv):
        raise AssertionError(f"probe must not shell out for status: {argv}")

    probe = tree(tmp_path)
    probe._run = run
    assert probe.status("matinee").state == "started"


def test_probe_respawned_child_has_new_pid(tmp_path):
    probe = tree(tmp_path, procs={100: ("supervise-daemon", 1, [205]), 205: ("gunicorn", 100, [])})
    assert probe.status("matinee").pid == 205


def test_probe_children_file_missing_falls_back_to_scanning_proc(tmp_path):
    probe = tree(tmp_path, children_file=False,
                 procs={100: ("supervise-daemon", 1, []), 7: ("other (odd) name", 1, []), 101: ("gunicorn", 100, []), 102: ("gunicorn", 101, [])})
    assert probe.status("matinee").pid == 101


def test_probe_supervisor_between_respawns_is_started_without_pid(tmp_path):
    st = tree(tmp_path, procs={100: ("supervise-daemon", 1, [])}).status("matinee")
    assert (st.state, st.pid) == ("started", None)


def test_probe_plain_daemon_reports_pidfile_pid(tmp_path):
    st = tree(tmp_path, procs={100: ("sshd", 1, [150])}).status("matinee")
    assert (st.state, st.pid) == ("started", 100)


def test_probe_stopped_service(tmp_path):
    assert tree(tmp_path, started=()).status("matinee").state == "stopped"


def test_probe_unknown_service(tmp_path):
    assert tree(tmp_path, started=(), initd=("other",)).status("matinee").state == "unknown"


def test_probe_started_but_process_gone_is_crashed(tmp_path):
    assert tree(tmp_path, procs={}).status("matinee").state == "crashed"


def test_probe_started_but_pidfile_gone_is_crashed(tmp_path):
    assert tree(tmp_path, pidfile_pid=None).status("matinee").state == "crashed"


def test_probe_started_without_daemon_entry_has_no_pid(tmp_path):
    st = tree(tmp_path, daemon_entry=False).status("matinee")
    assert (st.state, st.pid) == ("started", None)


def test_probe_not_an_openrc_host_is_unknown(tmp_path):
    probe = OpenRCProbe(openrc_run_dir=str(tmp_path / "nope"), initd_dir=str(tmp_path / "nope2"), proc_dir=str(tmp_path))
    assert probe.status("matinee").state == "unknown"


def test_openrc_probe_rejects_unsafe_names(tmp_path):
    probe = tree(tmp_path)
    assert probe.status("../../etc/passwd").state == "unknown"
    assert probe.status("x; rm -rf /").state == "unknown"


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
