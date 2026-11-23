from pathlib import Path

import yaml

from logwatch.cli import main
from logwatch.config import load_config
from logwatch.suggest import render_config, suggest_sources


def box(tmp_path, services):
    """services: {name: (argv list, init script text or None)}"""
    run, initd = tmp_path / "run" / "openrc", tmp_path / "init.d"
    (run / "daemons").mkdir(parents=True)
    initd.mkdir()
    for name, (argv, script) in services.items():
        d = run / "daemons" / name
        d.mkdir()
        lines = ["exec=" + argv[0]] + [f"argv_{i}={a}" for i, a in enumerate(argv)] + [f"pidfile=/var/run/supervise-{name}.pid"]
        (d / "001").write_text("\n".join(lines) + "\n")
        if script is not None:
            (initd / name).write_text(script)
    return run, initd


GUNICORN = ["/usr/bin/gunicorn", "--workers", "2", "--access-logfile", "/var/log/matinee.log", "--error-logfile", "/var/log/matinee.log", "app:app"]


def by_name(sources):
    return {s["name"]: s for s in sources}


def test_gunicorn_shared_access_and_error_file_is_one_combined_log(tmp_path):
    run, initd = box(tmp_path, {"matinee": (GUNICORN, None)})
    assert suggest_sources(run, initd) == [
        {"name": "matinee", "service": "matinee", "logs": [{"path": "/var/log/matinee.log", "format": "combined"}]}
    ]


def test_separate_access_and_error_files(tmp_path):
    argv = ["/usr/bin/gunicorn", "--access-logfile=/var/log/app/access.log", "--error-logfile", "/var/log/app/error.log"]
    run, initd = box(tmp_path, {"app": (argv, None)})
    assert suggest_sources(run, initd)[0]["logs"] == [
        {"path": "/var/log/app/access.log", "format": "combined"},
        {"path": "/var/log/app/error.log", "format": "plain"},
    ]


def test_init_script_output_and_error_log(tmp_path):
    script = '#!/sbin/openrc-run\nsupervisor=supervise-daemon\noutput_log="/var/log/${RC_SVCNAME}.log"\nerror_log=/var/log/$RC_SVCNAME.err\n'
    run, initd = box(tmp_path, {"mcp-server-harmony": (["/opt/x/bin/python", "-m", "server"], script)})
    assert suggest_sources(run, initd)[0]["logs"] == [
        {"path": "/var/log/mcp-server-harmony.log", "format": "plain"},
        {"path": "/var/log/mcp-server-harmony.err", "format": "plain"},
    ]


def test_unresolvable_variables_and_relative_paths_are_skipped(tmp_path):
    script = 'output_log="${LOGDIR}/x.log"\nerror_log="logs/err.log"\n'
    run, initd = box(tmp_path, {"app": (["/bin/app", "--log-file", "relative.log", "--access-logfile", "-"], script)})
    assert suggest_sources(run, initd) == [{"name": "app", "service": "app", "logs": []}]


def test_any_var_log_argument_is_picked_up(tmp_path):
    run, initd = box(tmp_path, {"app": (["/bin/app", "--whatever", "/var/log/app/custom.log", "/etc/app.conf"], None)})
    assert suggest_sources(run, initd)[0]["logs"] == [{"path": "/var/log/app/custom.log", "format": "plain"}]


def test_system_services_skipped_unless_asked(tmp_path):
    run, initd = box(tmp_path, {n: (["/usr/sbin/" + n], None) for n in ("sshd", "crond", "dbus", "syslog", "docker", "tailscale", "roasted")})
    assert [s["name"] for s in suggest_sources(run, initd)] == ["roasted"]
    assert len(suggest_sources(run, initd, include_system=True)) == 7


def test_logwatch_itself_and_odd_names_are_skipped(tmp_path):
    run, initd = box(tmp_path, {"logwatch": (["/opt/logwatch/venv/bin/logwatch"], None), "ok-app": (["/bin/x"], None)})
    (run / "daemons" / "bad name!").mkdir()
    assert [s["name"] for s in suggest_sources(run, initd)] == ["ok-app"]


def test_sorted_and_empty(tmp_path):
    run, initd = box(tmp_path, {"zeta": (["/bin/z"], None), "alpha": (["/bin/a"], None)})
    assert [s["name"] for s in suggest_sources(run, initd)] == ["alpha", "zeta"]
    assert suggest_sources(tmp_path / "missing", initd) == []


def test_rendered_config_loads_and_keeps_secrets_out(tmp_path):
    run, initd = box(tmp_path, {"matinee": (GUNICORN, None), "quiet-app": (["/bin/q"], None)})
    text = render_config(suggest_sources(run, initd))
    p = tmp_path / "config.yaml"
    p.write_text(text)
    cfg = load_config(p)
    assert [s.name for s in cfg.sources] == ["matinee", "quiet-app", "logwatch"]
    assert cfg.sources[0].logs[0].path == "/var/log/matinee.log"
    assert cfg.llm.model == "claude-haiku-5-5" and cfg.llm.api_key_env == "LOGWATCH_LLM_API_KEY"
    assert cfg.rules_path == "/etc/logwatch/rules.yaml"
    assert "no log path found" in text  # quiet-app is flagged for a human to fill in
    data = yaml.safe_load(text)
    assert data["notify"]["service"] == "CHANGE_ME"


def test_rendered_config_with_no_services_still_loads(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text(render_config([]))
    assert [s.name for s in load_config(p).sources] == ["logwatch"]


def test_cli_suggest_config(tmp_path, capsys):
    run, initd = box(tmp_path, {"matinee": (GUNICORN, None), "sshd": (["/usr/sbin/sshd"], None)})
    assert main(["suggest-config", "--run-dir", str(run), "--initd-dir", str(initd)]) == 0
    out = capsys.readouterr().out
    assert "name: matinee" in out and "sshd" not in out
    assert main(["suggest-config", "--all", "--run-dir", str(run), "--initd-dir", str(initd)]) == 0
    assert "name: sshd" in capsys.readouterr().out


def test_cli_list_logs(tmp_path, capsys):
    run, initd = box(tmp_path, {"matinee": (GUNICORN, None)})
    p = tmp_path / "config.yaml"
    p.write_text(render_config(suggest_sources(run, initd)))
    assert main(["list-logs", str(p)]) == 0
    assert capsys.readouterr().out.split() == ["/var/log/matinee.log", "/var/log/logwatch/error.log"]
