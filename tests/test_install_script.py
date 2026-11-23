import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "deploy" / "install.sh"


def run(*args):
    return subprocess.run(["sh", str(SCRIPT), *args], capture_output=True, text=True, timeout=60)


def test_syntax_is_posix_sh():
    assert subprocess.run(["sh", "-n", str(SCRIPT)], capture_output=True).returncode == 0
    text = SCRIPT.read_text()
    assert text.startswith("#!/bin/sh\n")
    assert "[[" not in text and "function " not in text  # busybox ash on Alpine, not bash


def test_help():
    r = run("--help")
    assert r.returncode == 0
    for flag in ("--dry-run", "--grant-log-access", "--src"):
        assert flag in r.stdout


def test_unknown_flag_exits_2():
    r = run("--frobnicate")
    assert r.returncode == 2 and "--frobnicate" in r.stderr


def test_refuses_to_run_for_real_without_root():
    import os

    if os.geteuid() == 0:
        return  # cannot exercise this as root
    r = run()
    assert r.returncode == 1 and "root" in r.stderr


def test_dry_run_prints_every_step_and_changes_nothing(tmp_path):
    before = sorted(p.name for p in Path("/etc").iterdir())
    r = run("--dry-run", "--src", str(ROOT))
    assert r.returncode == 0, r.stderr
    out = r.stdout
    wanted = [
        "adduser",
        "mkdir -p /etc/logwatch /var/lib/logwatch /var/log/logwatch /opt/logwatch",
        "python3 -m venv /opt/logwatch/venv",
        "/opt/logwatch/venv/bin/pip install",
        "/etc/logwatch/rules.yaml",
        "suggest-config",
        "/etc/conf.d/logwatch",
        "/etc/init.d/logwatch",
        "check-config",
    ]
    positions = [out.find(w) for w in wanted]
    assert all(p >= 0 for p in positions), [w for w, p in zip(wanted, positions) if p < 0]
    assert positions == sorted(positions), "steps out of order"
    assert "rc-service logwatch start" in out  # printed as a next step, never run
    assert "+ rc-service logwatch start" not in out and "+ rc-update" not in out
    assert "+ setfacl" not in out  # log access is opt-in
    assert not Path("/etc/logwatch").exists() or "logwatch" in before
    assert sorted(p.name for p in Path("/etc").iterdir()) == before


def test_dry_run_with_grant_shows_setfacl():
    r = run("--dry-run", "--grant-log-access", "--src", str(ROOT))
    assert r.returncode == 0, r.stderr
    assert "setfacl" in r.stdout
