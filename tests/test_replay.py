import json
import shutil
from pathlib import Path

import pytest
import yaml

from logwatch.cli import main
from logwatch.replay import replay

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"
CASES = sorted(p.name for p in FIXTURES.iterdir() if (p / "fixture.json").exists())


def test_all_spec_cases_present():
    assert CASES == sorted([
        "access-denied-40", "injection-line", "llm-garbage", "new-traceback", "oom-crash",
        "path-scan-300", "quiet-day", "restart-loop", "rotation-midrun",
    ])


@pytest.mark.parametrize("case", CASES)
def test_fixture(case):
    assert replay(FIXTURES / case, ROOT / "rules" / "default.yaml") == []


def _broken_copy(tmp_path, mutate):
    dst = tmp_path / "case"
    shutil.copytree(FIXTURES / "path-scan-300", dst)
    data = json.loads((dst / "fixture.json").read_text())
    mutate(data)
    (dst / "fixture.json").write_text(json.dumps(data))
    return dst


def test_replay_reports_wrong_finding_count(tmp_path):
    d = _broken_copy(tmp_path, lambda f: f["expected"]["findings"][0].update(count=299))
    problems = replay(d, ROOT / "rules" / "default.yaml")
    assert len(problems) == 1 and "findings" in problems[0]


def test_replay_reports_missing_alert_and_digest_text(tmp_path):
    def m(f):
        f["expected"]["alerts"] = [["Service down: app", "high"]]
        f["expected"]["digest_contains"] = ["this text is not in the digest"]
        f["expected"]["digest_absent"] = ["path-scanning"]

    problems = replay(_broken_copy(tmp_path, m), ROOT / "rules" / "default.yaml")
    assert len(problems) == 3


def test_cli_replay_exit_codes(tmp_path, capsys):
    assert main(["replay", str(FIXTURES / "quiet-day"), "--rules", str(ROOT / "rules" / "default.yaml")]) == 0
    d = _broken_copy(tmp_path, lambda f: f["expected"]["findings"][0].update(count=1))
    assert main(["replay", str(d), "--rules", str(ROOT / "rules" / "default.yaml")]) == 1
    assert "findings" in capsys.readouterr().out


def _config(tmp_path, mutate=lambda d: None):
    data = yaml.safe_load((ROOT / "config.example.yaml").read_text())
    data["rules_path"] = str(ROOT / "rules" / "default.yaml")
    mutate(data)
    p = tmp_path / "config.yaml"
    p.write_text(yaml.safe_dump(data))
    return p


def test_check_config_exit_codes(tmp_path, capsys):
    assert main(["check-config", str(_config(tmp_path))]) == 0
    assert "sources" in capsys.readouterr().out
    assert main(["check-config", str(_config(tmp_path, lambda d: d.pop("sources")))]) == 2
    assert "sources" in capsys.readouterr().err
    assert main(["check-config", str(_config(tmp_path, lambda d: d.update(rules_path="/nonexistent/rules.yaml")))]) == 2
    assert "rules" in capsys.readouterr().err


def test_once_requires_notify_token(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("LOGWATCH_HA_TOKEN", raising=False)
    cfg = _config(tmp_path, lambda d: d.update(state_dir=str(tmp_path / "state"), report_dir=str(tmp_path / "reports")))
    assert main(["once", "collect", str(cfg)]) == 2
    assert "LOGWATCH_HA_TOKEN" in capsys.readouterr().err


def test_no_args_shows_usage(capsys):
    assert main([]) == 2
