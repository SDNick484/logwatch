from pathlib import Path

import pytest
import yaml

from logwatch.config import ConfigError, load_config

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / "config.example.yaml"


def _write(tmp_path, mutate):
    data = yaml.safe_load(EXAMPLE.read_text())
    mutate(data)
    p = tmp_path / "c.yaml"
    p.write_text(yaml.safe_dump(data))
    return p


def test_loads_example():
    cfg = load_config(EXAMPLE)
    names = [s.name for s in cfg.sources]
    assert names[:2] == ["dinner-app", "cloudflared"]
    assert (cfg.tier1_interval_s, cfg.collect_interval_s, cfg.digest_time) == (120, 3600, "07:00")
    assert (cfg.restart_threshold, cfg.restart_window_s) == (3, 600)
    assert cfg.sources[0].logs[0].format == "combined"
    assert cfg.sources[1].docker == "cloudflared"
    assert cfg.llm.model == "claude-haiku-5-5"
    assert cfg.cloudflare is not None


def test_cloudflare_optional(tmp_path):
    cfg = load_config(_write(tmp_path, lambda d: d.pop("cloudflare")))
    assert cfg.cloudflare is None


def test_docker_api_url_optional(tmp_path):
    assert load_config(EXAMPLE).docker_api_url is None
    cfg = load_config(_write(tmp_path, lambda d: d.update(docker_api_url="http://127.0.0.1:2375/")))
    assert cfg.docker_api_url == "http://127.0.0.1:2375"


def test_duplicate_source_name(tmp_path):
    p = _write(tmp_path, lambda d: d["sources"].append(dict(d["sources"][0])))
    with pytest.raises(ConfigError, match="dinner-app"):
        load_config(p)


def test_source_needs_service_docker_or_logs(tmp_path):
    p = _write(tmp_path, lambda d: d["sources"].append({"name": "empty"}))
    with pytest.raises(ConfigError, match="empty"):
        load_config(p)


def test_unknown_format(tmp_path):
    def m(d):
        d["sources"][0]["logs"][0]["format"] = "xml"

    with pytest.raises(ConfigError, match="xml"):
        load_config(_write(tmp_path, m))


def test_relative_log_path_rejected(tmp_path):
    def m(d):
        d["sources"][0]["logs"][0]["path"] = "var/log/x.log"

    with pytest.raises(ConfigError, match="absolute"):
        load_config(_write(tmp_path, m))


def test_bad_names_rejected(tmp_path):
    def m(d):
        d["sources"][0]["service"] = "x; rm -rf /"

    with pytest.raises(ConfigError, match="service"):
        load_config(_write(tmp_path, m))


def test_missing_file_is_config_error(tmp_path):
    with pytest.raises(ConfigError):
        load_config(tmp_path / "nope.yaml")


def test_not_a_mapping_is_config_error(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("- just\n- a list\n")
    with pytest.raises(ConfigError):
        load_config(p)
