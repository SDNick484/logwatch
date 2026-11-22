"""Load and validate the YAML config into frozen dataclasses."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml

FORMATS = ("combined", "plain", "json")
_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_TIME_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class LogFile:
    path: str
    format: Literal["combined", "plain", "json"]


@dataclass(frozen=True)
class Source:
    name: str
    service: str | None
    docker: str | None
    logs: tuple[LogFile, ...]
    quiet_minutes: int | None


@dataclass(frozen=True)
class LLMConfig:
    enabled: bool
    base_url: str
    model: str
    api_key_env: str


@dataclass(frozen=True)
class NotifyConfig:
    base_url: str
    token_env: str
    service: str


@dataclass(frozen=True)
class CloudflareConfig:
    account_id_env: str
    token_env: str


@dataclass(frozen=True, kw_only=True)
class Config:
    sources: tuple[Source, ...]
    state_dir: str
    report_dir: str
    rules_path: str
    llm: LLMConfig
    notify: NotifyConfig
    cloudflare: CloudflareConfig | None = None
    tier1_interval_s: int = 120
    collect_interval_s: int = 3600
    digest_time: str = "07:00"
    restart_threshold: int = 3
    restart_window_s: int = 600


def _need(d: dict, key: str, where: str) -> Any:
    if not isinstance(d, dict) or key not in d or d[key] is None:
        raise ConfigError(f"{where}: missing '{key}'")
    return d[key]


def _name(value: Any, what: str, where: str) -> str:
    if not isinstance(value, str) or not _NAME_RE.match(value):
        raise ConfigError(f"{where}: {what} {value!r} must match [A-Za-z0-9._-]+")
    return value


def _pos_int(value: Any, what: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ConfigError(f"{what} must be a positive integer, got {value!r}")
    return value


def _source(raw: Any, seen: set[str]) -> Source:
    name = _name(_need(raw, "name", "source"), "name", "source")
    where = f"source '{name}'"
    if name in seen:
        raise ConfigError(f"duplicate source name '{name}'")
    seen.add(name)
    service = raw.get("service")
    docker = raw.get("docker")
    if service is not None:
        _name(service, "service", where)
    if docker is not None:
        _name(docker, "docker", where)
    logs = []
    for entry in raw.get("logs") or []:
        path = _need(entry, "path", where)
        fmt = entry.get("format", "plain")
        if not isinstance(path, str) or not path.startswith("/"):
            raise ConfigError(f"{where}: log path {path!r} must be absolute")
        if fmt not in FORMATS:
            raise ConfigError(f"{where}: unknown format '{fmt}' (use one of {', '.join(FORMATS)})")
        logs.append(LogFile(path=path, format=fmt))
    if service is None and docker is None and not logs:
        raise ConfigError(f"{where}: needs at least one of service, docker, or logs")
    quiet = raw.get("quiet_minutes")
    if quiet is not None:
        _pos_int(quiet, f"{where}: quiet_minutes")
    return Source(name=name, service=service, docker=docker, logs=tuple(logs), quiet_minutes=quiet)


def load_config(path: Path) -> Config:
    try:
        data = yaml.safe_load(Path(path).read_text())
    except OSError as e:
        raise ConfigError(f"cannot read config {path}: {e.strerror}") from e
    except yaml.YAMLError as e:
        raise ConfigError(f"config {path} is not valid YAML: {e}") from e
    if not isinstance(data, dict):
        raise ConfigError(f"config {path} must be a mapping at the top level")

    raw_sources = _need(data, "sources", "config")
    if not isinstance(raw_sources, list) or not raw_sources:
        raise ConfigError("config: 'sources' must be a non-empty list")
    seen: set[str] = set()
    sources = tuple(_source(s, seen) for s in raw_sources)

    llm_raw = _need(data, "llm", "config")
    llm = LLMConfig(
        enabled=bool(llm_raw.get("enabled", True)),
        base_url=str(_need(llm_raw, "base_url", "llm")).rstrip("/"),
        model=str(_need(llm_raw, "model", "llm")),
        api_key_env=str(_need(llm_raw, "api_key_env", "llm")),
    )
    n_raw = _need(data, "notify", "config")
    notify = NotifyConfig(
        base_url=str(_need(n_raw, "base_url", "notify")).rstrip("/"),
        token_env=str(_need(n_raw, "token_env", "notify")),
        service=_name(_need(n_raw, "service", "notify"), "service", "notify"),
    )
    cf = None
    if data.get("cloudflare"):
        c = data["cloudflare"]
        cf = CloudflareConfig(
            account_id_env=str(_need(c, "account_id_env", "cloudflare")),
            token_env=str(_need(c, "token_env", "cloudflare")),
        )

    opts: dict[str, Any] = {}
    for key in ("tier1_interval_s", "collect_interval_s", "restart_threshold", "restart_window_s"):
        if key in data:
            opts[key] = _pos_int(data[key], key)
    if "digest_time" in data:
        if not isinstance(data["digest_time"], str) or not _TIME_RE.match(data["digest_time"]):
            raise ConfigError("digest_time must be a quoted HH:MM string")
        opts["digest_time"] = data["digest_time"]

    return Config(
        sources=sources,
        state_dir=str(_need(data, "state_dir", "config")),
        report_dir=str(_need(data, "report_dir", "config")),
        rules_path=str(_need(data, "rules_path", "config")),
        llm=llm,
        notify=notify,
        cloudflare=cf,
        **opts,
    )
