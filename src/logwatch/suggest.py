"""Draft a config from what OpenRC is running. The output is a starting point for a
human to edit: sources are still declared explicitly, nothing is watched until it is
in the config file."""
from __future__ import annotations

import json
import re
from pathlib import Path

_SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]+$")
_INIT_LOG = re.compile(r"""^\s*(?:output_log|error_log)=["']?([^"'\s#]+)["']?""", re.MULTILINE)
_SVCNAME = re.compile(r"\$\{?(?:RC_SVCNAME|SVCNAME)\}?")

ACCESS_FLAGS = {"--access-logfile", "--access-log"}
LOG_FLAGS = {"--error-logfile", "--log-file", "--logfile", "--log", "--error-log"}
SYSTEM_SERVICES = {
    "acpid", "avahi-daemon", "chronyd", "containerd", "crond", "dbus", "docker", "networking",
    "ntpd", "runsvdir", "s6-svscan", "sshd", "syslog", "syslog-ng", "tailscale", "udev", "user",
}
SELF = "logwatch"


def _usable(path: str) -> bool:
    return path.startswith("/") and "$" not in path and len(path) > 1


def _from_argv(argv: list[str]) -> dict[str, str]:
    found: dict[str, str] = {}

    def add(path: str, fmt: str) -> None:
        if _usable(path) and (fmt == "combined" or path not in found):
            found[path] = fmt

    i = 0
    while i < len(argv):
        flag, _, inline = argv[i].partition("=")
        if flag in ACCESS_FLAGS or flag in LOG_FLAGS:
            value = inline if inline else (argv[i + 1] if i + 1 < len(argv) else "")
            if not inline:
                i += 1
            add(value, "combined" if flag in ACCESS_FLAGS else "plain")
        else:
            for candidate in (argv[i], inline):
                if candidate.startswith("/var/log/"):
                    add(candidate, "plain")
        i += 1
    return found


def _daemon_argv(entry: Path) -> list[str]:
    args: dict[int, str] = {}
    for line in entry.read_text(errors="replace").splitlines():
        m = re.match(r"argv_(\d+)=(.*)$", line)
        if m:
            args[int(m.group(1))] = m.group(2)
    return [args[k] for k in sorted(args)]


def suggest_sources(run_dir: Path, initd_dir: Path, include_system: bool = False) -> list[dict]:
    """One source per running OpenRC daemon, with any log paths that can be seen."""
    daemons = Path(run_dir) / "daemons"
    try:
        names = sorted(d.name for d in daemons.iterdir() if d.is_dir())
    except OSError:
        return []
    sources = []
    for name in names:
        if not _SAFE_NAME.match(name) or name == SELF:
            continue
        if name in SYSTEM_SERVICES and not include_system:
            continue
        logs: dict[str, str] = {}
        try:
            for entry in sorted((daemons / name).iterdir()):
                for path, fmt in _from_argv(_daemon_argv(entry)).items():
                    if fmt == "combined" or path not in logs:
                        logs[path] = fmt
        except OSError:
            pass
        try:
            script = (Path(initd_dir) / name).read_text(errors="replace")
        except OSError:
            script = ""
        for raw in _INIT_LOG.findall(script):
            path = _SVCNAME.sub(name, raw)
            if _usable(path):
                logs.setdefault(path, "plain")
        sources.append({"name": name, "service": name, "logs": [{"path": p, "format": f} for p, f in logs.items()]})
    return sources


_HEADER = """\
# Drafted by `logwatch suggest-config`. Review every source before starting the service.
# Nothing is watched unless it is listed here.
state_dir: /var/lib/logwatch
report_dir: /var/lib/logwatch/reports
rules_path: /etc/logwatch/rules.yaml

llm:
  enabled: true
  base_url: https://api.anthropic.com
  model: claude-haiku-5-5
  api_key_env: LOGWATCH_LLM_API_KEY      # name of the env var, never the key itself

notify:
  base_url: http://homeassistant.local:8123   # CHANGE: your Home Assistant URL
  token_env: LOGWATCH_HA_TOKEN
  service: CHANGE_ME                          # CHANGE: e.g. mobile_app_your_phone

cloudflare:                               # remove this block to skip Access logs
  account_id_env: LOGWATCH_CF_ACCOUNT_ID
  token_env: LOGWATCH_CF_TOKEN

# format: combined (web access logs), json, or plain
sources:
"""

_FOOTER = """\
  - name: logwatch                        # its own errors show up in the next digest
    logs:
      - path: /var/log/logwatch/error.log
        format: plain
"""


def render_config(sources: list[dict]) -> str:
    out = [_HEADER]
    for s in sources:
        out.append(f"  - name: {s['name']}\n    service: {s['service']}\n")
        if s["logs"]:
            out.append("    logs:\n")
            for lf in s["logs"]:
                out.append(f"      - path: {json.dumps(lf['path'])}\n        format: {lf['format']}\n")
        else:
            out.append("    # no log path found: add `logs:` here, or keep this as an up/down check only\n")
    out.append(_FOOTER)
    return "".join(out)
