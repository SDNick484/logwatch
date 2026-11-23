"""Tier 1: are the declared services up? No AI, no log reading, report only."""
from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Literal, Protocol

import httpx

from .config import Config
from .notify import enqueue
from .state import State

_SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]+$")
_OOM_LINE = re.compile(r"Killed process \d+ \(([^)]+)\)")


@dataclass(frozen=True)
class ServiceStatus:
    state: Literal["started", "stopped", "crashed", "unknown"]
    pid: int | None = None


class ServiceProbe(Protocol):
    def status(self, name: str) -> ServiceStatus: ...
    def container_running(self, name: str) -> bool | None: ...
    def oom_victims(self, since: datetime) -> list[str]: ...


def _default_run(argv: list[str]) -> tuple[int, str]:
    done = subprocess.run(argv, capture_output=True, text=True, timeout=10, check=False)  # never a shell
    return done.returncode, done.stdout + done.stderr


class OpenRCProbe:
    """Reads service state on an OpenRC host from files any user can read.

    `rc-service <name> status` is not used: it sources /etc/conf.d/<name>, which is
    root-only wherever that file holds secrets, so it fails for an unprivileged user.
    This mirrors what OpenRC itself checks: the service is marked started, and the
    pid in its pidfile is alive. See deploy/probe-notes.md.
    """

    def __init__(
        self,
        run: Callable[[list[str]], tuple[int, str]] = _default_run,
        memory_events_path: str = "/sys/fs/cgroup/memory.events",
        openrc_run_dir: str = "/run/openrc",
        initd_dir: str = "/etc/init.d",
        proc_dir: str = "/proc",
        docker_api_url: str | None = None,
        http_client: httpx.Client | None = None,
    ):
        self._run = run
        self._memory_events = memory_events_path
        self._run_dir = Path(openrc_run_dir)
        self._initd = Path(initd_dir)
        self._proc = Path(proc_dir)
        self._docker = docker_api_url
        self._http = http_client or httpx.Client(timeout=5.0)
        self._oom_kills: int | None = None

    def status(self, name: str) -> ServiceStatus:
        if not _SAFE_NAME.match(name) or not (self._run_dir / "started").is_dir():
            return ServiceStatus("unknown")
        if not os.path.lexists(self._run_dir / "started" / name):
            return ServiceStatus("stopped" if (self._initd / name).exists() else "unknown")
        pids = self._pidfile_pids(name)
        if pids is None:
            return ServiceStatus("started")  # no daemon record we can read: trust the started mark
        if any(pid is None or not (self._proc / str(pid)).exists() for pid in pids):
            return ServiceStatus("crashed")
        return ServiceStatus("started", self._app_pid(pids[0]))  # type: ignore[arg-type]

    def _pidfile_pids(self, name: str) -> list[int | None] | None:
        """Pids recorded for the service's daemons. A None entry: pidfile gone. None: nothing to check."""
        pids: list[int | None] = []
        try:
            for entry in sorted((self._run_dir / "daemons" / name).iterdir()):
                for line in entry.read_text().splitlines():
                    if line.startswith("pidfile="):
                        try:
                            pids.append(int(Path(line.split("=", 1)[1]).read_text().split()[0]))
                        except FileNotFoundError:
                            pids.append(None)
        except (OSError, ValueError, IndexError):
            return None
        return pids or None

    def _app_pid(self, pid: int) -> int | None:
        """The pid whose change means a restart: the supervised child under supervise-daemon."""
        try:
            if (self._proc / str(pid) / "comm").read_text().strip() != "supervise-daemon":
                return pid
        except OSError:
            return pid
        try:
            kids = [int(k) for k in (self._proc / str(pid) / "task" / str(pid) / "children").read_text().split()]
        except (OSError, ValueError):
            kids = []
            for d in self._proc.iterdir():
                if d.name.isdigit():
                    try:
                        if int((d / "stat").read_text().rsplit(")", 1)[1].split()[1]) == pid:
                            kids.append(int(d.name))
                    except (OSError, ValueError, IndexError):
                        continue
        return min(kids) if kids else None  # None: between respawns

    def container_running(self, name: str) -> bool | None:
        if not self._docker or not _SAFE_NAME.match(name):
            return None
        try:
            resp = self._http.get(f"{self._docker}/containers/{name}/json")
            if resp.status_code == 404:
                return False
            resp.raise_for_status()
            return bool(resp.json().get("State", {}).get("Running"))
        except (httpx.HTTPError, ValueError, AttributeError):
            return None

    def oom_victims(self, since: datetime) -> list[str]:
        """Names from the kernel log when readable; otherwise "*" when the cgroup OOM counter moved."""
        try:
            text = Path(self._memory_events).read_text()
            current = next(int(l.split()[1]) for l in text.splitlines() if l.startswith("oom_kill "))
        except (OSError, ValueError, StopIteration, IndexError):
            return []
        previous, self._oom_kills = self._oom_kills, current
        if previous is None or current <= previous:
            return []
        try:
            code, output = self._run(["dmesg"])
            names = _OOM_LINE.findall(output)[-(current - previous):] if code == 0 else []
        except (OSError, subprocess.SubprocessError):
            names = []
        return names or ["*"]


class ScriptedProbe:
    """Test double. Each script entry is one cycle:
    {"services": {name: [state, pid]}, "containers": {name: bool|None}, "oom": [names]}"""

    def __init__(self, script: list[dict]):
        self._script = script or [{}]
        self._i = 0

    def advance(self) -> None:
        self._i = min(self._i + 1, len(self._script) - 1)

    def _now(self) -> dict:
        return self._script[self._i]

    def status(self, name: str) -> ServiceStatus:
        state, pid = self._now().get("services", {}).get(name, ["started", None])
        return ServiceStatus(state, pid)

    def container_running(self, name: str) -> bool | None:
        return self._now().get("containers", {}).get(name, True)

    def oom_victims(self, since: datetime) -> list[str]:
        return list(self._now().get("oom", []))


def tier1_cycle(
    config: Config,
    state: State,
    probe: ServiceProbe,
    now: datetime,
    mtime: Callable[[str], float] = os.path.getmtime,
) -> None:
    window_start = now - timedelta(seconds=config.restart_window_s)

    for src in config.sources:
        name = src.name
        if src.service:
            st = probe.status(src.service)
            down_key, unknown_key, loop_key = f"svc:{name}:down", f"svc:{name}:unknown", f"svc:{name}:loop"
            pid_key = f"pid:{name}"
            if st.state in ("crashed", "stopped"):
                state.clear_alert(unknown_key, now)
                if state.open_alert(down_key, "high", f"Service down: {name}", st.state, now):
                    state.record_event(name, "down", now)
                    enqueue(state, f"Service down: {name}", f"OpenRC reports {src.service} as {st.state}.", "high")
            elif st.state == "started":
                state.clear_alert(unknown_key, now)
                recovered = state.clear_alert(down_key, now)
                if recovered:
                    enqueue(state, f"Recovered: {name}", f"{src.service} is running again.", "low")
                last = state.get_kv(pid_key)
                if st.pid is not None:
                    if last is not None and not recovered and str(st.pid) != last:
                        state.record_event(name, "respawn", now)
                    state.set_kv(pid_key, str(st.pid))
            else:
                if state.open_alert(unknown_key, "low", f"Cannot read service state: {name}", "", now):
                    enqueue(
                        state,
                        f"Cannot read service state: {name}",
                        f"rc-service gave no usable status for {src.service}. Check the name and permissions.",
                        "low",
                    )
            churn = state.count_events(name, "down", window_start) + state.count_events(name, "respawn", window_start)
            if churn >= config.restart_threshold:
                if state.open_alert(loop_key, "high", f"Restart loop: {name}", str(churn), now):
                    enqueue(
                        state,
                        f"Restart loop: {name}",
                        f"{churn} crashes or respawns in the last {config.restart_window_s // 60} minutes.",
                        "high",
                    )
            elif state.clear_alert(loop_key, now):
                enqueue(state, f"Stable again: {name}", f"{src.service} has stopped restarting.", "low")

        if src.docker:
            running = probe.container_running(src.docker)
            key = f"ctr:{name}:down"
            if running is False:
                if state.open_alert(key, "high", f"Container down: {name}", "", now):
                    enqueue(state, f"Container down: {name}", f"Container {src.docker} is not running.", "high")
            elif running is True and state.clear_alert(key, now):
                enqueue(state, f"Recovered: {name}", f"Container {src.docker} is running again.", "low")

        if src.quiet_minutes and src.logs:
            try:
                newest = max(mtime(lf.path) for lf in src.logs)
            except OSError:
                newest = None  # unreadable files are reported by the collect cycle
            key = f"src:{name}:quiet"
            if newest is not None:
                silent_min = (now.timestamp() - newest) / 60
                if silent_min > src.quiet_minutes:
                    if state.open_alert(key, "medium", f"Log gone quiet: {name}", "", now):
                        enqueue(
                            state,
                            f"Log gone quiet: {name}",
                            f"No log writes for {int(silent_min)} minutes (expected within {src.quiet_minutes}).",
                            "medium",
                        )
                else:
                    state.clear_alert(key, now)

    victims = probe.oom_victims(window_start)
    for victim in dict.fromkeys(victims):
        owner = next((s.name for s in config.sources if victim in (s.name, s.service, s.docker)), None)
        if owner:
            enqueue(state, f"OOM kill: {owner}", f"The kernel killed {victim} for running out of memory.", "high")
        else:
            detail = "" if victim == "*" else f" Process: {victim[:60]}."
            enqueue(state, "OOM kill in container", f"The kernel OOM killer ran in this container.{detail}", "high")

    state.prune_events(now - timedelta(days=2))
