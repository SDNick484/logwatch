# Service probe: what is verified and what is not

## Observed on the target container (2026-11-22)

- `rc-service <name> status` **fails for an unprivileged user** (exit 2): it sources
  `/etc/conf.d/<name>`, which is root-only. The probe therefore does not call `rc-service`.
- Nearly every app runs under `supervise-daemon`.
- `/run/openrc/daemons/<name>/001` records `pidfile=/var/run/supervise-<name>.pid`
  (the supervisor's pid, not the app's).
- A stopped service has no entry under `/run/openrc/daemons/`.
- `/sys/fs/cgroup/memory.events` exists and has an `oom_kill` counter.
- `dmesg` is denied inside the container, so OOM alerts cannot name the process.

## How the probe decides

| State | Rule |
|---|---|
| started | `/run/openrc/started/<name>` exists and every recorded pidfile's pid is alive in `/proc` |
| crashed | marked started, but a pidfile is gone or its pid is dead (the supervisor gave up) |
| stopped | not marked started, and `/etc/init.d/<name>` exists |
| unknown | no such init script, a name with odd characters, or `/run/openrc/started` is missing |

A restart is detected when the supervisor's only child changes pid between two checks.
Three of those (or outages) in ten minutes is a restart loop.

## Confirmed as an unprivileged user (2026-11-22)

All four reads the probe depends on work without root:

```sh
ls /run/openrc/started/ | head -3
cat /run/openrc/daemons/matinee/001 | grep pidfile
cat /var/run/supervise-matinee.pid
cat /proc/$(cat /var/run/supervise-matinee.pid)/task/*/children; echo
```

They returned service names, the `pidfile=` line, the supervisor's pid, and one child pid.
Re-run them as the `logwatch` user after install; the result should be the same.

If one ever fails:

- `started/` unreadable: every service reports "Cannot read service state" (low). Nothing else breaks.
- `daemons/` or the pidfile unreadable: up and stopped still work; crashes and restart loops are not seen.
- `children` missing (kernel built without it): the probe falls back to scanning `/proc/*/stat`. No action needed.

## Containers

`container_running` only works when `docker_api_url` points at a GET-only Docker socket
proxy. Without it, Docker sources are skipped by Tier 1. If cloudflared is the only
container, the simpler option is to make it log to a file and declare that file as a
normal source with `quiet_minutes`.
