# Service probe: what is verified and what is not

`OpenRCProbe` was written from OpenRC's documented behavior, without access to the
target container. Everything below marked UNVERIFIED should be checked once on the box.
All commands are read-only. Run them as the `logwatch` user (or any unprivileged user).

## Checks to run

```sh
# 1. Service state. Expect " * status: started" and exit code 0.
rc-service <one-app> status; echo "exit=$?"

# 2. Stop that service as root, then repeat as the unprivileged user.
#    Expect "stopped" (exit 3). If you kill the process instead of stopping it,
#    expect "crashed" (exit 32) for a plain OpenRC service.
rc-service <one-app> status; echo "exit=$?"

# 3. How is each app supervised?
grep -l supervise-daemon /etc/init.d/* 2>/dev/null
ls /run/openrc/daemons/<one-app>/ && cat /run/openrc/daemons/<one-app>/*

# 4. OOM visibility from inside the container.
cat /sys/fs/cgroup/memory.events      # expect a line "oom_kill N"
dmesg | tail -3; echo "exit=$?"       # often denied in an LXC; that is fine
```

## Assumptions in the code

| Behavior | Status |
|---|---|
| `rc-service <name> status` works for an unprivileged user | UNVERIFIED |
| Output contains `status: started|stopped|crashed`; exit codes 0, 3, 32 | UNVERIFIED (text is preferred over the code) |
| Daemon pid is found through `pidfile=` in `/run/openrc/daemons/<name>/*` | UNVERIFIED |
| Under `supervise-daemon`, the pidfile holds the supervisor and the app is its only child | UNVERIFIED |
| `/sys/fs/cgroup/memory.events` exists (cgroup v2) and is readable | UNVERIFIED |

## What happens if an assumption is wrong

- Status not readable: one low-severity "Cannot read service state" alert per service. Nothing else breaks.
- Pid not found: down and recovered alerts still work; restart-loop detection only counts full
  down events, so a service that `supervise-daemon` respawns quickly would go unnoticed. If that
  is your setup and check 3 shows a different layout, tell me what `/run/openrc/daemons/<name>/`
  contains and the lookup can be fixed in `OpenRCProbe._pid`.
- No `memory.events`: OOM detection is silently off.
- `dmesg` denied: OOM alerts say "OOM kill in container" without naming the process.

## Containers

`container_running` only works when `docker_api_url` points at a GET-only Docker socket
proxy. Without it, Docker sources are skipped by Tier 1. If cloudflared is the only
container, the simpler option is to make it log to a file and declare that file as a
normal source with `quiet_minutes`.
