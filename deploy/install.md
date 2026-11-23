# Installing logwatch on Alpine (OpenRC)

These steps were written without access to the target container and have not been run
there. Read each command before running it. Steps marked **root** change the system and
are run by you; the service itself never runs as root and never needs these rights.

Requires Python 3.11 or newer (`python3 --version`).

## 1. User, directories, code (root)

```sh
addgroup -S logwatch
adduser -S -D -H -h /var/lib/logwatch -s /sbin/nologin -G logwatch logwatch

mkdir -p /etc/logwatch /var/lib/logwatch /var/log/logwatch /opt/logwatch
chown logwatch:logwatch /var/lib/logwatch /var/log/logwatch
chmod 0750 /var/lib/logwatch /var/log/logwatch

apk add python3 git
git clone https://github.com/SDNick484/logwatch /opt/logwatch/src
python3 -m venv /opt/logwatch/venv
/opt/logwatch/venv/bin/pip install /opt/logwatch/src
```

## 2. Config and rules (root)

```sh
cp /opt/logwatch/src/config.example.yaml /etc/logwatch/config.yaml
cp /opt/logwatch/src/rules/default.yaml  /etc/logwatch/rules.yaml
vim /etc/logwatch/config.yaml      # declare your sources; nothing is auto-discovered
chown root:logwatch /etc/logwatch/*.yaml && chmod 0640 /etc/logwatch/*.yaml
```

For each app, list its OpenRC service name and every log file with a format
(`combined` for access logs, `json`, or `plain`).

## 3. Read access to the logs (root)

`logwatch` needs read access to each declared log file and execute on its directory.
Pick one per app:

- The app's log directory is group-readable: `addgroup logwatch <app-group>`
- Otherwise, with ACLs (`apk add acl`):
  `setfacl -R -m u:logwatch:rX /var/log/<app> && setfacl -d -m u:logwatch:rX /var/log/<app>`
  (the second command covers files created later, including after rotation)

Do not make logs world-readable and do not add `logwatch` to `wheel` or `docker`.

## 4. Secrets (root)

```sh
cp /opt/logwatch/src/deploy/logwatch.confd.example /etc/conf.d/logwatch
chmod 0600 /etc/conf.d/logwatch && chown root:root /etc/conf.d/logwatch
vim /etc/conf.d/logwatch
```

- **Home Assistant:** a long-lived access token. The service only calls
  `notify.<service>`; set `notify.service` in the config to your phone's notify service.
- **Cloudflare:** an API token with only *Access: Audit Logs Read*. Free-plan Access logs
  are kept about 24 hours; logwatch polls hourly.
- **Model key:** used once a day for the digest. Only redacted cluster templates and up to
  two redacted sample lines per cluster are sent. Set `llm.enabled: false` to send nothing.

## 5. Check before starting (root shell, runs as logwatch)

```sh
run_as_logwatch() {
  ( set -a; . /etc/conf.d/logwatch; set +a
    su logwatch -s /bin/sh -c "/opt/logwatch/venv/bin/logwatch $*" )
}
run_as_logwatch check-config /etc/logwatch/config.yaml   # expect "ok: N sources" and no warnings
run_as_logwatch once tier1 /etc/logwatch/config.yaml     # expect "0 alerts open" when everything is up
run_as_logwatch once collect /etc/logwatch/config.yaml   # first run only records where each log ends
```

Also run the four read-only checks in `probe-notes.md` once. They confirm how service
state looks on your box.

## 6. Start (root)

```sh
install -m 0755 /opt/logwatch/src/deploy/logwatch.initd /etc/init.d/logwatch
rc-update add logwatch default
rc-service logwatch start
```

If the digest time has already passed today, the first digest arrives within a minute
of starting. On a fresh install it will say "Nothing notable"; that is your end-to-end test
of the notification path.

## 7. Live test

1. `rc-service <one-app> stop` and wait up to two minutes: one "Service down" notification.
2. `rc-service <one-app> start`: one "Recovered" notification on the next cycle.
3. `run_as_logwatch once digest /etc/logwatch/config.yaml`: a report appears under
   `/var/lib/logwatch/reports/`.

## What watches the watcher

Nothing does, by design. If the daily digest stops arriving, logwatch is down or cannot
reach Home Assistant. `supervise-daemon` restarts it up to 5 times in 5 minutes. Its own
errors go to `/var/log/logwatch/error.log`, which the example config declares as a source,
so a failing cycle shows up in the next digest as a traceback finding.

## Where things are

| What | Where |
|---|---|
| State (cursors, alerts, queue) | `/var/lib/logwatch/logwatch.db` |
| Digests | `/var/lib/logwatch/reports/digest-YYYY-MM-DD.md` |
| Every model request and response | `/var/lib/logwatch/audit/*.json` |
| Service output | `/var/log/logwatch/` |

The audit and report directories are not pruned automatically.

## Upgrade

```sh
git -C /opt/logwatch/src pull
/opt/logwatch/venv/bin/pip install /opt/logwatch/src
rc-service logwatch restart
```

## Uninstall (root)

```sh
rc-service logwatch stop
rc-update del logwatch default
rm /etc/init.d/logwatch /etc/conf.d/logwatch
rm -r /opt/logwatch /etc/logwatch /var/lib/logwatch /var/log/logwatch
deluser logwatch
# and undo step 3: remove logwatch from app groups, or setfacl -R -x u:logwatch /var/log/<app>
```

Revoke the Home Assistant token, the Cloudflare token, and the model key if they were
created only for this.
