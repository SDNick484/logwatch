#!/bin/sh
# Install or upgrade logwatch on Alpine Linux (OpenRC). Run as root. Safe to re-run.
#
# It never starts the service, never writes secrets, and never changes permissions on
# your application logs unless you pass --grant-log-access.
# Preview everything first with:  sh deploy/install.sh --dry-run
set -eu

DRY_RUN=0
GRANT=0
SRC=$(cd "$(dirname "$0")/.." && pwd)
PREFIX=/opt/logwatch
VENV=$PREFIX/venv
ETC=/etc/logwatch
CONFD=/etc/conf.d/logwatch
INITD=/etc/init.d/logwatch
LW=$VENV/bin/logwatch

usage() {
	cat <<EOF
Usage: sh install.sh [--dry-run] [--grant-log-access] [--src DIR]

  --dry-run            print every command without running it; changes nothing
  --grant-log-access   give the logwatch user read access (setfacl u:logwatch:r) to each
                       log file in the config that it cannot already read
  --src DIR            source checkout to install from (default: this script's repo)
EOF
}

while [ $# -gt 0 ]; do
	case "$1" in
		--dry-run) DRY_RUN=1 ;;
		--grant-log-access) GRANT=1 ;;
		--src)
			[ $# -ge 2 ] || { echo "install.sh: --src needs a directory" >&2; exit 2; }
			SRC=$2
			shift
			;;
		-h | --help) usage; exit 0 ;;
		*) echo "install.sh: unknown option $1" >&2; usage >&2; exit 2 ;;
	esac
	shift
done

say() { printf '\n== %s\n' "$*"; }
note() { printf '   %s\n' "$*"; }
run() {
	printf '+ %s\n' "$*"
	[ "$DRY_RUN" -eq 1 ] || "$@"
}

if [ "$DRY_RUN" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
	echo "install.sh: must run as root (or use --dry-run to preview)" >&2
	exit 1
fi
[ -f "$SRC/pyproject.toml" ] || { echo "install.sh: $SRC is not a logwatch checkout" >&2; exit 1; }
[ "$DRY_RUN" -eq 0 ] || echo "DRY RUN: nothing below is executed."

say "Python"
command -v python3 >/dev/null 2>&1 || run apk add --no-cache python3
if command -v python3 >/dev/null 2>&1; then
	if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'; then
		echo "install.sh: Python 3.11 or newer is required, found $(python3 --version 2>&1)" >&2
		exit 1
	fi
	note "$(python3 --version 2>&1) is new enough"
fi

say "User and directories"
getent group logwatch >/dev/null 2>&1 || run addgroup -S logwatch
id logwatch >/dev/null 2>&1 || run adduser -S -D -H -h /var/lib/logwatch -s /sbin/nologin -G logwatch logwatch
run mkdir -p /etc/logwatch /var/lib/logwatch /var/log/logwatch /opt/logwatch
run chown logwatch:logwatch /var/lib/logwatch /var/log/logwatch
run chmod 0750 /var/lib/logwatch /var/log/logwatch

say "Program"
[ -x "$VENV/bin/python" ] || run python3 -m venv $VENV
run $VENV/bin/pip install --quiet --upgrade "$SRC"

say "Rules and config"
if [ ! -e "$ETC/rules.yaml" ]; then
	run cp "$SRC/rules/default.yaml" $ETC/rules.yaml
elif ! cmp -s "$SRC/rules/default.yaml" "$ETC/rules.yaml"; then
	note "kept your $ETC/rules.yaml; current defaults are in $SRC/rules/default.yaml"
fi
if [ ! -e "$ETC/config.yaml" ]; then
	run sh -c "$LW suggest-config > $ETC/config.yaml"
	note "drafted $ETC/config.yaml from the running services: review it before starting"
else
	note "kept your $ETC/config.yaml"
fi
run chown root:logwatch $ETC/config.yaml $ETC/rules.yaml
run chmod 0640 $ETC/config.yaml $ETC/rules.yaml

say "Secrets file and service script"
if [ ! -e "$CONFD" ]; then
	run install -m 0600 -o root -g root "$SRC/deploy/logwatch.confd.example" $CONFD
	note "created $CONFD with empty values (root only)"
else
	note "kept your $CONFD"
fi
run install -m 0755 "$SRC/deploy/logwatch.initd" $INITD

say "Log read access"
if [ "$DRY_RUN" -eq 1 ] && [ ! -x "$LW" ]; then
	if [ "$GRANT" -eq 1 ]; then
		echo "+ setfacl -m u:logwatch:r <each log file in the config that logwatch cannot read>"
	else
		note "would list the log files logwatch cannot read; --grant-log-access would fix them"
	fi
else
	can() { su logwatch -s /bin/sh -c "test -$1 \"\$1\"" sh "$2" 2>/dev/null; }
	list=$(mktemp)
	"$LW" list-logs "$ETC/config.yaml" >"$list" 2>/dev/null || note "could not read $ETC/config.yaml yet"
	blocked=0
	while IFS= read -r f; do
		case "$f" in /var/log/logwatch/*) continue ;; esac
		if [ ! -e "$f" ]; then
			note "missing (fix the path in the config, or ignore until the app writes it): $f"
		elif can r "$f"; then
			:
		elif [ "$GRANT" -eq 1 ]; then
			command -v setfacl >/dev/null 2>&1 || run apk add --no-cache acl
			# The file needs read; each directory above it needs traverse (x), nothing more.
			d=$(dirname "$f")
			while [ "$d" != "/" ]; do
				can x "$d" || run setfacl -m u:logwatch:x "$d" || note "setfacl failed on $d"
				d=$(dirname "$d")
			done
			run setfacl -m u:logwatch:r "$f" || note "setfacl failed on $f"
			if [ "$DRY_RUN" -eq 0 ] && ! can r "$f"; then
				blocked=1
				note "STILL not readable by logwatch: $f"
			fi
		else
			blocked=1
			note "not readable by logwatch: $f"
		fi
	done <"$list"
	rm -f "$list"
	if [ "$blocked" -eq 1 ] && [ "$GRANT" -eq 1 ]; then
		note "ACLs did not take for the files marked STILL. The filesystem may not support"
		note "ACLs; grant access another way (group ownership) or remove them from the config."
	elif [ "$blocked" -eq 1 ]; then
		note "re-run with --grant-log-access to add a read-only ACL for each file above"
		note "(read on the file, traverse on its directories), or grant access yourself."
		note "logwatch reports unreadable files as a low alert."
	fi
fi

say "Config check (as the logwatch user)"
run sh -c "set -a; . $CONFD; set +a; exec su logwatch -s /bin/sh -c '$LW check-config $ETC/config.yaml'" ||
	note "check-config reported a problem (see above); fix it before starting"

cat <<EOF

== Done. The service is installed but NOT started. Next:

  1. Put your tokens in $CONFD
       vim $CONFD
  2. Review $ETC/config.yaml: set notify.base_url and notify.service,
     and check each source's log paths
       vim $ETC/config.yaml
  3. Try one cycle by hand (sends a real notification if something is down):
       ( set -a; . $CONFD; set +a; su logwatch -s /bin/sh -c '$LW once tier1 $ETC/config.yaml' )
  4. Start it and enable it at boot:
       rc-update add logwatch default
       rc-service logwatch start

  To remove everything, see the Uninstall section of deploy/install.md.
EOF
