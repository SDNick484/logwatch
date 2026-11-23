"""Command line entrypoint."""
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from .config import ConfigError, load_config
from .notify import flush
from .replay import replay
from .rules import RuleSet
from .runner import build_runtime, collect_cycle, digest_cycle, run_forever
from .services import tier1_cycle
from .state import State
from .suggest import render_config, suggest_sources


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="logwatch", description="Read-only service and log watcher.")
    sub = p.add_subparsers(dest="command", required=True)
    c = sub.add_parser("check-config", help="validate a config file and its rules")
    c.add_argument("config")
    r = sub.add_parser("run", help="run the service loop")
    r.add_argument("config")
    o = sub.add_parser("once", help="run one cycle and deliver pending notifications")
    o.add_argument("cycle", choices=["tier1", "collect", "digest"])
    o.add_argument("config")
    y = sub.add_parser("replay", help="replay a synthetic incident fixture")
    y.add_argument("fixture")
    y.add_argument("--rules", default="rules/default.yaml")
    g = sub.add_parser("suggest-config", help="print a draft config from the running OpenRC services")
    g.add_argument("--all", action="store_true", help="include system services (sshd, crond, ...)")
    g.add_argument("--run-dir", default="/run/openrc")
    g.add_argument("--initd-dir", default="/etc/init.d")
    l = sub.add_parser("list-logs", help="print every log path declared in a config, one per line")
    l.add_argument("config")
    return p


def _check_config(path: str) -> int:
    config = load_config(Path(path))
    try:
        RuleSet.load(Path(config.rules_path))
    except (OSError, ValueError) as e:
        print(f"logwatch: rules file {config.rules_path}: {e}", file=sys.stderr)
        return 2
    print(f"ok: {len(config.sources)} sources, rules loaded from {config.rules_path}")
    for src in config.sources:
        for lf in src.logs:
            if not os.path.lexists(lf.path) and os.access(os.path.dirname(lf.path), os.X_OK):
                print(f"note: {lf.path} does not exist yet (source {src.name})")
            elif not os.access(lf.path, os.R_OK):
                print(f"warning: cannot read {lf.path} as this user (source {src.name})")
    wanted = [config.notify.token_env]
    if config.llm.enabled:
        wanted.append(config.llm.api_key_env)
    if config.cloudflare:
        wanted += [config.cloudflare.account_id_env, config.cloudflare.token_env]
    for name in wanted:
        if not os.environ.get(name):
            print(f"warning: environment variable {name} is not set")
    return 0


def _once(cycle: str, path: str) -> int:
    config = load_config(Path(path))
    rt = build_runtime(config)
    state = State(Path(config.state_dir) / "logwatch.db")
    now = datetime.now(timezone.utc)
    if cycle == "tier1":
        tier1_cycle(config, state, rt.probe, now)
    elif cycle == "collect":
        remainder = collect_cycle(config, state, rt.rules, now, rt.cf_fetch)
        print(f"collected; {len(remainder)} unmatched lines held for the digest")
    else:
        print(f"digest written to {digest_cycle(config, state, rt.client, datetime.now().astimezone())}")
    delivered = flush(state, rt.notifier)
    print(f"{delivered} notifications delivered, {len(state.outbox_pending())} still queued, {len(state.open_alerts())} alerts open")
    state.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
    except SystemExit as e:
        return int(e.code or 0)
    try:
        if args.command == "check-config":
            return _check_config(args.config)
        if args.command == "run":
            run_forever(load_config(Path(args.config)))
            return 0
        if args.command == "once":
            return _once(args.cycle, args.config)
        if args.command == "suggest-config":
            print(render_config(suggest_sources(Path(args.run_dir), Path(args.initd_dir), args.all)), end="")
            return 0
        if args.command == "list-logs":
            for src in load_config(Path(args.config)).sources:
                for lf in src.logs:
                    print(lf.path)
            return 0
        problems = replay(Path(args.fixture), Path(args.rules))
        for line in problems:
            print(line)
        print("ok" if not problems else f"{len(problems)} mismatches")
        return 1 if problems else 0
    except ConfigError as e:
        print(f"logwatch: {e}", file=sys.stderr)
        return 2
    except (OSError, ValueError) as e:
        print(f"logwatch: {type(e).__name__}: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
