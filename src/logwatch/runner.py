"""The collect and digest cycles, and the long-running loop that schedules them."""
from __future__ import annotations

import os
import signal
import sys
import threading
import time
import traceback
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Mapping

import httpx

from .cloudflare import fetch_access_events
from .cluster import cluster
from .config import Config, ConfigError
from .events import Event
from .llm import AnthropicClient, LLMClient, classify
from .notify import HomeAssistantNotifier, Notifier, enqueue, flush
from .parse import parse_line
from .report import render_digest, summarize
from .rules import RuleSet
from .services import OpenRCProbe, ServiceProbe, tier1_cycle
from .state import State
from .tail import read_new

CfFetch = Callable[[datetime], list[Event]]
CF_ALERT = "src:cloudflare-access:unreadable"


def collect_cycle(config: Config, state: State, rules: RuleSet, now: datetime, cf_fetch: CfFetch | None = None) -> list[Event]:
    """Read new lines from every declared file, apply rules, store findings. Returns the remainder."""
    events: list[Event] = []
    for src in config.sources:
        for lf in src.logs:
            key = f"src:{lf.path}:unreadable"
            try:
                lines, cursor = read_new(lf.path, state.get_cursor(lf.path))
            except OSError as e:
                if state.open_alert(key, "low", f"Cannot read log: {src.name}", lf.path, now):
                    enqueue(state, f"Cannot read log: {src.name}", f"{lf.path}: {e.strerror or type(e).__name__}", "low")
                continue
            state.clear_alert(key, now)
            state.set_cursor(lf.path, cursor)
            events += [parse_line(src.name, lf.path, lf.format, line) for line in lines if line.strip()]

    if cf_fetch is not None:
        stored = state.get_kv("cf:since")
        since = datetime.fromisoformat(stored) if stored else now - timedelta(seconds=config.collect_interval_s)
        try:
            fetched = cf_fetch(since)
        except (httpx.HTTPError, ValueError) as e:
            if state.open_alert(CF_ALERT, "low", "Cannot read Cloudflare Access logs", "", now):
                enqueue(state, "Cannot read Cloudflare Access logs", f"API call failed: {type(e).__name__}", "low")
        else:
            state.clear_alert(CF_ALERT, now)
            newest = max((e.ts for e in fetched if e.ts is not None), default=None)
            state.set_kv("cf:since", ((newest + timedelta(seconds=1)) if newest else now).isoformat())
            events += fetched

    findings, remainder = rules.apply(events)
    state.add_findings(findings, now)
    for f in findings:
        if f.severity == "high":
            enqueue(state, f"{f.rule}: {f.subject}", f"{f.summary} (source: {f.source})", "high")
    state.add_remainder(remainder)
    return remainder


def digest_cycle(config: Config, state: State, client: LLMClient | None, now: datetime) -> Path:
    """Write the digest report and enqueue one notification. Returns the report path."""
    last = state.get_kv("digest:last")
    since = datetime.fromisoformat(last) if last else now - timedelta(hours=24)
    findings = state.findings_since(since)
    clusters = cluster(state.take_remainder())
    if not clusters:
        classifications = []
    elif client is None:
        classifications = None
    else:
        classifications = classify(clusters, client, Path(config.state_dir) / "audit")

    report_dir = Path(config.report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    path = report_dir / f"digest-{now.date().isoformat()}.md"
    path.write_text(render_digest(findings, clusters, classifications, now))

    severity, counts = summarize(findings, clusters, classifications)
    note = "" if classifications is not None else " Model classification was unavailable."
    enqueue(state, "Daily digest", f"{counts}{note} Report: {path}", severity)
    state.set_kv("digest:last", now.isoformat())
    state.prune_findings(now - timedelta(days=7))
    return path


def digest_due(now_local: datetime, last: datetime | None, digest_time: str) -> bool:
    hour, minute = (int(x) for x in digest_time.split(":"))
    slot = now_local.replace(hour=hour, minute=minute, second=0, microsecond=0)
    return now_local >= slot and (last is None or last < slot)


@dataclass
class Runtime:
    probe: ServiceProbe
    notifier: Notifier
    client: LLMClient | None
    rules: RuleSet
    cf_fetch: CfFetch | None


def build_runtime(config: Config, env: Mapping[str, str] = os.environ) -> Runtime:
    """Wire real implementations from config and environment. Secrets come only from env."""
    token = env.get(config.notify.token_env)
    if not token:
        raise ConfigError(f"environment variable {config.notify.token_env} is not set (notification token)")
    client: LLMClient | None = None
    if config.llm.enabled:
        key = env.get(config.llm.api_key_env)
        if key:
            client = AnthropicClient(config.llm.base_url, key, config.llm.model)
        else:
            print(f"logwatch: {config.llm.api_key_env} is not set; digests will ship without model classification", file=sys.stderr)
    cf_fetch: CfFetch | None = None
    if config.cloudflare:
        account, cf_token = env.get(config.cloudflare.account_id_env), env.get(config.cloudflare.token_env)
        if account and cf_token:
            http = httpx.Client(timeout=30.0)
            cf_fetch = lambda since: fetch_access_events(account, cf_token, since, http)  # noqa: E731
        else:
            print("logwatch: Cloudflare env vars are not set; Access logs will not be collected", file=sys.stderr)
    return Runtime(
        probe=OpenRCProbe(docker_api_url=config.docker_api_url),
        notifier=HomeAssistantNotifier(config.notify.base_url, token, config.notify.service),
        client=client,
        rules=RuleSet.load(Path(config.rules_path)),
        cf_fetch=cf_fetch,
    )


def _safe(what: str, fn: Callable[[], object]) -> None:
    """One failing cycle must not stop the others."""
    try:
        fn()
    except Exception:  # noqa: BLE001
        print(f"logwatch: {what} cycle failed", file=sys.stderr)
        traceback.print_exc()


def run_forever(config: Config) -> None:
    rt = build_runtime(config)
    state = State(Path(config.state_dir) / "logwatch.db")
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())

    last_tier1 = last_collect = last_digest_try = float("-inf")
    while not stop.is_set():
        mono = time.monotonic()
        now = datetime.now(timezone.utc)
        if mono - last_tier1 >= config.tier1_interval_s:
            last_tier1 = mono
            _safe("tier1", lambda: tier1_cycle(config, state, rt.probe, now))
        if mono - last_collect >= config.collect_interval_s:
            last_collect = mono
            _safe("collect", lambda: collect_cycle(config, state, rt.rules, now, rt.cf_fetch))
        local = datetime.now().astimezone()
        stored = state.get_kv("digest:last")
        due = digest_due(local, datetime.fromisoformat(stored) if stored else None, config.digest_time)
        if due and mono - last_digest_try >= 600:  # a failing digest is retried every 10 minutes, not every loop
            last_digest_try = mono
            _safe("digest", lambda: digest_cycle(config, state, rt.client, local))
        _safe("notify", lambda: flush(state, rt.notifier))
        stop.wait(5)
    state.close()
