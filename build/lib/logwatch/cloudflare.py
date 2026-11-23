"""Cloudflare Access authentication log collector (read-only).

Token permission needed: "Access: Audit Logs Read". Free-plan retention is about
24 hours, so this is polled every collect cycle.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

import httpx

from .events import Event
from .redact import redact

API_BASE = "https://api.cloudflare.com/client/v4"
SOURCE = "cloudflare-access"
_ACCOUNT_ID = re.compile(r"^[0-9a-f]{32}$")


def _ts(value: object) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def fetch_access_events(account_id: str, token: str, since: datetime, client: httpx.Client) -> list[Event]:
    """Return login events since the given time. Raises httpx.HTTPError on failure."""
    if not _ACCOUNT_ID.match(account_id):
        raise ValueError("Cloudflare account id must be 32 lowercase hex characters")
    resp = client.get(
        f"{API_BASE}/accounts/{account_id}/access/logs/access_requests",
        params={
            "since": since.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "direction": "asc",
            "limit": 1000,
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    resp.raise_for_status()
    events = []
    for item in resp.json().get("result") or []:
        if not isinstance(item, dict):
            continue
        action = "allowed" if item.get("allowed") else "denied"
        app = str(item.get("app_domain") or "-")[:200]
        fields = {"app": app, "action": action}
        for key, name in (("ip_address", "ip"), ("connection", "connection")):
            if item.get(key):
                fields[name] = str(item[key])[:100]
        # The user's email is deliberately left out of both text and fields.
        text = f"access {action} app={app} ip={fields.get('ip', '-')} via {fields.get('connection', '-')}"
        events.append(Event(source=SOURCE, file="api", ts=_ts(item.get("created_at")), text=redact(text), fields=fields))
    return events
