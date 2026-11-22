"""Notifications with a durable outbox, so an unreachable notifier never loses an alert."""
from __future__ import annotations

from typing import Protocol

import httpx

from .state import State

MAX_TITLE_CHARS = 120
MAX_MESSAGE_CHARS = 1000


class Notifier(Protocol):
    def send(self, title: str, message: str, severity: str) -> bool: ...


class HomeAssistantNotifier:
    def __init__(self, base_url: str, token: str, service: str, http_client: httpx.Client | None = None):
        self._url = f"{base_url.rstrip('/')}/api/services/notify/{service}"
        self._token = token
        self._http = http_client or httpx.Client(timeout=10.0)

    def send(self, title: str, message: str, severity: str) -> bool:
        try:
            resp = self._http.post(
                self._url,
                headers={"Authorization": f"Bearer {self._token}"},
                json={"title": f"[{severity}] {title}", "message": message},
            )
            return resp.status_code < 300
        except httpx.HTTPError:
            return False


class MemoryNotifier:
    """Test double and replay sink."""

    def __init__(self, fail: bool = False):
        self.fail = fail
        self.sent: list[tuple[str, str, str]] = []

    def send(self, title: str, message: str, severity: str) -> bool:
        if self.fail:
            return False
        self.sent.append((title, message, severity))
        return True


def enqueue(state: State, title: str, message: str, severity: str) -> None:
    state.outbox_put(title[:MAX_TITLE_CHARS], message[:MAX_MESSAGE_CHARS], severity)


def flush(state: State, notifier: Notifier) -> int:
    """Deliver pending messages in order. Stops at the first failure; returns the number delivered."""
    delivered = 0
    for id_, title, message, severity in state.outbox_pending():
        try:
            ok = notifier.send(title, message, severity)
        except Exception:  # noqa: BLE001 - a broken notifier must not lose the message
            ok = False
        if not ok:
            break
        state.outbox_done(id_)
        delivered += 1
    return delivered
