import json

import httpx

from logwatch.notify import HomeAssistantNotifier, MemoryNotifier, enqueue, flush
from logwatch.state import State


def _state(tmp_path):
    return State(tmp_path / "s.db")


def test_flush_delivers_in_order(tmp_path):
    s, n = _state(tmp_path), MemoryNotifier()
    enqueue(s, "t1", "m1", "high")
    enqueue(s, "t2", "m2", "low")
    assert flush(s, n) == 2
    assert n.sent == [("t1", "m1", "high"), ("t2", "m2", "low")]
    assert s.outbox_pending() == []


def test_failure_keeps_message(tmp_path):
    s, n = _state(tmp_path), MemoryNotifier(fail=True)
    enqueue(s, "t1", "m1", "high")
    assert flush(s, n) == 0
    assert len(s.outbox_pending()) == 1


def test_recovery_sends_once(tmp_path):
    s, n = _state(tmp_path), MemoryNotifier(fail=True)
    enqueue(s, "t1", "m1", "high")
    enqueue(s, "t2", "m2", "high")
    flush(s, n)
    n.fail = False
    assert flush(s, n) == 2
    assert flush(s, n) == 0
    assert [t for t, _, _ in n.sent] == ["t1", "t2"]


def test_stops_at_first_failure_preserving_order(tmp_path):
    s = _state(tmp_path)

    class Flaky:
        def __init__(self):
            self.sent = []

        def send(self, title, message, severity):
            if title == "t2" and "t2-ok" not in self.sent:
                self.sent.append("t2-ok")
                return False
            self.sent.append(title)
            return True

    n = Flaky()
    for t in ("t1", "t2", "t3"):
        enqueue(s, t, "m", "low")
    assert flush(s, n) == 1
    assert [p[1] for p in s.outbox_pending()] == ["t2", "t3"]


def test_notifier_exception_counts_as_failure(tmp_path):
    s = _state(tmp_path)

    class Boom:
        def send(self, *a):
            raise RuntimeError("x")

    enqueue(s, "t", "m", "low")
    assert flush(s, Boom()) == 0
    assert len(s.outbox_pending()) == 1


def test_message_truncated_to_1000_chars(tmp_path):
    s, n = _state(tmp_path), MemoryNotifier()
    enqueue(s, "T" * 500, "m" * 5000, "low")
    flush(s, n)
    title, message, _ = n.sent[0]
    assert len(message) == 1000 and len(title) == 120


def test_ha_payload_shape():
    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        seen["auth"] = request.headers.get("authorization")
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json=[])

    n = HomeAssistantNotifier("http://ha.example:8123", "TOKEN123", "mobile_app_phone",
                              http_client=httpx.Client(transport=httpx.MockTransport(handler)))
    assert n.send("Service down", "dinner-app stopped", "high") is True
    assert seen["url"] == "http://ha.example:8123/api/services/notify/mobile_app_phone"
    assert seen["auth"] == "Bearer TOKEN123"
    assert seen["body"]["title"] == "[high] Service down"
    assert seen["body"]["message"] == "dinner-app stopped"
    assert "TOKEN123" not in json.dumps(seen["body"])


def test_ha_error_returns_false():
    n = HomeAssistantNotifier("http://ha.example:8123", "T", "svc",
                              http_client=httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(401))))
    assert n.send("t", "m", "low") is False

    def boom(request):
        raise httpx.ConnectError("unreachable")

    n = HomeAssistantNotifier("http://ha.example:8123", "T", "svc",
                              http_client=httpx.Client(transport=httpx.MockTransport(boom)))
    assert n.send("t", "m", "low") is False
