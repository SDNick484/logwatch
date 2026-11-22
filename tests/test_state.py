from datetime import datetime, timedelta, timezone

from logwatch.events import Finding
from logwatch.state import Cursor, State

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def _state(tmp_path):
    return State(tmp_path / "s.db")


def test_cursor_roundtrip(tmp_path):
    s = _state(tmp_path)
    assert s.get_cursor("/var/log/a.log") is None
    s.set_cursor("/var/log/a.log", Cursor(inode=7, offset=42))
    assert s.get_cursor("/var/log/a.log") == Cursor(7, 42)
    s.set_cursor("/var/log/a.log", Cursor(8, 0))
    assert s.get_cursor("/var/log/a.log") == Cursor(8, 0)


def test_alert_dedupe(tmp_path):
    s = _state(tmp_path)
    assert s.open_alert("svc:a:down", "high", "t", "m", NOW) is True
    assert s.open_alert("svc:a:down", "high", "t", "m", NOW) is False
    assert s.open_alert("svc:b:down", "high", "t", "m", NOW) is True


def test_alert_clear_then_reopen(tmp_path):
    s = _state(tmp_path)
    s.open_alert("k", "high", "t", "m", NOW)
    assert s.clear_alert("k", NOW) is True
    assert s.clear_alert("k", NOW) is False
    assert s.open_alert("k", "high", "t", "m", NOW) is True


def test_open_alerts_listing(tmp_path):
    s = _state(tmp_path)
    s.open_alert("a", "low", "t", "m", NOW)
    s.open_alert("b", "high", "t", "m", NOW)
    s.clear_alert("a", NOW)
    assert s.open_alerts() == [("b", "high")]


def test_count_events_window(tmp_path):
    s = _state(tmp_path)
    s.record_event("app", "down", NOW - timedelta(minutes=30))
    s.record_event("app", "down", NOW - timedelta(minutes=5))
    s.record_event("app", "down", NOW - timedelta(minutes=1))
    s.record_event("other", "down", NOW)
    s.record_event("app", "respawn", NOW)
    assert s.count_events("app", "down", NOW - timedelta(minutes=10)) == 2


def test_findings_roundtrip_and_window(tmp_path):
    s = _state(tmp_path)
    f = Finding("path-scanning", "medium", "app", "203.0.113.9", 300, "scan", ("a", "b"))
    s.add_findings([f], NOW - timedelta(days=2))
    s.add_findings([f], NOW)
    assert s.findings_since(NOW - timedelta(hours=1)) == [f]


def test_outbox_order_and_done(tmp_path):
    s = _state(tmp_path)
    a = s.outbox_put("t1", "m1", "high")
    b = s.outbox_put("t2", "m2", "low")
    assert s.outbox_pending() == [(a, "t1", "m1", "high"), (b, "t2", "m2", "low")]
    s.outbox_done(a)
    assert s.outbox_pending() == [(b, "t2", "m2", "low")]


def test_kv(tmp_path):
    s = _state(tmp_path)
    assert s.get_kv("pid:app") is None
    s.set_kv("pid:app", "123")
    s.set_kv("pid:app", "456")
    assert s.get_kv("pid:app") == "456"


def test_reopen_db_persists(tmp_path):
    s = _state(tmp_path)
    s.set_cursor("/x", Cursor(1, 2))
    s.open_alert("k", "high", "t", "m", NOW)
    s.close()
    s2 = _state(tmp_path)
    assert s2.get_cursor("/x") == Cursor(1, 2)
    assert s2.open_alert("k", "high", "t", "m", NOW) is False


def test_bulk_remainder_insert_is_one_transaction(tmp_path):
    import time

    from logwatch.events import Event

    s = _state(tmp_path)
    events = [Event("app", "f", None, f"line {i}", {"path": "/x"}) for i in range(20_000)]
    start = time.perf_counter()
    s.add_remainder(events)
    took = time.perf_counter() - start
    back = s.take_remainder()
    assert len(back) == 20_000 and back[0].text == "line 0" and back[0].fields == {"path": "/x"}
    assert s.take_remainder() == []
    assert took < 2.0, f"bulk insert took {took:.1f}s"
