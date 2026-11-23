from datetime import datetime, timezone

import httpx
import pytest

from logwatch.cloudflare import fetch_access_events

SINCE = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
ITEMS = [
    {"action": "login", "allowed": False, "app_domain": "dinner.example.com", "app_uid": "u1", "connection": "onetimepin",
     "created_at": "2026-01-01T12:05:00Z", "ip_address": "198.51.100.7", "ray_id": "r1", "user_email": "someone@example.com"},
    {"action": "login", "allowed": True, "app_domain": "dinner.example.com", "app_uid": "u1", "connection": "google",
     "created_at": "2026-01-01T12:06:00.123456Z", "ip_address": "198.51.100.8", "ray_id": "r2", "user_email": "family@example.com"},
]


def client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_cf_maps_fields():
    seen = {}

    def handler(request):
        seen["url"] = request.url
        seen["auth"] = request.headers["authorization"]
        return httpx.Response(200, json={"success": True, "result": ITEMS})

    events = fetch_access_events("0123456789abcdef0123456789abcdef", "TOKEN", SINCE, client(handler))
    assert seen["url"].path == "/client/v4/accounts/0123456789abcdef0123456789abcdef/access/logs/access_requests"
    assert seen["url"].params["since"] == "2026-01-01T12:00:00Z"
    assert seen["url"].params["direction"] == "asc"
    assert seen["auth"] == "Bearer TOKEN"
    assert [e.source for e in events] == ["cloudflare-access"] * 2
    assert events[0].fields == {"app": "dinner.example.com", "action": "denied", "ip": "198.51.100.7", "connection": "onetimepin"}
    assert events[1].fields["action"] == "allowed"
    assert events[0].ts == datetime(2026, 1, 1, 12, 5, tzinfo=timezone.utc)
    for e in events:
        assert "example.com" not in e.text.replace("dinner.example.com", "")
        assert "someone@" not in e.text and "family@" not in e.text


def test_cf_tolerates_missing_and_odd_fields():
    def handler(request):
        return httpx.Response(200, json={"success": True, "result": [{"allowed": False}, "junk", {"created_at": "not a date", "allowed": True}]})

    events = fetch_access_events("0123456789abcdef0123456789abcdef", "T", SINCE, client(handler))
    assert len(events) == 2
    assert events[0].fields["action"] == "denied" and events[0].fields["app"] == "-"
    assert events[1].ts is None


def test_cf_http_error_raises():
    with pytest.raises(httpx.HTTPError):
        fetch_access_events("0123456789abcdef0123456789abcdef", "T", SINCE, client(lambda r: httpx.Response(403, json={"success": False})))


def test_cf_rejects_odd_account_id():
    with pytest.raises(ValueError):
        fetch_access_events("../../zones", "T", SINCE, client(lambda r: httpx.Response(200, json={"result": []})))
