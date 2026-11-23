import pytest

from logwatch.redact import redact, residual_secret_scan

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"


def test_redact_email():
    out = redact("login failed for someone@example.com from 203.0.113.9")
    assert "someone@example.com" not in out and "<email>" in out
    assert "203.0.113.9" in out  # IPs are kept for per-source counting


def test_redact_bearer():
    out = redact("upstream call with Bearer abc.DEF-123_xyz ok")
    assert "abc.DEF-123_xyz" not in out and "<token>" in out


def test_redact_jwt_anywhere():
    out = redact(f"session {JWT} started")
    assert JWT not in out and "dozjgNryP4J3" not in out


def test_redact_cookie_and_authorization_headers():
    out = redact("Cookie: sid=abc123def; theme=dark")
    assert "abc123def" not in out and "theme=dark" not in out
    out = redact("Authorization: Basic dXNlcjpwYXNz")
    assert "dXNlcjpwYXNz" not in out
    out = redact('{"set-cookie": "sid=zzz999; Path=/", "msg": "kept"}')
    assert "zzz999" not in out and "kept" in out


def test_redact_query_string():
    out = redact('GET /search?q=private+words&page=2 HTTP/1.1')
    assert "private" not in out and "/search?<query>" in out


@pytest.mark.parametrize("line", [
    "password=hunter2 rejected",
    "db secret: s3cr3tvalue",
    'config {"api_key": "k-998877"}',
    "token=abcdef012345",
])
def test_redact_key_value(line):
    out = redact(line)
    for secret in ("hunter2", "s3cr3tvalue", "k-998877", "abcdef012345"):
        assert secret not in out
    assert "<redacted>" in out


@pytest.mark.parametrize("line", [
    "login failed for someone@example.com",
    "Cookie: sid=abc123def; theme=dark",
    "GET /login?token=abc123 HTTP/1.1",
    "password=hunter2 and Bearer abc.def",
    f"jwt {JWT}",
    "plain line with nothing secret",
])
def test_redact_idempotent(line):
    once = redact(line)
    assert redact(once) == once


def test_plain_text_untouched():
    line = "worker 3 finished job 8812 in 40ms"
    assert redact(line) == line


def test_residual_scan_masks_long_token():
    tok = "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hJ6kL9m"
    out = residual_secret_scan(f"unexpected value {tok} in handler")
    assert tok not in out and "unexpected value" in out


def test_residual_scan_masks_key_prefixes():
    out = residual_secret_scan("using sk-test-000111222333444 now")
    assert "000111222333444" not in out


def test_residual_scan_leaves_ordinary_words():
    line = "configuration_reloaded_successfully_again at /var/lib/app/releases/current/config"
    assert residual_secret_scan(line) == line


def test_residual_scan_leaves_placeholders():
    line = "user <*> took <*>ms token=<redacted>"
    assert residual_secret_scan(line) == line
