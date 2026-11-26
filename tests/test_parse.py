from logwatch.parse import parse_line

ACCESS = '203.0.113.9 - - [10/Oct/2026:13:55:36 +0000] "GET /.env HTTP/1.1" 404 153 "-" "curl/8.0"'


def test_combined_fields():
    e = parse_line("app", "/var/log/app/access.log", "combined", ACCESS)
    assert e.fields["status"] == "404"
    assert e.fields["path"] == "/.env"
    assert e.fields["ip"] == "203.0.113.9"
    assert e.fields["method"] == "GET"
    assert e.fields["ua"] == "curl/8.0"
    assert e.ts is not None and e.ts.year == 2026
    assert e.source == "app" and e.file == "/var/log/app/access.log"


def test_combined_strips_query():
    line = ACCESS.replace("/.env", "/login?token=abc123&next=/home")
    e = parse_line("app", "f", "combined", line)
    assert e.fields["path"] == "/login"
    assert "abc123" not in e.text
    assert all("abc123" not in v for v in e.fields.values())


def test_combined_garbage_has_no_fields():
    e = parse_line("app", "f", "combined", "\x00\x01 not an access line")
    assert e.fields == {}
    assert "not an access line" in e.text


def test_plain_never_raises():
    e = parse_line("app", "f", "plain", "}{ [[ \\ %s %d \udcff")
    assert e.fields == {}


def test_json_line():
    e = parse_line("app", "f", "json", '{"level":"error","msg":"x","status":500,"nested":{"a":1}}')
    assert e.fields["level"] == "error"
    assert e.fields["status"] == "500"
    assert "nested" not in e.fields


def test_json_invalid_falls_back():
    e = parse_line("app", "f", "json", "{not json")
    assert e.fields == {}
    assert e.text == "{not json"


def test_json_field_values_redacted():
    e = parse_line("app", "f", "json", '{"user":"someone@example.com","msg":"hi"}')
    assert "someone@example.com" not in e.text
    assert e.fields["user"] == "<email>"


def test_unknown_format_treated_as_plain():
    assert parse_line("app", "f", "weird", "hello").fields == {}


def test_uvicorn_access_line_in_a_plain_log():
    e = parse_line("mcp", "f", "plain", 'INFO uvicorn.access: x.x.x.12:54321 - "POST /mcp?session=abc HTTP/1.1" 202')
    assert (e.fields["method"], e.fields["path"], e.fields["status"]) == ("POST", "/mcp", "202")
    assert "abc" not in e.text


def test_timestamped_access_line_in_a_plain_log():
    e = parse_line("mcp", "f", "plain", '2026-11-25 07:00:01,123 INFO x.x.x.9:1 - "GET /healthz HTTP/1.1" 200 OK')
    assert (e.fields["method"], e.fields["path"], e.fields["status"]) == ("GET", "/healthz", "200")


def test_combined_line_declared_plain_is_still_parsed():
    e = parse_line("app", "f", "plain", ACCESS)
    assert e.fields["ip"] == "203.0.113.9" and e.fields["status"] == "404" and e.fields["path"] == "/.env"


def test_ordinary_plain_line_gets_no_http_fields():
    assert parse_line("app", "f", "plain", 'worker said "GET ready" 200 times').fields == {}
