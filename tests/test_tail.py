import os

import pytest

from logwatch.state import Cursor
from logwatch.tail import MAX_LINE_CHARS, read_new


def _append(path, data: bytes):
    with open(path, "ab") as f:
        f.write(data)


def test_first_sight_starts_at_end(tmp_path):
    p = tmp_path / "a.log"
    p.write_bytes(b"one\ntwo\nthree\n")
    lines, cur = read_new(str(p), None)
    assert lines == []
    assert cur == Cursor(os.stat(p).st_ino, 14)


def test_reads_appended_lines(tmp_path):
    p = tmp_path / "a.log"
    p.write_bytes(b"old\n")
    _, cur = read_new(str(p), None)
    _append(p, b"new1\nnew2\n")
    lines, cur2 = read_new(str(p), cur)
    assert lines == ["new1", "new2"]
    assert read_new(str(p), cur2)[0] == []


def test_partial_line_held_back(tmp_path):
    p = tmp_path / "a.log"
    p.write_bytes(b"")
    _, cur = read_new(str(p), None)
    _append(p, b"abc")
    lines, cur = read_new(str(p), cur)
    assert lines == []
    _append(p, b"\n")
    lines, cur = read_new(str(p), cur)
    assert lines == ["abc"]


def test_rotation_reads_old_tail_then_new(tmp_path):
    p = tmp_path / "a.log"
    p.write_bytes(b"seen\n")
    _, cur = read_new(str(p), None)
    _append(p, b"old-tail\n")
    os.rename(p, tmp_path / "a.log.1")
    p.write_bytes(b"new-1\nnew-2\n")
    lines, cur = read_new(str(p), cur)
    assert lines == ["old-tail", "new-1", "new-2"]
    assert cur.inode == os.stat(p).st_ino
    assert read_new(str(p), cur)[0] == []


def test_rotation_without_old_file(tmp_path):
    p = tmp_path / "a.log"
    p.write_bytes(b"seen\n")
    _, cur = read_new(str(p), None)
    os.remove(p)
    (tmp_path / "other").write_bytes(b"x")  # make inode reuse less likely
    p.write_bytes(b"fresh\n")
    if os.stat(p).st_ino == cur.inode:
        pytest.skip("filesystem reused the inode")
    assert read_new(str(p), cur)[0] == ["fresh"]


def test_truncation_restarts_at_zero(tmp_path):
    p = tmp_path / "a.log"
    p.write_bytes(b"a long first line\n")
    _, cur = read_new(str(p), None)
    with open(p, "wb") as f:  # truncate in place, same inode
        f.write(b"short\n")
    assert read_new(str(p), cur)[0] == ["short"]


def test_invalid_utf8_replaced(tmp_path):
    p = tmp_path / "a.log"
    p.write_bytes(b"")
    _, cur = read_new(str(p), None)
    _append(p, b"\xff\xfeok\n")
    lines, _ = read_new(str(p), cur)
    assert len(lines) == 1 and "ok" in lines[0]


def test_long_line_truncated(tmp_path):
    p = tmp_path / "a.log"
    p.write_bytes(b"")
    _, cur = read_new(str(p), None)
    _append(p, b"x" * 3_000_000 + b"\nafter\n")
    lines, _ = read_new(str(p), cur)
    assert len(lines[0]) == MAX_LINE_CHARS
    assert lines[1] == "after"


def test_cap_then_catch_up(tmp_path):
    p = tmp_path / "a.log"
    p.write_bytes(b"")
    _, cur = read_new(str(p), None)
    n = 120_000
    with open(p, "ab") as f:
        for i in range(n):
            f.write(b"line %09d %s\n" % (i, b"p" * 84))  # 100 bytes per line, 12 MB total
    got = []
    calls = 0
    while True:
        lines, cur = read_new(str(p), cur, max_bytes=5_000_000)
        if not lines:
            break
        calls += 1
        got.extend(lines)
    assert calls == 3
    assert len(got) == n
    assert got[0].startswith("line 000000000") and got[-1].startswith("line %09d" % (n - 1))


def test_single_line_longer_than_cap_is_not_stuck(tmp_path):
    p = tmp_path / "a.log"
    p.write_bytes(b"")
    _, cur = read_new(str(p), None)
    _append(p, b"y" * 20_000 + b"\nnext\n")
    lines, cur = read_new(str(p), cur, max_bytes=1_000)
    assert len(lines) >= 1 and len(lines[0]) == MAX_LINE_CHARS
    lines2, _ = read_new(str(p), cur, max_bytes=1_000)
    assert (lines + lines2)[-1] == "next"


def test_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        read_new(str(tmp_path / "nope.log"), None)
