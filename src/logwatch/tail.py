"""Read new complete lines from a log file, surviving rotation and truncation."""
from __future__ import annotations

import os

from .state import Cursor

MAX_LINE_CHARS = 4000
_HEAD_BYTES = MAX_LINE_CHARS * 4  # enough bytes to fill MAX_LINE_CHARS even with 4-byte characters


def _decode(raw: bytes) -> str:
    return raw.decode("utf-8", errors="replace").rstrip("\r")[:MAX_LINE_CHARS]


def _read_from(path: str, offset: int, max_bytes: int) -> tuple[list[str], int]:
    """Return complete lines starting at offset and the offset after the last one."""
    with open(path, "rb") as f:
        f.seek(offset)
        data = f.read(max_bytes)
        end = data.rfind(b"\n")
        if end != -1:
            return [_decode(line) for line in data[: end + 1].split(b"\n")[:-1]], offset + end + 1
        if len(data) < max_bytes:
            return [], offset  # partial line, wait for the newline
        # One line longer than the cap: keep its head, skip to its end.
        head = data[:_HEAD_BYTES]
        consumed = len(data)
        while True:
            chunk = f.read(65536)
            if not chunk:
                return [], offset  # still being written
            if len(head) < _HEAD_BYTES:
                head += chunk[: _HEAD_BYTES - len(head)]
            i = chunk.find(b"\n")
            if i != -1:
                nl = head.find(b"\n")
                if nl != -1:
                    head = head[:nl]
                return [_decode(head)], offset + consumed + i + 1
            consumed += len(chunk)


def read_new(path: str, cursor: Cursor | None, max_bytes: int = 5_000_000) -> tuple[list[str], Cursor]:
    st = os.stat(path)
    if cursor is None:
        return [], Cursor(st.st_ino, st.st_size)  # first sight: start at the end, no backlog

    lines: list[str] = []
    if cursor.inode != st.st_ino:
        rotated = path + ".1"
        try:
            if os.stat(rotated).st_ino == cursor.inode:
                lines, _ = _read_from(rotated, cursor.offset, max_bytes)
        except OSError:
            pass
        offset = 0
    elif st.st_size < cursor.offset:
        offset = 0  # truncated in place
    else:
        offset = cursor.offset

    new_lines, new_offset = _read_from(path, offset, max_bytes)
    return lines + new_lines, Cursor(st.st_ino, new_offset)
