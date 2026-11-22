"""Mask secrets and personal data. Runs before rules, clustering, storage, and model calls.

IP addresses are deliberately kept: rules count activity per source address.
"""
from __future__ import annotations

import re

_HEADER = re.compile(r"""(?i)\b(authorization|set-cookie|cookie)\b(["']?\s*[:=]\s*)("[^"]*"|[^\n]*)""")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
_BEARER = re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]+")
_QUERY = re.compile(r"""(?<=[^\s?])\?[^\s"'<>]+""")
_KV = re.compile(
    r"""(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|key)"""
    r"""(["']?\s*[=:]\s*["']?)([^\s"'&,;<>]+)"""
)
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

_KEY_PREFIX = re.compile(r"\b(?:sk|pk|rk|ghp|gho|ghs|glpat|xox[abprs])[-_][-_A-Za-z0-9]{10,}|\bAKIA[A-Z0-9]{12,}")
_LONG_TOKEN = re.compile(r"[A-Za-z0-9+/_=-]{24,}")
_HEX = re.compile(r"[0-9a-fA-F]{32,}")


def redact(text: str) -> str:
    text = _HEADER.sub(r"\1\2<redacted>", text)
    text = _JWT.sub("<token>", text)
    text = _BEARER.sub(r"\1 <token>", text)
    text = _QUERY.sub("?<query>", text)
    text = _KV.sub(r"\1\2<redacted>", text)
    text = _EMAIL.sub("<email>", text)
    return text


def _looks_secret(token: str) -> bool:
    if _HEX.fullmatch(token):
        return True
    return (
        any(c.isdigit() for c in token)
        and any(c.islower() for c in token)
        and any(c.isupper() for c in token)
        and len(set(token)) >= 10
    )


def residual_secret_scan(text: str) -> str:
    """Second pass before text leaves the box: mask key-like and high-entropy tokens."""
    text = _KEY_PREFIX.sub("<secret>", text)
    return _LONG_TOKEN.sub(lambda m: "<secret>" if _looks_secret(m.group(0)) else m.group(0), text)
