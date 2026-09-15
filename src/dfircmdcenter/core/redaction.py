"""Conservative redaction for data that may be persisted or displayed."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import fields, is_dataclass
from typing import Any

REDACTED = "[REDACTED]"

_SECRET_KEYS = frozenset(
    {
        "accesstoken",
        "apikey",
        "apitoken",
        "authorization",
        "clientsecret",
        "cookie",
        "credential",
        "password",
        "passwd",
        "passphrase",
        "privatekey",
        "proxyauthorization",
        "recoverycode",
        "refreshtoken",
        "secret",
        "secretkey",
        "setcookie",
        "signingkey",
        "token",
    }
)

_TEXT_PATTERNS = (
    re.compile(r"(?i)(\b(?:authorization|proxy-authorization)\s*:\s*(?:bearer|basic)\s+)[^\s,;]+"),
    re.compile(
        r"(?i)(\b(?:api[_-]?key|api[_-]?token|access[_-]?token|refresh[_-]?token|"
        r"client[_-]?secret|password|passwd|passphrase)\s*[=:]\s*)"
        r"(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
    ),
)


def _normalized_key(key: object) -> str:
    return re.sub(r"[^a-z0-9]", "", str(key).casefold())


def is_secret_field(key: object) -> bool:
    return _normalized_key(key) in _SECRET_KEYS


def redact_text(value: str) -> str:
    redacted = value
    for pattern in _TEXT_PATTERNS:
        redacted = pattern.sub(lambda match: f"{match.group(1)}{REDACTED}", redacted)
    return redacted


def redact(value: Any) -> Any:
    """Return a JSON-like copy with secret fields and token text redacted."""

    if is_dataclass(value) and not isinstance(value, type):
        value = {field.name: getattr(value, field.name) for field in fields(value)}
    if isinstance(value, Mapping):
        return {
            key: REDACTED if is_secret_field(key) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, tuple):
        return tuple(redact(item) for item in value)
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return type(value)(redact(item) for item in value)
    if isinstance(value, str):
        return redact_text(value)
    return value


def contains_secret_fields(value: Any) -> bool:
    if is_dataclass(value) and not isinstance(value, type):
        value = {field.name: getattr(value, field.name) for field in fields(value)}
    if isinstance(value, Mapping):
        return any(
            is_secret_field(key) or contains_secret_fields(item)
            for key, item in value.items()
        )
    if isinstance(value, (list, tuple, set, frozenset)):
        return any(contains_secret_fields(item) for item in value)
    if isinstance(value, str):
        return redact_text(value) != value
    return False

