"""Splunk index, host, and sourcetype naming governance."""

from __future__ import annotations

import re
from dataclasses import dataclass

_INDEX_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
_HOST_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_SOURCETYPE_RE = re.compile(
    r"^dfir:[a-z0-9][a-z0-9_-]*:[a-z0-9][a-z0-9_-]*:v[1-9][0-9]*$"
)


class NamingError(ValueError):
    """Splunk metadata is missing, ambiguous, or outside policy."""


@dataclass(frozen=True, slots=True)
class HostName:
    host: str
    host_raw: str | None


def validate_index(value: str, *, approved: frozenset[str] = frozenset({"dfir"})) -> str:
    if value != value.casefold() or not _INDEX_RE.fullmatch(value) or "kvstore" in value:
        raise NamingError("index must be a valid lowercase governed name")
    if value not in approved:
        raise NamingError("index is not in the approved index allowlist")
    return value


def normalize_host(value: str, *, forbidden: frozenset[str] = frozenset()) -> HostName:
    raw = value.strip().rstrip(".")
    normalized = raw.casefold()
    if not normalized or len(normalized) > 253:
        raise NamingError("host must be a non-empty FQDN or short hostname")
    labels = normalized.split(".")
    if any(not _HOST_LABEL_RE.fullmatch(label) for label in labels):
        raise NamingError("host must be a valid FQDN or short hostname")
    if normalized in {item.casefold().rstrip(".") for item in forbidden}:
        raise NamingError("host is forbidden for this ingest context")
    return HostName(host=normalized, host_raw=value if value != normalized else None)


def validate_sourcetype(value: str) -> str:
    if value != value.casefold() or not _SOURCETYPE_RE.fullmatch(value):
        raise NamingError("sourcetype must match dfir:<producer>:<schema>:v<integer>")
    return value

