"""Deterministic JSON encoding and SHA-256 digests for control records."""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping, Set
from dataclasses import fields, is_dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Any

type CanonicalPath = tuple[str | int, ...]
type UnorderedPaths = set[CanonicalPath] | frozenset[CanonicalPath]


def _normalize(
    value: Any,
    *,
    path: CanonicalPath,
    unordered_paths: UnorderedPaths,
) -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("canonical JSON numbers must be finite")
        return value
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("canonical JSON timestamps must be timezone-aware")
        return value.astimezone(UTC).isoformat()
    if isinstance(value, Enum):
        return _normalize(value.value, path=path, unordered_paths=unordered_paths)
    if is_dataclass(value) and not isinstance(value, type):
        value = {field.name: getattr(value, field.name) for field in fields(value)}
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("canonical JSON object keys must be strings")
            normalized[key] = _normalize(
                item,
                path=(*path, key),
                unordered_paths=unordered_paths,
            )
        return normalized
    if isinstance(value, Set) and not isinstance(value, (str, bytes, bytearray)):
        normalized_items = [
            _normalize(item, path=(*path, index), unordered_paths=unordered_paths)
            for index, item in enumerate(value)
        ]
        return sorted(normalized_items, key=_sort_key)
    if isinstance(value, (list, tuple)):
        normalized_items = [
            _normalize(item, path=(*path, index), unordered_paths=unordered_paths)
            for index, item in enumerate(value)
        ]
        if path in unordered_paths:
            normalized_items.sort(key=_sort_key)
        return normalized_items
    raise TypeError(f"unsupported canonical JSON value: {type(value).__name__}")


def _sort_key(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_json(value: Any, *, unordered_paths: UnorderedPaths = frozenset()) -> str:
    """Encode *value* as stable UTF-8-compatible JSON.

    Sequence order is preserved unless its exact path is explicitly supplied in
    ``unordered_paths``. Sets are intrinsically unordered and are always sorted.
    """

    normalized = _normalize(value, path=(), unordered_paths=unordered_paths)
    return json.dumps(
        normalized,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def canonical_bytes(value: Any, *, unordered_paths: UnorderedPaths = frozenset()) -> bytes:
    return canonical_json(value, unordered_paths=unordered_paths).encode("utf-8")


def canonical_digest(value: Any, *, unordered_paths: UnorderedPaths = frozenset()) -> str:
    return hashlib.sha256(canonical_bytes(value, unordered_paths=unordered_paths)).hexdigest()
