"""Bounded Action1 pagination and safe identifier handling."""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from dfircmdcenter.core.redaction import redact

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


class Action1ResponseError(RuntimeError):
    """Action1 response is denied, malformed, incomplete, or rate limited."""


@dataclass(frozen=True, slots=True)
class Action1Page:
    """One page of an Action1 list response.

    Action1 never returns an integer ``next_page``: real responses carry
    either a relative continuation URL (e.g.
    ``/API/endpoints/managed?from=60&limit=10``) or no ``next_page`` field at
    all, with ``total_items``/``limit`` left for the caller to page through
    via ``from`` offsets. ``next_page`` is kept here only as
    informational/diagnostic text, never as pagination control flow -- see
    :func:`collect_all`.
    """

    items: tuple[Mapping[str, Any], ...]
    total_items: int | None
    limit: int
    next_page: str | None = None


def safe_identifier(value: str, field: str) -> str:
    if not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{field} is not a safe configured identifier")
    return value


def managed_endpoints_path(organization_id: str) -> str:
    return f"/endpoints/managed/{safe_identifier(organization_id, 'organization_id')}"


def parse_page(body: bytes) -> Action1Page:
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Action1ResponseError("Action1 returned malformed JSON") from exc
    if not isinstance(value, dict):
        raise Action1ResponseError("Action1 page root is malformed")
    items = value.get("items")
    total = value.get("total_items")
    limit = value.get("limit")
    next_page = value.get("next_page")
    if (
        not isinstance(items, list)
        or any(not isinstance(item, dict) for item in items)
        or (total is not None and not isinstance(total, int))
        or not isinstance(limit, int)
        or limit <= 0
        or (next_page is not None and not isinstance(next_page, str))
    ):
        raise Action1ResponseError("Action1 pagination fields are malformed")
    sanitized = redact(items)
    assert isinstance(sanitized, list)
    return Action1Page(tuple(sanitized), total, limit, next_page)


def collect_all(
    fetch: Callable[[int], Action1Page],
    *,
    max_pages: int = 100,
) -> tuple[Mapping[str, Any], ...]:
    """Walk bounded ``from`` offsets, ignoring ``next_page`` for control flow.

    ``fetch`` is called with the offset ("from") of the next page to
    request, mirroring how :class:`Action1LiveClient._paginate` walks the
    real API. A page is the last one when it is empty, shorter than its own
    declared ``limit``, or the running offset reaches a declared
    ``total_items``.
    """

    items: list[Mapping[str, Any]] = []
    declared_total: int | None = None
    offset = 0
    for _ in range(max_pages):
        page = fetch(offset)
        if page.total_items is not None:
            if declared_total is None:
                declared_total = page.total_items
            elif page.total_items != declared_total:
                raise Action1ResponseError("Action1 total changed during pagination")
        items.extend(page.items)
        offset += len(page.items)
        exhausted = (
            len(page.items) == 0
            or len(page.items) < page.limit
            or (declared_total is not None and offset >= declared_total)
        )
        if exhausted:
            break
    else:
        raise Action1ResponseError("Action1 pagination loop or page limit detected")
    if declared_total is not None and len(items) != declared_total:
        raise Action1ResponseError("Action1 pagination is incomplete")
    return tuple(items)


def safe_oauth_error(status_code: int) -> Action1ResponseError:
    """Return a body-free authentication error safe for logs and receipts."""

    return Action1ResponseError(f"Action1 OAuth request failed with status {status_code}")
