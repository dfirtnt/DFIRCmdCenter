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
    items: tuple[Mapping[str, Any], ...]
    total_items: int
    limit: int
    next_page: int | None


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
        or not isinstance(total, int)
        or not isinstance(limit, int)
        or limit <= 0
        or (next_page is not None and not isinstance(next_page, int))
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
    page_number = 0
    seen_pages: set[int] = set()
    items: list[Mapping[str, Any]] = []
    declared_total: int | None = None
    while True:
        if page_number in seen_pages or len(seen_pages) >= max_pages:
            raise Action1ResponseError("Action1 pagination loop or page limit detected")
        seen_pages.add(page_number)
        page = fetch(page_number)
        if declared_total is None:
            declared_total = page.total_items
        elif page.total_items != declared_total:
            raise Action1ResponseError("Action1 total changed during pagination")
        items.extend(page.items)
        if page.next_page is None:
            break
        page_number = page.next_page
    if len(items) != declared_total:
        raise Action1ResponseError("Action1 pagination is incomplete")
    return tuple(items)


def safe_oauth_error(status_code: int) -> Action1ResponseError:
    """Return a body-free authentication error safe for logs and receipts."""

    return Action1ResponseError(f"Action1 OAuth request failed with status {status_code}")
