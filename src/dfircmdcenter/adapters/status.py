"""Bounded, redacted status records shared by platform adapters."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from dfircmdcenter.core.records import Platform, RedactionStatus, Snapshot
from dfircmdcenter.core.redaction import REDACTED, is_secret_field, redact_text
from dfircmdcenter.core.time import ensure_utc
from dfircmdcenter.core.untrusted import InjectionFinding, inspect_untrusted_text

MAX_FIXTURE_BYTES = 4 * 1024 * 1024


class StatusLevel(StrEnum):
    OK = "ok"
    DEGRADED = "degraded"
    UNKNOWN = "unknown"


class FixtureError(ValueError):
    """A fixture is malformed, ambiguous, or outside resource bounds."""


@dataclass(frozen=True, slots=True)
class PaginationResult:
    items: tuple[Mapping[str, Any], ...]
    complete: bool
    issue: str | None = None


@dataclass(frozen=True, slots=True)
class StatusReport:
    platform: Platform
    level: StatusLevel
    captured_at: datetime
    source: str
    state: Mapping[str, Any]
    unavailable: tuple[str, ...] = ()
    findings: tuple[InjectionFinding, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "captured_at", ensure_utc(self.captured_at))

    def snapshot(self) -> Snapshot:
        return Snapshot.create(
            platform=self.platform,
            scope={"status": "platform"},
            captured_at=self.captured_at,
            source_interface=self.source,
            source_version=None,
            state={
                "level": self.level,
                "inventory": self.state,
                "unavailable": self.unavailable,
                "injection_findings": [
                    {
                        "source": item.source,
                        "indicator": item.indicator,
                        "excerpt": item.excerpt,
                    }
                    for item in self.findings
                ],
            },
            redaction_status=RedactionStatus.REDACTED,
        )

    def to_mapping(self) -> Mapping[str, Any]:
        snapshot = self.snapshot()
        return {
            "platform": self.platform,
            "level": self.level,
            "captured_at": self.captured_at,
            "source": self.source,
            "state": self.state,
            "unavailable": self.unavailable,
            "injection_findings": [
                {
                    "source": item.source,
                    "indicator": item.indicator,
                    "excerpt": item.excerpt,
                }
                for item in self.findings
            ],
            "state_digest": snapshot.state_digest,
            "snapshot_digest": snapshot.snapshot_digest,
        }


def _unique_object(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FixtureError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_fixture(path: Path) -> Mapping[str, Any]:
    size = path.stat().st_size
    if size > MAX_FIXTURE_BYTES:
        raise FixtureError("fixture exceeds the configured byte limit")
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                FixtureError(f"non-finite JSON number: {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FixtureError("fixture is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise FixtureError("fixture root must be an object")
    return value


def sanitize_untrusted(value: Any, *, source: str) -> tuple[Any, tuple[InjectionFinding, ...]]:
    findings: list[InjectionFinding] = []

    def walk(item: Any, location: str, key: str | None = None) -> Any:
        if key is not None and is_secret_field(key):
            return REDACTED
        if isinstance(item, Mapping):
            return {
                str(child_key): walk(child, f"{location}.{child_key}", str(child_key))
                for child_key, child in item.items()
            }
        if isinstance(item, list):
            return [walk(child, f"{location}[{index}]") for index, child in enumerate(item)]
        if isinstance(item, str):
            inspected = inspect_untrusted_text(redact_text(item), source=f"{source}:{location}")
            findings.extend(inspected.findings)
            return inspected.text
        if item is None or isinstance(item, (bool, int, float)):
            return item
        raise FixtureError(f"unsupported fixture value at {location}")

    return walk(value, "$"), tuple(findings)


def collect_paginated(pages: object, *, source: str) -> PaginationResult:
    """Collect offset pages only when continuity and declared totals agree."""

    if not isinstance(pages, list) or not pages:
        return PaginationResult((), False, f"{source}: missing pagination pages")
    items: list[Mapping[str, Any]] = []
    declared_total: int | None = None
    expected_offset = 0
    for number, raw_page in enumerate(pages, start=1):
        if not isinstance(raw_page, dict):
            return PaginationResult(tuple(items), False, f"{source}: page {number} is malformed")
        status = raw_page.get("status", 200)
        if status in {401, 403}:
            return PaginationResult(tuple(items), False, f"{source}: permission denied ({status})")
        if status == 429:
            return PaginationResult(tuple(items), False, f"{source}: rate limited")
        if status != 200:
            return PaginationResult(tuple(items), False, f"{source}: unavailable ({status})")
        offset = raw_page.get("offset")
        total = raw_page.get("total")
        page_items = raw_page.get("items")
        if (
            not isinstance(offset, int)
            or not isinstance(total, int)
            or not isinstance(page_items, list)
        ):
            return PaginationResult(tuple(items), False, f"{source}: page {number} is malformed")
        if offset != expected_offset:
            return PaginationResult(tuple(items), False, f"{source}: pagination gap")
        if declared_total is None:
            declared_total = total
        elif total != declared_total:
            return PaginationResult(tuple(items), False, f"{source}: total changed during paging")
        if any(not isinstance(item, dict) for item in page_items):
            return PaginationResult(tuple(items), False, f"{source}: item is malformed")
        items.extend(page_items)
        expected_offset = len(items)
    if declared_total != len(items):
        return PaginationResult(tuple(items), False, f"{source}: incomplete pagination")
    return PaginationResult(tuple(items), True)


def fixture_report(
    *,
    platform: Platform,
    path: Path,
    captured_at: datetime,
    paginated_sections: Sequence[str],
    required_sections: Sequence[str],
) -> StatusReport:
    loaded = load_fixture(path)
    unavailable: list[str] = []
    inventory: dict[str, Any] = {}
    for section in required_sections:
        if section not in loaded:
            inventory[section] = "unknown"
            unavailable.append(f"{section}: missing")
        elif section in paginated_sections:
            result = collect_paginated(loaded[section], source=section)
            inventory[section] = list(result.items)
            if not result.complete:
                unavailable.append(result.issue or f"{section}: incomplete")
        else:
            inventory[section] = loaded[section]

    sanitized, findings = sanitize_untrusted(inventory, source=str(path))
    assert isinstance(sanitized, dict)
    if unavailable:
        level = StatusLevel.UNKNOWN
    elif findings:
        level = StatusLevel.DEGRADED
    else:
        level = StatusLevel.OK
    return StatusReport(
        platform=platform,
        level=level,
        captured_at=captured_at,
        source=f"fixture:{path.name}",
        state=sanitized,
        unavailable=tuple(unavailable),
        findings=findings,
    )
