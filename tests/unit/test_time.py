from __future__ import annotations

from datetime import UTC, datetime

import pytest

from dfircmdcenter.core.time import (
    AmbiguousLocalTimeError,
    NonexistentLocalTimeError,
    SourceZoneDecision,
    ensure_utc,
    parse_source_timestamp,
    render_eastern,
    resolve_eastern_local,
)


def test_internal_instants_are_normalized_to_utc_and_rendered_with_eastern_offset() -> None:
    instant = ensure_utc(datetime.fromisoformat("2026-07-04T16:00:00+00:00"))

    assert instant.tzinfo is UTC
    assert render_eastern(instant) == "2026-07-04T12:00:00-04:00"


def test_rejects_naive_instant() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        ensure_utc(datetime(2026, 1, 1, 12))


def test_rejects_nonexistent_eastern_wall_time() -> None:
    with pytest.raises(NonexistentLocalTimeError):
        resolve_eastern_local(datetime(2026, 3, 8, 2, 30))


def test_repeated_eastern_wall_time_requires_fold_and_is_distinguishable() -> None:
    repeated = datetime(2026, 11, 1, 1, 30)

    with pytest.raises(AmbiguousLocalTimeError):
        resolve_eastern_local(repeated)
    first = resolve_eastern_local(repeated, fold=0)
    second = resolve_eastern_local(repeated, fold=1)

    assert first.utcoffset().total_seconds() == -4 * 3600
    assert second.utcoffset().total_seconds() == -5 * 3600
    assert ensure_utc(first) != ensure_utc(second)


def test_source_timestamp_preserves_raw_value_and_decision() -> None:
    parsed = parse_source_timestamp("2026-09-14T13:00:00Z")

    assert parsed.raw == "2026-09-14T13:00:00Z"
    assert parsed.zone_decision is SourceZoneDecision.UTC_Z
    assert parsed.instant_utc == datetime(2026, 9, 14, 13, tzinfo=UTC)


def test_naive_source_timestamp_requires_documented_zone_decision() -> None:
    with pytest.raises(ValueError, match="source_zone"):
        parse_source_timestamp("2026-09-14T13:00:00")

    parsed = parse_source_timestamp(
        "2026-09-14T13:00:00",
        source_zone="America/New_York",
        rationale="Producer documentation states local Eastern time.",
    )
    assert parsed.zone_decision is SourceZoneDecision.ASSUMED_IANA_ZONE
    assert parsed.rationale

