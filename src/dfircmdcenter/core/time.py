"""Strict timestamp handling for evidence and local workflows."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

EASTERN_ZONE_NAME = "America/New_York"
EASTERN = ZoneInfo(EASTERN_ZONE_NAME)


class LocalTimeError(ValueError):
    """Base class for invalid local wall-clock timestamps."""


class NonexistentLocalTimeError(LocalTimeError):
    """The wall-clock time falls in a daylight-saving gap."""


class AmbiguousLocalTimeError(LocalTimeError):
    """The wall-clock time occurs twice and needs an explicit fold."""


class SourceZoneDecision(StrEnum):
    UTC_Z = "utc_z"
    EXPLICIT_OFFSET = "explicit_offset"
    ASSUMED_IANA_ZONE = "assumed_iana_zone"


@dataclass(frozen=True, slots=True)
class SourceTimestamp:
    raw: str
    instant_utc: datetime
    zone_decision: SourceZoneDecision
    source_zone: str | None = None
    fold: int | None = None
    rationale: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "instant_utc", ensure_utc(self.instant_utc))


def ensure_utc(value: datetime) -> datetime:
    """Reject naive datetimes and normalize aware instants to UTC."""

    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    normalized = value.astimezone(UTC)
    # ``astimezone(UTC)`` normally returns the UTC singleton; replace makes the
    # invariant explicit for custom zero-offset tzinfo implementations.
    return normalized.replace(tzinfo=UTC)


def _valid_local_candidates(value: datetime, zone: ZoneInfo) -> dict[int, datetime]:
    candidates: dict[int, datetime] = {}
    for fold in (0, 1):
        aware = value.replace(tzinfo=zone, fold=fold)
        round_trip = aware.astimezone(UTC).astimezone(zone)
        if round_trip.replace(tzinfo=None) == value:
            candidates[fold] = aware
    return candidates


def resolve_local(value: datetime, zone: ZoneInfo, *, fold: int | None = None) -> datetime:
    """Attach *zone* while rejecting gaps and requiring a fold for repeats."""

    if value.tzinfo is not None:
        raise ValueError("local wall-clock timestamp must be naive")
    if fold not in (None, 0, 1):
        raise ValueError("fold must be 0 or 1")

    candidates = _valid_local_candidates(value, zone)
    unique_instants = {ensure_utc(candidate) for candidate in candidates.values()}
    if not candidates:
        raise NonexistentLocalTimeError(
            f"{value.isoformat()} does not exist in {zone.key} due to a clock change"
        )
    if len(unique_instants) > 1:
        if fold is None:
            raise AmbiguousLocalTimeError(
                f"{value.isoformat()} occurs twice in {zone.key}; specify fold=0 or fold=1"
            )
        return candidates[fold]

    # An explicit fold is harmless for an ordinary wall time, but normalize it
    # to the sole actual instant rather than preserving meaningless fold state.
    return next(iter(candidates.values())).replace(fold=0)


def resolve_eastern_local(value: datetime, *, fold: int | None = None) -> datetime:
    return resolve_local(value, EASTERN, fold=fold)


def render_eastern(value: datetime) -> str:
    """Render an instant in local Eastern time with its numeric UTC offset."""

    return ensure_utc(value).astimezone(EASTERN).isoformat()


def workflow_now() -> datetime:
    """Return a UTC instant suitable for internal record storage."""

    return datetime.now(UTC)


def parse_source_timestamp(
    raw: str,
    *,
    source_zone: str | None = None,
    fold: int | None = None,
    rationale: str | None = None,
) -> SourceTimestamp:
    """Parse a source timestamp without discarding how its zone was decided."""

    if not isinstance(raw, str) or not raw.strip():
        raise ValueError("raw source timestamp must be a non-empty string")
    cleaned = raw.strip()
    try:
        parsed = datetime.fromisoformat(cleaned)
    except ValueError as exc:
        raise ValueError(f"invalid ISO 8601 source timestamp: {raw!r}") from exc

    if parsed.tzinfo is not None and parsed.utcoffset() is not None:
        decision = (
            SourceZoneDecision.UTC_Z
            if cleaned.upper().endswith("Z")
            else SourceZoneDecision.EXPLICIT_OFFSET
        )
        return SourceTimestamp(
            raw=raw,
            instant_utc=ensure_utc(parsed),
            zone_decision=decision,
            source_zone=None,
            fold=parsed.fold if decision is SourceZoneDecision.EXPLICIT_OFFSET else None,
            rationale=rationale,
        )

    if source_zone is None:
        raise ValueError("naive source timestamp requires a documented source_zone")
    if not rationale or not rationale.strip():
        raise ValueError("an assumed source_zone requires a non-empty rationale")
    try:
        zone = ZoneInfo(source_zone)
    except ZoneInfoNotFoundError as exc:
        raise ValueError(f"unknown IANA source_zone: {source_zone}") from exc
    local = resolve_local(parsed, zone, fold=fold)
    return SourceTimestamp(
        raw=raw,
        instant_utc=ensure_utc(local),
        zone_decision=SourceZoneDecision.ASSUMED_IANA_ZONE,
        source_zone=source_zone,
        fold=local.fold if len(_valid_local_candidates(parsed, zone)) > 1 else None,
        rationale=rationale.strip(),
    )

