"""Explicit timestamp policy for normalized Splunk CSV data."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from dfircmdcenter.core.time import SourceTimestamp, parse_source_timestamp, render_eastern


@dataclass(frozen=True, slots=True)
class TimestampPolicy:
    field: str
    source_zone: str | None = None
    fold: int | None = None
    rationale: str | None = None

    def parse(self, raw: str) -> SourceTimestamp:
        return parse_source_timestamp(
            raw,
            source_zone=self.source_zone,
            fold=self.fold,
            rationale=self.rationale,
        )


def event_range_eastern(values: list[datetime]) -> tuple[str, str]:
    if not values:
        raise ValueError("at least one event timestamp is required")
    return render_eastern(min(values)), render_eastern(max(values))

