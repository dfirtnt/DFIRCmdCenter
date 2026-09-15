"""Validation for Splunk-specific immutable receipt details."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class IngestVerification:
    expected_events: int
    indexed_events: int
    index: str
    host: str
    source: str
    sourcetype: str
    observed_license_bytes: int | None
    time_range_eastern: tuple[str, str]

    @property
    def complete(self) -> bool:
        return (
            self.expected_events == self.indexed_events
            and self.observed_license_bytes is not None
        )

    def as_details(self) -> Mapping[str, Any]:
        return {
            "expected_events": self.expected_events,
            "indexed_events": self.indexed_events,
            "index": self.index,
            "host": self.host,
            "source": self.source,
            "sourcetype": self.sourcetype,
            "observed_license_bytes": self.observed_license_bytes,
            "time_range_eastern": self.time_range_eastern,
            "complete": self.complete,
        }
