"""Read-only LimaCharlie detection inventory status."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from dfircmdcenter.adapters.status import StatusLevel, StatusReport, fixture_report
from dfircmdcenter.core.records import Platform

_SECTIONS = ("identity", "rules")


def fixture_status(path: Path, *, captured_at: datetime) -> StatusReport:
    return fixture_report(
        platform=Platform.LIMACHARLIE,
        path=path,
        captured_at=captured_at,
        paginated_sections=("rules",),
        required_sections=_SECTIONS,
    )


def unavailable_live_status(*, captured_at: datetime) -> StatusReport:
    return StatusReport(
        platform=Platform.LIMACHARLIE,
        level=StatusLevel.UNKNOWN,
        captured_at=captured_at,
        source="live:limacharlie",
        state={"identity": "unknown", "rules": "unknown"},
        unavailable=("credentialed LimaCharlie status is not configured; no credential was read",),
    )

