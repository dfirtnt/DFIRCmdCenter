"""Read-only Action1 inventory status."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from dfircmdcenter.adapters.status import StatusLevel, StatusReport, fixture_report
from dfircmdcenter.core.records import Platform

_SECTIONS = ("identity", "organizations", "endpoints", "packages", "automations", "deployments")
_PAGINATED = ("organizations", "endpoints", "packages", "automations", "deployments")


def fixture_status(path: Path, *, captured_at: datetime) -> StatusReport:
    return fixture_report(
        platform=Platform.ACTION1,
        path=path,
        captured_at=captured_at,
        paginated_sections=_PAGINATED,
        required_sections=_SECTIONS,
    )


def unavailable_live_status(*, captured_at: datetime) -> StatusReport:
    return StatusReport(
        platform=Platform.ACTION1,
        level=StatusLevel.UNKNOWN,
        captured_at=captured_at,
        source="live:action1",
        state={"identity": "unknown"},
        unavailable=(
            "credentialed Action1 status is not configured; no credential was read",
            "package, automation, and deployment-history API surfaces remain contract-disabled",
        ),
    )

