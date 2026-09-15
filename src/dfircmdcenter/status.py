"""Status orchestration for the four configured DFIR platforms."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import datetime
from pathlib import Path

from dfircmdcenter.adapters.action1 import status as action1_status
from dfircmdcenter.adapters.limacharlie import status as limacharlie_status
from dfircmdcenter.adapters.splunk import status as splunk_status
from dfircmdcenter.adapters.status import StatusReport
from dfircmdcenter.adapters.velociraptor import status as velociraptor_status
from dfircmdcenter.core.records import Platform


def status_reports(
    platforms: Iterable[Platform],
    *,
    captured_at: datetime,
    fixture_root: Path | None = None,
) -> tuple[StatusReport, ...]:
    reports: list[StatusReport] = []
    for platform in platforms:
        if fixture_root is not None:
            fixture = fixture_root / platform.value / "fixtures" / "status.json"
            fixture_reader: Callable[..., StatusReport] = {
                Platform.ACTION1: action1_status.fixture_status,
                Platform.LIMACHARLIE: limacharlie_status.fixture_status,
                Platform.VELOCIRAPTOR: velociraptor_status.fixture_status,
                Platform.SPLUNK: splunk_status.fixture_status,
            }[platform]
            reports.append(fixture_reader(fixture, captured_at=captured_at))
            continue
        live_reader: Callable[..., StatusReport] = {
            Platform.ACTION1: action1_status.unavailable_live_status,
            Platform.LIMACHARLIE: limacharlie_status.unavailable_live_status,
            Platform.VELOCIRAPTOR: velociraptor_status.local_status,
            Platform.SPLUNK: splunk_status.local_status,
        }[platform]
        reports.append(live_reader(captured_at=captured_at))
    return tuple(reports)
