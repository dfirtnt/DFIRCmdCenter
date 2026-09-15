"""Action1 install verification plus fresh Velociraptor check-in."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from dfircmdcenter.core.records import Verification, VerificationStatus
from dfircmdcenter.core.time import ensure_utc

UNSIGNED_SUBJECT_CODE = "0x800B0100"


@dataclass(frozen=True, slots=True)
class Action1InstallState:
    operation_status: str
    installed: bool
    installed_version: str | None
    warning_codes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class VelociraptorCheckin:
    client_id: str
    observed_at: datetime
    identity_correlated: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "observed_at", ensure_utc(self.observed_at))


def verify_deployment(
    *,
    checked_at: datetime,
    expected_version: str,
    expected_client_id: str,
    deployment_started_at: datetime,
    checkin_window: timedelta,
    action1: Action1InstallState,
    velociraptor: VelociraptorCheckin | None,
) -> Verification:
    checked = ensure_utc(checked_at)
    started = ensure_utc(deployment_started_at)
    unsigned_warning = UNSIGNED_SUBJECT_CODE in action1.warning_codes
    checks = {
        "action1_operation_status": action1.operation_status,
        "action1_installed": action1.installed,
        "installed_version": action1.installed_version,
        "unsigned_installer_warning_preserved": unsigned_warning,
        "velociraptor_client_id": None if velociraptor is None else velociraptor.client_id,
        "velociraptor_checkin_at": None if velociraptor is None else velociraptor.observed_at,
        "identity_correlated": (
            False if velociraptor is None else velociraptor.identity_correlated
        ),
    }
    if not action1.installed or action1.installed_version != expected_version:
        return Verification(
            status=VerificationStatus.FAILED,
            checked_at=checked,
            checks=checks,
            summary="Action1 does not confirm the exact expected installed version.",
        )
    if velociraptor is None:
        return Verification(
            status=VerificationStatus.PARTIAL,
            checked_at=checked,
            checks=checks,
            summary="Action1 install succeeded but no matching Velociraptor check-in exists.",
        )
    fresh = started <= velociraptor.observed_at <= started + checkin_window
    if (
        velociraptor.client_id != expected_client_id
        or not velociraptor.identity_correlated
        or not fresh
    ):
        return Verification(
            status=VerificationStatus.PARTIAL,
            checked_at=checked,
            checks={**checks, "checkin_fresh": fresh},
            summary="Velociraptor check-in identity or freshness did not verify.",
        )
    return Verification(
        status=VerificationStatus.PASSED,
        checked_at=checked,
        checks={**checks, "checkin_fresh": True},
        summary=(
            "Exact Action1 installation and fresh correlated Velociraptor check-in verified; "
            "the unsigned-installer warning remains recorded."
        ),
    )

