"""Splunk Free operational-ceiling calculations."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from dfircmdcenter.core.time import EASTERN, ensure_utc

OPERATIONAL_CEILING_BYTES = 400_000_000
HARD_LICENSE_BYTES = 500_000_000


@dataclass(frozen=True, slots=True)
class BudgetDecision:
    allowed: bool
    license_day: str
    measured_bytes: int | None
    pending_bytes: int
    competing_bytes: int | None
    proposed_bytes: int
    projected_bytes: int | None
    remaining_operational_bytes: int | None
    reason: str


def evaluate_budget(
    *,
    now: datetime,
    measured_bytes: int | None,
    pending_bytes: int,
    competing_bytes: int | None,
    proposed_bytes: int,
    measurement_complete: bool,
    reset_boundary_confirmed: bool,
) -> BudgetDecision:
    values = (pending_bytes, proposed_bytes)
    if any(value < 0 for value in values) or (
        measured_bytes is not None and measured_bytes < 0
    ) or (competing_bytes is not None and competing_bytes < 0):
        raise ValueError("budget byte counts must be non-negative")
    day = ensure_utc(now).astimezone(EASTERN).date().isoformat()
    if (
        measured_bytes is None
        or competing_bytes is None
        or not measurement_complete
        or not reset_boundary_confirmed
    ):
        return BudgetDecision(
            False,
            day,
            measured_bytes,
            pending_bytes,
            competing_bytes,
            proposed_bytes,
            None,
            None,
            "usage, competing-input, measurement, or reset-boundary state is unknown",
        )
    projected = measured_bytes + pending_bytes + competing_bytes + proposed_bytes
    remaining = OPERATIONAL_CEILING_BYTES - projected
    return BudgetDecision(
        projected <= OPERATIONAL_CEILING_BYTES,
        day,
        measured_bytes,
        pending_bytes,
        competing_bytes,
        proposed_bytes,
        projected,
        remaining,
        (
            "within the operational ceiling"
            if projected <= OPERATIONAL_CEILING_BYTES
            else "projected bytes exceed the operational ceiling"
        ),
    )

