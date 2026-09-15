"""Collection integrity checks that do not confuse FINISHED with complete."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from enum import IntEnum

from dfircmdcenter.core.records import Verification, VerificationStatus


class CollectionLogExit(IntEnum):
    CLEAN = 0
    TOOL_UNAVAILABLE = 1
    MISSING_OR_MALFORMED = 2


def verify_collection(
    *,
    checked_at: datetime,
    helper_exit: int,
    flow_state: str,
    table_rows: Mapping[str, int],
    upload_bytes: Mapping[str, int],
    expected_tables: tuple[str, ...],
    expected_upload_classes: tuple[str, ...],
    max_upload_bytes: int,
    truncation_detected: bool = False,
) -> Verification:
    try:
        log_result = CollectionLogExit(helper_exit)
    except ValueError:
        return Verification(
            status=VerificationStatus.UNKNOWN,
            checked_at=checked_at,
            checks={"helper_exit": helper_exit},
            summary="Collection log helper returned an undocumented exit code.",
        )
    checks = {
        "helper_exit": int(log_result),
        "flow_state": flow_state,
        "table_rows": table_rows,
        "upload_bytes": upload_bytes,
        "truncation_detected": truncation_detected,
    }
    if log_result is CollectionLogExit.TOOL_UNAVAILABLE:
        return Verification(
            status=VerificationStatus.FAILED,
            checked_at=checked_at,
            checks=checks,
            summary="One or more collection tools were unavailable.",
        )
    if log_result is CollectionLogExit.MISSING_OR_MALFORMED:
        return Verification(
            status=VerificationStatus.UNKNOWN,
            checked_at=checked_at,
            checks=checks,
            summary="Collection logs are missing or malformed.",
        )
    if flow_state != "FINISHED":
        return Verification(
            status=VerificationStatus.PARTIAL,
            checked_at=checked_at,
            checks=checks,
            summary="The exact flow has not reached FINISHED.",
        )
    if any(name not in table_rows or table_rows[name] <= 0 for name in expected_tables):
        return Verification(
            status=VerificationStatus.PARTIAL,
            checked_at=checked_at,
            checks=checks,
            summary="An expected result table is missing or has zero verified rows.",
        )
    if any(name not in upload_bytes for name in expected_upload_classes):
        return Verification(
            status=VerificationStatus.PARTIAL,
            checked_at=checked_at,
            checks=checks,
            summary="An expected upload class is missing.",
        )
    if sum(upload_bytes.values()) > max_upload_bytes or truncation_detected:
        return Verification(
            status=VerificationStatus.FAILED,
            checked_at=checked_at,
            checks=checks,
            summary="Uploads exceeded the ceiling or contain truncation.",
        )
    return Verification(
        status=VerificationStatus.PASSED,
        checked_at=checked_at,
        checks=checks,
        summary="Flow, tables, uploads, ceilings, and collection logs passed.",
    )

