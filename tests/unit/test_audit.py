from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from dfircmdcenter.core.approvals import ControlStore
from dfircmdcenter.core.audit import AuditLog, ReceiptWriter, UnsafeReceiptError, make_receipt
from dfircmdcenter.core.records import (
    ExecutionStatus,
    Platform,
    Verification,
    VerificationStatus,
)

NOW = datetime(2026, 9, 15, 16, tzinfo=UTC)


def test_audit_events_append_in_order_and_redact(tmp_path: Path) -> None:
    audit = AuditLog(ControlStore(tmp_path / "state.sqlite3"))
    audit.append(
        event_id="evt-one",
        event_type="proposal.created",
        occurred_at=NOW,
        proposal_digest="a" * 64,
        details={"password": "not-for-disk", "rule": "one"},
    )
    audit.append(
        event_id="evt-two",
        event_type="approval.recorded",
        occurred_at=NOW,
        details={"approval_id": "apr-one"},
    )

    events = audit.events()
    assert [event["event_id"] for event in events] == ["evt-one", "evt-two"]
    assert events[0]["details"]["password"] == "[REDACTED]"


def receipt(*, details: dict[str, str] | None = None):  # type: ignore[no-untyped-def]
    check = Verification(
        status=VerificationStatus.PASSED,
        checked_at=NOW,
        checks={"rule_present": True},
        summary="Verified.",
    )
    return make_receipt(
        proposal_digest="a" * 64,
        execution_id="exe-one",
        platform=Platform.LIMACHARLIE,
        operation="set_detection",
        scope={"rule": "one"},
        outcome=ExecutionStatus.VERIFIED,
        completed_at=NOW,
        verification=check,
        details=details or {"response_id": "request-one"},
    )


def test_receipt_publication_is_complete_and_exclusive(tmp_path: Path) -> None:
    writer = ReceiptWriter(tmp_path / "receipts")
    record = receipt()
    path = writer.write(record)

    assert json.loads(path.read_text(encoding="utf-8"))["receipt_id"] == record.receipt_id
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        writer.write(record)
    assert list(path.parent.glob("*.tmp")) == []


def test_receipt_refuses_secret_shaped_data(tmp_path: Path) -> None:
    writer = ReceiptWriter(tmp_path / "receipts")
    with pytest.raises(UnsafeReceiptError):
        writer.write(receipt(details={"api_key": "must-not-persist"}))
    assert list((tmp_path / "receipts").iterdir()) == []

