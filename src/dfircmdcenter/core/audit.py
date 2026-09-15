"""Append-only audit events and atomically published execution receipts."""

from __future__ import annotations

import os
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

from .approvals import ControlStore
from .canonical import canonical_bytes, canonical_digest
from .records import ExecutionStatus, Platform, Receipt, Verification
from .redaction import contains_secret_fields


class UnsafeReceiptError(ValueError):
    """A receipt contained a secret-shaped field or value."""


class AuditLog:
    def __init__(self, store: ControlStore) -> None:
        self.store = store

    def append(
        self,
        *,
        event_id: str,
        event_type: str,
        occurred_at: datetime,
        details: Mapping[str, Any],
        execution_id: str | None = None,
        proposal_digest: str | None = None,
    ) -> None:
        self.store.append_audit_event(
            event_id=event_id,
            event_type=event_type,
            occurred_at=occurred_at,
            details=details,
            execution_id=execution_id,
            proposal_digest=proposal_digest,
        )

    def events(self) -> list[Mapping[str, Any]]:
        return self.store.audit_events()


def make_receipt(
    *,
    proposal_digest: str,
    execution_id: str,
    platform: Platform,
    operation: str,
    scope: Mapping[str, Any],
    outcome: ExecutionStatus,
    completed_at: datetime,
    verification: Verification,
    details: Mapping[str, Any],
) -> Receipt:
    material = {
        "proposal_digest": proposal_digest,
        "execution_id": execution_id,
        "platform": platform,
        "operation": operation,
        "scope": scope,
        "outcome": outcome,
        "completed_at": completed_at,
        "verification": verification,
        "details": details,
    }
    return Receipt(
        receipt_id=f"rcp-{canonical_digest(material)[:16]}",
        proposal_digest=proposal_digest,
        execution_id=execution_id,
        platform=platform,
        operation=operation,
        scope=scope,
        outcome=outcome,
        completed_at=completed_at,
        verification=verification,
        details=details,
    )


class ReceiptWriter:
    """Write complete receipts with an exclusive, atomic final publication."""

    def __init__(self, receipt_directory: Path) -> None:
        self.receipt_directory = receipt_directory
        receipt_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(receipt_directory, 0o700)

    def write(self, receipt: Receipt) -> Path:
        if contains_secret_fields(receipt):
            raise UnsafeReceiptError("receipt contains secret-shaped data")
        payload = canonical_bytes(receipt) + b"\n"
        final_path = self.receipt_directory / f"{receipt.receipt_id}.json"
        temporary_path = self.receipt_directory / (
            f".{receipt.receipt_id}.{os.getpid()}.{os.urandom(4).hex()}.tmp"
        )

        descriptor = os.open(temporary_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            # Hard-link publication is atomic and refuses to replace an existing receipt.
            os.link(temporary_path, final_path)
            directory_fd = os.open(self.receipt_directory, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            temporary_path.unlink(missing_ok=True)
        return final_path

