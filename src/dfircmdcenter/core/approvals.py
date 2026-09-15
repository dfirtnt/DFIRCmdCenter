"""Transactional private state for proposals, approvals, and executions."""

from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .canonical import canonical_json
from .records import Approval, ExecutionStatus, Proposal
from .redaction import redact
from .time import ensure_utc


class ApprovalError(RuntimeError):
    """Base class for approval interlock failures."""


class MissingApprovalError(ApprovalError):
    """The requested approval does not exist."""


class ExpiredApprovalError(ApprovalError):
    """The requested approval is no longer valid."""


class ApprovalDigestMismatchError(ApprovalError):
    """The approval is bound to a different proposal."""


class ConsumedApprovalError(ApprovalError):
    """The approval was already used."""


class FabricatedApprovalError(ApprovalError):
    """The approval identifier is inconsistent with its material fields."""


class UnknownProposalError(ApprovalError):
    """An approval or execution referred to an unregistered proposal."""


class TargetLockedError(ApprovalError):
    """Another execution already owns the exact target lock."""


class InvalidTransitionError(RuntimeError):
    """An execution state transition violated the common state machine."""


@dataclass(frozen=True, slots=True)
class StoredExecution:
    execution_id: str
    proposal_digest: str
    approval_id: str
    platform: str
    operation: str
    scope: Mapping[str, Any]
    target_key: str
    status: ExecutionStatus
    started_at: datetime
    updated_at: datetime
    details: Mapping[str, Any]


_TRANSITIONS: Mapping[ExecutionStatus, frozenset[ExecutionStatus]] = {
    ExecutionStatus.PLANNED: frozenset({ExecutionStatus.APPROVED, ExecutionStatus.FAILED}),
    ExecutionStatus.APPROVED: frozenset({ExecutionStatus.RESERVED, ExecutionStatus.FAILED}),
    ExecutionStatus.RESERVED: frozenset({ExecutionStatus.REVALIDATED, ExecutionStatus.FAILED}),
    ExecutionStatus.REVALIDATED: frozenset({ExecutionStatus.SUBMITTING, ExecutionStatus.FAILED}),
    ExecutionStatus.SUBMITTING: frozenset(
        {ExecutionStatus.SUBMITTED, ExecutionStatus.FAILED, ExecutionStatus.UNKNOWN}
    ),
    ExecutionStatus.SUBMITTED: frozenset(
        {ExecutionStatus.VERIFYING, ExecutionStatus.FAILED, ExecutionStatus.UNKNOWN}
    ),
    ExecutionStatus.VERIFYING: frozenset(
        {
            ExecutionStatus.VERIFIED,
            ExecutionStatus.FAILED,
            ExecutionStatus.PARTIAL,
            ExecutionStatus.UNKNOWN,
        }
    ),
    # Unknown outcomes may be reconciled with reads, but never resubmitted.
    ExecutionStatus.UNKNOWN: frozenset({ExecutionStatus.VERIFYING}),
    ExecutionStatus.VERIFIED: frozenset(),
    ExecutionStatus.FAILED: frozenset(),
    ExecutionStatus.PARTIAL: frozenset(),
}

_TERMINAL = frozenset(
    {ExecutionStatus.VERIFIED, ExecutionStatus.FAILED, ExecutionStatus.PARTIAL}
)


def _iso(value: datetime) -> str:
    return ensure_utc(value).isoformat()


def _parse_time(value: str) -> datetime:
    return ensure_utc(datetime.fromisoformat(value))


class ControlStore:
    """SQLite-backed attended safety interlock.

    The database is an audit and concurrency aid. It does not authenticate the
    person who approved an operation; chat remains the authority boundary.
    """

    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path
        self._prepare_private_path()
        self._initialize()

    def _prepare_private_path(self) -> None:
        self.database_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.database_path.parent, 0o700)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.database_path, timeout=5.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        try:
            yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self.connect() as connection:
            connection.executescript(
                """
                PRAGMA journal_mode = WAL;
                CREATE TABLE IF NOT EXISTS proposals (
                    proposal_digest TEXT PRIMARY KEY,
                    proposal_id TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    material_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS approvals (
                    approval_id TEXT PRIMARY KEY,
                    proposal_digest TEXT NOT NULL,
                    chat_reference TEXT NOT NULL,
                    approved_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    consumed_at TEXT,
                    FOREIGN KEY (proposal_digest) REFERENCES proposals(proposal_digest)
                );
                CREATE TABLE IF NOT EXISTS executions (
                    execution_id TEXT PRIMARY KEY,
                    proposal_digest TEXT NOT NULL,
                    approval_id TEXT NOT NULL,
                    platform TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    scope_json TEXT NOT NULL,
                    target_key TEXT NOT NULL,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    FOREIGN KEY (proposal_digest) REFERENCES proposals(proposal_digest),
                    FOREIGN KEY (approval_id) REFERENCES approvals(approval_id)
                );
                CREATE TABLE IF NOT EXISTS target_locks (
                    target_key TEXT PRIMARY KEY,
                    execution_id TEXT NOT NULL UNIQUE,
                    acquired_at TEXT NOT NULL,
                    FOREIGN KEY (execution_id) REFERENCES executions(execution_id)
                );
                CREATE TABLE IF NOT EXISTS splunk_reservations (
                    reservation_id TEXT PRIMARY KEY,
                    execution_id TEXT NOT NULL UNIQUE,
                    license_day TEXT NOT NULL,
                    source_bytes INTEGER NOT NULL CHECK (source_bytes >= 0),
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (execution_id) REFERENCES executions(execution_id)
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    event_type TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    execution_id TEXT,
                    proposal_digest TEXT,
                    details_json TEXT NOT NULL
                );
                """
            )
        os.chmod(self.database_path, 0o600)

    @staticmethod
    def _begin(connection: sqlite3.Connection) -> None:
        connection.execute("BEGIN IMMEDIATE")

    @staticmethod
    def _commit(connection: sqlite3.Connection) -> None:
        connection.execute("COMMIT")

    @staticmethod
    def _rollback(connection: sqlite3.Connection) -> None:
        if connection.in_transaction:
            connection.execute("ROLLBACK")

    def register_proposal(self, proposal: Proposal) -> None:
        material = canonical_json(proposal.digest_payload())
        with self.connect() as connection:
            try:
                self._begin(connection)
                existing = connection.execute(
                    "SELECT material_json FROM proposals WHERE proposal_digest = ?",
                    (proposal.proposal_digest,),
                ).fetchone()
                if existing is not None and existing["material_json"] != material:
                    raise ApprovalDigestMismatchError("stored proposal material differs")
                connection.execute(
                    """
                    INSERT OR IGNORE INTO proposals
                        (proposal_digest, proposal_id, expires_at, material_json, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        proposal.proposal_digest,
                        proposal.proposal_id,
                        _iso(proposal.expires_at),
                        material,
                        _iso(proposal.created_at),
                    ),
                )
                self._commit(connection)
            except BaseException:
                self._rollback(connection)
                raise

    def record_approval(self, approval: Approval) -> None:
        expected = Approval.create(
            proposal_digest=approval.proposal_digest,
            chat_reference=approval.chat_reference,
            approved_at=approval.approved_at,
            expires_at=approval.expires_at,
        )
        if approval.consumed_at is not None or approval.approval_id != expected.approval_id:
            raise FabricatedApprovalError("approval fields do not match approval_id")

        with self.connect() as connection:
            try:
                self._begin(connection)
                proposal = connection.execute(
                    "SELECT expires_at FROM proposals WHERE proposal_digest = ?",
                    (approval.proposal_digest,),
                ).fetchone()
                if proposal is None:
                    raise UnknownProposalError("approval refers to an unregistered proposal")
                if approval.expires_at > _parse_time(proposal["expires_at"]):
                    raise ExpiredApprovalError("approval cannot outlive its proposal")
                connection.execute(
                    """
                    INSERT INTO approvals
                        (approval_id, proposal_digest, chat_reference, approved_at, expires_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        approval.approval_id,
                        approval.proposal_digest,
                        approval.chat_reference,
                        _iso(approval.approved_at),
                        _iso(approval.expires_at),
                    ),
                )
                self._commit(connection)
            except sqlite3.IntegrityError as exc:
                self._rollback(connection)
                raise ConsumedApprovalError("approval is already recorded") from exc
            except BaseException:
                self._rollback(connection)
                raise

    def reserve_execution(
        self,
        *,
        approval_id: str,
        proposal: Proposal,
        execution_id: str,
        target_key: str,
        now: datetime,
    ) -> Approval:
        """Atomically consume an approval, create an execution, and lock its target."""

        if not target_key.strip():
            raise ValueError("target_key must be non-empty")
        now_utc = ensure_utc(now)
        with self.connect() as connection:
            try:
                self._begin(connection)
                proposal_row = connection.execute(
                    "SELECT expires_at FROM proposals WHERE proposal_digest = ?",
                    (proposal.proposal_digest,),
                ).fetchone()
                if proposal_row is None:
                    raise UnknownProposalError("execution refers to an unregistered proposal")
                if now_utc >= proposal.expires_at:
                    raise ExpiredApprovalError("proposal has expired")

                row = connection.execute(
                    "SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)
                ).fetchone()
                if row is None:
                    raise MissingApprovalError("approval does not exist")
                if row["proposal_digest"] != proposal.proposal_digest:
                    raise ApprovalDigestMismatchError("approval is for a different proposal")
                if row["consumed_at"] is not None:
                    raise ConsumedApprovalError("approval was already consumed")
                if now_utc >= _parse_time(row["expires_at"]):
                    raise ExpiredApprovalError("approval has expired")

                connection.execute(
                    """
                    INSERT INTO executions
                        (execution_id, proposal_digest, approval_id, platform, operation,
                         scope_json, target_key, status, started_at, updated_at, details_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        execution_id,
                        proposal.proposal_digest,
                        approval_id,
                        proposal.platform.value,
                        proposal.operation,
                        canonical_json(proposal.scope),
                        target_key,
                        ExecutionStatus.RESERVED.value,
                        _iso(now_utc),
                        _iso(now_utc),
                        "{}",
                    ),
                )
                try:
                    connection.execute(
                        "INSERT INTO target_locks VALUES (?, ?, ?)",
                        (target_key, execution_id, _iso(now_utc)),
                    )
                except sqlite3.IntegrityError as exc:
                    raise TargetLockedError(f"target is already locked: {target_key}") from exc
                changed = connection.execute(
                    """
                    UPDATE approvals SET consumed_at = ?
                    WHERE approval_id = ? AND consumed_at IS NULL
                    """,
                    (_iso(now_utc), approval_id),
                ).rowcount
                if changed != 1:
                    raise ConsumedApprovalError("approval consumption race was lost")
                self._insert_event(
                    connection,
                    event_id=f"evt-{execution_id}-reserved",
                    event_type="execution.reserved",
                    occurred_at=now_utc,
                    execution_id=execution_id,
                    proposal_digest=proposal.proposal_digest,
                    details={"target_key": target_key, "approval_id": approval_id},
                )
                self._commit(connection)
            except BaseException:
                self._rollback(connection)
                raise

        return Approval(
            approval_id=row["approval_id"],
            proposal_digest=row["proposal_digest"],
            chat_reference=row["chat_reference"],
            approved_at=_parse_time(row["approved_at"]),
            expires_at=_parse_time(row["expires_at"]),
            consumed_at=now_utc,
        )

    def transition_execution(
        self,
        execution_id: str,
        status: ExecutionStatus,
        *,
        now: datetime,
        details: Mapping[str, Any] | None = None,
        release_lock: bool | None = None,
    ) -> StoredExecution:
        """Advance one execution exactly one allowed state transition."""

        target_status = ExecutionStatus(status)
        safe_details = redact(details or {})
        with self.connect() as connection:
            try:
                self._begin(connection)
                row = connection.execute(
                    "SELECT * FROM executions WHERE execution_id = ?", (execution_id,)
                ).fetchone()
                if row is None:
                    raise KeyError(f"unknown execution: {execution_id}")
                current = ExecutionStatus(row["status"])
                if target_status not in _TRANSITIONS[current]:
                    raise InvalidTransitionError(
                        f"invalid transition: {current} -> {target_status}"
                    )
                merged_details = json.loads(row["details_json"])
                merged_details.update(safe_details)
                connection.execute(
                    """
                    UPDATE executions SET status = ?, updated_at = ?, details_json = ?
                    WHERE execution_id = ?
                    """,
                    (
                        target_status.value,
                        _iso(now),
                        canonical_json(merged_details),
                        execution_id,
                    ),
                )
                should_release = (
                    target_status in _TERMINAL if release_lock is None else release_lock
                )
                if should_release:
                    connection.execute(
                        "DELETE FROM target_locks WHERE execution_id = ?", (execution_id,)
                    )
                self._insert_event(
                    connection,
                    event_id=f"evt-{execution_id}-{target_status.value}-{os.urandom(4).hex()}",
                    event_type=f"execution.{target_status.value}",
                    occurred_at=now,
                    execution_id=execution_id,
                    proposal_digest=row["proposal_digest"],
                    details=safe_details,
                )
                self._commit(connection)
            except BaseException:
                self._rollback(connection)
                raise
        return self.get_execution(execution_id)

    def get_execution(self, execution_id: str) -> StoredExecution:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM executions WHERE execution_id = ?", (execution_id,)
            ).fetchone()
        if row is None:
            raise KeyError(f"unknown execution: {execution_id}")
        return StoredExecution(
            execution_id=row["execution_id"],
            proposal_digest=row["proposal_digest"],
            approval_id=row["approval_id"],
            platform=row["platform"],
            operation=row["operation"],
            scope=json.loads(row["scope_json"]),
            target_key=row["target_key"],
            status=ExecutionStatus(row["status"]),
            started_at=_parse_time(row["started_at"]),
            updated_at=_parse_time(row["updated_at"]),
            details=json.loads(row["details_json"]),
        )

    def add_splunk_reservation(
        self,
        *,
        reservation_id: str,
        execution_id: str,
        license_day: str,
        source_bytes: int,
        now: datetime,
    ) -> None:
        if source_bytes < 0:
            raise ValueError("source_bytes must be non-negative")
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO splunk_reservations
                    (reservation_id, execution_id, license_day, source_bytes, status, created_at)
                VALUES (?, ?, ?, ?, 'pending', ?)
                """,
                (reservation_id, execution_id, license_day, source_bytes, _iso(now)),
            )

    def pending_splunk_bytes(self, license_day: str) -> int:
        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT COALESCE(SUM(source_bytes), 0) AS total
                FROM splunk_reservations
                WHERE license_day = ? AND status = 'pending'
                """,
                (license_day,),
            ).fetchone()
        return int(row["total"])

    @staticmethod
    def _insert_event(
        connection: sqlite3.Connection,
        *,
        event_id: str,
        event_type: str,
        occurred_at: datetime,
        execution_id: str | None,
        proposal_digest: str | None,
        details: Mapping[str, Any],
    ) -> None:
        connection.execute(
            """
            INSERT INTO audit_events
                (event_id, event_type, occurred_at, execution_id, proposal_digest, details_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                event_type,
                _iso(occurred_at),
                execution_id,
                proposal_digest,
                canonical_json(redact(details)),
            ),
        )

    def append_audit_event(
        self,
        *,
        event_id: str,
        event_type: str,
        occurred_at: datetime,
        details: Mapping[str, Any],
        execution_id: str | None = None,
        proposal_digest: str | None = None,
    ) -> None:
        with self.connect() as connection:
            self._insert_event(
                connection,
                event_id=event_id,
                event_type=event_type,
                occurred_at=occurred_at,
                execution_id=execution_id,
                proposal_digest=proposal_digest,
                details=details,
            )

    def audit_events(self) -> list[Mapping[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute("SELECT * FROM audit_events ORDER BY sequence").fetchall()
        return [
            {
                "sequence": row["sequence"],
                "event_id": row["event_id"],
                "event_type": row["event_type"],
                "occurred_at": row["occurred_at"],
                "execution_id": row["execution_id"],
                "proposal_digest": row["proposal_digest"],
                "details": json.loads(row["details_json"]),
            }
            for row in rows
        ]
