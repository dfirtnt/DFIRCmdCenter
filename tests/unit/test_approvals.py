from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from dfircmdcenter.core.approvals import (
    ApprovalDigestMismatchError,
    ConsumedApprovalError,
    ControlStore,
    ExpiredApprovalError,
    FabricatedApprovalError,
    MissingApprovalError,
    TargetLockedError,
)
from dfircmdcenter.core.records import Approval, ExecutionStatus, Platform, Proposal

NOW = datetime(2026, 9, 15, 14, tzinfo=UTC)


def proposal(*, scope: dict[str, str] | None = None) -> Proposal:
    return Proposal.create(
        platform=Platform.SPLUNK,
        operation="ingest_csv",
        scope=scope or {"index": "dfir", "file_sha256": "f" * 64},
        preconditions={"state_digest": "a" * 64},
        policy_version="1",
        dependency_hashes={"contract": "b" * 64},
        validation={"passed": True},
        expires_at=NOW + timedelta(hours=2),
        expected_effects={"source_bytes": 100},
        before_state={"events": 0},
        proposed_after_state={"events": "increase"},
        human_diff="Ingest one exact CSV file.",
        rollback_or_recovery="Delete only the explicitly identified test data if required.",
        created_at=NOW,
    )


def approval_for(candidate: Proposal, *, expires_at: datetime | None = None) -> Approval:
    return Approval.create(
        proposal_digest=candidate.proposal_digest,
        chat_reference="chat-turn-42",
        approved_at=NOW + timedelta(minutes=1),
        expires_at=expires_at or NOW + timedelta(hours=1),
    )


def prepared_store(tmp_path: Path) -> tuple[ControlStore, Proposal, Approval]:
    store = ControlStore(tmp_path / "var" / "control" / "state.sqlite3")
    candidate = proposal()
    approval = approval_for(candidate)
    store.register_proposal(candidate)
    store.record_approval(approval)
    return store, candidate, approval


def test_private_database_permissions_and_one_time_consumption(tmp_path: Path) -> None:
    store, candidate, approval = prepared_store(tmp_path)
    database = tmp_path / "var" / "control" / "state.sqlite3"

    consumed = store.reserve_execution(
        approval_id=approval.approval_id,
        proposal=candidate,
        execution_id="exe-first",
        target_key="splunk:index=dfir:file=f",
        now=NOW + timedelta(minutes=2),
    )

    assert database.stat().st_mode & 0o777 == 0o600
    assert database.parent.stat().st_mode & 0o777 == 0o700
    assert consumed.consumed_at == NOW + timedelta(minutes=2)
    assert store.get_execution("exe-first").status is ExecutionStatus.RESERVED
    with pytest.raises(ConsumedApprovalError):
        store.reserve_execution(
            approval_id=approval.approval_id,
            proposal=candidate,
            execution_id="exe-reuse",
            target_key="splunk:index=dfir:file=other",
            now=NOW + timedelta(minutes=3),
        )


def test_missing_mismatched_expired_and_fabricated_approvals(tmp_path: Path) -> None:
    store, candidate, approval = prepared_store(tmp_path)
    other = proposal(scope={"index": "dfir", "file_sha256": "e" * 64})
    store.register_proposal(other)

    with pytest.raises(MissingApprovalError):
        store.reserve_execution(
            approval_id="apr-missing",
            proposal=candidate,
            execution_id="exe-missing",
            target_key="one",
            now=NOW + timedelta(minutes=2),
        )
    with pytest.raises(ApprovalDigestMismatchError):
        store.reserve_execution(
            approval_id=approval.approval_id,
            proposal=other,
            execution_id="exe-mismatch",
            target_key="two",
            now=NOW + timedelta(minutes=2),
        )
    with pytest.raises(ExpiredApprovalError):
        store.reserve_execution(
            approval_id=approval.approval_id,
            proposal=candidate,
            execution_id="exe-expired",
            target_key="three",
            now=NOW + timedelta(hours=1),
        )

    fabricated = Approval(
        approval_id="apr-fabricated",
        proposal_digest=candidate.proposal_digest,
        chat_reference="chat-turn-42",
        approved_at=NOW + timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=30),
    )
    with pytest.raises(FabricatedApprovalError):
        store.record_approval(fabricated)


def test_target_lock_failure_does_not_consume_second_approval(tmp_path: Path) -> None:
    store, candidate, first = prepared_store(tmp_path)
    second = Approval.create(
        proposal_digest=candidate.proposal_digest,
        chat_reference="chat-turn-43",
        approved_at=NOW + timedelta(minutes=1, seconds=1),
        expires_at=NOW + timedelta(hours=1),
    )
    store.record_approval(second)
    store.reserve_execution(
        approval_id=first.approval_id,
        proposal=candidate,
        execution_id="exe-lock-owner",
        target_key="same-target",
        now=NOW + timedelta(minutes=2),
    )

    with pytest.raises(TargetLockedError):
        store.reserve_execution(
            approval_id=second.approval_id,
            proposal=candidate,
            execution_id="exe-lock-loser",
            target_key="same-target",
            now=NOW + timedelta(minutes=3),
        )

    store.transition_execution(
        "exe-lock-owner", ExecutionStatus.FAILED, now=NOW + timedelta(minutes=4)
    )
    consumed = store.reserve_execution(
        approval_id=second.approval_id,
        proposal=candidate,
        execution_id="exe-after-release",
        target_key="same-target",
        now=NOW + timedelta(minutes=5),
    )
    assert consumed.approval_id == second.approval_id


def test_two_connections_cannot_consume_one_approval(tmp_path: Path) -> None:
    store, candidate, approval = prepared_store(tmp_path)

    def attempt(number: int) -> str:
        try:
            store.reserve_execution(
                approval_id=approval.approval_id,
                proposal=candidate,
                execution_id=f"exe-race-{number}",
                target_key=f"target-{number}",
                now=NOW + timedelta(minutes=2),
            )
        except ConsumedApprovalError:
            return "consumed"
        return "reserved"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(attempt, (1, 2)))

    assert sorted(outcomes) == ["consumed", "reserved"]


def test_pending_splunk_reservations_are_counted(tmp_path: Path) -> None:
    store, candidate, approval = prepared_store(tmp_path)
    store.reserve_execution(
        approval_id=approval.approval_id,
        proposal=candidate,
        execution_id="exe-budget",
        target_key="splunk-budget",
        now=NOW + timedelta(minutes=2),
    )
    store.add_splunk_reservation(
        reservation_id="res-1",
        execution_id="exe-budget",
        license_day="2026-09-15",
        source_bytes=125,
        now=NOW + timedelta(minutes=2),
    )

    assert store.pending_splunk_bytes("2026-09-15") == 125
    assert store.pending_splunk_bytes("2026-09-16") == 0

