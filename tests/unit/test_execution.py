from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from dfircmdcenter.core.approvals import ConsumedApprovalError, ControlStore
from dfircmdcenter.core.execution import ExecutionEngine, StaleProposalError, WriteOutcomeUnknown
from dfircmdcenter.core.records import (
    Approval,
    ExecutionStatus,
    Platform,
    Proposal,
    Verification,
    VerificationStatus,
)

NOW = datetime(2026, 9, 15, 15, tzinfo=UTC)


def proposal() -> Proposal:
    return Proposal.create(
        platform=Platform.LIMACHARLIE,
        operation="set_detection",
        scope={"organization": "oid", "rule": "suspicious-process"},
        preconditions={
            "target_identity": "oid",
            "decision_relevant_state": "a" * 64,
            "policy": "b" * 64,
            "platform_contract": "c" * 64,
            "dependency_hashes": {"rule": "d" * 64},
        },
        policy_version="1",
        dependency_hashes={"rule": "d" * 64},
        validation={"validator": "passed", "tests": "passed"},
        expires_at=NOW + timedelta(hours=2),
        expected_effects={"rule_count_delta": 1},
        before_state={"rule": None},
        proposed_after_state={"rule": "report-only"},
        human_diff="Create one report-only detection.",
        rollback_or_recovery="Delete the exact rule after a separate approval.",
        created_at=NOW,
    )


def prepare(tmp_path: Path) -> tuple[ControlStore, Proposal, Approval]:
    store = ControlStore(tmp_path / "state.sqlite3")
    candidate = proposal()
    approval = Approval.create(
        proposal_digest=candidate.proposal_digest,
        chat_reference="chat-turn-100",
        approved_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )
    store.register_proposal(candidate)
    store.record_approval(approval)
    return store, candidate, approval


def verification(status: VerificationStatus) -> Verification:
    return Verification(
        status=status,
        checked_at=NOW + timedelta(minutes=4),
        checks={"rule_present": status is VerificationStatus.PASSED},
        summary=status.value,
    )


def test_apply_submits_once_and_verifies(tmp_path: Path) -> None:
    store, candidate, approval = prepare(tmp_path)
    submissions = 0

    def submit(_: Proposal) -> dict[str, str]:
        nonlocal submissions
        submissions += 1
        return {"rule": "suspicious-process"}

    engine = ExecutionEngine(store, clock=lambda: NOW + timedelta(minutes=2))
    result = engine.apply(
        proposal=candidate,
        approval_id=approval.approval_id,
        target_key="limacharlie:oid:rule:suspicious-process",
        revalidate=lambda _: candidate.preconditions,
        submit=submit,
        verify=lambda _proposal, _response: verification(VerificationStatus.PASSED),
    )

    assert submissions == 1
    assert result.execution.status is ExecutionStatus.VERIFIED
    assert result.verification is not None
    statuses = [event["event_type"] for event in store.audit_events()]
    assert statuses == [
        "execution.reserved",
        "execution.revalidated",
        "execution.submitting",
        "execution.submitted",
        "execution.verifying",
        "execution.verified",
    ]


def test_changed_preconditions_invalidate_consumed_approval(tmp_path: Path) -> None:
    store, candidate, approval = prepare(tmp_path)
    engine = ExecutionEngine(store, clock=lambda: NOW + timedelta(minutes=2))

    with pytest.raises(StaleProposalError):
        engine.apply(
            proposal=candidate,
            approval_id=approval.approval_id,
            target_key="limacharlie:oid:rule:suspicious-process",
            revalidate=lambda _: {**candidate.preconditions, "target_identity": "other"},
            submit=lambda _: pytest.fail("a stale proposal must not submit"),
            verify=lambda _proposal, _response: pytest.fail("a stale proposal must not verify"),
        )

    with pytest.raises(ConsumedApprovalError):
        store.reserve_execution(
            approval_id=approval.approval_id,
            proposal=candidate,
            execution_id="exe-retry",
            target_key="different-target",
            now=NOW + timedelta(minutes=3),
        )


def test_ambiguous_write_is_not_retried_and_can_be_read_reconciled(tmp_path: Path) -> None:
    store, candidate, approval = prepare(tmp_path)
    submissions = 0
    engine = ExecutionEngine(store, clock=lambda: NOW + timedelta(minutes=2))

    def ambiguous(_: Proposal) -> dict[str, str]:
        nonlocal submissions
        submissions += 1
        raise WriteOutcomeUnknown("request timed out after bytes were sent")

    result = engine.apply(
        proposal=candidate,
        approval_id=approval.approval_id,
        target_key="limacharlie:oid:rule:suspicious-process",
        revalidate=lambda _: candidate.preconditions,
        submit=ambiguous,
        verify=lambda _proposal, _response: pytest.fail("unknown submissions are not verified yet"),
    )

    assert submissions == 1
    assert result.execution.status is ExecutionStatus.UNKNOWN
    reconciled = engine.reconcile(
        proposal=candidate,
        execution_id=result.execution.execution_id,
        reconcile=lambda _proposal, _execution: verification(VerificationStatus.PASSED),
    )
    assert submissions == 1
    assert reconciled.execution.status is ExecutionStatus.VERIFIED


def test_failed_reconciliation_remains_unknown(tmp_path: Path) -> None:
    store, candidate, approval = prepare(tmp_path)
    engine = ExecutionEngine(store, clock=lambda: NOW + timedelta(minutes=2))
    result = engine.apply(
        proposal=candidate,
        approval_id=approval.approval_id,
        target_key="limacharlie:oid:rule:suspicious-process",
        revalidate=lambda _: candidate.preconditions,
        submit=lambda _: (_ for _ in ()).throw(WriteOutcomeUnknown("ambiguous")),
        verify=lambda _proposal, _response: verification(VerificationStatus.UNKNOWN),
    )

    reconciled = engine.reconcile(
        proposal=candidate,
        execution_id=result.execution.execution_id,
        reconcile=lambda _proposal, _execution: (_ for _ in ()).throw(
            ConnectionError("read unavailable")
        ),
    )
    assert reconciled.execution.status is ExecutionStatus.UNKNOWN
    assert reconciled.verification is None

