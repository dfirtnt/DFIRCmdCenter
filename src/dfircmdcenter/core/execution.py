"""Single-submission execution engine for every mutating adapter operation."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import uuid4

from .approvals import ControlStore, StoredExecution
from .canonical import canonical_digest
from .records import (
    ErrorKind,
    ExecutionStatus,
    NormalizedPlatformError,
    Proposal,
    Verification,
    VerificationStatus,
)
from .time import workflow_now

Revalidate = Callable[[Proposal], Mapping[str, Any]]
Submit = Callable[[Proposal], Mapping[str, Any]]
Verify = Callable[[Proposal, Mapping[str, Any]], Verification]
Reconcile = Callable[[Proposal, StoredExecution], Verification]


class StaleProposalError(RuntimeError):
    """Live preconditions no longer match the approved proposal."""


class WriteOutcomeUnknown(RuntimeError):
    """Submission may have reached the platform and must not be retried."""

    def __init__(self, message: str, *, error: NormalizedPlatformError | None = None) -> None:
        super().__init__(message)
        self.error = error


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    execution: StoredExecution
    verification: Verification | None


def _verification_status(status: VerificationStatus) -> ExecutionStatus:
    return {
        VerificationStatus.PASSED: ExecutionStatus.VERIFIED,
        VerificationStatus.FAILED: ExecutionStatus.FAILED,
        VerificationStatus.PARTIAL: ExecutionStatus.PARTIAL,
        VerificationStatus.UNKNOWN: ExecutionStatus.UNKNOWN,
    }[status]


class ExecutionEngine:
    """Enforce approval, revalidation, one submission, and verification."""

    def __init__(
        self,
        store: ControlStore,
        *,
        clock: Callable[[], datetime] = workflow_now,
    ) -> None:
        self.store = store
        self.clock = clock

    def apply(
        self,
        *,
        proposal: Proposal,
        approval_id: str,
        target_key: str,
        revalidate: Revalidate,
        submit: Submit,
        verify: Verify,
    ) -> ExecutionResult:
        execution_id = f"exe-{uuid4().hex}"
        self.store.reserve_execution(
            approval_id=approval_id,
            proposal=proposal,
            execution_id=execution_id,
            target_key=target_key,
            now=self.clock(),
        )

        try:
            actual_preconditions = revalidate(proposal)
        except Exception as exc:
            execution = self.store.transition_execution(
                execution_id,
                ExecutionStatus.FAILED,
                now=self.clock(),
                details={"phase": "revalidation", "error": str(exc)},
            )
            return ExecutionResult(execution=execution, verification=None)

        if canonical_digest(actual_preconditions) != canonical_digest(proposal.preconditions):
            self.store.transition_execution(
                execution_id,
                ExecutionStatus.FAILED,
                now=self.clock(),
                details={
                    "phase": "revalidation",
                    "reason": "approved preconditions changed",
                    "expected_digest": canonical_digest(proposal.preconditions),
                    "actual_digest": canonical_digest(actual_preconditions),
                },
            )
            raise StaleProposalError("approved proposal is stale; create a new proposal")

        self.store.transition_execution(
            execution_id,
            ExecutionStatus.REVALIDATED,
            now=self.clock(),
            details={"preconditions_digest": canonical_digest(actual_preconditions)},
        )
        # Persisting SUBMITTING is the durable submission intent boundary.
        self.store.transition_execution(
            execution_id,
            ExecutionStatus.SUBMITTING,
            now=self.clock(),
            details={"submission_attempts": 1},
        )

        try:
            response = submit(proposal)
        except WriteOutcomeUnknown as exc:
            error = exc.error or NormalizedPlatformError(
                platform=proposal.platform,
                kind=ErrorKind.UNKNOWN,
                message=str(exc),
                retryable=False,
                outcome_ambiguous=True,
            )
            execution = self.store.transition_execution(
                execution_id,
                ExecutionStatus.UNKNOWN,
                now=self.clock(),
                details={"phase": "submission", "error": error},
                release_lock=False,
            )
            return ExecutionResult(execution=execution, verification=None)
        except Exception as exc:
            execution = self.store.transition_execution(
                execution_id,
                ExecutionStatus.FAILED,
                now=self.clock(),
                details={"phase": "submission", "error": str(exc)},
            )
            return ExecutionResult(execution=execution, verification=None)

        self.store.transition_execution(
            execution_id,
            ExecutionStatus.SUBMITTED,
            now=self.clock(),
            details={"response": response},
        )
        self.store.transition_execution(
            execution_id,
            ExecutionStatus.VERIFYING,
            now=self.clock(),
        )
        try:
            verification = verify(proposal, response)
        except Exception as exc:
            execution = self.store.transition_execution(
                execution_id,
                ExecutionStatus.UNKNOWN,
                now=self.clock(),
                details={"phase": "verification", "error": str(exc)},
                release_lock=False,
            )
            return ExecutionResult(execution=execution, verification=None)

        outcome = _verification_status(verification.status)
        execution = self.store.transition_execution(
            execution_id,
            outcome,
            now=self.clock(),
            details={"verification": verification},
            release_lock=outcome is not ExecutionStatus.UNKNOWN,
        )
        return ExecutionResult(execution=execution, verification=verification)

    def reconcile(
        self,
        *,
        proposal: Proposal,
        execution_id: str,
        reconcile: Reconcile,
    ) -> ExecutionResult:
        execution = self.store.get_execution(execution_id)
        if execution.status is not ExecutionStatus.UNKNOWN:
            raise ValueError("only an unknown execution can be reconciled")
        if execution.proposal_digest != proposal.proposal_digest:
            raise ValueError("execution and proposal digests differ")
        self.store.transition_execution(
            execution_id,
            ExecutionStatus.VERIFYING,
            now=self.clock(),
            details={"phase": "read_only_reconciliation"},
            release_lock=False,
        )
        try:
            verification = reconcile(proposal, execution)
        except Exception as exc:
            # A failed read keeps the outcome unknown and the target locked.
            current = self.store.transition_execution(
                execution_id,
                ExecutionStatus.UNKNOWN,
                now=self.clock(),
                details={"phase": "read_only_reconciliation", "error": str(exc)},
                release_lock=False,
            )
            return ExecutionResult(execution=current, verification=None)
        outcome = _verification_status(verification.status)
        current = self.store.transition_execution(
            execution_id,
            outcome,
            now=self.clock(),
            details={"reconciliation": verification},
            release_lock=outcome is not ExecutionStatus.UNKNOWN,
        )
        return ExecutionResult(execution=current, verification=verification)
