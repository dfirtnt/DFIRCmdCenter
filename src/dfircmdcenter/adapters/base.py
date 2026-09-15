"""Stable structural contract implemented by every platform adapter.

The protocol deliberately does not import concrete adapters or the persistence
layer.  The common execution engine can therefore coordinate fixture and live
adapters without giving an adapter a way around approval/revalidation.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Literal, Protocol, runtime_checkable

JsonObject = Mapping[str, object]
CapabilityMode = Literal["read", "write"]


@dataclass(frozen=True, slots=True)
class AdapterCapability:
    """One explicitly contracted operation exposed by an adapter."""

    name: str
    mode: CapabilityMode
    enabled: bool
    disabled_reason: str | None = None

    def __post_init__(self) -> None:
        if not self.name or self.name.strip() != self.name:
            raise ValueError("capability name must be non-empty and normalized")
        if self.enabled and self.disabled_reason is not None:
            raise ValueError("an enabled capability cannot have a disabled reason")
        if not self.enabled and not self.disabled_reason:
            raise ValueError("a disabled capability must explain why it is disabled")


@dataclass(frozen=True, slots=True)
class AdapterIdentity:
    """Minimum identity needed to prove which live platform is addressed."""

    platform: str
    instance_id: str
    version: str | None
    attributes: JsonObject = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RevalidationResult:
    """Result of comparing a proposal's preconditions with fresh live state."""

    valid: bool
    current_state_digest: str
    reason: str | None = None

    def __post_init__(self) -> None:
        if self.valid and self.reason is not None:
            raise ValueError("a valid revalidation cannot include a failure reason")
        if not self.valid and not self.reason:
            raise ValueError("an invalid revalidation must explain the drift")


@dataclass(frozen=True, slots=True)
class SubmissionResult:
    """Bounded result of exactly one adapter submission attempt."""

    outcome: Literal["accepted", "rejected", "unknown"]
    remote_id: str | None = None
    summary: str = ""


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """Read-derived verification or reconciliation outcome."""

    outcome: Literal["verified", "failed", "partial", "unknown"]
    state_digest: str | None = None
    summary: str = ""


@runtime_checkable
class Adapter(Protocol):
    """Common lifecycle boundary for platform implementations.

    Proposal and snapshot values are intentionally opaque here.  Their
    canonical record definitions belong to ``core.records``; adapters must not
    construct approvals or execute outside the common engine.
    """

    platform: str

    def capabilities(self) -> Sequence[AdapterCapability]: ...

    def identity(self) -> AdapterIdentity: ...

    def status_snapshot(self, *, scope: JsonObject) -> object: ...

    def build_proposal(
        self,
        *,
        operation: str,
        scope: JsonObject,
        desired: JsonObject,
        snapshot: object,
    ) -> object: ...

    def revalidate(self, *, proposal: object) -> RevalidationResult: ...

    def submit(self, *, proposal: object, execution_id: str) -> SubmissionResult: ...

    def verify(
        self,
        *,
        proposal: object,
        submission: SubmissionResult,
    ) -> VerificationResult: ...

    def reconcile(self, *, proposal: object, execution_id: str) -> VerificationResult: ...
