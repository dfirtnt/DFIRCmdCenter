"""Immutable, versioned control-plane records."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any
from uuid import uuid4

from .canonical import canonical_digest
from .redaction import redact, redact_text
from .time import ensure_utc
from .untrusted import escape_terminal_controls

SCHEMA_VERSION = 1
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class Platform(StrEnum):
    ACTION1 = "action1"
    LIMACHARLIE = "limacharlie"
    VELOCIRAPTOR = "velociraptor"
    SPLUNK = "splunk"


class RedactionStatus(StrEnum):
    REDACTED = "redacted"
    NOT_REQUIRED = "not_required"


class ExecutionStatus(StrEnum):
    PLANNED = "planned"
    APPROVED = "approved"
    RESERVED = "reserved"
    REVALIDATED = "revalidated"
    SUBMITTING = "submitting"
    SUBMITTED = "submitted"
    VERIFYING = "verifying"
    VERIFIED = "verified"
    FAILED = "failed"
    PARTIAL = "partial"
    UNKNOWN = "unknown"


class VerificationStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    PARTIAL = "partial"
    UNKNOWN = "unknown"


class ErrorKind(StrEnum):
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    CONFLICT = "conflict"
    INVALID_REQUEST = "invalid_request"
    NOT_FOUND = "not_found"
    RATE_LIMITED = "rate_limited"
    TIMEOUT = "timeout"
    TRANSPORT = "transport"
    UNSAFE_DATA = "unsafe_data"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


def _freeze(value: Any) -> Any:
    """Recursively freeze a JSON-like value without changing its semantics."""

    if isinstance(value, Mapping):
        frozen: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("record mapping keys must be strings")
            frozen[key] = _freeze(item)
        return MappingProxyType(frozen)
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(_freeze(item) for item in value)
    return value


def freeze(value: Any) -> Any:
    """Public helper for adapters constructing deeply immutable payloads."""

    return _freeze(value)


def _platform(value: Platform | str) -> Platform:
    return value if isinstance(value, Platform) else Platform(value)


def _require_text(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")


def _require_digest(value: str, field_name: str) -> None:
    if not _SHA256_RE.fullmatch(value):
        raise ValueError(f"{field_name} must be a lowercase SHA-256 digest")


def _snapshot_state_payload(
    *,
    schema_version: int,
    platform: Platform,
    scope: Mapping[str, Any],
    state: Mapping[str, Any],
) -> Mapping[str, Any]:
    return {
        "schema_version": schema_version,
        "platform": platform,
        "scope": scope,
        "state": state,
    }


@dataclass(frozen=True, slots=True, kw_only=True)
class Snapshot:
    platform: Platform
    scope: Mapping[str, Any]
    captured_at: datetime
    source_interface: str
    source_version: str | None
    redaction_status: RedactionStatus
    state: Mapping[str, Any]
    state_digest: str
    snapshot_digest: str
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "platform", _platform(self.platform))
        object.__setattr__(self, "scope", _freeze(self.scope))
        object.__setattr__(self, "state", _freeze(self.state))
        object.__setattr__(self, "captured_at", ensure_utc(self.captured_at))
        object.__setattr__(
            self,
            "redaction_status",
            RedactionStatus(self.redaction_status),
        )
        _require_text(self.source_interface, "source_interface")
        _require_digest(self.state_digest, "state_digest")
        _require_digest(self.snapshot_digest, "snapshot_digest")
        expected_state = canonical_digest(
            _snapshot_state_payload(
                schema_version=self.schema_version,
                platform=self.platform,
                scope=self.scope,
                state=self.state,
            )
        )
        if self.state_digest != expected_state:
            raise ValueError("state_digest does not match normalized decision state")
        if self.snapshot_digest != canonical_digest(self.envelope(include_digest=False)):
            raise ValueError("snapshot_digest does not match snapshot envelope")

    @classmethod
    def create(
        cls,
        *,
        platform: Platform | str,
        scope: Mapping[str, Any],
        captured_at: datetime,
        source_interface: str,
        source_version: str | None,
        state: Mapping[str, Any],
        redaction_status: RedactionStatus | str = RedactionStatus.REDACTED,
        schema_version: int = SCHEMA_VERSION,
    ) -> Snapshot:
        normalized_platform = _platform(platform)
        frozen_scope = _freeze(scope)
        frozen_state = _freeze(state)
        normalized_time = ensure_utc(captured_at)
        state_digest = canonical_digest(
            _snapshot_state_payload(
                schema_version=schema_version,
                platform=normalized_platform,
                scope=frozen_scope,
                state=frozen_state,
            )
        )
        envelope = {
            "schema_version": schema_version,
            "platform": normalized_platform,
            "scope": frozen_scope,
            "captured_at": normalized_time,
            "source_interface": source_interface,
            "source_version": source_version,
            "redaction_status": RedactionStatus(redaction_status),
            "state": frozen_state,
            "state_digest": state_digest,
        }
        return cls(
            platform=normalized_platform,
            scope=frozen_scope,
            captured_at=normalized_time,
            source_interface=source_interface,
            source_version=source_version,
            redaction_status=RedactionStatus(redaction_status),
            state=frozen_state,
            state_digest=state_digest,
            snapshot_digest=canonical_digest(envelope),
            schema_version=schema_version,
        )

    def envelope(self, *, include_digest: bool = True) -> Mapping[str, Any]:
        envelope: dict[str, Any] = {
            "schema_version": self.schema_version,
            "platform": self.platform,
            "scope": self.scope,
            "captured_at": self.captured_at,
            "source_interface": self.source_interface,
            "source_version": self.source_version,
            "redaction_status": self.redaction_status,
            "state": self.state,
            "state_digest": self.state_digest,
        }
        if include_digest:
            envelope["snapshot_digest"] = self.snapshot_digest
        return MappingProxyType(envelope)


def _proposal_payload(
    *,
    schema_version: int,
    platform: Platform,
    operation: str,
    scope: Mapping[str, Any],
    preconditions: Mapping[str, Any],
    policy_version: str,
    dependency_hashes: Mapping[str, Any],
    validation: Mapping[str, Any],
    expires_at: datetime,
    expected_effects: Mapping[str, Any],
    before_state: Mapping[str, Any],
    proposed_after_state: Mapping[str, Any],
    human_diff: str,
    rollback_or_recovery: str,
) -> Mapping[str, Any]:
    return {
        "schema_version": schema_version,
        "platform": platform,
        "operation": operation,
        "scope": scope,
        "preconditions": preconditions,
        "policy_version": policy_version,
        "dependency_hashes": dependency_hashes,
        "validation": validation,
        "expires_at": expires_at,
        "expected_effects": expected_effects,
        "before_state": before_state,
        "proposed_after_state": proposed_after_state,
        "human_diff": human_diff,
        "rollback_or_recovery": rollback_or_recovery,
    }


@dataclass(frozen=True, slots=True, kw_only=True)
class Proposal:
    proposal_id: str
    proposal_digest: str
    platform: Platform
    operation: str
    scope: Mapping[str, Any]
    preconditions: Mapping[str, Any]
    policy_version: str
    dependency_hashes: Mapping[str, Any]
    validation: Mapping[str, Any]
    expires_at: datetime
    expected_effects: Mapping[str, Any]
    before_state: Mapping[str, Any]
    proposed_after_state: Mapping[str, Any]
    human_diff: str
    rollback_or_recovery: str
    created_at: datetime
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "platform", _platform(self.platform))
        for field_name in (
            "scope",
            "preconditions",
            "dependency_hashes",
            "validation",
            "expected_effects",
            "before_state",
            "proposed_after_state",
        ):
            object.__setattr__(self, field_name, _freeze(getattr(self, field_name)))
        object.__setattr__(self, "expires_at", ensure_utc(self.expires_at))
        object.__setattr__(self, "created_at", ensure_utc(self.created_at))
        for field_name in (
            "proposal_id",
            "operation",
            "policy_version",
            "human_diff",
            "rollback_or_recovery",
        ):
            _require_text(getattr(self, field_name), field_name)
        _require_digest(self.proposal_digest, "proposal_digest")
        if self.expires_at <= self.created_at:
            raise ValueError("expires_at must be later than created_at")
        if self.proposal_digest != canonical_digest(self.digest_payload()):
            raise ValueError("proposal_digest does not match the material proposal")
        if self.proposal_id != f"prp-{self.proposal_digest[:16]}":
            raise ValueError("proposal_id is not derived from proposal_digest")

    @classmethod
    def create(
        cls,
        *,
        platform: Platform | str,
        operation: str,
        scope: Mapping[str, Any],
        preconditions: Mapping[str, Any],
        policy_version: str,
        dependency_hashes: Mapping[str, Any],
        validation: Mapping[str, Any],
        expires_at: datetime,
        expected_effects: Mapping[str, Any],
        before_state: Mapping[str, Any],
        proposed_after_state: Mapping[str, Any],
        human_diff: str,
        rollback_or_recovery: str,
        created_at: datetime,
        schema_version: int = SCHEMA_VERSION,
    ) -> Proposal:
        normalized_platform = _platform(platform)
        normalized_expiry = ensure_utc(expires_at)
        frozen = {
            "scope": _freeze(scope),
            "preconditions": _freeze(preconditions),
            "dependency_hashes": _freeze(dependency_hashes),
            "validation": _freeze(validation),
            "expected_effects": _freeze(expected_effects),
            "before_state": _freeze(before_state),
            "proposed_after_state": _freeze(proposed_after_state),
        }
        payload = _proposal_payload(
            schema_version=schema_version,
            platform=normalized_platform,
            operation=operation,
            scope=frozen["scope"],
            preconditions=frozen["preconditions"],
            policy_version=policy_version,
            dependency_hashes=frozen["dependency_hashes"],
            validation=frozen["validation"],
            expires_at=normalized_expiry,
            expected_effects=frozen["expected_effects"],
            before_state=frozen["before_state"],
            proposed_after_state=frozen["proposed_after_state"],
            human_diff=human_diff,
            rollback_or_recovery=rollback_or_recovery,
        )
        digest = canonical_digest(payload)
        return cls(
            proposal_id=f"prp-{digest[:16]}",
            proposal_digest=digest,
            platform=normalized_platform,
            operation=operation,
            policy_version=policy_version,
            expires_at=normalized_expiry,
            human_diff=human_diff,
            rollback_or_recovery=rollback_or_recovery,
            created_at=ensure_utc(created_at),
            schema_version=schema_version,
            **frozen,
        )

    def digest_payload(self) -> Mapping[str, Any]:
        return _proposal_payload(
            schema_version=self.schema_version,
            platform=self.platform,
            operation=self.operation,
            scope=self.scope,
            preconditions=self.preconditions,
            policy_version=self.policy_version,
            dependency_hashes=self.dependency_hashes,
            validation=self.validation,
            expires_at=self.expires_at,
            expected_effects=self.expected_effects,
            before_state=self.before_state,
            proposed_after_state=self.proposed_after_state,
            human_diff=self.human_diff,
            rollback_or_recovery=self.rollback_or_recovery,
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class Approval:
    approval_id: str
    proposal_digest: str
    chat_reference: str
    approved_at: datetime
    expires_at: datetime
    consumed_at: datetime | None = None
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _require_text(self.approval_id, "approval_id")
        _require_text(self.chat_reference, "chat_reference")
        _require_digest(self.proposal_digest, "proposal_digest")
        object.__setattr__(self, "approved_at", ensure_utc(self.approved_at))
        object.__setattr__(self, "expires_at", ensure_utc(self.expires_at))
        if self.consumed_at is not None:
            object.__setattr__(self, "consumed_at", ensure_utc(self.consumed_at))
        if self.expires_at <= self.approved_at:
            raise ValueError("approval expires_at must be later than approved_at")

    @classmethod
    def create(
        cls,
        *,
        proposal_digest: str,
        chat_reference: str,
        approved_at: datetime,
        expires_at: datetime,
    ) -> Approval:
        material = {
            "proposal_digest": proposal_digest,
            "chat_reference": chat_reference,
            "approved_at": ensure_utc(approved_at),
            "expires_at": ensure_utc(expires_at),
        }
        return cls(
            approval_id=f"apr-{canonical_digest(material)[:16]}",
            proposal_digest=proposal_digest,
            chat_reference=chat_reference,
            approved_at=approved_at,
            expires_at=expires_at,
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class Verification:
    status: VerificationStatus
    checked_at: datetime
    checks: Mapping[str, Any]
    resulting_snapshot_digest: str | None = None
    summary: str = ""
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "status", VerificationStatus(self.status))
        object.__setattr__(self, "checked_at", ensure_utc(self.checked_at))
        object.__setattr__(self, "checks", _freeze(self.checks))
        if self.resulting_snapshot_digest is not None:
            _require_digest(self.resulting_snapshot_digest, "resulting_snapshot_digest")


@dataclass(frozen=True, slots=True, kw_only=True)
class NormalizedPlatformError:
    platform: Platform
    kind: ErrorKind
    message: str
    code: str | None = None
    retryable: bool = False
    outcome_ambiguous: bool = False
    details: Mapping[str, Any] | None = None
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "platform", _platform(self.platform))
        object.__setattr__(self, "kind", ErrorKind(self.kind))
        _require_text(self.message, "message")
        safe_message = escape_terminal_controls(redact_text(self.message))
        object.__setattr__(self, "message", safe_message)
        if self.details is not None:
            object.__setattr__(self, "details", _freeze(redact(self.details)))


@dataclass(frozen=True, slots=True, kw_only=True)
class Execution:
    execution_id: str
    proposal_digest: str
    platform: Platform
    operation: str
    scope: Mapping[str, Any]
    status: ExecutionStatus
    started_at: datetime
    completed_at: datetime | None = None
    approval_id: str | None = None
    response_summary: Mapping[str, Any] | None = None
    error: NormalizedPlatformError | None = None
    verification: Verification | None = None
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _require_text(self.execution_id, "execution_id")
        _require_digest(self.proposal_digest, "proposal_digest")
        object.__setattr__(self, "platform", _platform(self.platform))
        _require_text(self.operation, "operation")
        object.__setattr__(self, "scope", _freeze(self.scope))
        object.__setattr__(self, "status", ExecutionStatus(self.status))
        object.__setattr__(self, "started_at", ensure_utc(self.started_at))
        if self.completed_at is not None:
            object.__setattr__(self, "completed_at", ensure_utc(self.completed_at))
        if self.response_summary is not None:
            object.__setattr__(self, "response_summary", _freeze(self.response_summary))

    @classmethod
    def start(
        cls,
        *,
        proposal_digest: str,
        platform: Platform | str,
        operation: str,
        scope: Mapping[str, Any],
        started_at: datetime,
        approval_id: str | None = None,
    ) -> Execution:
        return cls(
            execution_id=f"exe-{uuid4().hex}",
            proposal_digest=proposal_digest,
            platform=_platform(platform),
            operation=operation,
            scope=scope,
            status=ExecutionStatus.SUBMITTING,
            started_at=started_at,
            approval_id=approval_id,
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class Receipt:
    receipt_id: str
    proposal_digest: str
    execution_id: str
    platform: Platform
    operation: str
    scope: Mapping[str, Any]
    outcome: ExecutionStatus
    completed_at: datetime
    verification: Verification
    details: Mapping[str, Any]
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _require_text(self.receipt_id, "receipt_id")
        _require_digest(self.proposal_digest, "proposal_digest")
        _require_text(self.execution_id, "execution_id")
        object.__setattr__(self, "platform", _platform(self.platform))
        _require_text(self.operation, "operation")
        object.__setattr__(self, "scope", _freeze(self.scope))
        object.__setattr__(self, "outcome", ExecutionStatus(self.outcome))
        object.__setattr__(self, "completed_at", ensure_utc(self.completed_at))
        object.__setattr__(self, "details", _freeze(self.details))


@dataclass(frozen=True, slots=True, kw_only=True)
class Capability:
    platform: Platform
    name: str
    supported: bool
    mutating: bool
    constraints: Mapping[str, Any]
    reason: str | None = None
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "platform", _platform(self.platform))
        _require_text(self.name, "name")
        object.__setattr__(self, "constraints", _freeze(self.constraints))


PlatformError = NormalizedPlatformError
