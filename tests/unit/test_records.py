from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta

import pytest

from dfircmdcenter.core.canonical import canonical_digest, canonical_json
from dfircmdcenter.core.records import (
    ErrorKind,
    Execution,
    ExecutionStatus,
    NormalizedPlatformError,
    Platform,
    Proposal,
    Snapshot,
)


def test_canonical_json_is_deterministic_and_preserves_unicode() -> None:
    left = {"z": "café", "a": {"b": 2, "a": 1}}
    right = {"a": {"a": 1, "b": 2}, "z": "café"}

    assert canonical_json(left) == canonical_json(right)
    assert "café" in canonical_json(left)
    assert canonical_digest(left) == canonical_digest(right)


def test_canonical_json_preserves_order_unless_path_is_declared_unordered() -> None:
    left = {"rules": [{"id": "b"}, {"id": "a"}]}
    right = {"rules": [{"id": "a"}, {"id": "b"}]}

    assert canonical_digest(left) != canonical_digest(right)
    assert canonical_digest(left, unordered_paths={("rules",)}) == canonical_digest(
        right, unordered_paths={("rules",)}
    )


@pytest.mark.parametrize("number", [float("nan"), float("inf"), float("-inf")])
def test_canonical_json_rejects_non_finite_numbers(number: float) -> None:
    with pytest.raises(ValueError, match="finite"):
        canonical_json({"value": number})


def test_snapshot_separates_state_and_envelope_digests() -> None:
    first = Snapshot.create(
        platform=Platform.SPLUNK,
        scope={"index": "dfir"},
        captured_at=datetime(2026, 9, 14, 16, tzinfo=UTC),
        source_interface="fixture",
        source_version="1",
        state={"indexes": ["dfir"]},
    )
    later = Snapshot.create(
        platform=Platform.SPLUNK,
        scope={"index": "dfir"},
        captured_at=datetime(2026, 9, 14, 17, tzinfo=UTC),
        source_interface="fixture",
        source_version="1",
        state={"indexes": ["dfir"]},
    )

    assert first.state_digest == later.state_digest
    assert first.snapshot_digest != later.snapshot_digest
    assert first.captured_at.tzinfo is UTC
    with pytest.raises((FrozenInstanceError, AttributeError, TypeError)):
        first.state["new"] = True  # type: ignore[index]


def test_material_proposal_changes_invalidate_digest() -> None:
    base = dict(
        platform=Platform.VELOCIRAPTOR,
        operation="collect",
        scope={"client_id": "C.123", "artifact": "Windows.System.Pslist"},
        preconditions={"state_digest": "a" * 64},
        policy_version="1",
        dependency_hashes={"artifact": "b" * 64},
        validation={"status": "passed"},
        expires_at=datetime(2026, 9, 14, 18, tzinfo=UTC),
        expected_effects={"flow_count": 1},
        before_state={"flows": 0},
        proposed_after_state={"flows": 1},
        human_diff="Launch one collection",
        rollback_or_recovery="Cancel if not started; otherwise preserve results.",
        created_at=datetime(2026, 9, 14, 17, tzinfo=UTC),
    )
    original = Proposal.create(**base)
    changed_scope = Proposal.create(**{**base, "scope": {"client_id": "C.999"}})
    changed_policy = Proposal.create(**{**base, "policy_version": "2"})

    assert original.proposal_digest != changed_scope.proposal_digest
    assert original.proposal_digest != changed_policy.proposal_digest
    assert original.proposal_id.startswith("prp-")


def test_execution_attempt_ids_are_distinct_from_proposal() -> None:
    now = datetime(2026, 9, 14, 17, tzinfo=UTC)
    one = Execution.start(
        proposal_digest="a" * 64,
        platform=Platform.ACTION1,
        operation="deploy",
        scope={"endpoint": "device-1"},
        started_at=now,
    )
    two = Execution.start(
        proposal_digest="a" * 64,
        platform=Platform.ACTION1,
        operation="deploy",
        scope={"endpoint": "device-1"},
        started_at=now + timedelta(seconds=1),
    )

    assert one.execution_id != two.execution_id
    assert one.status is ExecutionStatus.SUBMITTING


def test_normalized_platform_error_redacts_secrets_and_terminal_controls() -> None:
    error = NormalizedPlatformError(
        platform=Platform.LIMACHARLIE,
        kind=ErrorKind.AUTHENTICATION,
        message="password=hunter2 status\x1b[31m",
        details={"api_key": "secret", "request_id": "req-1"},
    )

    assert "hunter2" not in error.message
    assert "\x1b" not in error.message
    assert "\\x1b" in error.message
    assert error.details == {"api_key": "[REDACTED]", "request_id": "req-1"}
