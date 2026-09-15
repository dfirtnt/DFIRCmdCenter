from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from dfircmdcenter.adapters.limacharlie.client import (
    complete_metadata_payload,
    rule_data_path,
)
from dfircmdcenter.adapters.limacharlie.replay import ReplayResult
from dfircmdcenter.adapters.limacharlie.rules import (
    RuleDefinition,
    RuleGovernanceError,
    build_rule_proposal,
    load_rule,
    merge_complete_metadata,
)
from dfircmdcenter.adapters.limacharlie.validation import (
    RuleTestResult,
    validate_rule_results,
)

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "platforms" / "limacharlie" / "rules"
NOW = datetime(2026, 9, 15, 18, tzinfo=UTC)


def rule(name: str = "windows-suspicious-powershell") -> RuleDefinition:
    return load_rule(RULES / f"{name}.yaml")


def passing_validation(candidate: RuleDefinition) -> dict[str, object]:
    event_type = next(iter(candidate.event_types))
    return validate_rule_results(
        candidate,
        validator_rule_digest=candidate.digest,
        validator_passed=True,
        tests=(
            RuleTestResult("expected suspicious event", event_type, True, True),
            RuleTestResult("expected benign event", event_type, False, False),
        ),
    )


def test_all_initial_rules_are_disabled_report_only_and_versioned() -> None:
    loaded = [load_rule(path) for path in sorted(RULES.glob("*.yaml"))]

    assert len(loaded) == 5
    assert all(not candidate.enabled for candidate in loaded)
    assert all(candidate.version == 1 for candidate in loaded)
    assert all(
        response["action"] == "report"
        for candidate in loaded
        for response in candidate.respond
    )


def test_unknown_response_action_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "unsafe.yaml"
    path.write_text(
        """
name: unsafe-rule
version: 1
enabled: false
stateful: false
detect:
  events: [NEW_PROCESS]
  op: exists
  path: event/FILE_PATH
respond:
  - action: isolate
usr_mtd:
  description: unsafe
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(RuleGovernanceError, match="report"):
        load_rule(path)


def test_metadata_update_preserves_complete_current_object() -> None:
    current = {
        "description": "old",
        "author": "Andrew",
        "false_positives": ["admin"],
        "custom": {"ticket": "one"},
    }
    updated = merge_complete_metadata(current, {"description": "new"})

    assert updated == {**current, "description": "new"}
    assert complete_metadata_payload(updated) == {"usr_mtd": updated}


def test_validator_and_tests_bind_to_exact_rule_version() -> None:
    candidate = rule()
    with pytest.raises(RuleGovernanceError, match="different rule version"):
        validate_rule_results(
            candidate,
            validator_rule_digest="a" * 64,
            validator_passed=True,
            tests=(
                RuleTestResult("match", "NEW_PROCESS", True, True),
                RuleTestResult("non-match", "NEW_PROCESS", False, False),
            ),
        )
    with pytest.raises(RuleGovernanceError, match="outcome differs"):
        validate_rule_results(
            candidate,
            validator_rule_digest=candidate.digest,
            validator_passed=True,
            tests=(
                RuleTestResult("false non-match", "NEW_PROCESS", False, True),
                RuleTestResult("match", "NEW_PROCESS", True, True),
            ),
        )


def test_stateful_rule_requires_completed_exact_replay() -> None:
    base = rule()
    stateful = RuleDefinition(
        name=base.name,
        detect=base.detect,
        respond=base.respond,
        usr_mtd=base.usr_mtd,
        enabled=base.enabled,
        version=base.version,
        stateful=True,
    )
    validation = passing_validation(stateful)
    with pytest.raises(RuleGovernanceError, match="Replay"):
        build_rule_proposal(
            organization_id="oid-fixture",
            operation="create",
            desired=stateful,
            current=None,
            validation=validation,
            replay=None,
            policy_version="1",
            created_at=NOW,
        )

    replay = ReplayResult(
        rule_digest=stateful.digest,
        sensor_ids=("sensor-one",),
        start_at=NOW - timedelta(hours=1),
        end_at=NOW,
        job_id="replay-one",
        completed=True,
        passed=True,
    )
    proposal = build_rule_proposal(
        organization_id="oid-fixture",
        operation="create",
        desired=stateful,
        current=None,
        validation=validation,
        replay=replay.validation(stateful),
        policy_version="1",
        created_at=NOW,
    )
    assert proposal.operation == "rule_create"
    assert proposal.validation["replay"]["sensor_ids"] == ("sensor-one",)  # type: ignore[index]


def test_rule_proposal_pins_current_rule_and_complete_metadata() -> None:
    current = rule()
    desired = RuleDefinition(
        name=current.name,
        detect=current.detect,
        respond=current.respond,
        usr_mtd=merge_complete_metadata(current.usr_mtd, {"description": "reviewed update"}),
        enabled=True,
        version=2,
        stateful=False,
    )
    proposal = build_rule_proposal(
        organization_id="oid-fixture",
        operation="update",
        desired=desired,
        current=current,
        validation=passing_validation(desired),
        replay=None,
        policy_version="1",
        created_at=NOW,
    )

    assert proposal.preconditions["current_rule_digest"] == current.digest
    assert proposal.preconditions["complete_usr_mtd_digest"]
    assert proposal.dependency_hashes["rule"] == desired.digest


def test_api_paths_reject_arbitrary_path_content() -> None:
    assert rule_data_path("oid-fixture", "safe-rule").endswith("/safe-rule/data")
    with pytest.raises(ValueError):
        rule_data_path("oid-fixture", "../other")

