"""Bind LimaCharlie validator and fixture tests to one exact rule version."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from .rules import RuleDefinition, RuleGovernanceError


@dataclass(frozen=True, slots=True)
class RuleTestResult:
    name: str
    event_type: str
    expected_match: bool
    observed_match: bool


def validate_rule_results(
    rule: RuleDefinition,
    *,
    validator_rule_digest: str,
    validator_passed: bool,
    tests: Sequence[RuleTestResult],
) -> dict[str, object]:
    if validator_rule_digest != rule.digest:
        raise RuleGovernanceError("validator result belongs to a different rule version")
    if not validator_passed:
        raise RuleGovernanceError("LimaCharlie validator rejected the rule")
    if not tests or not any(item.expected_match for item in tests) or not any(
        not item.expected_match for item in tests
    ):
        raise RuleGovernanceError("rule tests require meaningful match and non-match cases")
    for result in tests:
        if result.event_type not in rule.event_types:
            raise RuleGovernanceError("rule test event type does not match the rule")
        if result.expected_match is not result.observed_match:
            raise RuleGovernanceError(f"rule test outcome differs from expectation: {result.name}")
    return {
        "passed": True,
        "rule_digest": rule.digest,
        "validator_passed": True,
        "tests": [
            {
                "name": item.name,
                "event_type": item.event_type,
                "expected_match": item.expected_match,
                "observed_match": item.observed_match,
            }
            for item in tests
        ],
    }

