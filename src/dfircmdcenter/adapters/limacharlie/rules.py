"""Versioned report-only LimaCharlie D&R rule lifecycle."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from dfircmdcenter.config import load_yaml
from dfircmdcenter.core.canonical import canonical_digest
from dfircmdcenter.core.records import Platform, Proposal

_RULE_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,127}$")
_OPERATIONS = frozenset({"create", "update", "enable", "disable", "delete", "metadata"})


class RuleGovernanceError(ValueError):
    """A rule or requested lifecycle action is outside the safe contract."""


@dataclass(frozen=True, slots=True)
class RuleDefinition:
    name: str
    detect: Mapping[str, Any]
    respond: tuple[Mapping[str, Any], ...]
    usr_mtd: Mapping[str, Any]
    enabled: bool
    version: int
    stateful: bool

    @property
    def digest(self) -> str:
        return canonical_digest(
            {
                "name": self.name,
                "detect": self.detect,
                "respond": self.respond,
                "usr_mtd": self.usr_mtd,
                "enabled": self.enabled,
                "version": self.version,
                "stateful": self.stateful,
            }
        )

    @property
    def event_types(self) -> frozenset[str]:
        raw = self.detect.get("events", self.detect.get("event", ()))
        if isinstance(raw, str):
            return frozenset({raw})
        if isinstance(raw, Sequence) and not isinstance(raw, str):
            return frozenset(item for item in raw if isinstance(item, str))
        return frozenset()


def _mapping(value: object, field: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise RuleGovernanceError(f"{field} must be a mapping")
    return value


def _responses(value: object) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, list) or not value:
        raise RuleGovernanceError("respond must be a non-empty list")
    responses: list[Mapping[str, Any]] = []
    for response in value:
        mapped = _mapping(response, "respond item")
        if mapped.get("action") != "report":
            raise RuleGovernanceError("initial LimaCharlie rules may only use report actions")
        responses.append(mapped)
    return tuple(responses)


def load_rule(path: Path) -> RuleDefinition:
    loaded = load_yaml(path)
    if not isinstance(loaded, dict):
        raise RuleGovernanceError("rule file root must be a mapping")
    name = loaded.get("name")
    version = loaded.get("version")
    enabled = loaded.get("enabled", False)
    stateful = loaded.get("stateful", False)
    if not isinstance(name, str) or not _RULE_NAME.fullmatch(name):
        raise RuleGovernanceError("rule name is invalid")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise RuleGovernanceError("rule version must be a positive integer")
    if not isinstance(enabled, bool) or not isinstance(stateful, bool):
        raise RuleGovernanceError("enabled and stateful must be booleans")
    detect = _mapping(loaded.get("detect"), "detect")
    if not detect:
        raise RuleGovernanceError("detect must not be empty")
    metadata = _mapping(loaded.get("usr_mtd"), "usr_mtd")
    rule = RuleDefinition(
        name=name,
        detect=detect,
        respond=_responses(loaded.get("respond")),
        usr_mtd=metadata,
        enabled=enabled,
        version=version,
        stateful=stateful,
    )
    if not rule.event_types:
        raise RuleGovernanceError("rule must declare at least one event type")
    return rule


def merge_complete_metadata(
    current: Mapping[str, Any],
    updates: Mapping[str, Any],
    *,
    remove_keys: frozenset[str] = frozenset(),
) -> Mapping[str, Any]:
    result = dict(current)
    for key in remove_keys:
        result.pop(key, None)
    result.update(updates)
    return result


def build_rule_proposal(
    *,
    organization_id: str,
    operation: str,
    desired: RuleDefinition | None,
    current: RuleDefinition | None,
    validation: Mapping[str, Any],
    replay: Mapping[str, Any] | None,
    policy_version: str,
    created_at: datetime,
) -> Proposal:
    if operation not in _OPERATIONS:
        raise RuleGovernanceError("unsupported rule operation")
    if operation == "create" and current is not None:
        raise RuleGovernanceError("create requires the rule to be absent")
    if operation != "create" and current is None:
        raise RuleGovernanceError(f"{operation} requires an existing live rule")
    if operation == "delete":
        rule = current
    else:
        rule = desired
    if rule is None:
        raise RuleGovernanceError("the operation has no exact rule definition")
    if current is not None and desired is not None and current.name != desired.name:
        raise RuleGovernanceError("rule rename is not a supported lifecycle operation")
    if validation.get("rule_digest") != rule.digest or validation.get("passed") is not True:
        raise RuleGovernanceError("validation is not bound to the exact rule digest")
    if rule.stateful:
        if (
            replay is None
            or replay.get("rule_digest") != rule.digest
            or replay.get("passed") is not True
        ):
            raise RuleGovernanceError("stateful rule requires a passing bound Replay")

    before = None if current is None else {"rule_digest": current.digest, "rule": current}
    after = None if operation == "delete" else {"rule_digest": rule.digest, "rule": rule}
    return Proposal.create(
        platform=Platform.LIMACHARLIE,
        operation=f"rule_{operation}",
        scope={"organization_id": organization_id, "rule_name": rule.name},
        preconditions={
            "organization_id": organization_id,
            "current_rule_digest": current.digest if current is not None else None,
            "complete_usr_mtd_digest": (
                canonical_digest(current.usr_mtd) if current is not None else None
            ),
        },
        policy_version=policy_version,
        dependency_hashes={"rule": rule.digest},
        validation={"rule_validation": validation, "replay": replay},
        expires_at=created_at + timedelta(minutes=20),
        expected_effects={
            "operation": operation,
            "enabled": None if after is None else rule.enabled,
        },
        before_state={"live": before},
        proposed_after_state={"live": after},
        human_diff=f"{operation} report-only LimaCharlie rule {rule.name} in {organization_id}.",
        rollback_or_recovery=(
            "Re-read the complete rule and metadata. Any reversal or deletion requires a new "
            "proposal and approval."
        ),
        created_at=created_at,
    )
