"""Stateful-rule Replay scope and completion checks."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from dfircmdcenter.core.time import ensure_utc

from .rules import RuleDefinition, RuleGovernanceError


@dataclass(frozen=True, slots=True)
class ReplayResult:
    rule_digest: str
    sensor_ids: tuple[str, ...]
    start_at: datetime
    end_at: datetime
    job_id: str
    completed: bool
    passed: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "start_at", ensure_utc(self.start_at))
        object.__setattr__(self, "end_at", ensure_utc(self.end_at))
        if not self.sensor_ids or self.end_at <= self.start_at:
            raise ValueError("Replay requires exact sensors and a valid time range")

    def validation(self, rule: RuleDefinition) -> dict[str, object]:
        if self.rule_digest != rule.digest:
            raise RuleGovernanceError("Replay result belongs to a different rule version")
        if not self.completed or not self.passed:
            raise RuleGovernanceError("Replay did not complete with a passing result")
        return {
            "passed": True,
            "rule_digest": self.rule_digest,
            "sensor_ids": self.sensor_ids,
            "start_at": self.start_at,
            "end_at": self.end_at,
            "job_id": self.job_id,
        }

