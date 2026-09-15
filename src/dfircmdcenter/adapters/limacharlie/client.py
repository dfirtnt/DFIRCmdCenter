"""Fixed LimaCharlie D&R API path and payload shapes."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")


def _identifier(value: str, field: str) -> str:
    if not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{field} is not a safe configured identifier")
    return value


def rule_data_path(organization_id: str, rule_name: str) -> str:
    return (
        f"/hive/dr-general/{_identifier(organization_id, 'organization_id')}/"
        f"{_identifier(rule_name, 'rule_name')}/data"
    )


def rule_metadata_path(organization_id: str, rule_name: str) -> str:
    return (
        f"/hive/dr-general/{_identifier(organization_id, 'organization_id')}/"
        f"{_identifier(rule_name, 'rule_name')}/mtd"
    )


def complete_metadata_payload(metadata: Mapping[str, Any]) -> Mapping[str, Any]:
    """Return the complete replacement object expected by LimaCharlie metadata POST."""

    return {"usr_mtd": dict(metadata)}

