"""Exact Velociraptor collection specifications and proposals."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from dfircmdcenter.config import load_yaml
from dfircmdcenter.core.canonical import canonical_digest
from dfircmdcenter.core.records import Platform, Proposal

from .scope import ResolvedClientScope


@dataclass(frozen=True, slots=True)
class CollectionSpec:
    artifact: str
    artifact_sha256: str
    parameters: Mapping[str, Any]
    timeout_seconds: int
    max_rows: int
    max_upload_bytes: int
    expected_tables: tuple[str, ...]
    expected_upload_classes: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.artifact.strip() or len(self.artifact_sha256) != 64:
            raise ValueError("collection requires an exact artifact and SHA-256")
        if min(self.timeout_seconds, self.max_rows, self.max_upload_bytes) <= 0:
            raise ValueError("collection resource limits must be positive")

    @property
    def digest(self) -> str:
        return canonical_digest(self)


def load_collection_spec(path: Path) -> CollectionSpec:
    loaded = load_yaml(path)
    if not isinstance(loaded, dict):
        raise ValueError("collection specification must be a mapping")
    expected = loaded.get("expected_tables")
    uploads = loaded.get("expected_upload_classes")
    parameters = loaded.get("parameters")
    if not isinstance(expected, list) or not all(isinstance(item, str) for item in expected):
        raise ValueError("expected_tables must be a list of names")
    if not isinstance(uploads, list) or not all(isinstance(item, str) for item in uploads):
        raise ValueError("expected_upload_classes must be a list of names")
    if not isinstance(parameters, dict):
        raise ValueError("parameters must be a mapping")
    return CollectionSpec(
        artifact=str(loaded.get("artifact", "")),
        artifact_sha256=str(loaded.get("artifact_sha256", "")),
        parameters=parameters,
        timeout_seconds=int(loaded.get("timeout_seconds", 0)),
        max_rows=int(loaded.get("max_rows", 0)),
        max_upload_bytes=int(loaded.get("max_upload_bytes", 0)),
        expected_tables=tuple(expected),
        expected_upload_classes=tuple(uploads),
    )


def build_collection_proposal(
    *,
    scope: ResolvedClientScope,
    specification: CollectionSpec,
    policy_version: str,
    server_identity: str,
    created_at: datetime,
) -> Proposal:
    return Proposal.create(
        platform=Platform.VELOCIRAPTOR,
        operation="launch_collection",
        scope={
            "server_identity": server_identity,
            "client_ids": scope.client_ids,
            "source_label": scope.source_label,
            "artifact": specification.artifact,
        },
        preconditions={
            "server_identity": server_identity,
            "client_scope_digest": scope.digest,
            "artifact_sha256": specification.artifact_sha256,
        },
        policy_version=policy_version,
        dependency_hashes={"collection_spec": specification.digest},
        validation={
            "parameters": specification.parameters,
            "timeout_seconds": specification.timeout_seconds,
            "max_rows": specification.max_rows,
            "max_upload_bytes": specification.max_upload_bytes,
        },
        expires_at=created_at + timedelta(minutes=20),
        expected_effects={
            "flow_count": len(scope.client_ids),
            "expected_tables": specification.expected_tables,
            "expected_upload_classes": specification.expected_upload_classes,
        },
        before_state={"client_ids": scope.client_ids},
        proposed_after_state={"new_flow_per_client": True},
        human_diff=(
            f"Launch {specification.artifact} once on exact clients "
            f"{', '.join(scope.client_ids)}."
        ),
        rollback_or_recovery=(
            "Cancel only flows that have not started. Preserve completed results; any further "
            "collection is a separate approved operation."
        ),
        created_at=created_at,
    )
