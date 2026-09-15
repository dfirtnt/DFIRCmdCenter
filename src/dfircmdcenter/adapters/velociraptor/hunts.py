"""Immediate and standing Velociraptor hunt proposals."""

from __future__ import annotations

from datetime import datetime, timedelta

from dfircmdcenter.core.records import Platform, Proposal

from .collections import CollectionSpec
from .scope import ResolvedClientScope, StandingHuntScope


def build_hunt_proposal(
    *,
    scope: ResolvedClientScope | StandingHuntScope,
    specification: CollectionSpec,
    policy_version: str,
    server_identity: str,
    created_at: datetime,
) -> Proposal:
    scope_payload: dict[str, object]
    if isinstance(scope, StandingHuntScope):
        standing = True
        scope_payload = {
            "kind": "standing_label",
            "label": scope.label,
            "current_client_ids": scope.current_client_ids,
            "includes_future_matching_clients": True,
        }
    else:
        standing = False
        scope_payload = {
            "kind": "resolved_clients",
            "client_ids": scope.client_ids,
            "source_label": scope.source_label,
            "includes_future_matching_clients": False,
        }
    return Proposal.create(
        platform=Platform.VELOCIRAPTOR,
        operation="create_standing_hunt" if standing else "create_resolved_hunt",
        scope={
            "server_identity": server_identity,
            "target": scope_payload,
            "artifact": specification.artifact,
        },
        preconditions={
            "server_identity": server_identity,
            "scope_digest": scope.digest,
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
            "hunt_count": 1,
            "includes_future_matching_clients": standing,
            "expected_tables": specification.expected_tables,
            "expected_upload_classes": specification.expected_upload_classes,
        },
        before_state={"target": scope_payload},
        proposed_after_state={"hunt_created": True},
        human_diff=(
            f"Create one {'standing' if standing else 'resolved-client'} hunt for "
            f"{specification.artifact}; future matching clients="
            f"{'yes' if standing else 'no'}."
        ),
        rollback_or_recovery=(
            "Stop the exact hunt under a separate approval. Preserve any results already "
            "collected."
        ),
        created_at=created_at,
    )
