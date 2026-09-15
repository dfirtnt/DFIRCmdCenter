"""Supported Velociraptor flow and hunt export planning."""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

from dfircmdcenter.config import PROJECT_ROOT
from dfircmdcenter.core.records import Platform, Proposal

from .client import client_id, flow_id, hunt_id


def build_export_proposal(
    *,
    kind: str,
    identifier: str,
    client: str | None,
    server_identity: str,
    destination_root: Path,
    policy_version: str,
    created_at: datetime,
    allowed_export_root: Path | None = None,
) -> Proposal:
    if kind == "flow":
        if client is None:
            raise ValueError("flow export requires an exact client ID")
        exact_client = client_id(client)
        exact_identifier = flow_id(identifier)
    elif kind == "hunt":
        if client is not None:
            raise ValueError("hunt export does not accept a client ID")
        exact_client = None
        exact_identifier = hunt_id(identifier)
    else:
        raise ValueError("export kind must be flow or hunt")
    if not destination_root.is_absolute():
        raise ValueError("export root must be absolute")
    allowed = (allowed_export_root or PROJECT_ROOT / "var" / "velociraptor" / "exports").resolve(
        strict=False
    )
    destination = destination_root.resolve(strict=False)
    if destination != allowed and not destination.is_relative_to(allowed):
        raise ValueError("export destination is outside the governed output root")
    return Proposal.create(
        platform=Platform.VELOCIRAPTOR,
        operation=f"create_{kind}_export",
        scope={
            "server_identity": server_identity,
            "kind": kind,
            "identifier": exact_identifier,
            "client_id": exact_client,
            "destination_root": str(destination),
        },
        preconditions={
            "server_identity": server_identity,
            "source_state": "finished",
            "source_identifier": exact_identifier,
        },
        policy_version=policy_version,
        dependency_hashes={"export_contract": f"create_{kind}_download_v1"},
        validation={"destination_contained": True},
        expires_at=created_at + timedelta(minutes=20),
        expected_effects={"server_export_job_count": 1, "local_archive_count": 1},
        before_state={"export_exists": False},
        proposed_after_state={"export_prepared": True},
        human_diff=f"Prepare one supported {kind} export for {exact_identifier}.",
        rollback_or_recovery=(
            "Poll the exact export job with reads. Do not create another job after an "
            "ambiguous response; reconcile by identifier."
        ),
        created_at=created_at,
    )
