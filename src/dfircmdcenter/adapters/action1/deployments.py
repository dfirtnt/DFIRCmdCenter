"""Exact Action1 Velociraptor deployment proposals."""

from __future__ import annotations

from datetime import datetime, timedelta

from dfircmdcenter.core.canonical import canonical_digest
from dfircmdcenter.core.records import Platform, Proposal

from .inventory import DeploymentPackage, EndpointIdentity


def build_deployment_proposal(
    *,
    organization_id: str,
    automation_id: str,
    endpoint: EndpointIdentity,
    package: DeploymentPackage,
    expected_checkin_window_seconds: int,
    deployment_settings: dict[str, object],
    current_deployment_state: dict[str, object],
    policy_version: str,
    created_at: datetime,
) -> Proposal:
    endpoint.require_verified()
    if expected_checkin_window_seconds <= 0:
        raise ValueError("expected check-in window must be positive")
    return Proposal.create(
        platform=Platform.ACTION1,
        operation="deploy_velociraptor",
        scope={
            "organization_id": organization_id,
            "automation_id": automation_id,
            "endpoint_id": endpoint.action1_endpoint_id,
            "velociraptor_client_id": endpoint.velociraptor_client_id,
            "package_id": package.package_id,
            "package_version": package.version,
        },
        preconditions={
            "endpoint_identity_digest": canonical_digest(endpoint),
            "current_deployment_state_digest": canonical_digest(current_deployment_state),
            "package_upstream_sha256": package.upstream_sha256,
            "package_repackaged_sha256": package.repackaged_sha256,
            "client_configuration_sha256": package.client_configuration_sha256,
        },
        policy_version=policy_version,
        dependency_hashes={
            "package": canonical_digest(package),
            "deployment_settings": canonical_digest(deployment_settings),
        },
        validation={
            "endpoint_identity_correlated": True,
            "provenance": package.provenance,
            "expected_checkin_window_seconds": expected_checkin_window_seconds,
        },
        expires_at=created_at + timedelta(minutes=20),
        expected_effects={
            "installed_version": package.version,
            "fresh_velociraptor_checkin": True,
            "unsigned_installer_warning_may_remain": True,
        },
        before_state=current_deployment_state,
        proposed_after_state={
            "installed": True,
            "version": package.version,
            "velociraptor_checkin_required": True,
        },
        human_diff=(
            f"Deploy Velociraptor {package.version} through Action1 automation "
            f"{automation_id} to endpoint {endpoint.action1_endpoint_id}."
        ),
        rollback_or_recovery=(
            "Do not resubmit after ambiguity. Reconcile the exact Action1 deployment and "
            "Velociraptor client check-in. Removal is a separate approved operation."
        ),
        created_at=created_at,
    )

