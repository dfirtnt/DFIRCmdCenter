from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from dfircmdcenter.adapters.action1.client import (
    Action1Page,
    Action1ResponseError,
    collect_all,
    managed_endpoints_path,
    parse_page,
    safe_oauth_error,
)
from dfircmdcenter.adapters.action1.deployments import build_deployment_proposal
from dfircmdcenter.adapters.action1.inventory import DeploymentPackage, EndpointIdentity
from dfircmdcenter.adapters.action1.verification import (
    UNSIGNED_SUBJECT_CODE,
    Action1InstallState,
    VelociraptorCheckin,
    verify_deployment,
)
from dfircmdcenter.core.records import VerificationStatus

NOW = datetime(2026, 9, 15, 18, tzinfo=UTC)


def package() -> DeploymentPackage:
    return DeploymentPackage(
        package_id="package-velociraptor-0772",
        version="0.77.2",
        upstream_sha256="a" * 64,
        repackaged_sha256="b" * 64,
        client_configuration_sha256="c" * 64,
        provenance="locally built personal MSI from pinned Velociraptor client configuration",
    )


def identity(*, strong: bool = True) -> EndpointIdentity:
    return EndpointIdentity(
        action1_endpoint_id="endpoint-one",
        velociraptor_client_id="C.clientone",
        action1_hostname="lab-win11",
        velociraptor_hostname="lab-win11",
        action1_machine_id="machine-one" if strong else None,
        velociraptor_machine_id="machine-one" if strong else None,
    )


def test_action1_pagination_is_complete_and_secret_fields_are_redacted() -> None:
    # fetch is keyed by offset ("from"), matching every real Action1 list
    # response, not by an integer next_page (Action1 never returns one).
    pages = {
        0: Action1Page(
            ({"id": "one", "api_key": "secret"},), 2, 1, "/API/endpoints/managed?from=1&limit=1"
        ),
        1: Action1Page(({"id": "two"},), 2, 1, None),
    }
    collected = collect_all(pages.__getitem__)
    assert [item["id"] for item in collected] == ["one", "two"]

    # ResultPage envelope shape: next_page is a relative continuation URL.
    parsed = parse_page(
        json.dumps(
            {
                "items": [{"id": "one", "access_token": "secret"}],
                "total_items": 1,
                "limit": 50,
                "next_page": "/API/endpoints/managed?from=50&limit=50",
            }
        ).encode()
    )
    assert parsed.items[0]["access_token"] == "[REDACTED]"
    assert parsed.next_page == "/API/endpoints/managed?from=50&limit=50"

    # Offset envelope shape: no next_page field at all.
    parsed_offset_envelope = parse_page(
        json.dumps(
            {
                "items": [{"id": "two"}],
                "total_items": 1,
                "limit": 50,
                "from": 0,
            }
        ).encode()
    )
    assert parsed_offset_envelope.next_page is None
    assert parsed_offset_envelope.items[0]["id"] == "two"


def test_action1_pagination_detects_truncation_loop_and_changed_total() -> None:
    with pytest.raises(Action1ResponseError, match="incomplete"):
        collect_all(lambda _offset: Action1Page(({"id": "one"},), 2, 50, None))
    with pytest.raises(Action1ResponseError, match="page limit"):
        collect_all(
            lambda offset: Action1Page(({"id": f"item-{offset}"},), None, 1, None),
            max_pages=3,
        )

    pages = {
        0: Action1Page(({"id": "one"},), 2, 1, "/API/endpoints/managed?from=1&limit=1"),
        1: Action1Page(({"id": "two"},), 3, 1, None),
    }
    with pytest.raises(Action1ResponseError, match="total changed"):
        collect_all(pages.__getitem__)


def test_oauth_errors_and_paths_never_echo_secret_material() -> None:
    error = safe_oauth_error(401)
    assert "401" in str(error)
    assert "secret" not in str(error)
    assert managed_endpoints_path("org-one") == "/endpoints/managed/org-one"
    with pytest.raises(ValueError):
        managed_endpoints_path("../org-two")


def test_hostname_only_identity_is_rejected() -> None:
    with pytest.raises(ValueError, match="hostname alone"):
        identity(strong=False).require_verified()


def test_deployment_proposal_pins_package_endpoint_and_checkin() -> None:
    proposal = build_deployment_proposal(
        organization_id="org-one",
        automation_id="automation-one",
        endpoint=identity(),
        package=package(),
        expected_checkin_window_seconds=600,
        deployment_settings={"run_as": "system"},
        current_deployment_state={"installed_version": None},
        policy_version="1",
        created_at=NOW,
    )
    assert proposal.scope["endpoint_id"] == "endpoint-one"
    assert proposal.scope["velociraptor_client_id"] == "C.clientone"
    assert proposal.expected_effects["unsigned_installer_warning_may_remain"] is True


def install_state(*, version: str | None = "0.77.2") -> Action1InstallState:
    return Action1InstallState(
        operation_status="warning",
        installed=version is not None,
        installed_version=version,
        warning_codes=(UNSIGNED_SUBJECT_CODE,),
    )


def checkin(*, client: str = "C.clientone", minutes: int = 3) -> VelociraptorCheckin:
    return VelociraptorCheckin(
        client_id=client,
        observed_at=NOW + timedelta(minutes=minutes),
        identity_correlated=True,
    )


def verify(action1: Action1InstallState, velo: VelociraptorCheckin | None):
    return verify_deployment(
        checked_at=NOW + timedelta(minutes=10),
        expected_version="0.77.2",
        expected_client_id="C.clientone",
        deployment_started_at=NOW,
        checkin_window=timedelta(minutes=10),
        action1=action1,
        velociraptor=velo,
    )


def test_unsigned_warning_is_preserved_but_not_install_failure() -> None:
    result = verify(install_state(), checkin())
    assert result.status is VerificationStatus.PASSED
    assert result.checks["unsigned_installer_warning_preserved"] is True


def test_install_requires_exact_version_and_fresh_correlated_velociraptor_checkin() -> None:
    assert verify(install_state(version="0.77.1"), checkin()).status is VerificationStatus.FAILED
    assert verify(install_state(), None).status is VerificationStatus.PARTIAL
    assert verify(install_state(), checkin(client="C.other")).status is VerificationStatus.PARTIAL
    assert verify(install_state(), checkin(minutes=30)).status is VerificationStatus.PARTIAL

