from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml  # type: ignore[import-untyped]

from dfircmdcenter.adapters.base import (
    Adapter,
    AdapterCapability,
    AdapterIdentity,
    RevalidationResult,
    SubmissionResult,
    VerificationResult,
)

ROOT = Path(__file__).resolve().parents[2]
PLATFORMS = ("action1", "limacharlie", "velociraptor", "splunk")


def _contracts() -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for platform in PLATFORMS:
        path = ROOT / "platforms" / platform / "contracts.yaml"
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert isinstance(loaded, dict)
        result[platform] = loaded
    return result


def test_contracts_name_every_platform_and_use_fixed_safe_surfaces() -> None:
    for expected_platform, contract in _contracts().items():
        assert contract["schema_version"] == 1
        assert contract["contract_version"] == 1
        assert contract["platform"] == expected_platform
        assert contract["verified_at"]

        transport = contract["transport"]
        assert isinstance(transport, dict)
        assert transport.get("redirects", "disabled") == "disabled"
        for origin in transport.get("origins", []):
            parsed = urlsplit(origin)
            assert parsed.scheme == "https"
            assert parsed.hostname
            assert not parsed.username and not parsed.password
            assert parsed.path == "" and not parsed.query and not parsed.fragment
            assert "*" not in origin

        capabilities = contract["capabilities"]
        assert isinstance(capabilities, list) and capabilities
        names = [item["name"] for item in capabilities]
        assert len(names) == len(set(names))
        for capability in capabilities:
            assert capability["mode"] in {"read", "write"}
            assert isinstance(capability["enabled"], bool)
            assert capability["surface"]
            assert capability["required_permissions"]
            if capability["enabled"]:
                assert "disabled_reason" not in capability
            else:
                assert capability["disabled_reason"]


def test_unknown_write_safety_disables_writes() -> None:
    for contract in _contracts().values():
        conditional = contract["conditional_update"]
        idempotency = contract["idempotency"]
        assert isinstance(conditional, dict)
        assert isinstance(idempotency, dict)
        safety_unknown = "unknown" in {
            conditional["status"],
            idempotency["status"],
        }
        if safety_unknown:
            assert not any(
                capability["enabled"]
                for capability in contract["capabilities"]
                if capability["mode"] == "write"
            )


def test_contracts_contain_no_secret_material() -> None:
    forbidden_keys = {
        "access_token",
        "api_key",
        "authorization",
        "client_secret",
        "password",
        "private_key",
        "refresh_token",
    }

    def walk(value: object) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                assert str(key).lower() not in forbidden_keys
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    for contract in _contracts().values():
        walk(contract)


class FixtureAdapter:
    platform = "fixture"

    def capabilities(self) -> Sequence[AdapterCapability]:
        return (AdapterCapability("status", "read", True),)

    def identity(self) -> AdapterIdentity:
        return AdapterIdentity("fixture", "fixture-1", "1")

    def status_snapshot(self, *, scope: Mapping[str, object]) -> object:
        return {"scope": dict(scope), "status": "fixture"}

    def build_proposal(
        self,
        *,
        operation: str,
        scope: Mapping[str, object],
        desired: Mapping[str, object],
        snapshot: object,
    ) -> object:
        return {"operation": operation, "scope": scope, "desired": desired, "before": snapshot}

    def revalidate(self, *, proposal: object) -> RevalidationResult:
        return RevalidationResult(True, "fixture-state")

    def submit(self, *, proposal: object, execution_id: str) -> SubmissionResult:
        return SubmissionResult("accepted", remote_id=execution_id)

    def verify(
        self,
        *,
        proposal: object,
        submission: SubmissionResult,
    ) -> VerificationResult:
        return VerificationResult("verified", state_digest="fixture-after")

    def reconcile(self, *, proposal: object, execution_id: str) -> VerificationResult:
        return VerificationResult("unknown", summary=execution_id)


def test_fixture_adapter_satisfies_runtime_protocol_without_credentials() -> None:
    adapter = FixtureAdapter()
    assert isinstance(adapter, Adapter)
    assert adapter.identity().instance_id == "fixture-1"
    snapshot = adapter.status_snapshot(scope={"fixture": True})
    assert isinstance(snapshot, dict)
    assert snapshot["status"] == "fixture"
