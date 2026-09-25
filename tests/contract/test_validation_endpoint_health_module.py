from __future__ import annotations

import json
import re
from hashlib import sha256
from pathlib import Path
from typing import Any

import pytest
import yaml

from dfircmdcenter.core.redaction import contains_secret_fields
from dfircmdcenter.core.untrusted import escape_terminal_controls, scan_prompt_injection

ROOT = Path(__file__).resolve().parents[2]
MODULE_ROOT = ROOT / "hardening" / "modules" / "validation.endpoint-health"
FIXTURE_PATH = ROOT / "hardening" / "fixtures" / "windows11-home" / "endpoint-health.json"

EXPECTED_TOP_LEVEL_KEYS = {
    "SchemaVersion",
    "Module",
    "CapturedAtUtc",
    "CollectionMode",
    "OperatingSystem",
    "SecureBoot",
    "Tpm",
    "Antivirus",
    "Firewall",
    "PlatformProtections",
    "Agents",
    "CollectionErrors",
    "Limitations",
}

PROHIBITED_KEYS = {
    "hostname",
    "fqdn",
    "username",
    "sid",
    "serialnumber",
    "serial_number",
    "macaddress",
    "mac_address",
    "ipaddress",
    "ip_address",
    "ssid",
    "machineguid",
    "machine_guid",
    "deviceid",
    "device_id",
    "endpointid",
    "endpoint_id",
    "sensorid",
    "sensor_id",
    "installerid",
    "installer_id",
    "organizationid",
    "organization_id",
    "clientid",
    "client_id",
    "ownerauth",
    "recoverypassword",
    "recovery_password",
    "remediationpath",
    "remediation_path",
    "executablepath",
    "executable_path",
    "password",
    "token",
    "secret",
    "authorization",
    "recoverykey",
    "protectorid",
    "path",
}

EXPECTED_NESTED_KEYS = {
    "OperatingSystem": {
        "Status",
        "Family",
        "Edition",
        "Release",
        "Build",
        "Revision",
        "Architecture",
        "ProductType",
    },
    "SecureBoot": {"Status", "Supported", "Enabled"},
    "Tpm": {"Status", "Present", "Ready", "Enabled", "Activated", "SpecVersion"},
    "Antivirus": {
        "Status",
        "Products",
        "ActiveProviderFamilies",
        "Assessment",
        "DefenderDependentControls",
    },
    "Firewall": {
        "Status",
        "Products",
        "Profiles",
        "ActiveNetworkCategories",
        "Assessment",
    },
    "PlatformProtections": {"MemoryIntegrity"},
    "Agents": {"Action1", "LimaCharlie", "Velociraptor", "IdentityCorrelation"},
}

EXPECTED_PRODUCT_KEYS = {"ProviderFamily", "State", "Signatures"}
EXPECTED_PROFILE_KEYS = {
    "Name",
    "Enabled",
    "DefaultInboundAction",
    "DefaultOutboundAction",
    "LogBlocked",
}
EXPECTED_MEMORY_INTEGRITY_KEYS = {"Status", "Configured", "Running"}

PROHIBITED_MUTATION_PATTERNS = (
    r"\bSet-Item(?:Property)?\b",
    r"\bNew-Item(?:Property)?\b",
    r"\bRemove-Item(?:Property)?\b",
    r"\b(?:Start|Stop|Restart|Set)-Service\b",
    r"\b(?:Enable|Disable)-WindowsOptionalFeature\b",
    r"\bSet-MpPreference\b",
    r"\bSet-NetFirewall(?:Profile|Rule)\b",
    r"\bmanage-bde\b",
    r"\bauditpol(?:\.exe)?\s+/set\b",
    r"\breg(?:\.exe)?\s+(?:add|delete)\b",
    r"\bInvoke-WebRequest\b",
    r"\bStart-Process\b",
)


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_strict_json(path: Path) -> dict[str, Any]:
    data = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=_strict_object,
        parse_constant=lambda value: (_ for _ in ()).throw(
            ValueError(f"non-finite JSON number: {value}")
        ),
    )
    assert isinstance(data, dict)
    return data


def _walk_keys(value: Any) -> set[str]:
    keys: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            keys.add(key.lower())
            keys.update(_walk_keys(child))
    elif isinstance(value, list):
        for child in value:
            keys.update(_walk_keys(child))
    return keys


def test_endpoint_health_module_is_verify_only_and_hash_pinned() -> None:
    module = yaml.safe_load((MODULE_ROOT / "module.yaml").read_text(encoding="utf-8"))["module"]
    manifest = yaml.safe_load((MODULE_ROOT / "artifacts.yaml").read_text(encoding="utf-8"))

    assert module["id"] == "validation.endpoint-health"
    assert module["version"] == "1.0.0"
    assert module["scope"] == "endpoint"
    assert module["release_status"] == "staged-not-tested"
    assert module["modes"] == ["verify-only"]
    assert module["action"]["status"] == "source-staged-not-uploaded"
    assert module["action"]["changes_endpoint_state"] is False
    assert set(module["action"]) == {
        "type",
        "status",
        "changes_endpoint_state",
        "script_file",
    }
    assert module["action"]["type"] == "Action1 Script Library PowerShell"
    assert "install_file" not in module["action"]
    assert "rollback_file" not in module["action"]

    assert manifest["module"] == "validation.endpoint-health"
    assert manifest["version"] == "1.0.0"
    assert {artifact["name"] for artifact in manifest["artifacts"]} == {
        "collect-and-verify",
    }
    for artifact in manifest["artifacts"]:
        artifact_path = MODULE_ROOT / artifact["path"]
        assert artifact_path.is_file()
        assert artifact["sha256"] == sha256(artifact_path.read_bytes()).hexdigest()


def test_endpoint_health_scripts_are_structurally_read_only() -> None:
    scripts = [MODULE_ROOT / "scripts" / "Test-EndpointHealth.ps1"]

    for script_path in scripts:
        source = script_path.read_text(encoding="utf-8")
        for pattern in PROHIBITED_MUTATION_PATTERNS:
            assert re.search(pattern, source, flags=re.IGNORECASE) is None, (
                f"{script_path.name} contains prohibited mutation pattern {pattern}"
            )

    source = scripts[0].read_text(encoding="utf-8")
    assert "function Get-EndpointHealthObservationJson" in source
    assert "function Test-EndpointHealthObservationJson" in source
    assert "[CmdletBinding()]" not in source
    assert "ConvertTo-Json" in source
    assert "ConvertFrom-Json" in source
    assert "Test-ExactProperties" in source
    assert "SchemaVersion" in source
    assert "validation.endpoint-health@1.0.0" in source
    assert "Get-Tpm" not in source
    assert "New-Object -ComObject" not in source
    assert "IWSCProductList" in source
    assert 'case 0: return "out-of-date";' in source
    assert 'case 1: return "up-to-date";' in source
    assert "Win32_OperatingSystem.Caption" not in source
    assert "Observation = $safeObservation" in source
    assert "Observation = $observation" not in source
    assert "collection-errors-present" in source
    assert "unsupported-windows-edition" in source
    assert "unsupported-windows-release" in source
    assert "tpm-value-unknown" in source
    assert "memory-integrity-value-unknown" in source
    assert "agent-service-query-state-unknown" in source
    assert "firewall-profile-value-unknown" in source


def test_endpoint_health_fixture_matches_sanitized_output_contract() -> None:
    fixture = _load_strict_json(FIXTURE_PATH)

    assert set(fixture) == EXPECTED_TOP_LEVEL_KEYS
    assert fixture["SchemaVersion"] == 1
    assert fixture["Module"] == "validation.endpoint-health@1.0.0"
    assert fixture["CollectionMode"] == "read-only-local"
    assert fixture["OperatingSystem"]["Family"] == "windows_11"
    assert fixture["OperatingSystem"]["Edition"] == "home"
    assert fixture["Antivirus"]["ActiveProviderFamilies"] == ["mcafee"]
    assert fixture["Antivirus"]["DefenderDependentControls"] == "defer"
    assert fixture["Agents"]["IdentityCorrelation"] == "external-validation-required"
    for field, keys in EXPECTED_NESTED_KEYS.items():
        assert set(fixture[field]) == keys
    assert set(fixture["PlatformProtections"]["MemoryIntegrity"]) == (
        EXPECTED_MEMORY_INTEGRITY_KEYS
    )
    for product in fixture["Antivirus"]["Products"] + fixture["Firewall"]["Products"]:
        assert set(product) == EXPECTED_PRODUCT_KEYS
    for profile in fixture["Firewall"]["Profiles"]:
        assert set(profile) == EXPECTED_PROFILE_KEYS
    assert _walk_keys(fixture).isdisjoint(PROHIBITED_KEYS)
    assert not contains_secret_fields(fixture)

    serialized = json.dumps(fixture, sort_keys=True).lower()
    assert "password=" not in serialized
    assert "[redacted]" not in serialized
    assert "system:" not in serialized
    assert "ignore previous" not in serialized
    assert "c:\\" not in serialized
    assert escape_terminal_controls(serialized) == serialized
    assert not scan_prompt_injection(serialized, source=str(FIXTURE_PATH))


@pytest.mark.parametrize(
    "document",
    [
        '{"SchemaVersion":1,"SchemaVersion":2}',
        '{"value":NaN}',
        '{"value":Infinity}',
    ],
)
def test_strict_fixture_loader_rejects_ambiguous_json(tmp_path: Path, document: str) -> None:
    fixture_path = tmp_path / "endpoint-health.json"
    fixture_path.write_text(document, encoding="utf-8")

    with pytest.raises(ValueError):
        _load_strict_json(fixture_path)


def test_endpoint_health_contract_keeps_external_identity_and_trial_state_unproven() -> None:
    validation = yaml.safe_load((MODULE_ROOT / "validation.yaml").read_text(encoding="utf-8"))
    rollback = (MODULE_ROOT / "rollback.md").read_text(encoding="utf-8").lower()
    joined = "\n".join(validation["verification"]["cross_platform"])
    limitations = "\n".join(validation["failure_and_ambiguity"])

    assert "hostname-only" in joined
    assert "Action1" in joined
    assert "LimaCharlie" in joined
    assert "Velociraptor" in joined
    assert "subscription" in limitations
    assert "no endpoint state" in rollback
    assert "no rollback action" in rollback
