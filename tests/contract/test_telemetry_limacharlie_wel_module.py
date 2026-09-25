from __future__ import annotations

import json
import re
from hashlib import sha256
from pathlib import Path
from typing import Any

import yaml

from dfircmdcenter.core.redaction import contains_secret_fields

ROOT = Path(__file__).resolve().parents[2]
MODULE_ROOT = ROOT / "hardening" / "modules" / "telemetry.limacharlie-wel"
TEMPLATE_PATH = (
    ROOT
    / "platforms"
    / "limacharlie"
    / "artifact-rules"
    / "family-windows-wel-v1.yaml"
)
EXPECTATIONS_PATH = (
    ROOT
    / "platforms"
    / "limacharlie"
    / "detection-expectations"
    / "family-windows-wel-report-only-v1.yaml"
)
FIXTURE_PATH = (
    ROOT / "hardening" / "fixtures" / "windows11-home" / "limacharlie-wel-source.json"
)

EXPECTED_PATTERNS = {
    "wel://Security:*",
    "wel://System:*",
    "wel://Microsoft-Windows-PowerShell/Operational:*",
    "wel://Microsoft-Windows-Sysmon/Operational:*",
    "wel://Microsoft-Windows-Windows Defender/Operational:*",
    "wel://Microsoft-Windows-CodeIntegrity/Operational:*",
    "wel://Microsoft-Windows-AppLocker/MSI and Script:*",
    "wel://Microsoft-Windows-TaskScheduler/Operational:*",
    "wel://Microsoft-Windows-WMI-Activity/Operational:*",
}

PROHIBITED_VERIFY_PATTERNS = (
    r"\bSet-Item(?:Property)?\b",
    r"\bNew-Item(?:Property)?\b",
    r"\bRemove-Item(?:Property)?\b",
    r"\b(?:Start|Stop|Restart|Set)-Service\b",
    r"\bwevtutil\b",
    r"\bauditpol\b",
    r"\beventcreate\b",
    r"\bschtasks\b",
    r"\bStart-Process\b",
    r"\bInvoke-Command\b",
    r"\bInvoke-Expression\b",
    r"\bSet-CimInstance\b",
    r"\bNew-ScheduledTask\b",
    r"\bRegister-ScheduledTask\b",
    r"\bcurl(?:\.exe)?\b",
    r"\bwget(?:\.exe)?\b",
    r"\bInvoke-WebRequest\b",
    r"\bInvoke-RestMethod\b",
    r"System\.Net\.",
    r"System\.Diagnostics\.Process",
)


def _walk_keys(value: Any) -> set[str]:
    keys: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            keys.add(str(key).lower())
            keys.update(_walk_keys(child))
    elif isinstance(value, list):
        for child in value:
            keys.update(_walk_keys(child))
    return keys


def test_limacharlie_wel_module_is_endpoint_scoped_and_offline_staged() -> None:
    module = yaml.safe_load((MODULE_ROOT / "module.yaml").read_text(encoding="utf-8"))[
        "module"
    ]

    assert module["id"] == "telemetry.limacharlie-wel"
    assert module["version"] == "1.0.0"
    assert module["scope"] == "endpoint"
    assert module["release_status"] == "staged-not-tested"
    assert module["modes"] == ["enforce", "verify-only"]
    assert module["supported_platforms"] == [
        {
            "product": "Windows 11",
            "minimum_release": "22H2",
            "architecture": "x64",
        }
    ]
    collection = module["action"]["collection_template"]
    assert collection["status"] == "prepared-not-live-schema-validated"
    assert collection["changes_shared_platform_state"] is True
    assert module["action"]["local_preflight"]["changes_endpoint_state"] is False


def test_limacharlie_wel_artifacts_are_hash_pinned() -> None:
    manifest = yaml.safe_load((MODULE_ROOT / "artifacts.yaml").read_text(encoding="utf-8"))

    assert manifest["module"] == "telemetry.limacharlie-wel"
    assert manifest["version"] == "1.0.0"
    assert {artifact["name"] for artifact in manifest["artifacts"]} == {
        "local-source-preflight",
        "collection-desired-state",
        "report-only-detection-expectations",
    }
    for artifact in manifest["artifacts"]:
        artifact_path = ROOT / artifact["path"]
        assert artifact_path.is_file()
        assert artifact["sha256"] == sha256(artifact_path.read_bytes()).hexdigest()


def test_wel_desired_state_has_exact_modular_patterns_and_scope_guards() -> None:
    document = yaml.safe_load(TEMPLATE_PATH.read_text(encoding="utf-8"))
    template = document["template"]

    assert template["kind"] == "limacharlie-artifact-collection-desired-state"
    assert template["status"] == "prepared-not-live-schema-validated"
    scope = template["scope"]
    assert scope == {
        "platforms": ["windows"],
        "exact_sensor_scope_required": True,
        "tag_is_scope_authority": False,
        "private_resolved_sid_manifest_required": True,
        "target_cardinality_per_endpoint_proposal": 1,
        "immediate_prewrite_membership_reread_required": True,
        "abort_on_membership_drift": True,
    }
    patterns = {
        pattern
        for group in template["groups"]
        for pattern in group["patterns"]
    }
    assert patterns == EXPECTED_PATTERNS
    groups = {group["id"]: group for group in template["groups"]}
    assert groups["core"]["default_state"] == "required"
    assert groups["sysmon"]["default_state"] == "conditional"
    assert groups["appcontrol"]["default_state"] == "conditional"
    assert groups["defender"]["default_state"] == "deferred-when-third-party-av-primary"
    assert len({group["rule_id"] for group in template["groups"]}) == 4
    assert len({group["sensor_tag"] for group in template["groups"]}) == 4

    assert template["behavior"]["raw_evtx_collection"] == "prohibited"
    assert template["behavior"]["powershell_transcript_collection"] == "prohibited"
    assert template["apply_contract"]["live_schema_export_required"] is True
    assert template["apply_contract"]["automatic_apply"] is False
    assert template["apply_contract"]["one_rule_per_group"] is True
    assert template["apply_contract"]["resolved_group_manifest_required"] is True
    assert template["apply_contract"]["complete_impacted_sid_set_required"] is True
    assert template["apply_contract"]["live_wel_enablement_read_required"] is True
    assert template["apply_contract"]["unresolved_condition_action"] == "abort"
    assert "days_retention" not in _walk_keys(document)
    assert not contains_secret_fields(document)

    serialized = TEMPLATE_PATH.read_text(encoding="utf-8").lower()
    assert "organization_id:" not in serialized
    assert "sensor_id:" not in serialized
    assert "installation_key:" not in serialized
    assert "bearer" not in serialized


def test_wel_local_preflight_is_parameterless_read_only_and_bounded() -> None:
    source = (
        MODULE_ROOT / "scripts" / "Test-LimaCharlieWelSource.ps1"
    ).read_text(encoding="utf-8")

    for pattern in PROHIBITED_VERIFY_PATTERNS:
        assert re.search(pattern, source, flags=re.IGNORECASE) is None, pattern
    assert "[CmdletBinding()]" not in source
    script_prefix = source.split("function", maxsplit=1)[0]
    assert re.search(r"(?im)^\s*param\s*\(", script_prefix) is None
    assert "Get-WinEvent -ListLog" in source
    assert "Get-WinEvent -LogName" not in source
    assert "Message" not in source
    assert "ProviderName" not in source
    assert "Get-CimInstance" in source
    assert "Win32_OperatingSystem" in source
    assert "ProductType" in source
    assert "BuildNumber" in source
    assert "Is64BitOperatingSystem" in source
    assert "$build -ge 22621" in source
    assert "ConvertTo-Json" in source
    source_without_strings = re.sub(r"'[^']*'|\"[^\"]*\"", "", source)
    command_names = set(
        re.findall(
            r"\b[A-Z][A-Za-z0-9]+-[A-Z][A-Za-z0-9]+\b",
            source_without_strings,
        )
    )
    assert command_names <= {
        "Set-StrictMode",
        "Get-CimInstance",
        "Get-WinEvent",
        "ConvertTo-Json",
    }
    for pattern in EXPECTED_PATTERNS:
        channel = pattern.removeprefix("wel://").removesuffix(":*")
        assert channel in source


def test_wel_fixture_is_synthetic_bounded_and_contains_no_identifiers() -> None:
    fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))

    assert set(fixture) == {
        "SchemaVersion",
        "Module",
        "CollectionMode",
        "Platform",
        "Passed",
        "Channels",
        "Limitations",
    }
    assert fixture["Module"] == "telemetry.limacharlie-wel@1.0.0"
    assert fixture["CollectionMode"] == "read-only-local-preflight"
    assert fixture["Platform"] == {
        "Status": "collected",
        "Family": "windows_11",
        "Build": 26200,
        "Architecture": "x64",
        "ProductType": "client",
        "Supported": True,
    }
    assert len(fixture["Channels"]) == 9
    assert {item["Channel"] for item in fixture["Channels"]} == {
        pattern.removeprefix("wel://").removesuffix(":*")
        for pattern in EXPECTED_PATTERNS
    }
    assert all(
        set(item) == {"Channel", "Group", "Status", "Enabled"}
        for item in fixture["Channels"]
    )
    assert not contains_secret_fields(fixture)
    keys = _walk_keys(fixture)
    assert keys.isdisjoint(
        {
            "hostname",
            "fqdn",
            "username",
            "ip",
            "mac",
            "sid",
            "sensor_id",
            "organization_id",
            "device_id",
            "token",
            "secret",
            "path",
            "message",
            "event_body",
        }
    )


def test_wel_validation_maps_safe_events_and_preserves_privacy_boundary() -> None:
    validation = yaml.safe_load(
        (MODULE_ROOT / "validation.yaml").read_text(encoding="utf-8")
    )
    serialized = (MODULE_ROOT / "validation.yaml").read_text(encoding="utf-8")

    assert set(validation["test_event_mappings"]) == {
        "security",
        "system",
        "powershell",
        "sysmon",
        "task_scheduler",
        "wmi_activity",
        "appcontrol",
        "defender",
    }
    assert "4688" in serialized
    assert "4103" in serialized
    assert "4104" in serialized
    assert "Event ID 16" in serialized
    assert "separate approval" in serialized
    assert "EICAR" not in serialized
    assert "execute unsigned" not in serialized.lower()
    assert "one year" in serialized
    assert "event bodies" in serialized
    assert "Event Collection/Exfil" in serialized
    assert "sensor restart" in serialized
    assert "routing/sid" in serialized
    assert "routing/event_type" in serialized
    assert "routing/event_time" in serialized
    assert "event/EVENT/System/Channel" in serialized
    assert "event/EVENT/System/EventID" in serialized


def test_detection_expectations_are_non_executable_and_report_only() -> None:
    document = yaml.safe_load(EXPECTATIONS_PATH.read_text(encoding="utf-8"))

    assert document["status"] == "expectations-only-not-dr-rules"
    assert document["response_boundary"] == ["report"]
    assert document["automatic_apply"] is False
    allowed_keys = {
        "id",
        "source_group",
        "channel",
        "channels",
        "event_ids",
        "examples",
        "expected_response",
    }
    assert all(
        item["expected_response"] == "report"
        and set(item).issubset(allowed_keys)
        for item in document["expectations"]
    )
    serialized = EXPECTATIONS_PATH.read_text(encoding="utf-8").lower()
    for unsafe in (
        "action: isolate",
        "action: kill",
        "action: task",
        "action: add tag",
        "action: block",
    ):
        assert unsafe not in serialized


def test_wel_rollback_is_exact_and_does_not_delete_retained_telemetry() -> None:
    rollback = (MODULE_ROOT / "rollback.md").read_text(encoding="utf-8").lower()

    assert "separate" in rollback
    assert "exact" in rollback
    assert "before-state" in rollback
    assert "does not disable" in rollback
    assert "does not delete" in rollback
    assert "retained telemetry" in rollback
    assert "automatic" in rollback
