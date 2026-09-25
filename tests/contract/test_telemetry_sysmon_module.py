from __future__ import annotations

import re
import zipfile
from hashlib import sha256
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
MODULE_ROOT = ROOT / "hardening" / "modules" / "telemetry.sysmon"

EXPECTED_BINARY_SHA256 = (
    "83d31f2478dc6716cfdbf69e5c384bf043072b5f0d8d7b2eea365f709fda4352"
)
EXPECTED_CONFIG_SHA256 = (
    "4516404fa30ee87cea558567820cdc78863cc4ab07889519e49eac3cca92e0d2"
)
EXPECTED_BUNDLE_SHA256 = (
    "77bdecd54d2c4841c398a91dc08f505b459d9e83adef5e1efb144337857f861c"
)
LOCAL_BUNDLE = (
    ROOT
    / "var"
    / "staging"
    / "sysmon-2026-09-19"
    / "Sysmon-15.22-olaf-balanced-a507259-telemetry-sysmon-1.0.0.zip"
)

PROHIBITED_VERIFY_PATTERNS = (
    r"\bSet-Item(?:Property)?\b",
    r"\bNew-Item(?:Property)?\b",
    r"\bRemove-Item(?:Property)?\b",
    r"\b(?:Start|Stop|Restart|Set)-Service\b",
    r"\bStart-Process\b",
    r"\bInvoke-WebRequest\b",
    r"\bInvoke-RestMethod\b",
    r"\bSysmon64\.exe\b.*\s-(?:i|c|u)\b",
)


def test_sysmon_module_is_windows_11_only_and_not_release_eligible() -> None:
    module = yaml.safe_load((MODULE_ROOT / "module.yaml").read_text(encoding="utf-8"))[
        "module"
    ]

    assert module["id"] == "telemetry.sysmon"
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
    unsupported = "\n".join(module["unsupported_or_out_of_scope"])
    assert "Windows 10" in unsupported
    assert "Windows Server" in unsupported
    assert module["action"]["install"]["status"] == "source-staged-not-uploaded"
    assert module["action"]["verify"]["status"] == "source-staged-not-uploaded"


def test_sysmon_tracked_artifacts_are_hash_pinned() -> None:
    manifest = yaml.safe_load((MODULE_ROOT / "artifacts.yaml").read_text(encoding="utf-8"))

    assert manifest["module"] == "telemetry.sysmon"
    assert manifest["version"] == "1.0.0"
    assert {item["name"] for item in manifest["artifacts"]} == {
        "install",
        "verify",
        "rollback",
    }
    for artifact in manifest["artifacts"]:
        artifact_path = MODULE_ROOT / artifact["path"]
        assert artifact_path.is_file()
        assert artifact["sha256"] == sha256(artifact_path.read_bytes()).hexdigest()


def test_sysmon_external_inputs_and_bundle_are_exactly_pinned() -> None:
    manifest = yaml.safe_load((MODULE_ROOT / "artifacts.yaml").read_text(encoding="utf-8"))

    package_inputs = {item["name"]: item for item in manifest["package_inputs"]}
    assert package_inputs["sysmon64"]["version"] == "15.22"
    assert package_inputs["sysmon64"]["sha256"] == EXPECTED_BINARY_SHA256
    assert package_inputs["olaf-balanced-config"]["commit"] == (
        "a5072591e173b7f7a9fe518ebd5c10e5313ef6f8"
    )
    assert package_inputs["olaf-balanced-config"]["schema_version"] == "4.90"
    assert package_inputs["olaf-balanced-config"]["sha256"] == EXPECTED_CONFIG_SHA256

    bundle = manifest["deployment_bundle"]
    assert bundle["sha256"] == EXPECTED_BUNDLE_SHA256
    assert bundle["members"] == [
        "Sysmon64.exe",
        "sysmonconfig.xml",
        "Install-TelemetrySysmon.ps1",
        "Uninstall-TelemetrySysmon.ps1",
    ]
    assert bundle["tracked_scripts_match_bundle"] is True


def test_sysmon_installer_and_rollback_preserve_supply_chain_guards() -> None:
    install = (MODULE_ROOT / "scripts" / "Install-TelemetrySysmon.ps1").read_text(
        encoding="utf-8"
    )
    rollback = (MODULE_ROOT / "scripts" / "Uninstall-TelemetrySysmon.ps1").read_text(
        encoding="utf-8"
    )

    for source in (install, rollback):
        assert EXPECTED_BINARY_SHA256.upper() in source
        assert "Get-AuthenticodeSignature" in source
        assert "CN=Microsoft Corporation" in source
        assert "-u force" not in source.lower()
        assert "Invoke-WebRequest" not in source
        assert "Invoke-RestMethod" not in source

    assert EXPECTED_CONFIG_SHA256.upper() in install
    assert "Get-Service -Name 'Sysmon*'" in install
    assert "refuses to overwrite" in install
    assert "-accepteula -i" in install
    assert "-u" in rollback


def test_sysmon_install_and_rollback_are_scope_and_ownership_guarded() -> None:
    install = (MODULE_ROOT / "scripts" / "Install-TelemetrySysmon.ps1").read_text(
        encoding="utf-8"
    )
    rollback = (MODULE_ROOT / "scripts" / "Uninstall-TelemetrySysmon.ps1").read_text(
        encoding="utf-8"
    )

    assert "ProductType -ne 1" in install
    assert "$buildNumber -lt 22621" in install
    assert "Is64BitOperatingSystem" in install
    assert "module-state.json" in install
    assert "module-state.json" in rollback
    assert "Status -eq 'installing'" in install
    assert "Reconcile it read-only; do not retry automatically" in install
    assert "preInstallConfigurationRecordId" in install
    assert "RecordId -gt $preInstallConfigurationRecordId" in install
    assert "existingSysmonDriver" in install
    assert "ownership state is missing" in rollback
    assert "Refusing to remove an unowned Sysmon installation" in rollback
    assert "Get-ServiceBinaryPath" in rollback
    assert "Win32_SystemDriver" in rollback
    assert "do not force removal" in rollback.lower()


def test_local_private_sysmon_bundle_matches_manifest_when_present() -> None:
    if not LOCAL_BUNDLE.is_file():
        return

    assert sha256(LOCAL_BUNDLE.read_bytes()).hexdigest() == EXPECTED_BUNDLE_SHA256
    with zipfile.ZipFile(LOCAL_BUNDLE) as bundle:
        assert bundle.namelist() == [
            "Sysmon64.exe",
            "sysmonconfig.xml",
            "Install-TelemetrySysmon.ps1",
            "Uninstall-TelemetrySysmon.ps1",
        ]
        assert sha256(bundle.read("Sysmon64.exe")).hexdigest() == EXPECTED_BINARY_SHA256
        assert sha256(bundle.read("sysmonconfig.xml")).hexdigest() == EXPECTED_CONFIG_SHA256
        assert bundle.read("Install-TelemetrySysmon.ps1") == (
            MODULE_ROOT / "scripts" / "Install-TelemetrySysmon.ps1"
        ).read_bytes()
        assert bundle.read("Uninstall-TelemetrySysmon.ps1") == (
            MODULE_ROOT / "scripts" / "Uninstall-TelemetrySysmon.ps1"
        ).read_bytes()


def test_sysmon_verifier_is_read_only_and_checks_required_local_evidence() -> None:
    verifier = (MODULE_ROOT / "scripts" / "Test-TelemetrySysmon.ps1").read_text(
        encoding="utf-8"
    )

    for pattern in PROHIBITED_VERIFY_PATTERNS:
        assert re.search(pattern, verifier, flags=re.IGNORECASE) is None, pattern

    assert "[CmdletBinding()]" not in verifier
    script_prefix = verifier.split("function", maxsplit=1)[0]
    assert re.search(r"(?im)^\s*param\s*\(", script_prefix) is None
    assert "Win32_Service" in verifier
    assert "Win32_SystemDriver" in verifier
    assert "Sysmon64" in verifier
    assert "SysmonDrv" in verifier
    assert "Get-AuthenticodeSignature" in verifier
    assert EXPECTED_BINARY_SHA256.upper() in verifier
    assert "15.22" in verifier
    assert "Microsoft-Windows-Sysmon/Operational" in verifier
    assert "ConfigurationFileHash" in verifier
    assert EXPECTED_CONFIG_SHA256.upper() in verifier
    assert "EventId255AfterConfiguration" in verifier
    assert "NormalEventAfterConfiguration" in verifier
    assert "OwnershipState" in verifier
    assert "module-state.json" in verifier
    assert "FilterXPath" in verifier
    assert "not(EventID" not in verifier
    assert "EventID != 255" in verifier
    assert "-MaxEvents 256" not in verifier
    assert "LimaCharlie ingestion requires external validation" in verifier
    assert "ConvertTo-Json" in verifier


def test_sysmon_validation_requires_local_and_limacharlie_evidence() -> None:
    validation = yaml.safe_load(
        (MODULE_ROOT / "validation.yaml").read_text(encoding="utf-8")
    )
    rollback = (MODULE_ROOT / "rollback.md").read_text(encoding="utf-8").lower()

    local = "\n".join(validation["verification"]["local"])
    limacharlie = "\n".join(validation["verification"]["limacharlie"])
    safety = "\n".join(validation["verification"]["safety"])
    ambiguity = "\n".join(validation["failure_and_ambiguity"])

    assert "Sysmon64" in local
    assert "SysmonDrv" in local
    assert "ownership state" in local
    assert "Event ID 16" in local
    assert "Event ID 255" in local
    assert "wel://Microsoft-Windows-Sysmon/Operational:*" in limacharlie
    assert "same correlated sensor" in limacharlie
    assert "report-only" in safety
    assert "never resubmit automatically" in ambiguity
    assert "separate" in rollback
    assert "force" in rollback
