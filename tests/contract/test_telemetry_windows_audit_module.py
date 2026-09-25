from __future__ import annotations

from hashlib import sha256
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
MODULE_ROOT = ROOT / "hardening" / "modules" / "telemetry.windows-audit"


def test_telemetry_windows_audit_artifacts_are_hash_pinned() -> None:
    manifest = yaml.safe_load((MODULE_ROOT / "artifacts.yaml").read_text())

    assert manifest["module"] == "telemetry.windows-audit"
    assert manifest["version"] == "1.0.1"
    for artifact in manifest["artifacts"]:
        artifact_path = MODULE_ROOT / artifact["path"]
        assert artifact_path.is_file()
        assert artifact["sha256"] == sha256(artifact_path.read_bytes()).hexdigest()


def test_telemetry_windows_audit_stays_offline_until_windows_11_validation() -> None:
    module = yaml.safe_load((MODULE_ROOT / "module.yaml").read_text())["module"]
    validation = yaml.safe_load((MODULE_ROOT / "validation.yaml").read_text())
    rollback = (MODULE_ROOT / "rollback.md").read_text()

    assert module["release_status"] == "staged-not-tested"
    assert module["action"]["status"] == "source-staged-not-uploaded"
    assert any("event-log size" in item for item in module["unsupported_or_out_of_scope"])
    assert "4688" in "\n".join(validation["verification"]["limacharlie"])
    assert "auditpol /backup" in rollback


def test_telemetry_windows_audit_registry_helpers_preserve_existing_keys() -> None:
    install = (MODULE_ROOT / "scripts" / "Install-TelemetryWindowsAudit.ps1").read_text()
    rollback = (MODULE_ROOT / "scripts" / "Uninstall-TelemetryWindowsAudit.ps1").read_text()
    guarded_key_creation = (
        "if (-not (Test-Path -LiteralPath $Path)) {\n"
        "        $null = New-Item -Path $Path -ErrorAction Stop\n"
        "    }"
    )

    install_helper = install.split("function Set-RegistryValue", maxsplit=1)[1].split(
        "function Get-AuditPolicyValue", maxsplit=1
    )[0]
    rollback_helper = rollback.split("function Ensure-RegistryKey", maxsplit=1)[1].split(
        "function Convert-RegistryValue", maxsplit=1
    )[0]

    assert guarded_key_creation in install_helper
    assert install_helper.count("New-Item -Path $Path -ErrorAction Stop") == 1
    assert guarded_key_creation in rollback_helper
    assert rollback_helper.count("New-Item -Path $Path -ErrorAction Stop") == 1


def test_telemetry_windows_audit_parses_both_auditpol_report_shapes() -> None:
    install = (MODULE_ROOT / "scripts" / "Install-TelemetryWindowsAudit.ps1").read_text()
    verify = (MODULE_ROOT / "scripts" / "Test-TelemetryWindowsAudit.ps1").read_text()

    for script in (install, verify):
        assert "$rows[0].PSObject.Properties['Setting Value']" in script
        assert "$rows[0].PSObject.Properties['Inclusion Setting']" in script
        assert "'No Auditing' { '0'; break }" in script
        assert "'Success' { '1'; break }" in script
        assert "'Failure' { '2'; break }" in script
        assert "'Success and Failure' { '3'; break }" in script
        assert "$lastProperty" not in script
