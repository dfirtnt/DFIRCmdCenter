from __future__ import annotations

from hashlib import sha256
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
MODULE_ROOT = ROOT / "hardening" / "modules" / "telemetry.powershell"


def test_telemetry_powershell_artifacts_are_hash_pinned() -> None:
    manifest = yaml.safe_load((MODULE_ROOT / "artifacts.yaml").read_text())

    assert manifest["module"] == "telemetry.powershell"
    assert manifest["version"] == "1.0.0"
    for artifact in manifest["artifacts"]:
        artifact_path = MODULE_ROOT / artifact["path"]
        assert artifact_path.is_file()
        assert artifact["sha256"] == sha256(artifact_path.read_bytes()).hexdigest()


def test_telemetry_powershell_module_stays_offline_until_windows_11_validation() -> None:
    module = yaml.safe_load((MODULE_ROOT / "module.yaml").read_text())["module"]
    validation = yaml.safe_load((MODULE_ROOT / "validation.yaml").read_text())

    assert module["release_status"] == "staged-not-tested"
    assert module["action"]["status"] == "source-staged-not-uploaded"
    assert any(
        item.startswith("PowerShell 7 configuration")
        for item in module["unsupported_or_out_of_scope"]
    )
    assert "4103" in "\n".join(validation["verification"]["limacharlie"])
    assert "4104" in "\n".join(validation["verification"]["limacharlie"])


def test_telemetry_powershell_registry_helpers_preserve_existing_keys() -> None:
    install = (MODULE_ROOT / "scripts" / "Install-TelemetryPowerShell.ps1").read_text()
    rollback = (MODULE_ROOT / "scripts" / "Uninstall-TelemetryPowerShell.ps1").read_text()
    guarded_key_creation = (
        "if (-not (Test-Path -LiteralPath $Path)) {\n"
        "        $null = New-Item -Path $Path -ErrorAction Stop\n"
        "    }"
    )

    install_helper = install.split("function Set-RegistryValue", maxsplit=1)[1].split(
        "function Save-InitialState", maxsplit=1
    )[0]
    rollback_helper = rollback.split("function Ensure-RegistryKey", maxsplit=1)[1].split(
        "function Convert-RegistryValue", maxsplit=1
    )[0]

    assert guarded_key_creation in install_helper
    assert install_helper.count("New-Item -Path $Path -ErrorAction Stop") == 1
    assert guarded_key_creation in rollback_helper
    assert rollback_helper.count("New-Item -Path $Path -ErrorAction Stop") == 1


def test_telemetry_powershell_verifier_handles_zero_failed_policies() -> None:
    verifier = (MODULE_ROOT / "scripts" / "Test-TelemetryPowerShell.ps1").read_text()

    assert "@($policyResults | Where-Object { -not $_.Passed }).Count -eq 0" in verifier
