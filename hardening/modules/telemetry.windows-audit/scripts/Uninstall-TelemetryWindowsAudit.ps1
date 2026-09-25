#requires -RunAsAdministrator

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ModuleDirectory = Join-Path -Path $env:ProgramData -ChildPath 'FamilyHardening\telemetry.windows-audit'
$StatePath = Join-Path -Path $ModuleDirectory -ChildPath 'prechange-state.json'
$AuditPolPath = Join-Path -Path $env:SystemRoot -ChildPath 'System32\auditpol.exe'

function Assert-Administrator {
    $principal = [Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'telemetry.windows-audit rollback must run elevated.'
    }
}

function Ensure-RegistryKey {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        $null = New-Item -Path $Path -ErrorAction Stop
    }
}

function Convert-RegistryValue {
    param(
        [Parameter(Mandatory = $true)][string]$Kind,
        [AllowNull()][object]$Value
    )

    switch ($Kind) {
        'DWord' { return [int]$Value }
        'QWord' { return [long]$Value }
        'MultiString' { return @($Value) }
        'Binary' { return [byte[]]@($Value) }
        default { return [string]$Value }
    }
}

function Restore-RegistryValue {
    param([Parameter(Mandatory = $true)][psobject]$State)

    if ($State.ValueExists) {
        Ensure-RegistryKey -Path $State.Path
        $value = Convert-RegistryValue -Kind $State.Kind -Value $State.Value
        $null = New-ItemProperty -LiteralPath $State.Path -Name $State.Name -PropertyType ([string]$State.Kind) -Value $value -Force
        return
    }

    if (Test-Path -LiteralPath $State.Path) {
        Remove-ItemProperty -LiteralPath $State.Path -Name $State.Name -ErrorAction SilentlyContinue
    }
}

function Set-AuditPolicyValue {
    param(
        [Parameter(Mandatory = $true)][string]$Guid,
        [Parameter(Mandatory = $true)][ValidateRange(0, 3)][int]$Value
    )

    $success = if (($Value -band 1) -eq 1) { 'enable' } else { 'disable' }
    $failure = if (($Value -band 2) -eq 2) { 'enable' } else { 'disable' }
    $output = @(& $AuditPolPath '/set' "/subcategory:$Guid" "/success:$success" "/failure:$failure" 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "auditpol could not restore $($Guid): $($output -join ' ')"
    }
}

Assert-Administrator
if (-not (Test-Path -LiteralPath $AuditPolPath)) {
    throw "auditpol.exe was not found at $AuditPolPath."
}
if (-not (Test-Path -LiteralPath $StatePath)) {
    throw "No rollback state exists at $StatePath. Stop and reconcile the current policy manually."
}

$state = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
if ($state.ModuleId -ne 'telemetry.windows-audit' -or $state.SchemaVersion -ne 1) {
    throw 'Rollback state is not a telemetry.windows-audit schema version 1 record.'
}
if (@($state.AuditPolicies).Count -eq 0 -or @($state.RegistryValues).Count -ne 1) {
    throw 'Rollback state does not contain the expected telemetry.windows-audit values.'
}

foreach ($policy in $state.AuditPolicies) {
    Set-AuditPolicyValue -Guid ([string]$policy.Guid) -Value ([int]$policy.Value)
}
foreach ($registryValue in $state.RegistryValues) {
    Restore-RegistryValue -State $registryValue
}

[pscustomobject]@{
    Module = 'telemetry.windows-audit@1.0.1'
    Status = 'rolled back'
    StatePathRetained = $StatePath
    Note = 'Only audit and registry values captured before first apply were restored. The state file is retained for review.'
} | ConvertTo-Json -Compress
