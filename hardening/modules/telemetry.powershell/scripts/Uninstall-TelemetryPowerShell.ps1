#requires -RunAsAdministrator

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ModuleDirectory = Join-Path -Path $env:ProgramData -ChildPath 'FamilyHardening\telemetry.powershell'
$StatePath = Join-Path -Path $ModuleDirectory -ChildPath 'prechange-state.json'

function Assert-Administrator {
    $principal = [Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'telemetry.powershell rollback must run elevated.'
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

function Restore-DirectoryAcl {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [AllowNull()][string]$Sddl
    )

    if ([string]::IsNullOrWhiteSpace($Sddl) -or -not (Test-Path -LiteralPath $Path)) {
        return
    }

    $acl = Get-Acl -LiteralPath $Path
    $acl.SetSecurityDescriptorSddlForm($Sddl)
    Set-Acl -LiteralPath $Path -AclObject $acl
}

Assert-Administrator
if (-not (Test-Path -LiteralPath $StatePath)) {
    throw "No rollback state exists at $StatePath. Stop and reconcile the current policy manually."
}

$state = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
if ($state.ModuleId -ne 'telemetry.powershell' -or $state.SchemaVersion -ne 1) {
    throw 'Rollback state is not a telemetry.powershell schema version 1 record.'
}

foreach ($registryValue in $state.RegistryValues) {
    Restore-RegistryValue -State $registryValue
}

if ($state.TranscriptDirectory.ExistedBeforeApply) {
    Restore-DirectoryAcl -Path $state.TranscriptDirectory.Path -Sddl $state.TranscriptDirectory.SddlBeforeApply
}

[pscustomobject]@{
    Module = 'telemetry.powershell@1.0.0'
    Status = 'rolled back'
    StatePathRetained = $StatePath
    TranscriptDirectoryRetained = $state.TranscriptDirectory.Path
    Note = 'Existing transcripts and state are retained for review; do not delete them until retention is separately decided.'
} | ConvertTo-Json -Compress
