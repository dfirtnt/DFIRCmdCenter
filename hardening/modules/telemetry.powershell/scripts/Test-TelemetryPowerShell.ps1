#requires -RunAsAdministrator

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$TranscriptDirectory = Join-Path -Path $env:ProgramData -ChildPath 'FamilyHardening\PowerShellTranscripts'
$StatePath = Join-Path -Path $env:ProgramData -ChildPath 'FamilyHardening\telemetry.powershell\prechange-state.json'
$ExpectedPolicies = @(
    [pscustomobject]@{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
        Name = 'EnableScriptBlockLogging'
        Value = 1
    },
    [pscustomobject]@{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
        Name = 'EnableModuleLogging'
        Value = 1
    },
    [pscustomobject]@{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames'
        Name = '*'
        Value = '*'
    },
    [pscustomobject]@{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
        Name = 'EnableTranscripting'
        Value = 1
    },
    [pscustomobject]@{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
        Name = 'EnableInvocationHeader'
        Value = 1
    },
    [pscustomobject]@{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
        Name = 'OutputDirectory'
        Value = $TranscriptDirectory
    }
)

function Get-RegistryValue {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return $null
    }

    $properties = Get-ItemProperty -LiteralPath $Path
    if (-not ($properties.PSObject.Properties.Name -contains $Name)) {
        return $null
    }
    return $properties.PSObject.Properties[$Name].Value
}

$policyResults = foreach ($policy in $ExpectedPolicies) {
    $actual = Get-RegistryValue -Path $policy.Path -Name $policy.Name
    [pscustomobject]@{
        Path = $policy.Path
        Name = $policy.Name
        Expected = $policy.Value
        Actual = $actual
        Passed = ($actual -eq $policy.Value)
    }
}

$operationalLog = Get-WinEvent -ListLog 'Microsoft-Windows-PowerShell/Operational'
$unexpectedAllow = @()
$transcriptAclOk = $false
if (Test-Path -LiteralPath $TranscriptDirectory) {
    $allowedIdentities = @('NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators')
    $unexpectedAllow = @(
        (Get-Acl -LiteralPath $TranscriptDirectory).Access | Where-Object {
            $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
            $_.IdentityReference.Value -notin $allowedIdentities
        }
    )
    $transcriptAclOk = $unexpectedAllow.Count -eq 0
}

$result = [pscustomobject]@{
    Module = 'telemetry.powershell@1.0.0'
    Passed = (@($policyResults | Where-Object { -not $_.Passed }).Count -eq 0) -and
        $operationalLog.IsEnabled -and
        $transcriptAclOk -and
        (Test-Path -LiteralPath $StatePath)
    WindowsPowerShellOperationalLogEnabled = $operationalLog.IsEnabled
    TranscriptDirectory = $TranscriptDirectory
    TranscriptDirectoryAclRestricted = $transcriptAclOk
    UnexpectedTranscriptAllowEntries = @($unexpectedAllow | ForEach-Object { $_.IdentityReference.Value })
    PrechangeStatePresent = Test-Path -LiteralPath $StatePath
    Policies = @($policyResults)
    Limitation = 'This checks configuration only. Confirm 4103 and 4104 arrival in LimaCharlie after a fresh PowerShell session runs.'
}

$result | ConvertTo-Json -Depth 6
if (-not $result.Passed) {
    exit 1
}
