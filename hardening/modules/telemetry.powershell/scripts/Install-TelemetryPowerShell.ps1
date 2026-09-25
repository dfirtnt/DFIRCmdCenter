#requires -RunAsAdministrator

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ModuleId = 'telemetry.powershell'
$ModuleVersion = '1.0.0'
$ModuleDirectory = Join-Path -Path $env:ProgramData -ChildPath 'FamilyHardening\telemetry.powershell'
$StatePath = Join-Path -Path $ModuleDirectory -ChildPath 'prechange-state.json'
$TranscriptDirectory = Join-Path -Path $env:ProgramData -ChildPath 'FamilyHardening\PowerShellTranscripts'

$PolicyValues = @(
    [pscustomobject]@{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
        Name = 'EnableScriptBlockLogging'
        Kind = 'DWord'
        Value = 1
    },
    [pscustomobject]@{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
        Name = 'EnableModuleLogging'
        Kind = 'DWord'
        Value = 1
    },
    [pscustomobject]@{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames'
        Name = '*'
        Kind = 'String'
        Value = '*'
    },
    [pscustomobject]@{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
        Name = 'EnableTranscripting'
        Kind = 'DWord'
        Value = 1
    },
    [pscustomobject]@{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
        Name = 'EnableInvocationHeader'
        Kind = 'DWord'
        Value = 1
    },
    [pscustomobject]@{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
        Name = 'OutputDirectory'
        Kind = 'String'
        Value = $TranscriptDirectory
    }
)

function Assert-Administrator {
    $principal = [Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'telemetry.powershell must run elevated.'
    }
}

function Ensure-Directory {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        $null = New-Item -ItemType Directory -Path $Path -Force
    }
}

function Set-RestrictedDirectoryAcl {
    param([Parameter(Mandatory = $true)][string]$Path)

    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $propagation = [Security.AccessControl.PropagationFlags]::None
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $fullControl = [Security.AccessControl.FileSystemRights]::FullControl

    $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $administrators = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true, $false)

    foreach ($rule in @($acl.Access)) {
        $null = $acl.RemoveAccessRuleAll($rule)
    }

    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $system, $fullControl, $inheritance, $propagation, $allow
    ))
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $administrators, $fullControl, $inheritance, $propagation, $allow
    ))
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Get-RegistryValueState {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return [pscustomobject]@{
            Path = $Path
            Name = $Name
            KeyExists = $false
            ValueExists = $false
            Kind = $null
            Value = $null
        }
    }

    $key = Get-Item -LiteralPath $Path
    $properties = Get-ItemProperty -LiteralPath $Path
    $valueExists = $properties.PSObject.Properties.Name -contains $Name
    if (-not $valueExists) {
        return [pscustomobject]@{
            Path = $Path
            Name = $Name
            KeyExists = $true
            ValueExists = $false
            Kind = $null
            Value = $null
        }
    }

    return [pscustomobject]@{
        Path = $Path
        Name = $Name
        KeyExists = $true
        ValueExists = $true
        Kind = $key.GetValueKind($Name).ToString()
        Value = $properties.PSObject.Properties[$Name].Value
    }
}

function Set-RegistryValue {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Kind,
        [Parameter(Mandatory = $true)][AllowEmptyString()][object]$Value
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        $null = New-Item -Path $Path -ErrorAction Stop
    }
    $null = New-ItemProperty -LiteralPath $Path -Name $Name -PropertyType $Kind -Value $Value -Force
}

function Save-InitialState {
    if (Test-Path -LiteralPath $StatePath) {
        return $false
    }

    $transcriptDirectoryExists = Test-Path -LiteralPath $TranscriptDirectory
    $transcriptSddl = $null
    if ($transcriptDirectoryExists) {
        $transcriptSddl = (Get-Acl -LiteralPath $TranscriptDirectory).Sddl
    }

    $state = [pscustomobject]@{
        SchemaVersion = 1
        ModuleId = $ModuleId
        ModuleVersion = $ModuleVersion
        CapturedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        RegistryValues = @($PolicyValues | ForEach-Object {
            Get-RegistryValueState -Path $_.Path -Name $_.Name
        })
        TranscriptDirectory = [pscustomobject]@{
            Path = $TranscriptDirectory
            ExistedBeforeApply = $transcriptDirectoryExists
            SddlBeforeApply = $transcriptSddl
        }
    }

    $state | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $StatePath -Encoding UTF8
    return $true
}

Assert-Administrator
Ensure-Directory -Path $ModuleDirectory
Set-RestrictedDirectoryAcl -Path $ModuleDirectory
$stateCreated = Save-InitialState

Ensure-Directory -Path $TranscriptDirectory
Set-RestrictedDirectoryAcl -Path $TranscriptDirectory

foreach ($setting in $PolicyValues) {
    Set-RegistryValue -Path $setting.Path -Name $setting.Name -Kind $setting.Kind -Value $setting.Value
}

[pscustomobject]@{
    Module = "$ModuleId@$ModuleVersion"
    Status = 'configured'
    InitialStateCaptured = $stateCreated
    TranscriptDirectory = $TranscriptDirectory
    ScriptBlockLogging = 'enabled'
    ModuleLogging = 'enabled for all modules'
    InvocationLogging = 'unchanged and intentionally not enabled'
    TranscriptInvocationHeader = 'enabled'
} | ConvertTo-Json -Compress
