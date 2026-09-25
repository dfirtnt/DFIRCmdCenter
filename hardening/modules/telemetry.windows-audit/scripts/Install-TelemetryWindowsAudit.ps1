#requires -RunAsAdministrator

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ModuleId = 'telemetry.windows-audit'
$ModuleVersion = '1.0.1'
$ModuleDirectory = Join-Path -Path $env:ProgramData -ChildPath 'FamilyHardening\telemetry.windows-audit'
$StatePath = Join-Path -Path $ModuleDirectory -ChildPath 'prechange-state.json'
$AuditPolPath = Join-Path -Path $env:SystemRoot -ChildPath 'System32\auditpol.exe'
$CommandLinePolicy = [pscustomobject]@{
    Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    Name = 'ProcessCreationIncludeCmdLine_Enabled'
    Kind = 'DWord'
    Value = 1
}

# Use GUIDs so this package works on supported Windows installations regardless of display language.
$AuditPolicies = @(
    [pscustomobject]@{ Name = 'Process Creation'; Guid = '{0CCE922B-69AE-11D9-BED3-505054503030}'; Value = 1 }
    [pscustomobject]@{ Name = 'Logon'; Guid = '{0CCE9215-69AE-11D9-BED3-505054503030}'; Value = 3 }
    [pscustomobject]@{ Name = 'Account Lockout'; Guid = '{0CCE9217-69AE-11D9-BED3-505054503030}'; Value = 3 }
    [pscustomobject]@{ Name = 'Special Logon'; Guid = '{0CCE921B-69AE-11D9-BED3-505054503030}'; Value = 1 }
    [pscustomobject]@{ Name = 'Credential Validation'; Guid = '{0CCE923F-69AE-11D9-BED3-505054503030}'; Value = 3 }
    [pscustomobject]@{ Name = 'User Account Management'; Guid = '{0CCE9235-69AE-11D9-BED3-505054503030}'; Value = 3 }
    [pscustomobject]@{ Name = 'Security Group Management'; Guid = '{0CCE9237-69AE-11D9-BED3-505054503030}'; Value = 3 }
    [pscustomobject]@{ Name = 'Audit Policy Change'; Guid = '{0CCE922F-69AE-11D9-BED3-505054503030}'; Value = 3 }
    [pscustomobject]@{ Name = 'Authentication Policy Change'; Guid = '{0CCE9230-69AE-11D9-BED3-505054503030}'; Value = 1 }
    [pscustomobject]@{ Name = 'Authorization Policy Change'; Guid = '{0CCE9231-69AE-11D9-BED3-505054503030}'; Value = 1 }
    [pscustomobject]@{ Name = 'Sensitive Privilege Use'; Guid = '{0CCE9228-69AE-11D9-BED3-505054503030}'; Value = 3 }
    [pscustomobject]@{ Name = 'Security System Extension'; Guid = '{0CCE9211-69AE-11D9-BED3-505054503030}'; Value = 3 }
    [pscustomobject]@{ Name = 'System Integrity'; Guid = '{0CCE9212-69AE-11D9-BED3-505054503030}'; Value = 3 }
)

function Assert-Administrator {
    $principal = [Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'telemetry.windows-audit must run elevated.'
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

function Get-AuditPolicyValue {
    param([Parameter(Mandatory = $true)][string]$Guid)

    $output = @(& $AuditPolPath '/get' "/subcategory:$Guid" '/r' 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "auditpol could not read $($Guid): $($output -join ' ')"
    }

    $csv = @($output | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    $rows = @($csv | ConvertFrom-Csv)
    if ($rows.Count -ne 1) {
        throw "auditpol returned an unexpected row count for $Guid."
    }

    $settingValueProperty = $rows[0].PSObject.Properties['Setting Value']
    if ($null -ne $settingValueProperty) {
        $rawValue = [string]$settingValueProperty.Value
    }
    else {
        # Some supported auditpol.exe builds omit the numeric Setting Value column
        # from /r output. PHANTOM returns this six-column form.
        $inclusionSettingProperty = $rows[0].PSObject.Properties['Inclusion Setting']
        if ($null -eq $inclusionSettingProperty) {
            throw "auditpol returned no recognized audit setting column for $Guid."
        }

        $rawValue = switch (([string]$inclusionSettingProperty.Value).Trim()) {
            'No Auditing' { '0'; break }
            'Success' { '1'; break }
            'Failure' { '2'; break }
            'Success and Failure' { '3'; break }
            default { throw "auditpol returned an unsupported Inclusion Setting for $Guid: $($inclusionSettingProperty.Value)" }
        }
    }

    $parsedValue = 0
    if (-not [int]::TryParse($rawValue, [ref]$parsedValue) -or $parsedValue -notin 0, 1, 2, 3) {
        throw "auditpol returned an unexpected audit value for $Guid."
    }
    return $parsedValue
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
        throw "auditpol could not set $($Guid): $($output -join ' ')"
    }
}

function Save-InitialState {
    if (Test-Path -LiteralPath $StatePath) {
        return $false
    }

    $state = [pscustomobject]@{
        SchemaVersion = 1
        ModuleId = $ModuleId
        ModuleVersion = $ModuleVersion
        CapturedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        AuditPolicies = @($AuditPolicies | ForEach-Object {
            [pscustomobject]@{
                Name = $_.Name
                Guid = $_.Guid
                Value = Get-AuditPolicyValue -Guid $_.Guid
            }
        })
        RegistryValues = @(
            Get-RegistryValueState -Path $CommandLinePolicy.Path -Name $CommandLinePolicy.Name
        )
    }

    $state | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $StatePath -Encoding UTF8
    return $true
}

Assert-Administrator
if (-not (Test-Path -LiteralPath $AuditPolPath)) {
    throw "auditpol.exe was not found at $AuditPolPath."
}

Ensure-Directory -Path $ModuleDirectory
Set-RestrictedDirectoryAcl -Path $ModuleDirectory
$stateCreated = Save-InitialState

Set-RegistryValue -Path $CommandLinePolicy.Path -Name $CommandLinePolicy.Name -Kind $CommandLinePolicy.Kind -Value $CommandLinePolicy.Value
foreach ($policy in $AuditPolicies) {
    Set-AuditPolicyValue -Guid $policy.Guid -Value $policy.Value
}

[pscustomobject]@{
    Module = "$ModuleId@$ModuleVersion"
    Status = 'configured'
    InitialStateCaptured = $stateCreated
    ProcessCreationCommandLine = 'enabled'
    AuditPoliciesConfigured = @($AuditPolicies | ForEach-Object { $_.Name })
    Note = 'Security event payloads can contain sensitive command-line data. Validate event 4688 arrival in LimaCharlie before promotion.'
} | ConvertTo-Json -Compress
