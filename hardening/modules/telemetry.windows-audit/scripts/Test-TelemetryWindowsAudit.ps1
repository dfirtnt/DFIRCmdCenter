#requires -RunAsAdministrator

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$StatePath = Join-Path -Path $env:ProgramData -ChildPath 'FamilyHardening\telemetry.windows-audit\prechange-state.json'
$AuditPolPath = Join-Path -Path $env:SystemRoot -ChildPath 'System32\auditpol.exe'
$CommandLinePolicy = [pscustomobject]@{
    Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    Name = 'ProcessCreationIncludeCmdLine_Enabled'
    Value = 1
}
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

if (-not (Test-Path -LiteralPath $AuditPolPath)) {
    throw "auditpol.exe was not found at $AuditPolPath."
}

$policyResults = foreach ($policy in $AuditPolicies) {
    $actual = Get-AuditPolicyValue -Guid $policy.Guid
    [pscustomobject]@{
        Name = $policy.Name
        Guid = $policy.Guid
        Expected = $policy.Value
        Actual = $actual
        Passed = ($actual -eq $policy.Value)
    }
}

$commandLineActual = Get-RegistryValue -Path $CommandLinePolicy.Path -Name $CommandLinePolicy.Name
$result = [pscustomobject]@{
    Module = 'telemetry.windows-audit@1.0.1'
    Passed = (($policyResults | Where-Object { -not $_.Passed }).Count -eq 0) -and
        ($commandLineActual -eq $CommandLinePolicy.Value) -and
        (Test-Path -LiteralPath $StatePath)
    ProcessCreationCommandLine = [pscustomobject]@{
        Expected = $CommandLinePolicy.Value
        Actual = $commandLineActual
        Passed = ($commandLineActual -eq $CommandLinePolicy.Value)
    }
    PrechangeStatePresent = Test-Path -LiteralPath $StatePath
    AuditPolicies = @($policyResults)
    Limitation = 'This checks configured policy only. Confirm fresh Security event 4688 with a populated CommandLine field arriving through LimaCharlie WEL before promotion.'
}

$result | ConvertTo-Json -Depth 6
if (-not $result.Passed) {
    exit 1
}
