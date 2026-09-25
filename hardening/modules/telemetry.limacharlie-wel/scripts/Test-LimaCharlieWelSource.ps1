#requires -Version 5.1
#requires -RunAsAdministrator

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$platformStatus = 'query-failed'
$family = 'unknown'
$build = $null
$architecture = 'unknown'
$productType = 'unknown'
$platformSupported = $false

try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -Property @(
        'BuildNumber',
        'ProductType'
    ) -ErrorAction Stop
    $build = [int]$os.BuildNumber
    if ([int]$os.ProductType -eq 1) {
        $productType = 'client'
        if ($build -ge 22000) {
            $family = 'windows_11'
        }
        else {
            $family = 'windows_client_other'
        }
    }
    else {
        $productType = 'server'
        $family = 'windows_server'
    }
    if ([Environment]::Is64BitOperatingSystem) {
        $architecture = 'x64'
    }
    else {
        $architecture = 'unsupported'
    }
    $platformSupported = (
        ($productType -eq 'client') -and
        ($family -eq 'windows_11') -and
        ($build -ge 22621) -and
        ($architecture -eq 'x64')
    )
    $platformStatus = 'collected'
}
catch [System.Exception] {
    $platformSupported = $false
}

$channelDefinitions = @(
    [pscustomobject][ordered]@{ Channel = 'Security'; Group = 'core'; Required = $true }
    [pscustomobject][ordered]@{ Channel = 'System'; Group = 'core'; Required = $true }
    [pscustomobject][ordered]@{ Channel = 'Microsoft-Windows-PowerShell/Operational'; Group = 'core'; Required = $true }
    [pscustomobject][ordered]@{ Channel = 'Microsoft-Windows-TaskScheduler/Operational'; Group = 'core'; Required = $true }
    [pscustomobject][ordered]@{ Channel = 'Microsoft-Windows-WMI-Activity/Operational'; Group = 'core'; Required = $true }
    [pscustomobject][ordered]@{ Channel = 'Microsoft-Windows-Sysmon/Operational'; Group = 'sysmon'; Required = $false }
    [pscustomobject][ordered]@{ Channel = 'Microsoft-Windows-CodeIntegrity/Operational'; Group = 'appcontrol'; Required = $false }
    [pscustomobject][ordered]@{ Channel = 'Microsoft-Windows-AppLocker/MSI and Script'; Group = 'appcontrol'; Required = $false }
    [pscustomobject][ordered]@{ Channel = 'Microsoft-Windows-Windows Defender/Operational'; Group = 'defender'; Required = $false }
)

$passed = $platformSupported
$channels = @()

foreach ($definition in $channelDefinitions) {
    $enabled = $null
    $status = 'query-failed'
    try {
        $log = Get-WinEvent -ListLog $definition.Channel -ErrorAction Stop
        $enabled = [bool]$log.IsEnabled
        if ($enabled) {
            $status = 'available-enabled'
        }
        else {
            $status = 'available-disabled'
        }
    }
    catch [System.Exception] {
        if ([string]$_.FullyQualifiedErrorId -like 'NoMatchingLogsFound*') {
            $status = 'unavailable'
        }
    }

    if ($definition.Required -and ($status -ne 'available-enabled')) {
        $passed = $false
    }

    $channels += [pscustomobject][ordered]@{
        Channel = $definition.Channel
        Group = $definition.Group
        Status = $status
        Enabled = $enabled
    }
}

$result = [pscustomobject][ordered]@{
    SchemaVersion = 1
    Module = 'telemetry.limacharlie-wel@1.0.0'
    CollectionMode = 'read-only-local-preflight'
    Platform = [pscustomobject][ordered]@{
        Status = $platformStatus
        Family = $family
        Build = $build
        Architecture = $architecture
        ProductType = $productType
        Supported = $platformSupported
    }
    Passed = $passed
    Channels = $channels
    Limitations = @(
        'channel-availability-does-not-prove-limacharlie-ingestion'
        'conditional-and-deferred-channel-absence-does-not-fail-core-preflight'
        'event-content-and-event-counts-not-read'
        'cloud-rule-and-sensor-health-require-external-validation'
        'windows-11-client-build-22621-or-later-x64-required'
    )
}

$result | ConvertTo-Json -Depth 4 -Compress
if (-not $result.Passed) { exit 1 }
