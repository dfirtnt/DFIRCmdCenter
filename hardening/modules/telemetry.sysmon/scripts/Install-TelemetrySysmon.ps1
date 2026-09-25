$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$ModuleIdentity = 'telemetry.sysmon@1.0.0'
$ExpectedBinarySha256 = '83D31F2478DC6716CFDBF69E5C384BF043072B5F0D8D7B2EEA365F709FDA4352'
$ExpectedConfigurationSha256 = '4516404FA30EE87CEA558567820CDC78863CC4AB07889519E49EAC3CCA92E0D2'
$PackageRoot = $PSScriptRoot
$BinaryPath = Join-Path -Path $PackageRoot -ChildPath 'Sysmon64.exe'
$ConfigurationPath = Join-Path -Path $PackageRoot -ChildPath 'sysmonconfig.xml'
$LogName = 'Microsoft-Windows-Sysmon/Operational'
$StateDirectory = Join-Path -Path $env:ProgramData -ChildPath 'FamilyHardening\telemetry.sysmon'
$StatePath = Join-Path -Path $StateDirectory -ChildPath 'module-state.json'

function Assert-SupportedPlatform {
    $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $buildNumber = [int]$operatingSystem.BuildNumber

    if ([int]$operatingSystem.ProductType -ne 1) {
        throw 'This module supports Windows 11 client only and refuses Windows Server.'
    }
    if ($buildNumber -lt 22621) {
        throw 'This module requires Windows 11 22H2 or later.'
    }
    if (-not [Environment]::Is64BitOperatingSystem) {
        throw 'This module requires x64 Windows.'
    }
}

function Assert-ExpectedSha256 {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw 'A required package file is missing.'
    }

    $actualSha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    if ($actualSha256 -ne $ExpectedSha256) {
        throw 'A required package file failed SHA-256 validation.'
    }
}

function Assert-MicrosoftSignature {
    param([Parameter(Mandatory = $true)][string]$Path)

    $signature = Get-AuthenticodeSignature -FilePath $Path
    if (
        $signature.Status -ne 'Valid' -or
        $null -eq $signature.SignerCertificate -or
        $signature.SignerCertificate.Subject -notmatch 'CN=Microsoft Corporation'
    ) {
        throw 'Sysmon64.exe does not have the expected valid Microsoft Authenticode signature.'
    }
}

function Get-ServiceBinaryPath {
    param([Parameter(Mandatory = $true)]$Service)

    $rawPath = [string]$Service.PathName
    if ($rawPath -match '^\s*"([^"]+)"') {
        return $Matches[1]
    }
    return ($rawPath -split '\s+', 2)[0]
}

function Get-EventDataValue {
    param(
        [Parameter(Mandatory = $true)]$Event,
        [Parameter(Mandatory = $true)][string]$Name
    )

    [xml]$eventXml = $Event.ToXml()
    $node = @($eventXml.Event.EventData.Data) | Where-Object {
        [string]$_.Name -eq $Name
    } | Select-Object -First 1
    if ($null -eq $node) {
        return $null
    }
    return [string]$node.'#text'
}

function Test-ConfigurationHash {
    param([Parameter(Mandatory = $true)]$Event)

    $value = Get-EventDataValue -Event $Event -Name 'ConfigurationFileHash'
    if ([string]::IsNullOrWhiteSpace($value)) {
        return $false
    }
    return $value.ToUpperInvariant().Contains("SHA256=$ExpectedConfigurationSha256")
}

function Get-LatestConfigurationEvent {
    try {
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = $LogName; Id = 16 } -MaxEvents 20 -ErrorAction Stop)
        return $events | Select-Object -First 1
    } catch {
        return $null
    }
}

function Set-StateDirectoryAcl {
    if (-not (Test-Path -LiteralPath $StateDirectory -PathType Container)) {
        $null = New-Item -Path $StateDirectory -ItemType Directory -ErrorAction Stop
    }

    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $inheritance = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $propagation = [System.Security.AccessControl.PropagationFlags]::None
    $access = [System.Security.AccessControl.AccessControlType]::Allow
    foreach ($identity in @('NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators')) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $identity,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            $propagation,
            $access
        )
        $null = $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $StateDirectory -AclObject $acl -ErrorAction Stop
}

function Write-ModuleState {
    param(
        [Parameter(Mandatory = $true)][string]$Status,
        [AllowNull()][string]$InstalledAtUtc,
        [AllowNull()][string]$RolledBackAtUtc
    )

    Set-StateDirectoryAcl
    [pscustomobject][ordered]@{
        SchemaVersion = 1
        Module = $ModuleIdentity
        Status = $Status
        ExpectedBinarySha256 = $ExpectedBinarySha256
        ExpectedConfigurationSha256 = $ExpectedConfigurationSha256
        InstalledAtUtc = $InstalledAtUtc
        RolledBackAtUtc = $RolledBackAtUtc
    } | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $StatePath -Encoding UTF8 -ErrorAction Stop
}

function Read-ModuleState {
    if (-not (Test-Path -LiteralPath $StatePath -PathType Leaf)) {
        return $null
    }

    $state = Get-Content -LiteralPath $StatePath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if (
        [int]$state.SchemaVersion -ne 1 -or
        [string]$state.Module -ne $ModuleIdentity -or
        [string]$state.ExpectedBinarySha256 -ne $ExpectedBinarySha256 -or
        [string]$state.ExpectedConfigurationSha256 -ne $ExpectedConfigurationSha256
    ) {
        throw 'The existing Sysmon module state does not match this exact module version.'
    }
    return $state
}

function Assert-ExactInstalledState {
    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='Sysmon64'" -ErrorAction Stop
    if (
        $null -eq $service -or
        [string]$service.State -ne 'Running' -or
        [string]$service.StartMode -ne 'Auto'
    ) {
        throw 'The module state says installed, but the Sysmon64 service is not running.'
    }

    $installedBinaryPath = Get-ServiceBinaryPath -Service $service
    Assert-ExpectedSha256 -Path $installedBinaryPath -ExpectedSha256 $ExpectedBinarySha256
    Assert-MicrosoftSignature -Path $installedBinaryPath

    $driver = Get-CimInstance -ClassName Win32_SystemDriver -Filter "Name='SysmonDrv'" -ErrorAction Stop
    if (
        $null -eq $driver -or
        [string]$driver.State -ne 'Running' -or
        [string]$driver.StartMode -ne 'Boot'
    ) {
        throw 'The module state says installed, but the SysmonDrv driver is not running.'
    }

    $configurationEvent = Get-LatestConfigurationEvent
    if ($null -eq $configurationEvent -or -not (Test-ConfigurationHash -Event $configurationEvent)) {
        throw 'The latest Sysmon configuration event does not match the pinned configuration.'
    }
}

Assert-SupportedPlatform
Assert-ExpectedSha256 -Path $BinaryPath -ExpectedSha256 $ExpectedBinarySha256
Assert-ExpectedSha256 -Path $ConfigurationPath -ExpectedSha256 $ExpectedConfigurationSha256
Assert-MicrosoftSignature -Path $BinaryPath

$state = Read-ModuleState
if ($null -ne $state -and [string]$state.Status -eq 'installed') {
    Assert-ExactInstalledState
    Write-Output 'telemetry.sysmon@1.0.0 is already installed with the exact pinned binary and configuration.'
    exit 0
}
if ($null -ne $state -and [string]$state.Status -eq 'installing') {
    throw 'A prior Sysmon installation has an ambiguous outcome. Reconcile it read-only; do not retry automatically.'
}
if ($null -ne $state -and [string]$state.Status -ne 'rolled-back') {
    throw 'The existing Sysmon module state is not eligible for installation.'
}

$existingSysmonService = @(Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue)
$existingSysmonDriver = Get-CimInstance -ClassName Win32_SystemDriver -Filter "Name='SysmonDrv'" -ErrorAction SilentlyContinue
if ($existingSysmonService.Count -ne 0 -or $null -ne $existingSysmonDriver) {
    throw 'A Sysmon service or driver already appears to be installed. This initial-install package refuses to overwrite an existing Sysmon instance.'
}

$preInstallConfigurationEvent = Get-LatestConfigurationEvent
$preInstallConfigurationRecordId = 0
if ($null -ne $preInstallConfigurationEvent) {
    $preInstallConfigurationRecordId = [long]$preInstallConfigurationEvent.RecordId
}

Write-ModuleState -Status 'installing' -InstalledAtUtc $null -RolledBackAtUtc $null

& $BinaryPath -accepteula -i $ConfigurationPath
if ($LASTEXITCODE -ne 0) {
    throw "Sysmon installation failed with exit code $LASTEXITCODE. The module state remains ambiguous."
}

$deadline = (Get-Date).AddSeconds(15)
do {
    Start-Sleep -Seconds 1
    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='Sysmon64'" -ErrorAction SilentlyContinue
    $driver = Get-CimInstance -ClassName Win32_SystemDriver -Filter "Name='SysmonDrv'" -ErrorAction SilentlyContinue
    $configurationEvent = Get-LatestConfigurationEvent
} until (
    ($null -ne $service -and [string]$service.State -eq 'Running') -and
    ($null -ne $driver -and [string]$driver.State -eq 'Running') -and
    (
        $null -ne $configurationEvent -and
        [long]$configurationEvent.RecordId -gt $preInstallConfigurationRecordId -and
        (Test-ConfigurationHash -Event $configurationEvent)
    ) -or
    (Get-Date) -ge $deadline
)

if (
    $null -eq $configurationEvent -or
    [long]$configurationEvent.RecordId -le $preInstallConfigurationRecordId -or
    -not (Test-ConfigurationHash -Event $configurationEvent)
) {
    throw 'No new Event ID 16 proves that this installation loaded the pinned configuration.'
}

Assert-ExactInstalledState
$log = Get-WinEvent -ListLog $LogName -ErrorAction Stop
if (-not $log.IsEnabled) {
    throw 'The Sysmon Operational log exists but is disabled.'
}

$installedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
Write-ModuleState -Status 'installed' -InstalledAtUtc $installedAtUtc -RolledBackAtUtc $null

Write-Output 'telemetry.sysmon@1.0.0 installation completed. Run the separate verifier and prove LimaCharlie ingestion.'
exit 0
