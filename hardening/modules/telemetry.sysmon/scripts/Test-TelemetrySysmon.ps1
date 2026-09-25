$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$ModuleIdentity = 'telemetry.sysmon@1.0.0'
$ExpectedBinarySha256 = '83D31F2478DC6716CFDBF69E5C384BF043072B5F0D8D7B2EEA365F709FDA4352'
$ExpectedConfigurationSha256 = '4516404FA30EE87CEA558567820CDC78863CC4AB07889519E49EAC3CCA92E0D2'
$ExpectedVersion = '15.22'
$LogName = 'Microsoft-Windows-Sysmon/Operational'
$StatePath = Join-Path -Path $env:ProgramData -ChildPath 'FamilyHardening\telemetry.sysmon\module-state.json'
$script:Checks = @()

function Add-Check {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][bool]$Passed,
        [Parameter(Mandatory = $true)][string]$Status
    )

    $script:Checks += [pscustomobject][ordered]@{
        Name = $Name
        Passed = $Passed
        Status = $Status
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

function Get-FirstEventOrNull {
    param([Parameter(Mandatory = $true)][string]$FilterXPath)

    try {
        return Get-WinEvent -LogName $LogName -FilterXPath $FilterXPath -MaxEvents 1 -ErrorAction Stop |
            Select-Object -First 1
    } catch {
        if ([string]$_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
            return $null
        }
        throw
    }
}

$configurationEvent = $null
$installedBinaryPath = $null

try {
    if (-not (Test-Path -LiteralPath $StatePath -PathType Leaf)) {
        Add-Check -Name 'OwnershipState' -Passed $false -Status 'missing'
    } else {
        $state = Get-Content -LiteralPath $StatePath -Raw -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
        $ownershipMatches = (
            [int]$state.SchemaVersion -eq 1 -and
            [string]$state.Module -eq $ModuleIdentity -and
            [string]$state.Status -eq 'installed' -and
            [string]$state.ExpectedBinarySha256 -eq $ExpectedBinarySha256 -and
            [string]$state.ExpectedConfigurationSha256 -eq $ExpectedConfigurationSha256 -and
            -not [string]::IsNullOrWhiteSpace([string]$state.InstalledAtUtc)
        )
        Add-Check -Name 'OwnershipState' -Passed $ownershipMatches -Status $(
            if ($ownershipMatches) { 'exact-installed-state' } else { 'mismatch-or-incomplete' }
        )
    }
} catch {
    Add-Check -Name 'OwnershipState' -Passed $false -Status 'query-failed'
}

try {
    $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $supportedPlatform = (
        [int]$operatingSystem.ProductType -eq 1 -and
        [int]$operatingSystem.BuildNumber -ge 22621 -and
        [Environment]::Is64BitOperatingSystem
    )
    Add-Check -Name 'SupportedPlatform' -Passed $supportedPlatform -Status $(
        if ($supportedPlatform) { 'windows-11-x64-supported' } else { 'unsupported-platform' }
    )
} catch {
    Add-Check -Name 'SupportedPlatform' -Passed $false -Status 'query-failed'
}

try {
    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='Sysmon64'" -ErrorAction Stop
    $servicePresent = $null -ne $service
    Add-Check -Name 'ServicePresent' -Passed $servicePresent -Status $(
        if ($servicePresent) { 'present' } else { 'absent' }
    )
    $serviceRunning = $servicePresent -and [string]$service.State -eq 'Running'
    Add-Check -Name 'ServiceRunning' -Passed $serviceRunning -Status $(
        if ($serviceRunning) { 'running' } else { 'not-running' }
    )
    $serviceAutomatic = $servicePresent -and [string]$service.StartMode -eq 'Auto'
    Add-Check -Name 'ServiceAutomatic' -Passed $serviceAutomatic -Status $(
        if ($serviceAutomatic) { 'automatic' } else { 'not-automatic' }
    )
    if ($servicePresent) {
        $installedBinaryPath = Get-ServiceBinaryPath -Service $service
    }
} catch {
    Add-Check -Name 'ServicePresent' -Passed $false -Status 'query-failed'
    Add-Check -Name 'ServiceRunning' -Passed $false -Status 'query-failed'
    Add-Check -Name 'ServiceAutomatic' -Passed $false -Status 'query-failed'
}

try {
    $driver = Get-CimInstance -ClassName Win32_SystemDriver -Filter "Name='SysmonDrv'" -ErrorAction Stop
    $driverPresent = $null -ne $driver
    Add-Check -Name 'DriverPresent' -Passed $driverPresent -Status $(
        if ($driverPresent) { 'present' } else { 'absent' }
    )
    $driverRunning = $driverPresent -and [string]$driver.State -eq 'Running'
    Add-Check -Name 'DriverRunning' -Passed $driverRunning -Status $(
        if ($driverRunning) { 'running' } else { 'not-running' }
    )
    $driverBootStart = $driverPresent -and [string]$driver.StartMode -eq 'Boot'
    Add-Check -Name 'DriverBootStart' -Passed $driverBootStart -Status $(
        if ($driverBootStart) { 'boot-start' } else { 'not-boot-start' }
    )
} catch {
    Add-Check -Name 'DriverPresent' -Passed $false -Status 'query-failed'
    Add-Check -Name 'DriverRunning' -Passed $false -Status 'query-failed'
    Add-Check -Name 'DriverBootStart' -Passed $false -Status 'query-failed'
}

if (-not [string]::IsNullOrWhiteSpace($installedBinaryPath) -and (Test-Path -LiteralPath $installedBinaryPath -PathType Leaf)) {
    try {
        $binaryHash = (Get-FileHash -LiteralPath $installedBinaryPath -Algorithm SHA256 -ErrorAction Stop).Hash
        $hashMatches = $binaryHash -eq $ExpectedBinarySha256
        Add-Check -Name 'BinaryHash' -Passed $hashMatches -Status $(
            if ($hashMatches) { 'pinned-hash-match' } else { 'hash-mismatch' }
        )
    } catch {
        Add-Check -Name 'BinaryHash' -Passed $false -Status 'query-failed'
    }

    try {
        $signature = Get-AuthenticodeSignature -FilePath $installedBinaryPath
        $signatureMatches = (
            $signature.Status -eq 'Valid' -and
            $null -ne $signature.SignerCertificate -and
            $signature.SignerCertificate.Subject -match 'CN=Microsoft Corporation'
        )
        Add-Check -Name 'BinarySignature' -Passed $signatureMatches -Status $(
            if ($signatureMatches) { 'valid-microsoft-signature' } else { 'signature-invalid' }
        )
    } catch {
        Add-Check -Name 'BinarySignature' -Passed $false -Status 'query-failed'
    }

    try {
        $version = [string](Get-Item -LiteralPath $installedBinaryPath -ErrorAction Stop).VersionInfo.ProductVersion
        $versionMatches = $version -match '^15\.22(?:\.|\s|$)'
        Add-Check -Name 'BinaryVersion' -Passed $versionMatches -Status $(
            if ($versionMatches) { $ExpectedVersion } else { 'version-mismatch' }
        )
    } catch {
        Add-Check -Name 'BinaryVersion' -Passed $false -Status 'query-failed'
    }
} else {
    Add-Check -Name 'BinaryHash' -Passed $false -Status 'binary-not-found'
    Add-Check -Name 'BinarySignature' -Passed $false -Status 'binary-not-found'
    Add-Check -Name 'BinaryVersion' -Passed $false -Status 'binary-not-found'
}

try {
    $log = Get-WinEvent -ListLog $LogName -ErrorAction Stop
    Add-Check -Name 'OperationalLogEnabled' -Passed ([bool]$log.IsEnabled) -Status $(
        if ($log.IsEnabled) { 'enabled' } else { 'disabled' }
    )
} catch {
    Add-Check -Name 'OperationalLogEnabled' -Passed $false -Status 'query-failed'
}

try {
    $configurationEvent = @(Get-WinEvent -FilterHashtable @{ LogName = $LogName; Id = 16 } -MaxEvents 20 -ErrorAction Stop) | Select-Object -First 1
    $configurationPresent = $null -ne $configurationEvent
    Add-Check -Name 'ConfigurationEventPresent' -Passed $configurationPresent -Status $(
        if ($configurationPresent) { 'event-16-present' } else { 'event-16-absent' }
    )

    $configurationHashValue = $null
    if ($configurationPresent) {
        $configurationHashValue = Get-EventDataValue -Event $configurationEvent -Name 'ConfigurationFileHash'
    }
    $configurationHashMatches = (
        -not [string]::IsNullOrWhiteSpace($configurationHashValue) -and
        $configurationHashValue.ToUpperInvariant().Contains("SHA256=$ExpectedConfigurationSha256")
    )
    Add-Check -Name 'ConfigurationFileHash' -Passed $configurationHashMatches -Status $(
        if ($configurationHashMatches) { 'pinned-hash-match' } else { 'hash-missing-or-mismatch' }
    )
} catch {
    Add-Check -Name 'ConfigurationEventPresent' -Passed $false -Status 'query-failed'
    Add-Check -Name 'ConfigurationFileHash' -Passed $false -Status 'query-failed'
}

if ($null -ne $configurationEvent) {
    try {
        $recordId = [long]$configurationEvent.RecordId
        $normalEvent = Get-FirstEventOrNull -FilterXPath "*[System[(EventRecordID > $recordId) and (EventID != 4) and (EventID != 16) and (EventID != 255)]]"
        $normalPresent = $null -ne $normalEvent
        Add-Check -Name 'NormalEventAfterConfiguration' -Passed $normalPresent -Status $(
            if ($normalPresent) { 'present' } else { 'absent' }
        )
        $errorEvent = Get-FirstEventOrNull -FilterXPath "*[System[(EventRecordID > $recordId) and (EventID=255)]]"
        $noErrors = $null -eq $errorEvent
        Add-Check -Name 'EventId255AfterConfiguration' -Passed $noErrors -Status $(
            if ($noErrors) { 'none' } else { 'present' }
        )
    } catch {
        Add-Check -Name 'NormalEventAfterConfiguration' -Passed $false -Status 'query-failed'
        Add-Check -Name 'EventId255AfterConfiguration' -Passed $false -Status 'query-failed'
    }
} else {
    Add-Check -Name 'NormalEventAfterConfiguration' -Passed $false -Status 'not-evaluated'
    Add-Check -Name 'EventId255AfterConfiguration' -Passed $false -Status 'not-evaluated'
}

$passed = @($script:Checks | Where-Object { -not $_.Passed }).Count -eq 0
$result = [pscustomobject][ordered]@{
    SchemaVersion = 1
    Module = $ModuleIdentity
    Passed = $passed
    Checks = $script:Checks
    Limitations = @(
        'LimaCharlie ingestion requires external validation from the correlated sensor.'
        'Action1 and Velociraptor health require separate platform validation.'
    )
}

$result | ConvertTo-Json -Depth 5
if (-not $passed) {
    exit 1
}
exit 0
