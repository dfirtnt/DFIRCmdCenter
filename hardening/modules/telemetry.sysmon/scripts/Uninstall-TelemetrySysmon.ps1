$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$ModuleIdentity = 'telemetry.sysmon@1.0.0'
$ExpectedBinarySha256 = '83D31F2478DC6716CFDBF69E5C384BF043072B5F0D8D7B2EEA365F709FDA4352'
$ExpectedConfigurationSha256 = '4516404FA30EE87CEA558567820CDC78863CC4AB07889519E49EAC3CCA92E0D2'
$BinaryPath = Join-Path -Path $PSScriptRoot -ChildPath 'Sysmon64.exe'
$StateDirectory = Join-Path -Path $env:ProgramData -ChildPath 'FamilyHardening\telemetry.sysmon'
$StatePath = Join-Path -Path $StateDirectory -ChildPath 'module-state.json'

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

if (-not (Test-Path -LiteralPath $StatePath -PathType Leaf)) {
    throw 'The telemetry.sysmon ownership state is missing. Refusing to remove an unowned Sysmon installation.'
}

$state = Get-Content -LiteralPath $StatePath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
if (
    [int]$state.SchemaVersion -ne 1 -or
    [string]$state.Module -ne $ModuleIdentity -or
    [string]$state.ExpectedBinarySha256 -ne $ExpectedBinarySha256 -or
    [string]$state.ExpectedConfigurationSha256 -ne $ExpectedConfigurationSha256
) {
    throw 'The Sysmon ownership state does not match this exact module version.'
}

Assert-ExpectedSha256 -Path $BinaryPath -ExpectedSha256 $ExpectedBinarySha256
Assert-MicrosoftSignature -Path $BinaryPath

$service = Get-CimInstance -ClassName Win32_Service -Filter "Name='Sysmon64'" -ErrorAction SilentlyContinue
$driver = Get-CimInstance -ClassName Win32_SystemDriver -Filter "Name='SysmonDrv'" -ErrorAction SilentlyContinue
if ([string]$state.Status -eq 'rolled-back') {
    if ($null -ne $service -or $null -ne $driver) {
        throw 'The module state says rolled back, but the Sysmon service or driver is present. Reconcile read-only.'
    }
    Write-Output 'telemetry.sysmon@1.0.0 is already rolled back.'
    exit 0
}
if ([string]$state.Status -notin @('installing', 'installed')) {
    throw 'The Sysmon ownership state is not eligible for rollback.'
}
if ($null -eq $service) {
    throw 'The module-owned Sysmon service is absent. Reconcile the ambiguous state; do not force removal.'
}

$installedBinaryPath = Get-ServiceBinaryPath -Service $service
Assert-ExpectedSha256 -Path $installedBinaryPath -ExpectedSha256 $ExpectedBinarySha256
Assert-MicrosoftSignature -Path $installedBinaryPath

& $BinaryPath -u
if ($LASTEXITCODE -ne 0) {
    throw "Sysmon uninstallation failed with exit code $LASTEXITCODE. Reconcile before retrying."
}

Start-Sleep -Seconds 2
$remainingService = Get-CimInstance -ClassName Win32_Service -Filter "Name='Sysmon64'" -ErrorAction SilentlyContinue
$remainingDriver = Get-CimInstance -ClassName Win32_SystemDriver -Filter "Name='SysmonDrv'" -ErrorAction SilentlyContinue
if ($null -ne $remainingService -or $null -ne $remainingDriver) {
    throw 'Sysmon service or driver remains after uninstallation. Do not use force removal automatically.'
}

[pscustomobject][ordered]@{
    SchemaVersion = 1
    Module = $ModuleIdentity
    Status = 'rolled-back'
    ExpectedBinarySha256 = $ExpectedBinarySha256
    ExpectedConfigurationSha256 = $ExpectedConfigurationSha256
    InstalledAtUtc = $state.InstalledAtUtc
    RolledBackAtUtc = (Get-Date).ToUniversalTime().ToString('o')
} | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $StatePath -Encoding UTF8 -ErrorAction Stop

Write-Output 'telemetry.sysmon@1.0.0 rollback completed without force removal.'
exit 0
