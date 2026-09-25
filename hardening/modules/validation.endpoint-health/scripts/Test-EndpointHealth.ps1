#requires -Version 5.1
#requires -RunAsAdministrator

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Add-UniqueCode {
    param(
        [Parameter(Mandatory = $true)][System.Collections.Generic.List[string]]$Codes,
        [Parameter(Mandatory = $true)][string]$Code
    )
    if (-not $Codes.Contains($Code)) { $Codes.Add($Code) }
}

function Convert-Edition {
    param([AllowNull()][string]$EditionId)
    switch -Regex ([string]$EditionId) {
        '^(Core|CoreSingleLanguage|CoreCountrySpecific)$' { return 'home' }
        '^Professional' { return 'pro' }
        '^Enterprise' { return 'enterprise' }
        '^Education' { return 'education' }
        default { return 'unknown' }
    }
}

function Convert-Architecture {
    param([AllowNull()][object]$Architecture)
    if ($null -eq $Architecture) { return 'unknown' }
    switch ([int]$Architecture) {
        0 { return 'x86' }
        9 { return 'x64' }
        12 { return 'arm64' }
        default { return 'unknown' }
    }
}

function Convert-FirewallAction {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return 'unknown' }
    switch -Regex (([string]$Value).ToLowerInvariant()) {
        '^allow$' { return 'allow' }
        '^block$' { return 'block' }
        '^notconfigured$' { return 'not-configured' }
        default { return 'unknown' }
    }
}

function Convert-OptionalBoolean {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    switch -Regex (([string]$Value).ToLowerInvariant()) {
        '^true$' { return $true }
        '^false$' { return $false }
        '^notconfigured$' { return $null }
        default { return $null }
    }
}

function Convert-NetworkCategory {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return 'unknown' }
    switch -Regex (([string]$Value).ToLowerInvariant()) {
        '^public$' { return 'public' }
        '^private$' { return 'private' }
        '^domainauthenticated$' { return 'domain-authenticated' }
        default { return 'unknown' }
    }
}

function Initialize-WscInterop {
    if ('EndpointHealth.WscReader' -as [type]) { return }
    Add-Type -Language CSharp -ErrorAction Stop -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace EndpointHealth
{
    [ComImport]
    [Guid("722A338C-6E8E-4E72-AC27-1417FB0C81C2")]
    [InterfaceType(ComInterfaceType.InterfaceIsDual)]
    internal interface IWSCProductList
    {
        [PreserveSig] int Initialize(uint provider);
        [PreserveSig] int get_Count(out int value);
        [PreserveSig] int get_Item(
            uint index,
            [MarshalAs(UnmanagedType.Interface)] out IWscProduct value);
    }

    [ComImport]
    [Guid("8C38232E-3A45-4A27-92B0-1A16A975F669")]
    [InterfaceType(ComInterfaceType.InterfaceIsDual)]
    internal interface IWscProduct
    {
        [PreserveSig] int get_ProductName([MarshalAs(UnmanagedType.BStr)] out string value);
        [PreserveSig] int get_ProductState(out int value);
        [PreserveSig] int get_SignatureStatus(out int value);
    }

    public sealed class WscProductRow
    {
        public string ProviderFamily { get; private set; }
        public string State { get; private set; }
        public string Signatures { get; private set; }

        internal WscProductRow(string family, string state, string signatures)
        {
            ProviderFamily = family;
            State = state;
            Signatures = signatures;
        }
    }

    public static class WscReader
    {
        private static readonly Guid ProductListClsid =
            new Guid("17072F7B-9ABE-4A74-A261-1EB76B55107A");

        public static WscProductRow[] GetProducts(uint provider, bool includeSignature)
        {
            if (provider != 1U && provider != 4U)
                throw new ArgumentOutOfRangeException("provider");

            object listRcw = null;
            try
            {
                Type listType = Type.GetTypeFromCLSID(ProductListClsid, true);
                listRcw = Activator.CreateInstance(listType);
                IWSCProductList list = (IWSCProductList)listRcw;
                RequireSOk(list.Initialize(provider), "Initialize");
                int count;
                RequireSOk(list.get_Count(out count), "get_Count");
                if (count < 0 || count > 16)
                    throw new InvalidOperationException("WSC product count outside accepted bound.");

                List<WscProductRow> rows = new List<WscProductRow>(count);
                for (int index = 0; index < count; index++)
                {
                    IWscProduct product = null;
                    try
                    {
                        RequireSOk(list.get_Item((uint)index, out product), "get_Item");
                        string rawName;
                        int rawState;
                        RequireSOk(product.get_ProductName(out rawName), "get_ProductName");
                        RequireSOk(product.get_ProductState(out rawState), "get_ProductState");
                        string signature = "not-applicable";
                        if (includeSignature)
                        {
                            int rawSignature;
                            RequireSOk(
                                product.get_SignatureStatus(out rawSignature),
                                "get_SignatureStatus");
                            signature = NormalizeSignature(rawSignature);
                        }
                        rows.Add(new WscProductRow(
                            NormalizeFamily(rawName), NormalizeState(rawState), signature));
                    }
                    finally
                    {
                        if (product != null && Marshal.IsComObject(product))
                            Marshal.FinalReleaseComObject(product);
                    }
                }
                return rows.ToArray();
            }
            finally
            {
                if (listRcw != null && Marshal.IsComObject(listRcw))
                    Marshal.FinalReleaseComObject(listRcw);
            }
        }

        private static void RequireSOk(int hr, string operation)
        {
            if (hr != 0) throw new COMException(operation + " returned non-S_OK.", hr);
        }

        private static string NormalizeFamily(string name)
        {
            string bounded = name ?? String.Empty;
            if (bounded.Length > 256) bounded = bounded.Substring(0, 256);
            if (Regex.IsMatch(
                    bounded, @"(?:microsoft|windows)\s+defender",
                    RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
                return "microsoft_defender";
            if (Regex.IsMatch(
                    bounded, @"\b(?:mcafee|trellix)\b",
                    RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
                return "mcafee";
            return "other";
        }

        private static string NormalizeState(int value)
        {
            switch (value)
            {
                case 0: return "on";
                case 1: return "off";
                case 2: return "snoozed";
                case 3: return "expired";
                default: return "unknown";
            }
        }

        private static string NormalizeSignature(int value)
        {
            switch (value)
            {
                case 0: return "out-of-date";
                case 1: return "up-to-date";
                default: return "unknown";
            }
        }
    }
}
'@
}

function Get-WscProducts {
    param(
        [Parameter(Mandatory = $true)][ValidateSet(1, 4)][int]$Provider,
        [Parameter(Mandatory = $true)][bool]$IncludeSignature
    )
    Initialize-WscInterop
    return @(
        [EndpointHealth.WscReader]::GetProducts([uint32]$Provider, $IncludeSignature) |
            Sort-Object ProviderFamily, State, Signatures |
            ForEach-Object {
                [pscustomobject]@{
                    ProviderFamily = [string]$_.ProviderFamily
                    State = [string]$_.State
                    Signatures = [string]$_.Signatures
                }
            }
    )
}

function Get-ServiceState {
    param(
        [Parameter(Mandatory = $true)][string]$Query,
        [Parameter(Mandatory = $true)][string]$ErrorCode,
        [Parameter(Mandatory = $true)][System.Collections.Generic.List[string]]$Errors
    )
    try {
        $matches = @(Get-CimInstance -Query $Query -ErrorAction Stop)
        if ($matches.Count -eq 0) { return 'absent' }
        if (@($matches | Where-Object { $_.State -eq 'Running' }).Count -gt 0) {
            return 'running'
        }
        return 'stopped'
    }
    catch {
        Add-UniqueCode -Codes $Errors -Code $ErrorCode
        return 'error'
    }
}

function Get-EndpointHealthObservationJson {
    $collectionErrors = New-Object 'System.Collections.Generic.List[string]'
    $operatingSystem = [ordered]@{
        Status = 'error'; Family = 'unknown'; Edition = 'unknown'; Release = 'unknown'
        Build = $null; Revision = $null; Architecture = 'unknown'; ProductType = 'unknown'
    }
    try {
        $os = @(Get-CimInstance -Query (
                'SELECT ProductType, BuildNumber FROM Win32_OperatingSystem'
            ) -ErrorAction Stop)[0]
        $processor = @(Get-CimInstance -Query (
                'SELECT Architecture FROM Win32_Processor'
            ) -ErrorAction Stop)[0]
        $registry = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::LocalMachine,
            [Microsoft.Win32.RegistryView]::Registry64)
        $currentVersion = $null
        try {
            $currentVersion = $registry.OpenSubKey(
                'SOFTWARE\Microsoft\Windows NT\CurrentVersion', $false)
            if ($null -eq $currentVersion) { throw 'CurrentVersion unavailable.' }
            $editionId = [string]$currentVersion.GetValue('EditionID', '')
            $displayVersion = [string]$currentVersion.GetValue('DisplayVersion', '')
            $registryBuild = [string]$currentVersion.GetValue('CurrentBuildNumber', '')
            $revisionValue = $currentVersion.GetValue('UBR', $null)
        }
        finally {
            if ($null -ne $currentVersion) { $currentVersion.Close() }
            $registry.Close()
        }

        $parsedBuild = 0
        if ([int]::TryParse([string]$os.BuildNumber, [ref]$parsedBuild)) {
            $operatingSystem.Build = $parsedBuild
        }
        else { Add-UniqueCode -Codes $collectionErrors -Code 'os_build_unavailable' }
        $parsedRevision = 0
        if ($null -ne $revisionValue -and
            [int]::TryParse([string]$revisionValue, [ref]$parsedRevision)) {
            $operatingSystem.Revision = $parsedRevision
        }
        else { Add-UniqueCode -Codes $collectionErrors -Code 'os_revision_unavailable' }
        if ($registryBuild -and $registryBuild -ne [string]$os.BuildNumber) {
            Add-UniqueCode -Codes $collectionErrors -Code 'os_build_source_mismatch'
        }
        $operatingSystem.Family = if ([int]$os.ProductType -ne 1) {
            'windows_server'
        }
        elseif ($parsedBuild -ge 22000) { 'windows_11' }
        else { 'windows_10' }
        $operatingSystem.Edition = Convert-Edition -EditionId $editionId
        $operatingSystem.Release = if ($displayVersion -match '^\d{2}H[12]$') {
            $displayVersion.ToLowerInvariant()
        }
        else { 'unknown' }
        $operatingSystem.Architecture = Convert-Architecture -Architecture $processor.Architecture
        $operatingSystem.ProductType = switch ([int]$os.ProductType) {
            1 { 'client' }; 2 { 'domain-controller' }; 3 { 'server' }; default { 'unknown' }
        }
        $operatingSystem.Status = 'collected'
    }
    catch { Add-UniqueCode -Codes $collectionErrors -Code 'os_query_failed' }

    $secureBoot = [ordered]@{ Status = 'error'; Supported = $null; Enabled = $null }
    try {
        $secureBoot.Enabled = [bool](Confirm-SecureBootUEFI -ErrorAction Stop)
        $secureBoot.Supported = $true
        $secureBoot.Status = 'collected'
    }
    catch {
        if ([string]$_.FullyQualifiedErrorId -match '(?i)not.?supported') {
            $secureBoot.Status = 'unsupported'
            $secureBoot.Supported = $false
            $secureBoot.Enabled = $null
        }
        else { Add-UniqueCode -Codes $collectionErrors -Code 'secure_boot_query_failed' }
    }

    $tpm = [ordered]@{
        Status = 'error'; Present = $null; Ready = $null; Enabled = $null
        Activated = $null; SpecVersion = 'unknown'
    }
    try {
        $tpmInstances = @(Get-CimInstance `
            -Namespace 'root\CIMV2\Security\MicrosoftTpm' `
            -Query ('SELECT IsActivated_InitialValue, IsEnabled_InitialValue, ' +
                'SpecVersion FROM Win32_Tpm') -ErrorAction Stop)
        if ($tpmInstances.Count -gt 1) { throw 'Unexpected TPM instance count.' }
        if ($tpmInstances.Count -eq 0) {
            $tpm.Status = 'collected'
            $tpm.Present = $false
        }
        else {
            $tpmCim = $tpmInstances[0]
            $ready = Invoke-CimMethod -InputObject $tpmCim -MethodName IsReady -ErrorAction Stop
            $enabled = Invoke-CimMethod -InputObject $tpmCim -MethodName IsEnabled -ErrorAction Stop
            $activated = Invoke-CimMethod `
                -InputObject $tpmCim -MethodName IsActivated -ErrorAction Stop
            if ([uint32]$ready.ReturnValue -ne 0 -or
                [uint32]$enabled.ReturnValue -ne 0 -or
                [uint32]$activated.ReturnValue -ne 0) {
                throw 'TPM status method returned nonzero.'
            }
            $tpm.Present = $true
            $tpm.Ready = [bool]$ready.IsReady
            $tpm.Enabled = [bool]$enabled.IsEnabled
            $tpm.Activated = [bool]$activated.IsActivated
            $rawSpec = [string]$tpmCim.SpecVersion
            if ($rawSpec -match '(^|[,;\s])2\.0([,;\s]|$)') { $tpm.SpecVersion = '2.0' }
            elseif ($rawSpec -match '(^|[,;\s])1\.2([,;\s]|$)') { $tpm.SpecVersion = '1.2' }
            $tpm.Status = 'collected'
        }
    }
    catch { Add-UniqueCode -Codes $collectionErrors -Code 'tpm_query_failed' }

    $wscState = Get-ServiceState `
        -Query "SELECT Name, State FROM Win32_Service WHERE Name='wscsvc'" `
        -ErrorCode 'security_center_service_query_failed' -Errors $collectionErrors
    if ($wscState -ne 'running') {
        Add-UniqueCode -Codes $collectionErrors -Code 'security_center_service_not_running'
    }

    $antivirus = [ordered]@{
        Status = 'error'; Products = @(); ActiveProviderFamilies = @()
        Assessment = 'unknown'; DefenderDependentControls = 'review'
    }
    try {
        $antivirus.Products = @(Get-WscProducts -Provider 4 -IncludeSignature $true)
        $activeProducts = @($antivirus.Products | Where-Object { $_.State -eq 'on' })
        $antivirus.ActiveProviderFamilies = @(
            $activeProducts | Select-Object -ExpandProperty ProviderFamily -Unique | Sort-Object)
        $antivirus.Status = 'collected'
        $antivirus.Assessment = switch ($activeProducts.Count) {
            0 { 'none-active' }; 1 { 'single-active' }; default { 'multiple-active' }
        }
        if (@($activeProducts | Where-Object {
                    $_.ProviderFamily -ne 'microsoft_defender'
                }).Count -gt 0) {
            $antivirus.DefenderDependentControls = 'defer'
        }
    }
    catch { Add-UniqueCode -Codes $collectionErrors -Code 'antivirus_wsc_query_failed' }

    $firewall = [ordered]@{
        Status = 'error'; Products = @(); Profiles = @(); ActiveNetworkCategories = @()
        Assessment = 'unknown'
    }
    try {
        try { $firewall.Products = @(Get-WscProducts -Provider 1 -IncludeSignature $false) }
        catch { Add-UniqueCode -Codes $collectionErrors -Code 'firewall_wsc_query_failed' }
        $firewall.Profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop |
            ForEach-Object {
                [pscustomobject]@{
                    Name = switch ([string]$_.Name) {
                        'Domain' { 'domain' }; 'Private' { 'private' }
                        'Public' { 'public' }; default { 'unknown' }
                    }
                    Enabled = Convert-OptionalBoolean -Value $_.Enabled
                    DefaultInboundAction = Convert-FirewallAction -Value $_.DefaultInboundAction
                    DefaultOutboundAction = Convert-FirewallAction -Value $_.DefaultOutboundAction
                    LogBlocked = Convert-OptionalBoolean -Value $_.LogBlocked
                }
            } | Sort-Object Name)
        $firewall.ActiveNetworkCategories = @(Get-NetConnectionProfile -ErrorAction Stop |
            ForEach-Object { Convert-NetworkCategory -Value $_.NetworkCategory } |
            Sort-Object -Unique)
        $firewall.Status = if ($firewall.Profiles.Count -eq 3) { 'collected' } else { 'unavailable' }
        $disabled = @($firewall.Profiles | Where-Object { $_.Enabled -ne $true })
        $firewall.Assessment = if ($firewall.Profiles.Count -eq 3 -and $disabled.Count -eq 0) {
            'all-windows-profiles-enabled'
        }
        else { 'attention-required' }
    }
    catch { Add-UniqueCode -Codes $collectionErrors -Code 'windows_firewall_query_failed' }

    $memoryIntegrity = [ordered]@{ Status = 'error'; Configured = $null; Running = $null }
    try {
        $deviceGuard = @(Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' `
            -Query ('SELECT SecurityServicesConfigured, SecurityServicesRunning ' +
                'FROM Win32_DeviceGuard') -ErrorAction Stop)
        if ($deviceGuard.Count -eq 0) { $memoryIntegrity.Status = 'unavailable' }
        else {
            $memoryIntegrity.Status = 'collected'
            $memoryIntegrity.Configured = @($deviceGuard[0].SecurityServicesConfigured) -contains 2
            $memoryIntegrity.Running = @($deviceGuard[0].SecurityServicesRunning) -contains 2
        }
    }
    catch { Add-UniqueCode -Codes $collectionErrors -Code 'memory_integrity_query_failed' }

    $agents = [ordered]@{
        Action1 = Get-ServiceState `
            -Query "SELECT Name, DisplayName, State FROM Win32_Service WHERE DisplayName='Action1 Agent'" `
            -ErrorCode 'action1_service_query_failed' -Errors $collectionErrors
        LimaCharlie = Get-ServiceState `
            -Query "SELECT Name, DisplayName, State FROM Win32_Service WHERE Name='rphcpsvc'" `
            -ErrorCode 'limacharlie_service_query_failed' -Errors $collectionErrors
        Velociraptor = Get-ServiceState `
            -Query "SELECT Name, DisplayName, State FROM Win32_Service WHERE Name='Velociraptor'" `
            -ErrorCode 'velociraptor_service_query_failed' -Errors $collectionErrors
        IdentityCorrelation = 'external-validation-required'
    }

    $observation = [ordered]@{
        SchemaVersion = 1
        Module = 'validation.endpoint-health@1.0.0'
        CapturedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        CollectionMode = 'read-only-local'
        OperatingSystem = $operatingSystem
        SecureBoot = $secureBoot
        Tpm = $tpm
        Antivirus = $antivirus
        Firewall = $firewall
        PlatformProtections = [ordered]@{ MemoryIntegrity = $memoryIntegrity }
        Agents = $agents
        CollectionErrors = @($collectionErrors | Sort-Object)
        Limitations = @(
            'antivirus-subscription-and-trial-state-not-assessed'
            'local-service-state-is-not-cloud-agent-health'
            'platform-identity-correlation-requires-external-strong-id-evidence'
            'windows-release-support-requires-current-review')
    }
    return ($observation | ConvertTo-Json -Depth 8 -Compress)
}

function Test-ExactProperties {
    param(
        [Parameter(Mandatory = $true)][object]$Object,
        [Parameter(Mandatory = $true)][string[]]$Expected
    )
    if ($null -eq $Object -or $Object -is [string] -or $Object -is [System.Array]) {
        return $false
    }
    $actual = @($Object.PSObject.Properties.Name | Sort-Object)
    $expectedSorted = @($Expected | Sort-Object)
    return ($actual -join "`n") -ceq ($expectedSorted -join "`n")
}

function Test-EnumValue {
    param([AllowNull()][object]$Value, [Parameter(Mandatory = $true)][string[]]$Allowed)
    return ($Value -is [string]) -and ([string]$Value -cin $Allowed)
}

function Test-NullableBoolean {
    param([AllowNull()][object]$Value)
    return ($null -eq $Value) -or ($Value -is [bool])
}

function Test-Integer {
    param(
        [AllowNull()][object]$Value,
        [Parameter(Mandatory = $true)][long]$Minimum,
        [Parameter(Mandatory = $true)][long]$Maximum,
        [switch]$AllowNull
    )
    if ($null -eq $Value) { return [bool]$AllowNull }
    if (-not ($Value -is [int] -or $Value -is [long])) { return $false }
    return [long]$Value -ge $Minimum -and [long]$Value -le $Maximum
}

function Test-BoundedArray {
    param([AllowNull()][object]$Value, [Parameter(Mandatory = $true)][int]$Maximum)
    return ($Value -is [System.Array]) -and @($Value).Count -le $Maximum
}

function Test-EnumArray {
    param(
        [AllowNull()][object]$Value,
        [Parameter(Mandatory = $true)][string[]]$Allowed,
        [Parameter(Mandatory = $true)][int]$Maximum
    )
    if (-not (Test-BoundedArray -Value $Value -Maximum $Maximum)) { return $false }
    $items = @($Value)
    foreach ($item in $items) {
        if (-not (Test-EnumValue -Value $item -Allowed $Allowed)) { return $false }
    }
    return @($items | Sort-Object -Unique).Count -eq $items.Count
}

function New-SafeObservation {
    param([Parameter(Mandatory = $true)][object]$InputObject)
    return [ordered]@{
        SchemaVersion = 1
        Module = 'validation.endpoint-health@1.0.0'
        CapturedAtUtc = [string]$InputObject.CapturedAtUtc
        CollectionMode = 'read-only-local'
        OperatingSystem = [ordered]@{
            Status = [string]$InputObject.OperatingSystem.Status
            Family = [string]$InputObject.OperatingSystem.Family
            Edition = [string]$InputObject.OperatingSystem.Edition
            Release = [string]$InputObject.OperatingSystem.Release
            Build = if ($null -eq $InputObject.OperatingSystem.Build) { $null } else {
                [int]$InputObject.OperatingSystem.Build
            }
            Revision = if ($null -eq $InputObject.OperatingSystem.Revision) { $null } else {
                [int]$InputObject.OperatingSystem.Revision
            }
            Architecture = [string]$InputObject.OperatingSystem.Architecture
            ProductType = [string]$InputObject.OperatingSystem.ProductType
        }
        SecureBoot = [ordered]@{
            Status = [string]$InputObject.SecureBoot.Status
            Supported = $InputObject.SecureBoot.Supported
            Enabled = $InputObject.SecureBoot.Enabled
        }
        Tpm = [ordered]@{
            Status = [string]$InputObject.Tpm.Status
            Present = $InputObject.Tpm.Present
            Ready = $InputObject.Tpm.Ready
            Enabled = $InputObject.Tpm.Enabled
            Activated = $InputObject.Tpm.Activated
            SpecVersion = [string]$InputObject.Tpm.SpecVersion
        }
        Antivirus = [ordered]@{
            Status = [string]$InputObject.Antivirus.Status
            Products = @($InputObject.Antivirus.Products | ForEach-Object {
                    [ordered]@{
                        ProviderFamily = [string]$_.ProviderFamily
                        State = [string]$_.State
                        Signatures = [string]$_.Signatures
                    }
                })
            ActiveProviderFamilies = @(
                $InputObject.Antivirus.ActiveProviderFamilies | ForEach-Object { [string]$_ })
            Assessment = [string]$InputObject.Antivirus.Assessment
            DefenderDependentControls = [string]$InputObject.Antivirus.DefenderDependentControls
        }
        Firewall = [ordered]@{
            Status = [string]$InputObject.Firewall.Status
            Products = @($InputObject.Firewall.Products | ForEach-Object {
                    [ordered]@{
                        ProviderFamily = [string]$_.ProviderFamily
                        State = [string]$_.State
                        Signatures = [string]$_.Signatures
                    }
                })
            Profiles = @($InputObject.Firewall.Profiles | ForEach-Object {
                    [ordered]@{
                        Name = [string]$_.Name
                        Enabled = $_.Enabled
                        DefaultInboundAction = [string]$_.DefaultInboundAction
                        DefaultOutboundAction = [string]$_.DefaultOutboundAction
                        LogBlocked = $_.LogBlocked
                    }
                })
            ActiveNetworkCategories = @(
                $InputObject.Firewall.ActiveNetworkCategories | ForEach-Object { [string]$_ })
            Assessment = [string]$InputObject.Firewall.Assessment
        }
        PlatformProtections = [ordered]@{
            MemoryIntegrity = [ordered]@{
                Status = [string]$InputObject.PlatformProtections.MemoryIntegrity.Status
                Configured = $InputObject.PlatformProtections.MemoryIntegrity.Configured
                Running = $InputObject.PlatformProtections.MemoryIntegrity.Running
            }
        }
        Agents = [ordered]@{
            Action1 = [string]$InputObject.Agents.Action1
            LimaCharlie = [string]$InputObject.Agents.LimaCharlie
            Velociraptor = [string]$InputObject.Agents.Velociraptor
            IdentityCorrelation = 'external-validation-required'
        }
        CollectionErrors = @($InputObject.CollectionErrors | ForEach-Object { [string]$_ })
        Limitations = @($InputObject.Limitations | ForEach-Object { [string]$_ })
    }
}

function Test-EndpointHealthObservationJson {
    param([Parameter(Mandatory = $true)][string]$ObservationJson)
    $validationErrors = New-Object 'System.Collections.Generic.List[string]'
    $findings = New-Object 'System.Collections.Generic.List[string]'
    $deferredControls = New-Object 'System.Collections.Generic.List[string]'
    $observation = $null
    $safeObservation = $null
    try {
        if ([string]::IsNullOrWhiteSpace($ObservationJson) -or
            $ObservationJson.Length -gt 65536) { throw 'Collector output invalid.' }
        $observation = $ObservationJson | ConvertFrom-Json -ErrorAction Stop
    }
    catch { Add-UniqueCode -Codes $validationErrors -Code 'collector-output-invalid' }

    if ($null -ne $observation) {
        try {
            $topLevel = @(
                'SchemaVersion', 'Module', 'CapturedAtUtc', 'CollectionMode',
                'OperatingSystem', 'SecureBoot', 'Tpm', 'Antivirus', 'Firewall',
                'PlatformProtections', 'Agents', 'CollectionErrors', 'Limitations')
            if (-not (Test-ExactProperties -Object $observation -Expected $topLevel)) {
                throw 'Unexpected top-level shape.'
            }
            $shapes = @(
                [pscustomobject]@{ Object = $observation.OperatingSystem; Keys = @(
                        'Status', 'Family', 'Edition', 'Release', 'Build', 'Revision',
                        'Architecture', 'ProductType') },
                [pscustomobject]@{ Object = $observation.SecureBoot; Keys = @(
                        'Status', 'Supported', 'Enabled') },
                [pscustomobject]@{ Object = $observation.Tpm; Keys = @(
                        'Status', 'Present', 'Ready', 'Enabled', 'Activated', 'SpecVersion') },
                [pscustomobject]@{ Object = $observation.Antivirus; Keys = @(
                        'Status', 'Products', 'ActiveProviderFamilies', 'Assessment',
                        'DefenderDependentControls') },
                [pscustomobject]@{ Object = $observation.Firewall; Keys = @(
                        'Status', 'Products', 'Profiles', 'ActiveNetworkCategories', 'Assessment') },
                [pscustomobject]@{ Object = $observation.PlatformProtections; Keys = @(
                        'MemoryIntegrity') },
                [pscustomobject]@{
                    Object = $observation.PlatformProtections.MemoryIntegrity
                    Keys = @('Status', 'Configured', 'Running')
                },
                [pscustomobject]@{ Object = $observation.Agents; Keys = @(
                        'Action1', 'LimaCharlie', 'Velociraptor', 'IdentityCorrelation') })
            foreach ($shape in $shapes) {
                if (-not (Test-ExactProperties -Object $shape.Object -Expected $shape.Keys)) {
                    throw 'Unexpected nested shape.'
                }
            }
            if (-not (Test-BoundedArray -Value $observation.Antivirus.Products -Maximum 16) -or
                -not (Test-BoundedArray -Value $observation.Firewall.Products -Maximum 16) -or
                -not (Test-BoundedArray -Value $observation.Firewall.Profiles -Maximum 3) -or
                -not (Test-BoundedArray -Value $observation.CollectionErrors -Maximum 32) -or
                -not (Test-BoundedArray -Value $observation.Limitations -Maximum 8)) {
                throw 'Unexpected array shape.'
            }
            foreach ($product in @($observation.Antivirus.Products) +
                @($observation.Firewall.Products)) {
                if (-not (Test-ExactProperties -Object $product -Expected @(
                            'ProviderFamily', 'State', 'Signatures')) -or
                    -not (Test-EnumValue -Value $product.ProviderFamily -Allowed @(
                            'microsoft_defender', 'mcafee', 'other', 'unknown')) -or
                    -not (Test-EnumValue -Value $product.State -Allowed @(
                            'on', 'off', 'snoozed', 'expired', 'unknown')) -or
                    -not (Test-EnumValue -Value $product.Signatures -Allowed @(
                            'up-to-date', 'out-of-date', 'not-applicable', 'unknown'))) {
                    throw 'Unexpected security product.'
                }
            }
            foreach ($profile in @($observation.Firewall.Profiles)) {
                if (-not (Test-ExactProperties -Object $profile -Expected @(
                            'Name', 'Enabled', 'DefaultInboundAction',
                            'DefaultOutboundAction', 'LogBlocked')) -or
                    -not (Test-EnumValue -Value $profile.Name -Allowed @(
                            'domain', 'private', 'public', 'unknown')) -or
                    -not (Test-NullableBoolean -Value $profile.Enabled) -or
                    -not (Test-EnumValue -Value $profile.DefaultInboundAction -Allowed @(
                            'allow', 'block', 'not-configured', 'unknown')) -or
                    -not (Test-EnumValue -Value $profile.DefaultOutboundAction -Allowed @(
                            'allow', 'block', 'not-configured', 'unknown')) -or
                    -not (Test-NullableBoolean -Value $profile.LogBlocked)) {
                    throw 'Unexpected firewall profile.'
                }
            }

            $probeStates = @('collected', 'unsupported', 'unavailable', 'error')
            $checks = @(
                (($observation.SchemaVersion -is [int] -or
                    $observation.SchemaVersion -is [long]) -and
                    [long]$observation.SchemaVersion -eq 1),
                (($observation.Module -is [string]) -and
                    $observation.Module -ceq 'validation.endpoint-health@1.0.0'),
                (($observation.CollectionMode -is [string]) -and
                    $observation.CollectionMode -ceq 'read-only-local'),
                (Test-EnumValue $observation.OperatingSystem.Status $probeStates),
                (Test-EnumValue $observation.OperatingSystem.Family @(
                        'windows_11', 'windows_10', 'windows_server', 'other', 'unknown')),
                (Test-EnumValue $observation.OperatingSystem.Edition @(
                        'home', 'pro', 'enterprise', 'education', 'unknown')),
                (($observation.OperatingSystem.Release -is [string]) -and
                    [string]$observation.OperatingSystem.Release -match '^(unknown|\d{2}h[12])$'),
                (Test-Integer $observation.OperatingSystem.Build 1 999999 -AllowNull),
                (Test-Integer $observation.OperatingSystem.Revision 0 2147483647 -AllowNull),
                (Test-EnumValue $observation.OperatingSystem.Architecture @(
                        'x64', 'arm64', 'x86', 'unknown')),
                (Test-EnumValue $observation.OperatingSystem.ProductType @(
                        'client', 'domain-controller', 'server', 'unknown')),
                (Test-EnumValue $observation.SecureBoot.Status $probeStates),
                (Test-NullableBoolean $observation.SecureBoot.Supported),
                (Test-NullableBoolean $observation.SecureBoot.Enabled),
                (Test-EnumValue $observation.Tpm.Status $probeStates),
                (Test-NullableBoolean $observation.Tpm.Present),
                (Test-NullableBoolean $observation.Tpm.Ready),
                (Test-NullableBoolean $observation.Tpm.Enabled),
                (Test-NullableBoolean $observation.Tpm.Activated),
                (Test-EnumValue $observation.Tpm.SpecVersion @('2.0', '1.2', 'unknown')),
                (Test-EnumValue $observation.Antivirus.Status $probeStates),
                (Test-EnumValue $observation.Antivirus.Assessment @(
                        'single-active', 'multiple-active', 'none-active', 'unknown')),
                (Test-EnumValue $observation.Antivirus.DefenderDependentControls @(
                        'defer', 'review')),
                (Test-EnumValue $observation.Firewall.Status $probeStates),
                (Test-EnumValue $observation.Firewall.Assessment @(
                        'all-windows-profiles-enabled', 'attention-required', 'unknown')),
                (Test-EnumValue $observation.PlatformProtections.MemoryIntegrity.Status $probeStates),
                (Test-NullableBoolean $observation.PlatformProtections.MemoryIntegrity.Configured),
                (Test-NullableBoolean $observation.PlatformProtections.MemoryIntegrity.Running),
                (Test-EnumValue $observation.Agents.Action1 @(
                        'running', 'stopped', 'absent', 'error')),
                (Test-EnumValue $observation.Agents.LimaCharlie @(
                        'running', 'stopped', 'absent', 'error')),
                (Test-EnumValue $observation.Agents.Velociraptor @(
                        'running', 'stopped', 'absent', 'error')),
                (($observation.Agents.IdentityCorrelation -is [string]) -and
                    $observation.Agents.IdentityCorrelation -ceq 'external-validation-required'))
            if (@($checks | Where-Object { $_ -ne $true }).Count -gt 0) {
                throw 'Unexpected normalized value.'
            }
            if (-not (Test-EnumArray $observation.Antivirus.ActiveProviderFamilies @(
                        'microsoft_defender', 'mcafee', 'other', 'unknown') 4) -or
                -not (Test-EnumArray $observation.Firewall.ActiveNetworkCategories @(
                        'public', 'private', 'domain-authenticated', 'unknown') 4)) {
                throw 'Unexpected normalized array.'
            }
            $allowedErrors = @(
                'os_build_unavailable', 'os_revision_unavailable', 'os_build_source_mismatch',
                'os_query_failed', 'secure_boot_query_failed', 'tpm_query_failed',
                'security_center_service_query_failed', 'security_center_service_not_running',
                'antivirus_wsc_query_failed', 'firewall_wsc_query_failed',
                'windows_firewall_query_failed', 'memory_integrity_query_failed',
                'action1_service_query_failed', 'limacharlie_service_query_failed',
                'velociraptor_service_query_failed')
            if (-not (Test-EnumArray $observation.CollectionErrors $allowedErrors 32)) {
                throw 'Unexpected collection error.'
            }
            $expectedLimitations = @(
                'antivirus-subscription-and-trial-state-not-assessed',
                'local-service-state-is-not-cloud-agent-health',
                'platform-identity-correlation-requires-external-strong-id-evidence',
                'windows-release-support-requires-current-review') | Sort-Object
            if (-not (Test-EnumArray $observation.Limitations $expectedLimitations 8) -or
                (@($observation.Limitations | Sort-Object) -join "`n") -cne
                    ($expectedLimitations -join "`n")) {
                throw 'Unexpected limitation set.'
            }
            $capturedAt = [datetimeoffset]::MinValue
            if (-not ($observation.CapturedAtUtc -is [string]) -or
                [string]$observation.CapturedAtUtc -notmatch
                    '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,7})?Z$' -or
                -not [datetimeoffset]::TryParse(
                    [string]$observation.CapturedAtUtc, [ref]$capturedAt)) {
                throw 'Unexpected capture time.'
            }
            $now = [datetimeoffset]::UtcNow
            if ($capturedAt -gt $now.AddMinutes(5) -or $capturedAt -lt $now.AddMinutes(-15)) {
                Add-UniqueCode -Codes $validationErrors -Code 'capture-time-not-fresh'
            }
            $safeObservation = New-SafeObservation -InputObject $observation
        }
        catch { Add-UniqueCode -Codes $validationErrors -Code 'observation-schema-invalid' }
    }

    if ($null -ne $safeObservation) {
        if (@($observation.CollectionErrors).Count -gt 0) {
            Add-UniqueCode -Codes $validationErrors -Code 'collection-errors-present'
        }
        if ($observation.OperatingSystem.Status -ne 'collected') {
            Add-UniqueCode -Codes $validationErrors -Code 'operating-system-not-collected'
        }
        if ($observation.OperatingSystem.Family -ne 'windows_11' -or
            $observation.OperatingSystem.ProductType -ne 'client') {
            Add-UniqueCode -Codes $validationErrors -Code 'unsupported-windows-product'
        }
        if ($observation.OperatingSystem.Edition -notin @('home', 'pro')) {
            Add-UniqueCode -Codes $validationErrors -Code 'unsupported-windows-edition'
        }
        if ($observation.OperatingSystem.Release -notin @('24h2', '25h2', '26h1')) {
            Add-UniqueCode -Codes $validationErrors -Code 'unsupported-windows-release'
        }
        if ($null -eq $observation.OperatingSystem.Build -or
            [long]$observation.OperatingSystem.Build -lt 26100) {
            Add-UniqueCode -Codes $validationErrors -Code 'unsupported-windows-build'
        }
        if ($null -eq $observation.OperatingSystem.Revision) {
            Add-UniqueCode -Codes $validationErrors -Code 'operating-system-revision-unknown'
        }
        if ($observation.OperatingSystem.Architecture -ne 'x64') {
            Add-UniqueCode -Codes $validationErrors -Code 'unsupported-architecture'
        }
        $secureBootConsistent =
            ($observation.SecureBoot.Status -eq 'collected' -and
                $observation.SecureBoot.Supported -eq $true -and
                $observation.SecureBoot.Enabled -is [bool]) -or
            ($observation.SecureBoot.Status -eq 'unsupported' -and
                $observation.SecureBoot.Supported -eq $false -and
                $null -eq $observation.SecureBoot.Enabled)
        if (-not $secureBootConsistent) {
            Add-UniqueCode -Codes $validationErrors -Code 'secure-boot-state-unknown'
        }
        elseif ($observation.SecureBoot.Enabled -ne $true) {
            $findings.Add('secure-boot-not-enabled')
        }
        if ($observation.Tpm.Status -ne 'collected') {
            Add-UniqueCode -Codes $validationErrors -Code 'tpm-state-unknown'
        }
        elseif ($null -eq $observation.Tpm.Present) {
            Add-UniqueCode -Codes $validationErrors -Code 'tpm-value-unknown'
        }
        elseif ($observation.Tpm.Present -eq $false) {
            if ($null -ne $observation.Tpm.Ready -or
                $null -ne $observation.Tpm.Enabled -or
                $null -ne $observation.Tpm.Activated -or
                $observation.Tpm.SpecVersion -ne 'unknown') {
                Add-UniqueCode -Codes $validationErrors -Code 'tpm-value-unknown'
            }
            $findings.Add('tpm-not-present')
        }
        else {
            if ($null -eq $observation.Tpm.Ready -or
                $null -eq $observation.Tpm.Enabled -or
                $null -eq $observation.Tpm.Activated) {
                Add-UniqueCode -Codes $validationErrors -Code 'tpm-value-unknown'
            }
            else {
                if ($observation.Tpm.Ready -eq $false) { $findings.Add('tpm-not-ready') }
                if ($observation.Tpm.Enabled -eq $false) { $findings.Add('tpm-not-enabled') }
                if ($observation.Tpm.Activated -eq $false) { $findings.Add('tpm-not-activated') }
            }
            if ($observation.Tpm.SpecVersion -eq 'unknown') {
                Add-UniqueCode -Codes $validationErrors -Code 'tpm-spec-state-unknown'
            }
            elseif ($observation.Tpm.SpecVersion -ne '2.0') {
                $findings.Add('tpm-2-not-confirmed')
            }
        }
        if ($observation.Antivirus.Status -ne 'collected') {
            Add-UniqueCode -Codes $validationErrors -Code 'antivirus-state-unknown'
        }
        else {
            $activeProducts = @($observation.Antivirus.Products |
                Where-Object { $_.State -eq 'on' })
            if (@($observation.Antivirus.Products |
                    Where-Object { $_.State -eq 'unknown' }).Count -gt 0) {
                Add-UniqueCode -Codes $validationErrors -Code 'antivirus-product-state-unknown'
            }
            $derivedFamilies = @($activeProducts |
                Select-Object -ExpandProperty ProviderFamily -Unique | Sort-Object)
            if (($derivedFamilies -join "`n") -cne
                (@($observation.Antivirus.ActiveProviderFamilies | Sort-Object) -join "`n")) {
                Add-UniqueCode -Codes $validationErrors -Code 'antivirus-summary-mismatch'
            }
            $expectedAssessment = switch ($activeProducts.Count) {
                0 { 'none-active' }; 1 { 'single-active' }; default { 'multiple-active' }
            }
            if ($observation.Antivirus.Assessment -ne $expectedAssessment) {
                Add-UniqueCode -Codes $validationErrors -Code 'antivirus-summary-mismatch'
            }
            $thirdPartyActive = @($activeProducts |
                Where-Object { $_.ProviderFamily -ne 'microsoft_defender' }).Count -gt 0
            $expectedDisposition = if ($thirdPartyActive) { 'defer' } else { 'review' }
            if ($observation.Antivirus.DefenderDependentControls -ne $expectedDisposition) {
                Add-UniqueCode -Codes $validationErrors -Code 'antivirus-summary-mismatch'
            }
            if ($expectedAssessment -eq 'none-active') {
                $findings.Add('antivirus-no-active-provider')
            }
            elseif ($expectedAssessment -eq 'multiple-active') {
                $findings.Add('antivirus-multiple-active-providers')
            }
            if (@($activeProducts | Where-Object { $_.Signatures -eq 'out-of-date' }).Count -gt 0) {
                $findings.Add('antivirus-signatures-out-of-date')
            }
            if (@($activeProducts | Where-Object {
                        $_.Signatures -in @('unknown', 'not-applicable')
                    }).Count -gt 0) {
                Add-UniqueCode -Codes $validationErrors -Code 'antivirus-signature-state-unknown'
            }
            if ($thirdPartyActive) {
                $findings.Add('third-party-antivirus-active')
                @('defense.defender', 'defense.asr', 'defense.controlled-folder-access') |
                    ForEach-Object { $deferredControls.Add($_) }
            }
        }
        if ($observation.Firewall.Status -ne 'collected') {
            Add-UniqueCode -Codes $validationErrors -Code 'firewall-state-unknown'
        }
        else {
            $profileNames = @($observation.Firewall.Profiles.Name | Sort-Object -Unique)
            if ($profileNames.Count -ne 3 -or
                ($profileNames -join "`n") -cne "domain`nprivate`npublic") {
                Add-UniqueCode -Codes $validationErrors -Code 'firewall-profile-set-invalid'
            }
            if (@($observation.Firewall.Profiles | Where-Object {
                        $null -eq $_.Enabled -or
                        $_.DefaultInboundAction -eq 'unknown' -or
                        $_.DefaultOutboundAction -eq 'unknown'
                    }).Count -gt 0) {
                Add-UniqueCode -Codes $validationErrors -Code 'firewall-profile-value-unknown'
            }
            $allEnabled = @($observation.Firewall.Profiles |
                Where-Object { $_.Enabled -ne $true }).Count -eq 0
            $expectedFirewall = if ($profileNames.Count -eq 3 -and $allEnabled) {
                'all-windows-profiles-enabled'
            }
            else { 'attention-required' }
            if ($observation.Firewall.Assessment -ne $expectedFirewall) {
                Add-UniqueCode -Codes $validationErrors -Code 'firewall-summary-mismatch'
            }
            if (-not $allEnabled) { $findings.Add('windows-firewall-attention-required') }
        }
        if ($observation.PlatformProtections.MemoryIntegrity.Status -ne 'collected') {
            Add-UniqueCode -Codes $validationErrors -Code 'memory-integrity-state-unknown'
        }
        elseif ($null -eq $observation.PlatformProtections.MemoryIntegrity.Configured -or
            $null -eq $observation.PlatformProtections.MemoryIntegrity.Running) {
            Add-UniqueCode -Codes $validationErrors -Code 'memory-integrity-value-unknown'
        }
        else {
            if ($observation.PlatformProtections.MemoryIntegrity.Configured -eq $false) {
                $findings.Add('memory-integrity-not-configured')
            }
            if ($observation.PlatformProtections.MemoryIntegrity.Running -eq $false) {
                $findings.Add('memory-integrity-not-running')
            }
        }
        foreach ($agentName in @('Action1', 'LimaCharlie', 'Velociraptor')) {
            if ($observation.Agents.$agentName -eq 'error') {
                Add-UniqueCode `
                    -Codes $validationErrors -Code 'agent-service-query-state-unknown'
            }
            elseif ($observation.Agents.$agentName -ne 'running') {
                $findings.Add(('{0}-local-service-not-running' -f $agentName.ToLowerInvariant()))
            }
        }
        $findings.Add('platform-identity-correlation-pending')
    }

    $localPassed = $validationErrors.Count -eq 0
    return [ordered]@{
        Module = 'validation.endpoint-health@1.0.0'
        Passed = $localPassed
        OverallStatus = if ($localPassed) { 'partial' } else { 'unknown' }
        ValidationErrors = @($validationErrors | Sort-Object)
        Findings = @($findings | Sort-Object -Unique)
        DeferredControls = @($deferredControls | Sort-Object -Unique)
        Observation = $safeObservation
        Limitation = ('Local read-only collection cannot prove current Action1, ' +
            'LimaCharlie, and Velociraptor platform identity or check-in health. ' +
            'Correlate fresh external strong-ID evidence; hostname-only matching is insufficient.')
    }
}

try {
    $observationJson = Get-EndpointHealthObservationJson
    $result = Test-EndpointHealthObservationJson -ObservationJson $observationJson
}
catch {
    $result = [ordered]@{
        Module = 'validation.endpoint-health@1.0.0'
        Passed = $false
        OverallStatus = 'unknown'
        ValidationErrors = @('collector-output-invalid')
        Findings = @()
        DeferredControls = @()
        Observation = $null
        Limitation = 'Local collection failed without exposing raw error text; no state changed.'
    }
}

$result | ConvertTo-Json -Depth 10 -Compress
if (-not $result.Passed) { exit 1 }
