param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("install", "remove-feature", "uninstall", "rollback", "commit", "resume")]
    [string]$Action,

    [Parameter(Mandatory = $true)]
    [string]$RootDir,

    [Parameter(Mandatory = $true)]
    [string]$ProductCode,

    [Parameter(Mandatory = $true)]
    [ValidateSet("install", "uninstall")]
    [string]$TransactionKind,

    [string]$UpgradeOwnerProductCode
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$script:RebootRequired = $false
$script:CurrentScriptPath = $PSCommandPath

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Virtual Display setup requires an elevated process."
    }
}

function ConvertTo-NormalizedProductCode {
    param([string]$Value)
    $parsed = [Guid]::Empty
    if (-not [Guid]::TryParseExact($Value, "B", [ref]$parsed)) {
        throw "ProductCode must be an uppercase-braced GUID."
    }
    $normalized = $parsed.ToString("B").ToUpperInvariant()
    if ($Value -cne $normalized) {
        throw "ProductCode is not normalized."
    }
    return $normalized
}

function Resolve-VirtualDisplayOwnership {
    param(
        [AllowNull()]
        [string]$OwnedProductCode,

        [string]$CurrentProductCode,

        [AllowNull()]
        [string]$RelatedUpgradeOwnerProductCode,

        [bool]$InstalledDevicePresent
    )
    $current = ConvertTo-NormalizedProductCode -Value $CurrentProductCode
    $related = if ([string]::IsNullOrWhiteSpace($RelatedUpgradeOwnerProductCode)) {
        $null
    } else {
        ConvertTo-NormalizedProductCode -Value $RelatedUpgradeOwnerProductCode
    }
    if ([string]::IsNullOrWhiteSpace($OwnedProductCode)) {
        if ($null -ne $related) {
            return [pscustomobject]@{
                Disposition = "related-upgrade-transfer"
                PreviousOwnerProductCode = $related
            }
        }
        if ($InstalledDevicePresent) {
            throw "Refusing to adopt a Virtual Display device without durable ProductCode ownership or verified related-upgrade ownership."
        }
        return [pscustomobject]@{
            Disposition = "unowned"
            PreviousOwnerProductCode = $null
        }
    }

    $owner = ConvertTo-NormalizedProductCode -Value $OwnedProductCode
    if ($owner -ceq $current) {
        if ($null -ne $related -and $related -cne $current) {
            throw "The related-upgrade VDD owner conflicts with the durable ProductCode ownership manifest."
        }
        return [pscustomobject]@{
            Disposition = "current-product"
            PreviousOwnerProductCode = $owner
        }
    }
    if ($null -eq $related -or $owner -cne $related) {
        throw "Refusing to mutate a Virtual Display owned by another ProductCode: $owner"
    }
    return [pscustomobject]@{
        Disposition = "related-upgrade-transfer"
        PreviousOwnerProductCode = $owner
    }
}

function New-VirtualDisplayTransactionIdentity {
    param(
        [string]$CurrentProductCode,
        [string]$CurrentTransactionKind
    )
    $product = ConvertTo-NormalizedProductCode -Value $CurrentProductCode
    if ($CurrentTransactionKind -notin @("install", "uninstall")) {
        throw "Virtual Display transaction kind is invalid."
    }
    $token = $product.Trim("{}").Replace("-", "")
    return [pscustomobject]@{
        ResumeTaskName = "Lumen Virtual Display Resume $token $CurrentTransactionKind"
        RebootMarkerSuffix = "$token\$CurrentTransactionKind"
    }
}

function Resolve-OwnershipCommitAction {
    param(
        [bool]$OwnershipCommitted,
        [AllowEmptyString()]
        [string]$PreviousManifestSha256,
        [AllowEmptyString()]
        [string]$CurrentManifestSha256,
        [bool]$IntendedOwnershipMatches
    )
    foreach ($hash in @($PreviousManifestSha256, $CurrentManifestSha256)) {
        if (-not [string]::IsNullOrEmpty($hash) -and $hash -cnotmatch '^[0-9A-F]{64}$') {
            throw "Virtual Display ownership manifest state contains an invalid SHA-256."
        }
    }
    if ($OwnershipCommitted) {
        if (-not $IntendedOwnershipMatches) {
            throw "Committed Virtual Display ownership no longer matches the transaction result."
        }
        return "already-committed"
    }
    if ($IntendedOwnershipMatches) {
        return "record-committed"
    }
    if ($CurrentManifestSha256 -cne $PreviousManifestSha256) {
        throw "The durable Virtual Display ownership manifest changed during the transaction."
    }
    return "apply"
}

function Resolve-OwnershipRollbackAction {
    param(
        [bool]$TransactionCommitted,
        [bool]$OwnershipCommitted,
        [AllowEmptyString()]
        [string]$PreviousManifestSha256,
        [AllowEmptyString()]
        [string]$CurrentManifestSha256
    )
    if ($TransactionCommitted) {
        return "complete-commit"
    }
    if ($OwnershipCommitted) {
        throw "Uncommitted Virtual Display state cannot own the committed manifest."
    }
    if ($CurrentManifestSha256 -cne $PreviousManifestSha256) {
        throw "The durable Virtual Display ownership manifest changed before rollback."
    }
    return "retain-previous"
}

function Assert-VirtualDisplayResumeAfterRestart {
    param(
        [string]$PendingBootIdentifier,
        [string]$CurrentBootIdentifier
    )
    if ($PendingBootIdentifier -cnotmatch '^\d+$' -or $CurrentBootIdentifier -cnotmatch '^\d+$') {
        throw "Virtual Display resume state has an invalid boot identifier."
    }
    if ($PendingBootIdentifier -ceq $CurrentBootIdentifier) {
        throw "Virtual Display resume is waiting for Windows to restart."
    }
}

Assert-Administrator
$ProductCode = ConvertTo-NormalizedProductCode -Value $ProductCode
if (-not [string]::IsNullOrWhiteSpace($UpgradeOwnerProductCode)) {
    $UpgradeOwnerProductCode = ConvertTo-NormalizedProductCode -Value $UpgradeOwnerProductCode
}
if ($Action -in @("install", "uninstall") -and $Action -ne $TransactionKind) {
    throw "Virtual Display transaction kind does not match the action."
}

$programData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
$rollbackRoot = Join-Path $programData "LumenVirtualDisplayInstallerV1"
$ownershipFile = Join-Path $rollbackRoot "owned-driver.json"
$rollbackProduct = Join-Path $rollbackRoot $ProductCode
$rollbackDirectory = Join-Path $rollbackProduct $TransactionKind
$rollbackState = Join-Path $rollbackDirectory "virtual-display-rollback.json"
$rollbackDriver = Join-Path $rollbackDirectory "virtual-display-driver"
$identityCheckDriver = Join-Path $rollbackDirectory "virtual-display-identity-check"
$forwardIdentityDriver = Join-Path $rollbackDirectory "virtual-display-forward-identity"
$rollbackScript = Join-Path $rollbackDirectory "virtual-display-setup.ps1"
$rollbackHelper = Join-Path $rollbackDirectory "lumen-vddctl.exe"
$packageInf = Join-Path $RootDir "drivers\virtual-display\LumenVirtualDisplay.inf"
$installedHelper = Join-Path $RootDir "tools\lumen-vddctl.exe"
$transactionIdentity = New-VirtualDisplayTransactionIdentity `
    -CurrentProductCode $ProductCode `
    -CurrentTransactionKind $TransactionKind
$resumeTaskName = $transactionIdentity.ResumeTaskName
$rebootMarker = "HKLM:\SOFTWARE\Lumen\Installer\PendingReboot\$($transactionIdentity.RebootMarkerSuffix)"

function New-SecureDirectoryAcl {
    $system = [Security.Principal.SecurityIdentifier]::new("S-1-5-18")
    $administrators = [Security.Principal.SecurityIdentifier]::new("S-1-5-32-544")
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($administrators)
    foreach ($sid in @($system, $administrators)) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        ))
    }
    return $acl
}

function Initialize-RollbackDirectory {
    $acl = New-SecureDirectoryAcl
    foreach ($path in @($rollbackRoot, $rollbackProduct, $rollbackDirectory)) {
        if (-not (Test-Path -LiteralPath $path)) {
            New-Item -ItemType Directory -Path $path -Force | Out-Null
        }
        $item = Get-Item -LiteralPath $path -Force
        if (-not $item.PSIsContainer -or
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Virtual Display rollback path is not a plain directory: $path"
        }
        Set-Acl -LiteralPath $path -AclObject $acl
    }
}

function Assert-RollbackDirectory {
    if (-not (Test-Path -LiteralPath $rollbackDirectory -PathType Container)) {
        throw "Virtual Display rollback directory is missing."
    }
    $expectedRoot = [IO.Path]::GetFullPath($rollbackRoot) + [IO.Path]::DirectorySeparatorChar
    $resolved = [IO.Path]::GetFullPath($rollbackDirectory) + [IO.Path]::DirectorySeparatorChar
    if (-not $resolved.StartsWith($expectedRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Virtual Display rollback directory escaped its protected root."
    }
    foreach ($item in @(Get-ChildItem -LiteralPath $rollbackDirectory -Force -Recurse)) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Virtual Display rollback directory contains a reparse point."
        }
    }
}

function Get-VirtualDisplayDevices {
    return @(
        Get-CimInstance Win32_PnPEntity -ErrorAction Stop | Where-Object {
            @($_.HardwareID) -contains "ROOT\LumenVirtualDisplay"
        }
    )
}

function Get-InstalledVirtualDisplay {
    $devices = @(Get-VirtualDisplayDevices)
    if ($devices.Count -gt 1) {
        throw "Expected at most one Lumen Virtual Display device; found $($devices.Count)."
    }
    if ($devices.Count -eq 0) {
        return $null
    }
    $property = Get-PnpDeviceProperty `
        -InstanceId $devices[0].PNPDeviceID `
        -KeyName "DEVPKEY_Device_DriverInfPath" `
        -ErrorAction Stop
    $infName = [string]$property.Data
    if ($infName -notmatch '^oem\d+\.inf$') {
        throw "Lumen Virtual Display reported an invalid driver INF: $infName"
    }
    return [pscustomobject]@{
        InstanceId = [string]$devices[0].PNPDeviceID
        InfName = $infName
        Status = [string]$devices[0].Status
    }
}

function Assert-PackageInf {
    if (-not (Test-Path -LiteralPath $packageInf -PathType Leaf)) {
        throw "Lumen Virtual Display package INF is missing: $packageInf"
    }
    $packageRoot = Split-Path -Parent $packageInf
    foreach ($name in @(
        "LumenVirtualDisplay.inf",
        "LumenVirtualDisplay.cat",
        "LumenVirtualDisplay.dll"
    )) {
        $path = Join-Path $packageRoot $name
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Lumen Virtual Display package contains a reparse point."
        }
    }
    if (-not (Select-String -LiteralPath $packageInf -SimpleMatch `
            -Pattern "ROOT\LumenVirtualDisplay" -Quiet)) {
        throw "Lumen Virtual Display package INF has the wrong hardware identity."
    }
    if (-not (Test-Path -LiteralPath $installedHelper -PathType Leaf)) {
        throw "Lumen Virtual Display lifecycle helper is missing: $installedHelper"
    }
}

function Invoke-VirtualDisplayHelper {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,
        [Parameter(Mandatory = $true)]
        [string]$Description
    )
    $helper = if (Test-Path -LiteralPath $rollbackHelper -PathType Leaf) {
        $rollbackHelper
    } else {
        $installedHelper
    }
    if (-not (Test-Path -LiteralPath $helper -PathType Leaf)) {
        throw "Lumen Virtual Display lifecycle helper is unavailable."
    }
    Write-Host $Description
    $output = & $helper @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    $output | ForEach-Object { if ($_.ToString().Trim()) { Write-Host "  $_" } }
    if ($exitCode -eq 3010) {
        $script:RebootRequired = $true
        return $exitCode
    }
    if ($exitCode -ne 0) {
        throw "$Description failed with exit code $exitCode."
    }
    return $exitCode
}

function Invoke-PnpUtil {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,
        [Parameter(Mandatory = $true)]
        [string]$Description
    )
    $pnpUtil = Join-Path $env:SystemRoot "System32\pnputil.exe"
    if (-not (Test-Path -LiteralPath $pnpUtil -PathType Leaf)) {
        throw "pnputil.exe is unavailable."
    }
    Write-Host "$Description"
    $output = & $pnpUtil @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    $output | ForEach-Object { if ($_.ToString().Trim()) { Write-Host "  $_" } }
    if ($exitCode -eq 3010) {
        $script:RebootRequired = $true
        return $exitCode
    }
    if ($exitCode -ne 0) {
        throw "$Description failed with exit code $exitCode."
    }
    return $exitCode
}

function Get-BootIdentifier {
    $operatingSystem = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    return $operatingSystem.LastBootUpTime.ToUniversalTime().Ticks.ToString(
        [Globalization.CultureInfo]::InvariantCulture)
}

function Set-RebootMarker {
    if (-not (Test-Path -LiteralPath $rebootMarker -PathType Container)) {
        New-Item -Path $rebootMarker -Force | Out-Null
    }
    New-ItemProperty `
        -LiteralPath $rebootMarker `
        -Name "Pending" `
        -PropertyType DWord `
        -Value 1 `
        -Force | Out-Null
}

function Clear-RebootMarker {
    if (Test-Path -LiteralPath $rebootMarker -PathType Container) {
        Remove-Item -LiteralPath $rebootMarker -Recurse -Force
    }
}

function Register-ResumeTask {
    if (-not (Test-Path -LiteralPath $rollbackScript -PathType Leaf)) {
        throw "The persisted Virtual Display resume helper is missing."
    }
    $powerShell = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
    $arguments = @(
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy", "Bypass",
        "-File", ('"{0}"' -f $rollbackScript),
        "-Action", "resume",
        "-RootDir", ('"{0}"' -f $RootDir),
        "-ProductCode", ('"{0}"' -f $ProductCode),
        "-TransactionKind", $TransactionKind
    ) -join " "
    $action = New-ScheduledTaskAction -Execute $powerShell -Argument $arguments
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal `
        -UserId "SYSTEM" `
        -LogonType ServiceAccount `
        -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 10) `
        -RestartCount 5 `
        -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask `
        -TaskName $resumeTaskName `
        -Action $action `
        -Trigger $trigger `
        -Principal $principal `
        -Settings $settings `
        -Force | Out-Null
}

function Unregister-ResumeTask {
    if ($null -ne (Get-ScheduledTask -TaskName $resumeTaskName -ErrorAction SilentlyContinue)) {
        Unregister-ScheduledTask -TaskName $resumeTaskName -Confirm:$false
    }
}

function Set-PendingReboot {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$State,
        [Parameter(Mandatory = $true)]
        [ValidateSet("forward-remove", "forward-verify", "commit-remove-previous", "rollback-remove", "rollback-verify")]
        [string]$Phase
    )
    $State.PendingPhase = $Phase
    $State.PendingBootIdentifier = Get-BootIdentifier
    Save-State -State $State
    Set-RebootMarker
    Register-ResumeTask
    $script:RebootRequired = $true
}

function Get-DriverManifestSha256 {
    param([object[]]$Files)
    $lines = @(
        $Files | Sort-Object FileName | ForEach-Object {
            "$($_.FileName.ToLowerInvariant()):$($_.Sha256)"
        }
    )
    $bytes = [Text.Encoding]::UTF8.GetBytes(($lines -join "`n"))
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha256.ComputeHash($bytes))).Replace("-", "")
    } finally {
        $sha256.Dispose()
    }
}

function Read-ExportedDriverPackage {
    param([string]$ExportRoot)
    $infs = @(
        Get-ChildItem -LiteralPath $ExportRoot -Filter "*.inf" -File -Recurse |
            Where-Object {
                Select-String -LiteralPath $_.FullName -SimpleMatch `
                    -Pattern "ROOT\LumenVirtualDisplay" -Quiet
            }
    )
    if ($infs.Count -ne 1) {
        throw "Expected exactly one exported Lumen Virtual Display INF."
    }
    $inf = $infs[0]
    $catalogLine = Select-String `
        -LiteralPath $inf.FullName `
        -Pattern '^\s*CatalogFile\s*=\s*(.+?)\s*$' | Select-Object -First 1
    if ($null -eq $catalogLine) {
        throw "The exported Lumen Virtual Display INF has no catalog identity."
    }
    $catalogName = $catalogLine.Matches[0].Groups[1].Value.Trim().Trim('"')
    if ([IO.Path]::GetFileName($catalogName) -cne $catalogName) {
        throw "The exported Lumen Virtual Display catalog path is invalid."
    }
    $packageDirectory = Split-Path -Parent $inf.FullName
    $catalog = Join-Path $packageDirectory $catalogName
    $driver = Join-Path $packageDirectory "LumenVirtualDisplay.dll"
    $required = @($inf.FullName, $catalog, $driver)
    $allFiles = @(Get-ChildItem -LiteralPath $ExportRoot -File -Recurse)
    if ($allFiles.Count -ne $required.Count -or
        @($allFiles | Where-Object { $required -notcontains $_.FullName }).Count -ne 0) {
        throw "The exported Lumen Virtual Display package has unexpected files."
    }
    $backupRoot = [IO.Path]::GetFullPath($ExportRoot) + [IO.Path]::DirectorySeparatorChar
    $files = foreach ($path in $required) {
        $fullPath = [IO.Path]::GetFullPath($path)
        if (-not $fullPath.StartsWith($backupRoot, [StringComparison]::OrdinalIgnoreCase) -or
            -not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
            throw "The exported Lumen Virtual Display package is incomplete."
        }
        $item = Get-Item -LiteralPath $fullPath -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "The exported Lumen Virtual Display package contains a reparse point."
        }
        [ordered]@{
            RelativePath = $fullPath.Substring($backupRoot.Length)
            FileName = [IO.Path]::GetFileName($fullPath)
            Sha256 = (Get-FileHash -LiteralPath $fullPath -Algorithm SHA256).Hash.ToUpperInvariant()
        }
    }
    if (@($files | Group-Object FileName | Where-Object { $_.Count -ne 1 }).Count -ne 0) {
        throw "The exported Lumen Virtual Display package has duplicate file identities."
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $catalog
    if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
        $null -eq $signature.SignerCertificate) {
        throw "The exported Lumen Virtual Display catalog signature is not valid."
    }
    $infEntry = @($files | Where-Object { $_.FileName -ceq $inf.Name })
    if ($infEntry.Count -ne 1) {
        throw "The exported Lumen Virtual Display INF identity is ambiguous."
    }
    return [pscustomobject]@{
        InfPath = $inf.FullName
        Files = @($files)
        InfSha256 = $infEntry[0].Sha256
        ManifestSha256 = Get-DriverManifestSha256 -Files @($files)
        CatalogSignerThumbprint = $signature.SignerCertificate.Thumbprint.ToUpperInvariant()
    }
}

function Export-InstalledDriver {
    param([string]$InfName)
    if (Test-Path -LiteralPath $rollbackDriver) {
        Remove-Item -LiteralPath $rollbackDriver -Recurse -Force
    }
    New-Item -ItemType Directory -Path $rollbackDriver | Out-Null
    Invoke-PnpUtil `
        -Arguments @("/export-driver", $InfName, $rollbackDriver) `
        -Description "Backing up the installed Lumen Virtual Display driver" | Out-Null
    return Read-ExportedDriverPackage -ExportRoot $rollbackDriver
}

function Read-InstalledDriverIdentity {
    param(
        [string]$InfName,
        [string]$ExportRoot,
        [string]$Description
    )
    if (Test-Path -LiteralPath $ExportRoot) {
        Remove-Item -LiteralPath $ExportRoot -Recurse -Force
    }
    New-Item -ItemType Directory -Path $ExportRoot | Out-Null
    try {
        Invoke-PnpUtil `
            -Arguments @("/export-driver", $InfName, $ExportRoot) `
            -Description $Description | Out-Null
        return Read-ExportedDriverPackage -ExportRoot $ExportRoot
    } catch {
        Remove-Item -LiteralPath $ExportRoot -Recurse -Force -ErrorAction SilentlyContinue
        throw
    }
}

function Assert-InstalledDriverIdentity {
    param(
        [string]$InfName,
        [string]$ExpectedInfSha256,
        [string]$ExpectedManifestSha256,
        [string]$ExpectedCatalogSignerThumbprint
    )
    foreach ($hash in @($ExpectedInfSha256, $ExpectedManifestSha256)) {
        if ($hash -cnotmatch '^[0-9A-F]{64}$') {
            throw "The saved Lumen Virtual Display package hash is invalid."
        }
    }
    if ($ExpectedCatalogSignerThumbprint -cnotmatch '^[0-9A-F]{40,128}$') {
        throw "The saved Lumen Virtual Display signer identity is invalid."
    }
    $actual = Read-InstalledDriverIdentity `
        -InfName $InfName `
        -ExportRoot $identityCheckDriver `
        -Description "Verifying the staged Lumen Virtual Display driver package"
    try {
        if ($actual.InfSha256 -cne $ExpectedInfSha256 -or
            $actual.ManifestSha256 -cne $ExpectedManifestSha256 -or
            $actual.CatalogSignerThumbprint -cne $ExpectedCatalogSignerThumbprint) {
            throw "The published Virtual Display INF name now refers to a different driver package: $InfName"
        }
    } finally {
        Remove-Item -LiteralPath $identityCheckDriver -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Assert-DriverIdentityFields {
    param([psobject]$Identity)
    if ([string]$Identity.PublishedInfName -cnotmatch '^oem\d+\.inf$' -or
        [string]$Identity.InfSha256 -cnotmatch '^[0-9A-F]{64}$' -or
        [string]$Identity.ManifestSha256 -cnotmatch '^[0-9A-F]{64}$' -or
        [string]$Identity.CatalogSignerThumbprint -cnotmatch '^[0-9A-F]{40,128}$') {
        throw "The saved Lumen Virtual Display ownership identity is invalid."
    }
}

function Assert-OwnedDriverManifestSchema {
    param([psobject]$Manifest)
    $expectedProperties = @(
        "CatalogSignerThumbprint",
        "InfSha256",
        "ManifestSha256",
        "ProductCode",
        "PublishedInfName",
        "Schema"
    )
    $actualProperties = @($Manifest.PSObject.Properties.Name | Sort-Object)
    if ([int]$Manifest.Schema -ne 1 -or
        $actualProperties.Count -ne $expectedProperties.Count -or
        @(Compare-Object $actualProperties $expectedProperties).Count -ne 0) {
        throw "The Lumen Virtual Display ownership manifest schema is invalid."
    }
}

function Assert-SecureOwnershipAcl {
    param([string]$Path)
    $allowed = @("S-1-5-18", "S-1-5-32-544")
    $acl = Get-Acl -LiteralPath $Path
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin $allowed) {
        throw "The Lumen Virtual Display ownership path has an untrusted owner."
    }
    $rules = $acl.GetAccessRules(
        $true,
        $true,
        [Security.Principal.SecurityIdentifier]
    )
    foreach ($rule in $rules) {
        if ($rule.IdentityReference.Value -notin $allowed -or
            $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
            throw "The Lumen Virtual Display ownership path grants untrusted access."
        }
    }
}

function Read-OwnedDriverIdentity {
    if (-not (Test-Path -LiteralPath $ownershipFile -PathType Leaf)) {
        return $null
    }
    $root = Get-Item -LiteralPath $rollbackRoot -Force -ErrorAction Stop
    $manifest = Get-Item -LiteralPath $ownershipFile -Force -ErrorAction Stop
    if (-not $root.PSIsContainer -or
        ($root.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        ($manifest.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "The Lumen Virtual Display ownership manifest path is not secure."
    }
    Assert-SecureOwnershipAcl -Path $rollbackRoot
    Assert-SecureOwnershipAcl -Path $ownershipFile
    $saved = Get-Content -LiteralPath $ownershipFile -Raw | ConvertFrom-Json
    Assert-OwnedDriverManifestSchema -Manifest $saved
    $saved.ProductCode = ConvertTo-NormalizedProductCode -Value ([string]$saved.ProductCode)
    Assert-DriverIdentityFields -Identity $saved
    return $saved
}

function Get-OwnershipManifestSha256 {
    if (-not (Test-Path -LiteralPath $ownershipFile -PathType Leaf)) {
        return ""
    }
    $manifest = Get-Item -LiteralPath $ownershipFile -Force -ErrorAction Stop
    if ($manifest.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "The Lumen Virtual Display ownership manifest is a reparse point."
    }
    $hash = (Get-FileHash -LiteralPath $ownershipFile -Algorithm SHA256).Hash.ToUpperInvariant()
    if ($hash -cnotmatch '^[0-9A-F]{64}$') {
        throw "The Lumen Virtual Display ownership manifest SHA-256 is invalid."
    }
    return $hash
}

function Write-OwnedDriverIdentity {
    param([psobject]$Identity)
    Assert-DriverIdentityFields -Identity $Identity
    if (-not (Test-Path -LiteralPath $rollbackRoot -PathType Container)) {
        New-Item -ItemType Directory -Path $rollbackRoot -Force | Out-Null
    }
    Set-Acl -LiteralPath $rollbackRoot -AclObject (New-SecureDirectoryAcl)
    $pending = Join-Path $rollbackRoot "owned-driver.pending"
    [ordered]@{
        Schema = 1
        ProductCode = $ProductCode
        PublishedInfName = [string]$Identity.PublishedInfName
        InfSha256 = [string]$Identity.InfSha256
        ManifestSha256 = [string]$Identity.ManifestSha256
        CatalogSignerThumbprint = [string]$Identity.CatalogSignerThumbprint
    } | ConvertTo-Json -Compress | Set-Content -LiteralPath $pending -Encoding UTF8
    Move-Item -LiteralPath $pending -Destination $ownershipFile -Force
}

function Remove-OwnedDriverIdentity {
    if (Test-Path -LiteralPath $ownershipFile -PathType Leaf) {
        $manifest = Get-Item -LiteralPath $ownershipFile -Force
        if ($manifest.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "The Lumen Virtual Display ownership manifest is a reparse point."
        }
        Remove-Item -LiteralPath $ownershipFile -Force
    }
}

function Save-State {
    param([psobject]$State)
    $pending = Join-Path $rollbackDirectory "virtual-display-rollback.pending"
    $State | ConvertTo-Json -Depth 5 -Compress | Set-Content -LiteralPath $pending -Encoding UTF8
    Move-Item -LiteralPath $pending -Destination $rollbackState -Force
}

function Read-State {
    Assert-RollbackDirectory
    $state = Get-Content -LiteralPath $rollbackState -Raw | ConvertFrom-Json
    $previousPublishedInf = [string]$state.PreviousPublishedInfName
    $forwardPublishedInf = [string]$state.ForwardPublishedInfName
    $previousFields = @(
        [string]$state.PreviousPublishedInfName,
        [string]$state.PreviousPublishedInfSha256,
        [string]$state.PreviousPackageManifestSha256,
        [string]$state.PreviousCatalogSignerThumbprint
    )
    $previousIdentityAbsent = @($previousFields | Where-Object { -not [string]::IsNullOrEmpty($_) }).Count -eq 0
    $previousIdentityValid =
        [string]$state.PreviousPublishedInfSha256 -cmatch '^[0-9A-F]{64}$' -and
        [string]$state.PreviousPackageManifestSha256 -cmatch '^[0-9A-F]{64}$' -and
        [string]$state.PreviousCatalogSignerThumbprint -cmatch '^[0-9A-F]{40,128}$'
    $forwardFields = @(
        [string]$state.ForwardPublishedInfName,
        [string]$state.ForwardPublishedInfSha256,
        [string]$state.ForwardPackageManifestSha256,
        [string]$state.ForwardCatalogSignerThumbprint
    )
    $forwardIdentityAbsent = @($forwardFields | Where-Object { -not [string]::IsNullOrEmpty($_) }).Count -eq 0
    $forwardIdentityValid =
        $forwardPublishedInf -cmatch '^oem\d+\.inf$' -and
        [string]$state.ForwardPublishedInfSha256 -cmatch '^[0-9A-F]{64}$' -and
        [string]$state.ForwardPackageManifestSha256 -cmatch '^[0-9A-F]{64}$' -and
        [string]$state.ForwardCatalogSignerThumbprint -cmatch '^[0-9A-F]{40,128}$'
    $resultFields = @(
        [string]$state.ResultPublishedInfName,
        [string]$state.ResultPublishedInfSha256,
        [string]$state.ResultPackageManifestSha256,
        [string]$state.ResultCatalogSignerThumbprint
    )
    $resultIdentityAbsent = @($resultFields | Where-Object { -not [string]::IsNullOrEmpty($_) }).Count -eq 0
    $resultIdentityValid =
        [string]$state.ResultPublishedInfName -cmatch '^oem\d+\.inf$' -and
        [string]$state.ResultPublishedInfSha256 -cmatch '^[0-9A-F]{64}$' -and
        [string]$state.ResultPackageManifestSha256 -cmatch '^[0-9A-F]{64}$' -and
        [string]$state.ResultCatalogSignerThumbprint -cmatch '^[0-9A-F]{40,128}$'
    $previousOwner = [string]$state.PreviousOwnerProductCode
    $ownershipDisposition = [string]$state.OwnershipDisposition
    $previousOwnerAbsent = [string]::IsNullOrEmpty($previousOwner)
    $previousOwnerValid = $previousOwner -cmatch '^\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}$'
    $ownershipValid =
        ($ownershipDisposition -ceq "unowned" -and $previousOwnerAbsent -and
            [string]::IsNullOrEmpty([string]$state.PreviousOwnershipManifestSha256)) -or
        ($ownershipDisposition -ceq "current-product" -and $previousOwner -ceq $ProductCode -and
            [string]$state.PreviousOwnershipManifestSha256 -cmatch '^[0-9A-F]{64}$') -or
        ($ownershipDisposition -ceq "related-upgrade-transfer" -and
            $previousOwnerValid -and $previousOwner -cne $ProductCode)
    $previousOwnershipManifestSha256 = [string]$state.PreviousOwnershipManifestSha256
    $previousOwnershipHashValid = [string]::IsNullOrEmpty($previousOwnershipManifestSha256) -or
        $previousOwnershipManifestSha256 -cmatch '^[0-9A-F]{64}$'
    $pendingPhase = [string]$state.PendingPhase
    $pendingBootIdentifier = [string]$state.PendingBootIdentifier
    $pendingBootValid = if ($pendingPhase -in @("none", "commit-ownership")) {
        [string]::IsNullOrEmpty($pendingBootIdentifier)
    } else {
        $pendingBootIdentifier -cmatch '^\d+$'
    }
    if ([int]$state.Schema -ne 6 -or
        [string]$state.ProductCode -cne $ProductCode -or
        [string]$state.TransactionKind -cne $TransactionKind -or
        -not $ownershipValid -or -not $previousOwnershipHashValid -or -not $pendingBootValid -or
        -not [IO.Path]::GetFullPath([string]$state.RootDir).Equals(
            [IO.Path]::GetFullPath($RootDir),
            [StringComparison]::OrdinalIgnoreCase) -or
        ([bool]$state.DriverWasPresent -and -not [bool]$state.PackageWasPresent) -or
        ([bool]$state.PackageWasPresent -and
            ($previousPublishedInf -cnotmatch '^oem\d+\.inf$' -or -not $previousIdentityValid)) -or
        (-not [bool]$state.PackageWasPresent -and -not $previousIdentityAbsent) -or
        (-not $forwardIdentityAbsent -and -not $forwardIdentityValid) -or
        (-not $resultIdentityAbsent -and -not $resultIdentityValid) -or
        ([bool]$state.DeferredPreviousPackageRemoval -and
            (-not [bool]$state.PackageWasPresent -or [bool]$state.DriverWasPresent)) -or
        ([bool]$state.OwnershipCommitted -and -not [bool]$state.Committed) -or
        ([bool]$state.OwnershipCommitted -and $pendingPhase -cne "none") -or
        ($pendingPhase -ceq "commit-ownership" -and -not [bool]$state.Committed) -or
        $pendingPhase -notin @(
            "none",
            "forward-remove",
            "forward-verify",
            "commit-remove-previous",
            "commit-ownership",
            "rollback-remove",
            "rollback-verify"
        )) {
        throw "Virtual Display rollback state does not match this transaction."
    }
    return $state
}

function Remove-StateLessBootstrap {
    if (Test-Path -LiteralPath $rollbackState -PathType Leaf) {
        throw "Refusing to remove a Virtual Display bootstrap after transaction state was published."
    }
    if (Test-Path -LiteralPath $rollbackDirectory -PathType Container) {
        Assert-RollbackDirectory
        Unregister-ResumeTask
        Clear-RebootMarker
        Remove-Item -LiteralPath $rollbackDirectory -Recurse -Force
    }
    foreach ($parent in @($rollbackProduct, $rollbackRoot)) {
        if ((Test-Path -LiteralPath $parent -PathType Container) -and
            @(Get-ChildItem -LiteralPath $parent -Force).Count -eq 0) {
            Remove-Item -LiteralPath $parent -Force
        }
    }
}

function Start-Transaction {
    param([bool]$DesiredPresent)
    Initialize-RollbackDirectory
    if ((Test-Path -LiteralPath $rollbackState) -or
        (Test-Path -LiteralPath $rollbackDriver) -or
        (Test-Path -LiteralPath $rollbackHelper)) {
        throw "A pending Virtual Display transaction must be resolved first."
    }
    try {
        Copy-Item -LiteralPath $script:CurrentScriptPath -Destination $rollbackScript -Force
        Copy-Item -LiteralPath $installedHelper -Destination $rollbackHelper -Force
        $current = Get-InstalledVirtualDisplay
        $previousOwnershipManifestSha256 = Get-OwnershipManifestSha256
        $owned = Read-OwnedDriverIdentity
        if ((Get-OwnershipManifestSha256) -cne $previousOwnershipManifestSha256) {
            throw "The durable Virtual Display ownership manifest changed while it was read."
        }
        $ownership = Resolve-VirtualDisplayOwnership `
            -OwnedProductCode $(if ($null -eq $owned) { $null } else { [string]$owned.ProductCode }) `
            -CurrentProductCode $ProductCode `
            -RelatedUpgradeOwnerProductCode $UpgradeOwnerProductCode `
            -InstalledDevicePresent ($null -ne $current)
        $packageInfName = $null
        if ($null -ne $current) {
            $packageInfName = $current.InfName
            if ($null -ne $owned) {
                if ([string]$owned.PublishedInfName -cne $current.InfName) {
                    throw "The active Virtual Display driver does not match Lumen's ownership manifest."
                }
                Assert-InstalledDriverIdentity `
                    -InfName $current.InfName `
                    -ExpectedInfSha256 ([string]$owned.InfSha256) `
                    -ExpectedManifestSha256 ([string]$owned.ManifestSha256) `
                    -ExpectedCatalogSignerThumbprint ([string]$owned.CatalogSignerThumbprint)
            }
        } elseif ($null -ne $owned) {
            $publishedInf = Join-Path (Join-Path $env:SystemRoot "INF") ([string]$owned.PublishedInfName)
            if (Test-Path -LiteralPath $publishedInf -PathType Leaf) {
                Assert-InstalledDriverIdentity `
                    -InfName ([string]$owned.PublishedInfName) `
                    -ExpectedInfSha256 ([string]$owned.InfSha256) `
                    -ExpectedManifestSha256 ([string]$owned.ManifestSha256) `
                    -ExpectedCatalogSignerThumbprint ([string]$owned.CatalogSignerThumbprint)
                $packageInfName = [string]$owned.PublishedInfName
            }
        } elseif (-not $DesiredPresent) {
            Write-Warning "No device or durable VDD ownership manifest exists; no staged package can be removed safely."
        }
        $backup = $null
        if (-not [string]::IsNullOrEmpty($packageInfName)) {
            $backup = Export-InstalledDriver -InfName $packageInfName
        }
        Save-State -State ([ordered]@{
            Schema = 6
            ProductCode = $ProductCode
            TransactionKind = $TransactionKind
            RootDir = $RootDir
            OwnershipDisposition = [string]$ownership.Disposition
            PreviousOwnerProductCode = [string]$ownership.PreviousOwnerProductCode
            PreviousOwnershipManifestSha256 = $previousOwnershipManifestSha256
            DriverWasPresent = $null -ne $current
            PackageWasPresent = $null -ne $backup
            DesiredPresent = $DesiredPresent
            PreviousPublishedInfName = if ($null -eq $backup) { $null } else { $packageInfName }
            PreviousPublishedInfSha256 = if ($null -eq $backup) { $null } else { $backup.InfSha256 }
            PreviousPackageManifestSha256 = if ($null -eq $backup) { $null } else { $backup.ManifestSha256 }
            PreviousCatalogSignerThumbprint = if ($null -eq $backup) {
                $null
            } else {
                $backup.CatalogSignerThumbprint
            }
            ForwardPublishedInfName = $null
            ForwardPublishedInfSha256 = $null
            ForwardPackageManifestSha256 = $null
            ForwardCatalogSignerThumbprint = $null
            ResultPublishedInfName = $null
            ResultPublishedInfSha256 = $null
            ResultPackageManifestSha256 = $null
            ResultCatalogSignerThumbprint = $null
            DeferredPreviousPackageRemoval = $null -ne $backup -and $null -eq $current
            PreserveForwardPackageOnRollback = $false
            BackedUpDriverInfPath = if ($null -eq $backup) { $null } else { $backup.InfPath }
            BackupFiles = if ($null -eq $backup) { @() } else { @($backup.Files) }
            BackupCatalogSignerThumbprint = if ($null -eq $backup) {
                $null
            } else {
                $backup.CatalogSignerThumbprint
            }
            PendingPhase = "none"
            PendingBootIdentifier = $null
            RollbackComplete = $false
            Committed = $false
            OwnershipCommitted = $false
        })
    } catch {
        $bootstrapError = $_
        if (-not (Test-Path -LiteralPath $rollbackState -PathType Leaf)) {
            try {
                Remove-StateLessBootstrap
            } catch {
                throw "Virtual Display transaction bootstrap failed and cleanup could not complete: $($bootstrapError.Exception.Message) $($_.Exception.Message)"
            }
        }
        throw $bootstrapError
    }
}

function Remove-PublishedDriverPackage {
    param(
        [string]$InfName,
        [string]$ExpectedInfSha256,
        [string]$ExpectedManifestSha256,
        [string]$ExpectedCatalogSignerThumbprint
    )
    if ([string]::IsNullOrEmpty($InfName)) {
        return $false
    }
    if ($InfName -cnotmatch '^oem\d+\.inf$') {
        throw "Lumen Virtual Display reported an invalid published INF: $InfName"
    }
    $publishedInf = Join-Path (Join-Path $env:SystemRoot "INF") $InfName
    if (-not (Test-Path -LiteralPath $publishedInf -PathType Leaf)) {
        return $false
    }
    Assert-InstalledDriverIdentity `
        -InfName $InfName `
        -ExpectedInfSha256 $ExpectedInfSha256 `
        -ExpectedManifestSha256 $ExpectedManifestSha256 `
        -ExpectedCatalogSignerThumbprint $ExpectedCatalogSignerThumbprint
    $deleteExit = Invoke-PnpUtil `
        -Arguments @("/delete-driver", $InfName, "/uninstall", "/force") `
        -Description "Removing the Lumen Virtual Display driver package"
    if ($deleteExit -eq 3010) {
        return $true
    }
    if (Test-Path -LiteralPath $publishedInf -PathType Leaf) {
        throw "Lumen Virtual Display driver package remained staged after removal: $InfName"
    }
    return $false
}

function Remove-CurrentDriver {
    param(
        [string]$ExpectedInfName,
        [string]$ExpectedInfSha256,
        [string]$ExpectedManifestSha256,
        [string]$ExpectedCatalogSignerThumbprint
    )
    $current = Get-InstalledVirtualDisplay
    if ($null -eq $current) {
        return $false
    }
    if ($current.InfName -cne $ExpectedInfName) {
        throw "The active Virtual Display package changed after transaction state was captured."
    }
    $removeExit = Invoke-PnpUtil `
        -Arguments @("/remove-device", $current.InstanceId) `
        -Description "Removing the Lumen Virtual Display device"
    if ($removeExit -eq 3010) {
        return $true
    }
    if (Remove-PublishedDriverPackage `
            -InfName $current.InfName `
            -ExpectedInfSha256 $ExpectedInfSha256 `
            -ExpectedManifestSha256 $ExpectedManifestSha256 `
            -ExpectedCatalogSignerThumbprint $ExpectedCatalogSignerThumbprint) {
        return $true
    }
    if ($null -ne (Get-InstalledVirtualDisplay)) {
        throw "Lumen Virtual Display is still present after removal."
    }
    return $false
}

function Remove-CurrentDeviceOnly {
    param([string]$ExpectedInfName)
    $current = Get-InstalledVirtualDisplay
    if ($null -eq $current) {
        return $false
    }
    if ($current.InfName -cne $ExpectedInfName) {
        throw "The active Virtual Display package changed before device-only rollback."
    }
    $removeExit = Invoke-PnpUtil `
        -Arguments @("/remove-device", $current.InstanceId) `
        -Description "Removing the rolled-back Lumen Virtual Display device"
    if ($removeExit -eq 3010) {
        return $true
    }
    if ($null -ne (Get-InstalledVirtualDisplay)) {
        throw "Lumen Virtual Display remained present after device-only rollback."
    }
    return $false
}

function Install-Driver {
    param([string]$InfPath)
    $installExit = Invoke-VirtualDisplayHelper `
        -Arguments @("install-or-update", $InfPath) `
        -Description "Installing the Lumen Virtual Display root device and driver"
    if ($installExit -eq 3010) {
        return $true
    }
    $current = Get-InstalledVirtualDisplay
    if ($null -eq $current -or $current.Status -ne "OK") {
        throw "Lumen Virtual Display did not become healthy after installation."
    }
    return $false
}

function Capture-ResultDriverIdentity {
    param([psobject]$State)
    $current = Get-InstalledVirtualDisplay
    if ($null -eq $current -or $current.Status -ne "OK") {
        throw "The installed Virtual Display cannot be recorded as Lumen-owned."
    }
    $identity = Read-InstalledDriverIdentity `
        -InfName $current.InfName `
        -ExportRoot $forwardIdentityDriver `
        -Description "Recording the installed Lumen Virtual Display package"
    $State.ResultPublishedInfName = $current.InfName
    $State.ResultPublishedInfSha256 = $identity.InfSha256
    $State.ResultPackageManifestSha256 = $identity.ManifestSha256
    $State.ResultCatalogSignerThumbprint = $identity.CatalogSignerThumbprint
    Save-State -State $State
}

function Get-ResultDriverIdentity {
    param([psobject]$State)
    return [pscustomobject]@{
        PublishedInfName = [string]$State.ResultPublishedInfName
        InfSha256 = [string]$State.ResultPublishedInfSha256
        ManifestSha256 = [string]$State.ResultPackageManifestSha256
        CatalogSignerThumbprint = [string]$State.ResultCatalogSignerThumbprint
    }
}

function Test-PreviousAndResultIdentityEqual {
    param([psobject]$State)
    return [string]$State.PreviousPublishedInfName -ceq [string]$State.ResultPublishedInfName -and
        [string]$State.PreviousPublishedInfSha256 -ceq [string]$State.ResultPublishedInfSha256 -and
        [string]$State.PreviousPackageManifestSha256 -ceq [string]$State.ResultPackageManifestSha256 -and
        [string]$State.PreviousCatalogSignerThumbprint -ceq [string]$State.ResultCatalogSignerThumbprint
}

function Remove-DeferredPreviousPackage {
    param([psobject]$State)
    $removeDeferredPackage = [bool]$State.DeferredPreviousPackageRemoval -and
        (-not [bool]$State.DesiredPresent -or
            -not (Test-PreviousAndResultIdentityEqual -State $State))
    if (-not $removeDeferredPackage) {
        return $false
    }
    return Remove-PublishedDriverPackage `
        -InfName ([string]$State.PreviousPublishedInfName) `
        -ExpectedInfSha256 ([string]$State.PreviousPublishedInfSha256) `
        -ExpectedManifestSha256 ([string]$State.PreviousPackageManifestSha256) `
        -ExpectedCatalogSignerThumbprint ([string]$State.PreviousCatalogSignerThumbprint)
}

function Apply-CommittedOwnership {
    param([psobject]$State)
    if ([bool]$State.DesiredPresent) {
        $identity = Get-ResultDriverIdentity -State $State
        Assert-DriverIdentityFields -Identity $identity
        $current = Get-InstalledVirtualDisplay
        if ($null -eq $current -or $current.InfName -cne $identity.PublishedInfName) {
            throw "The installed Virtual Display changed before ownership was committed."
        }
        Assert-InstalledDriverIdentity `
            -InfName $identity.PublishedInfName `
            -ExpectedInfSha256 $identity.InfSha256 `
            -ExpectedManifestSha256 $identity.ManifestSha256 `
            -ExpectedCatalogSignerThumbprint $identity.CatalogSignerThumbprint
        Write-OwnedDriverIdentity -Identity $identity
    } else {
        Remove-OwnedDriverIdentity
    }
}

function Test-CommittedOwnershipMatches {
    param([psobject]$State)
    if (-not [bool]$State.DesiredPresent) {
        return -not (Test-Path -LiteralPath $ownershipFile -PathType Leaf)
    }
    $owned = Read-OwnedDriverIdentity
    if ($null -eq $owned) {
        return $false
    }
    $identity = Get-ResultDriverIdentity -State $State
    return [string]$owned.ProductCode -ceq $ProductCode -and
        [string]$owned.PublishedInfName -ceq [string]$identity.PublishedInfName -and
        [string]$owned.InfSha256 -ceq [string]$identity.InfSha256 -and
        [string]$owned.ManifestSha256 -ceq [string]$identity.ManifestSha256 -and
        [string]$owned.CatalogSignerThumbprint -ceq [string]$identity.CatalogSignerThumbprint
}

function Complete-OwnershipCommit {
    param([psobject]$State)
    $currentManifestSha256 = Get-OwnershipManifestSha256
    $matches = Test-CommittedOwnershipMatches -State $State
    $action = Resolve-OwnershipCommitAction `
        -OwnershipCommitted ([bool]$State.OwnershipCommitted) `
        -PreviousManifestSha256 ([string]$State.PreviousOwnershipManifestSha256) `
        -CurrentManifestSha256 $currentManifestSha256 `
        -IntendedOwnershipMatches $matches
    if ($action -ceq "apply") {
        if ((Get-OwnershipManifestSha256) -cne $currentManifestSha256) {
            throw "The durable Virtual Display ownership manifest changed before the atomic commit."
        }
        Apply-CommittedOwnership -State $State
        if (-not (Test-CommittedOwnershipMatches -State $State)) {
            throw "Virtual Display ownership did not reach its committed state."
        }
    }
    $State.OwnershipCommitted = $true
    $State.PendingPhase = "none"
    $State.PendingBootIdentifier = $null
    Save-State -State $State
}

function Remove-RollbackArtifacts {
    if (-not (Test-Path -LiteralPath $rollbackDirectory)) {
        return
    }
    Assert-RollbackDirectory
    Unregister-ResumeTask
    Clear-RebootMarker
    Remove-Item -LiteralPath $rollbackDirectory -Recurse -Force
    foreach ($parent in @($rollbackProduct, $rollbackRoot)) {
        if ((Test-Path -LiteralPath $parent -PathType Container) -and
            @(Get-ChildItem -LiteralPath $parent -Force).Count -eq 0) {
            Remove-Item -LiteralPath $parent -Force
        }
    }
}

function Resolve-BackupInf {
    param([psobject]$State)
    $backup = [IO.Path]::GetFullPath([string]$State.BackedUpDriverInfPath)
    $backupRoot = [IO.Path]::GetFullPath($rollbackDriver) + [IO.Path]::DirectorySeparatorChar
    if (-not $backup.StartsWith($backupRoot, [StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-Path -LiteralPath $backup -PathType Leaf)) {
        throw "The previous Virtual Display INF backup is invalid."
    }
    $backupFiles = @($State.BackupFiles)
    if ($backupFiles.Count -ne 3) {
        throw "The previous Virtual Display backup manifest is incomplete."
    }
    $validatedPaths = [Collections.Generic.List[string]]::new()
    foreach ($entry in $backupFiles) {
        $relative = [string]$entry.RelativePath
        if ([string]::IsNullOrWhiteSpace($relative) -or [IO.Path]::IsPathRooted($relative)) {
            throw "The previous Virtual Display backup manifest contains an invalid path."
        }
        $path = [IO.Path]::GetFullPath((Join-Path $rollbackDriver $relative))
        if (-not $path.StartsWith($backupRoot, [StringComparison]::OrdinalIgnoreCase) -or
            -not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "The previous Virtual Display backup is missing a required file."
        }
        $item = Get-Item -LiteralPath $path -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "The previous Virtual Display backup contains a reparse point."
        }
        $expectedHash = [string]$entry.Sha256
        $actualHash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToUpperInvariant()
        if ($expectedHash -cnotmatch '^[0-9A-F]{64}$' -or $actualHash -cne $expectedHash) {
            throw "The previous Virtual Display backup failed its SHA-256 integrity check."
        }
        $validatedPaths.Add($path)
    }
    $catalogs = @($validatedPaths | Where-Object { [IO.Path]::GetExtension($_) -ieq ".cat" })
    $drivers = @($validatedPaths | Where-Object { [IO.Path]::GetFileName($_) -ieq "LumenVirtualDisplay.dll" })
    if ($catalogs.Count -ne 1 -or $drivers.Count -ne 1 -or
        -not ($validatedPaths | Where-Object { $_ -ieq $backup })) {
        throw "The previous Virtual Display backup manifest has the wrong package contents."
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $catalogs[0]
    $expectedSigner = [string]$State.BackupCatalogSignerThumbprint
    if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
        $null -eq $signature.SignerCertificate -or
        $expectedSigner -cnotmatch '^[0-9A-F]{40,128}$' -or
        $signature.SignerCertificate.Thumbprint.ToUpperInvariant() -cne $expectedSigner) {
        throw "The previous Virtual Display backup catalog signature changed."
    }
    return $backup
}

function Assert-DesiredState {
    param([bool]$Present)
    for ($attempt = 0; $attempt -lt 300; $attempt++) {
        $current = Get-InstalledVirtualDisplay
        if (($Present -and $null -ne $current -and $current.Status -eq "OK") -or
            (-not $Present -and $null -eq $current)) {
            return
        }
        Start-Sleep -Milliseconds 100
    }
    if ($Present) {
        throw "Lumen Virtual Display did not become healthy after the restart."
    }
    throw "Lumen Virtual Display remained installed after the restart."
}

function Complete-ForwardOperation {
    param([psobject]$State)
    if ([bool]$State.Committed) {
        $State.PendingPhase = "commit-ownership"
        $State.PendingBootIdentifier = $null
        Save-State -State $State
        Complete-OwnershipCommit -State $State
    } else {
        $State.PendingPhase = "none"
        $State.PendingBootIdentifier = $null
        Save-State -State $State
    }
    Clear-RebootMarker
    Unregister-ResumeTask
    if ([bool]$State.Committed) {
        Remove-RollbackArtifacts
    }
}

function Complete-RollbackOperation {
    param([psobject]$State)
    Resolve-OwnershipRollbackAction `
        -TransactionCommitted ([bool]$State.Committed) `
        -OwnershipCommitted ([bool]$State.OwnershipCommitted) `
        -PreviousManifestSha256 ([string]$State.PreviousOwnershipManifestSha256) `
        -CurrentManifestSha256 (Get-OwnershipManifestSha256) | Out-Null
    $State.PendingPhase = "none"
    $State.PendingBootIdentifier = $null
    $State.RollbackComplete = $true
    Save-State -State $State
    Remove-RollbackArtifacts
}

function Invoke-ForwardInstall {
    $state = Read-State
    if ([bool]$state.PackageWasPresent) {
        Resolve-BackupInf -State $state | Out-Null
    }
    if (-not [bool]$state.DeferredPreviousPackageRemoval) {
        $removeNeedsReboot = Remove-CurrentDriver `
            -ExpectedInfName ([string]$state.PreviousPublishedInfName) `
            -ExpectedInfSha256 ([string]$state.PreviousPublishedInfSha256) `
            -ExpectedManifestSha256 ([string]$state.PreviousPackageManifestSha256) `
            -ExpectedCatalogSignerThumbprint ([string]$state.PreviousCatalogSignerThumbprint)
        if ($removeNeedsReboot) {
            Set-PendingReboot -State $state -Phase "forward-remove"
            return
        }
        $deleteNeedsReboot = Remove-PublishedDriverPackage `
            -InfName ([string]$state.PreviousPublishedInfName) `
            -ExpectedInfSha256 ([string]$state.PreviousPublishedInfSha256) `
            -ExpectedManifestSha256 ([string]$state.PreviousPackageManifestSha256) `
            -ExpectedCatalogSignerThumbprint ([string]$state.PreviousCatalogSignerThumbprint)
        if ($deleteNeedsReboot) {
            Set-PendingReboot -State $state -Phase "forward-remove"
            return
        }
    }
    $installNeedsReboot = Install-Driver -InfPath $packageInf
    if ($installNeedsReboot) {
        Set-PendingReboot -State $state -Phase "forward-verify"
        return
    }
    Assert-DesiredState -Present $true
    Capture-ResultDriverIdentity -State $state
    Complete-ForwardOperation -State $state
}

function Invoke-ForwardUninstall {
    $state = Read-State
    if ([bool]$state.PackageWasPresent) {
        Resolve-BackupInf -State $state | Out-Null
    }
    if ([bool]$state.DeferredPreviousPackageRemoval) {
        Assert-DesiredState -Present $false
        Complete-ForwardOperation -State $state
        return
    }
    $removeNeedsReboot = Remove-CurrentDriver `
        -ExpectedInfName ([string]$state.PreviousPublishedInfName) `
        -ExpectedInfSha256 ([string]$state.PreviousPublishedInfSha256) `
        -ExpectedManifestSha256 ([string]$state.PreviousPackageManifestSha256) `
        -ExpectedCatalogSignerThumbprint ([string]$state.PreviousCatalogSignerThumbprint)
    if ($removeNeedsReboot) {
        Set-PendingReboot -State $state -Phase "forward-remove"
        return
    }
    $deleteNeedsReboot = Remove-PublishedDriverPackage `
        -InfName ([string]$state.PreviousPublishedInfName) `
        -ExpectedInfSha256 ([string]$state.PreviousPublishedInfSha256) `
        -ExpectedManifestSha256 ([string]$state.PreviousPackageManifestSha256) `
        -ExpectedCatalogSignerThumbprint ([string]$state.PreviousCatalogSignerThumbprint)
    if ($deleteNeedsReboot) {
        Set-PendingReboot -State $state -Phase "forward-remove"
        return
    }
    Assert-DesiredState -Present $false
    Complete-ForwardOperation -State $state
}

function Invoke-Rollback {
    if (-not (Test-Path -LiteralPath $rollbackState -PathType Leaf)) {
        return
    }
    $state = Read-State
    if ([bool]$state.Committed) {
        if ([string]$state.PendingPhase -notin @("none", "commit-ownership")) {
            throw "A committed Virtual Display change is waiting for post-restart verification."
        }
        $state.PendingPhase = "commit-ownership"
        Save-State -State $state
        Complete-OwnershipCommit -State $state
        Remove-RollbackArtifacts
        return
    }
    Resolve-OwnershipRollbackAction `
        -TransactionCommitted $false `
        -OwnershipCommitted ([bool]$state.OwnershipCommitted) `
        -PreviousManifestSha256 ([string]$state.PreviousOwnershipManifestSha256) `
        -CurrentManifestSha256 (Get-OwnershipManifestSha256) | Out-Null
    if ([bool]$state.RollbackComplete) {
        Remove-RollbackArtifacts
        return
    }
    if (-not [bool]$state.RollbackComplete) {
        if ([bool]$state.DriverWasPresent) {
            $backup = Resolve-BackupInf -State $state
        }
        $forward = Get-InstalledVirtualDisplay
        if ($null -ne $forward) {
            $forwardIdentity = Read-InstalledDriverIdentity `
                -InfName $forward.InfName `
                -ExportRoot $forwardIdentityDriver `
                -Description "Recording the installed Virtual Display package before rollback"
            $state.ForwardPublishedInfName = $forward.InfName
            $state.ForwardPublishedInfSha256 = $forwardIdentity.InfSha256
            $state.ForwardPackageManifestSha256 = $forwardIdentity.ManifestSha256
            $state.ForwardCatalogSignerThumbprint = $forwardIdentity.CatalogSignerThumbprint
            $state.PreserveForwardPackageOnRollback = [bool]$state.DeferredPreviousPackageRemoval -and
                [string]$state.PreviousPublishedInfName -ceq $forward.InfName -and
                [string]$state.PreviousPublishedInfSha256 -ceq $forwardIdentity.InfSha256 -and
                [string]$state.PreviousPackageManifestSha256 -ceq $forwardIdentity.ManifestSha256 -and
                [string]$state.PreviousCatalogSignerThumbprint -ceq $forwardIdentity.CatalogSignerThumbprint
            Save-State -State $state
        }
        $removeNeedsReboot = if ([bool]$state.PreserveForwardPackageOnRollback) {
            Remove-CurrentDeviceOnly -ExpectedInfName ([string]$state.ForwardPublishedInfName)
        } else {
            Remove-CurrentDriver `
                -ExpectedInfName ([string]$state.ForwardPublishedInfName) `
                -ExpectedInfSha256 ([string]$state.ForwardPublishedInfSha256) `
                -ExpectedManifestSha256 ([string]$state.ForwardPackageManifestSha256) `
                -ExpectedCatalogSignerThumbprint ([string]$state.ForwardCatalogSignerThumbprint)
        }
        if ($removeNeedsReboot) {
            Set-PendingReboot -State $state -Phase "rollback-remove"
            return
        }
        if (-not [bool]$state.PreserveForwardPackageOnRollback) {
            $deleteNeedsReboot = Remove-PublishedDriverPackage `
                -InfName ([string]$state.ForwardPublishedInfName) `
                -ExpectedInfSha256 ([string]$state.ForwardPublishedInfSha256) `
                -ExpectedManifestSha256 ([string]$state.ForwardPackageManifestSha256) `
                -ExpectedCatalogSignerThumbprint ([string]$state.ForwardCatalogSignerThumbprint)
            if ($deleteNeedsReboot) {
                Set-PendingReboot -State $state -Phase "rollback-remove"
                return
            }
        }
        if ([bool]$state.DriverWasPresent) {
            $installNeedsReboot = Install-Driver -InfPath $backup
            if ($installNeedsReboot) {
                Set-PendingReboot -State $state -Phase "rollback-verify"
                return
            }
        }
        Assert-DesiredState -Present ([bool]$state.DriverWasPresent)
        Complete-RollbackOperation -State $state
    }
}

function Invoke-Commit {
    if (-not (Test-Path -LiteralPath $rollbackState -PathType Leaf)) {
        return
    }
    $state = Read-State
    if ([string]$state.PendingPhase -ceq "commit-ownership") {
        Complete-OwnershipCommit -State $state
        Remove-RollbackArtifacts
        return
    }
    if ([string]$state.PendingPhase -ne "none") {
        $state.Committed = $true
        Save-State -State $state
        $script:RebootRequired = $true
        return
    }
    Resolve-OwnershipCommitAction `
        -OwnershipCommitted ([bool]$state.OwnershipCommitted) `
        -PreviousManifestSha256 ([string]$state.PreviousOwnershipManifestSha256) `
        -CurrentManifestSha256 (Get-OwnershipManifestSha256) `
        -IntendedOwnershipMatches (Test-CommittedOwnershipMatches -State $state) | Out-Null
    $deleteNeedsReboot = Remove-DeferredPreviousPackage -State $state
    if ($deleteNeedsReboot) {
        $state.Committed = $true
        Set-PendingReboot -State $state -Phase "commit-remove-previous"
        return
    }
    $state.Committed = $true
    $state.PendingPhase = "commit-ownership"
    Save-State -State $state
    Complete-OwnershipCommit -State $state
    Remove-RollbackArtifacts
}

function Invoke-Resume {
    if (-not (Test-Path -LiteralPath $rollbackState -PathType Leaf)) {
        return
    }
    $state = Read-State
    $phase = [string]$state.PendingPhase
    if ($phase -eq "none") {
        if ([bool]$state.Committed) {
            $state.PendingPhase = "commit-ownership"
            Save-State -State $state
            Complete-OwnershipCommit -State $state
            Remove-RollbackArtifacts
        } elseif ([bool]$state.RollbackComplete) {
            Remove-RollbackArtifacts
        }
        return
    }
    if ($phase -cne "commit-ownership") {
        Assert-VirtualDisplayResumeAfterRestart `
            -PendingBootIdentifier ([string]$state.PendingBootIdentifier) `
            -CurrentBootIdentifier (Get-BootIdentifier)
    }

    if ([bool]$state.Committed) {
        if ($phase -eq "commit-ownership") {
            Complete-OwnershipCommit -State $state
            Remove-RollbackArtifacts
            return
        } elseif ($phase -eq "commit-remove-previous") {
            $deleteNeedsReboot = Remove-PublishedDriverPackage `
                -InfName ([string]$state.PreviousPublishedInfName) `
                -ExpectedInfSha256 ([string]$state.PreviousPublishedInfSha256) `
                -ExpectedManifestSha256 ([string]$state.PreviousPackageManifestSha256) `
                -ExpectedCatalogSignerThumbprint ([string]$state.PreviousCatalogSignerThumbprint)
            if ($deleteNeedsReboot) {
                Set-PendingReboot -State $state -Phase "commit-remove-previous"
                return
            }
        } elseif ($phase -eq "forward-remove") {
            Assert-DesiredState -Present $false
            $deleteNeedsReboot = Remove-PublishedDriverPackage `
                -InfName ([string]$state.PreviousPublishedInfName) `
                -ExpectedInfSha256 ([string]$state.PreviousPublishedInfSha256) `
                -ExpectedManifestSha256 ([string]$state.PreviousPackageManifestSha256) `
                -ExpectedCatalogSignerThumbprint ([string]$state.PreviousCatalogSignerThumbprint)
            if ($deleteNeedsReboot) {
                Set-PendingReboot -State $state -Phase "forward-remove"
                return
            }
            if ([bool]$state.DesiredPresent) {
                $installNeedsReboot = Install-Driver -InfPath $packageInf
                if ($installNeedsReboot) {
                    Set-PendingReboot -State $state -Phase "forward-verify"
                    return
                }
                Assert-DesiredState -Present $true
                Capture-ResultDriverIdentity -State $state
            }
        } elseif ($phase -ne "forward-verify") {
            throw "Invalid committed Virtual Display resume phase: $phase"
        }
        Assert-DesiredState -Present ([bool]$state.DesiredPresent)
        if ([bool]$state.DesiredPresent -and
            [string]::IsNullOrEmpty([string]$state.ResultPublishedInfName)) {
            Capture-ResultDriverIdentity -State $state
        }
        $deleteNeedsReboot = Remove-DeferredPreviousPackage -State $state
        if ($deleteNeedsReboot) {
            Set-PendingReboot -State $state -Phase "commit-remove-previous"
            return
        }
        Complete-ForwardOperation -State $state
        return
    }

    if ($phase -eq "rollback-remove") {
        Assert-DesiredState -Present $false
        if (-not [bool]$state.PreserveForwardPackageOnRollback) {
            $deleteNeedsReboot = Remove-PublishedDriverPackage `
                -InfName ([string]$state.ForwardPublishedInfName) `
                -ExpectedInfSha256 ([string]$state.ForwardPublishedInfSha256) `
                -ExpectedManifestSha256 ([string]$state.ForwardPackageManifestSha256) `
                -ExpectedCatalogSignerThumbprint ([string]$state.ForwardCatalogSignerThumbprint)
            if ($deleteNeedsReboot) {
                Set-PendingReboot -State $state -Phase "rollback-remove"
                return
            }
        }
        if ([bool]$state.DriverWasPresent) {
            $backup = Resolve-BackupInf -State $state
            $installNeedsReboot = Install-Driver -InfPath $backup
            if ($installNeedsReboot) {
                Set-PendingReboot -State $state -Phase "rollback-verify"
                return
            }
        }
    } elseif ($phase -ne "rollback-verify") {
        throw "Invalid uncommitted Virtual Display resume phase: $phase"
    }
    Assert-DesiredState -Present ([bool]$state.DriverWasPresent)
    Complete-RollbackOperation -State $state
}

try {
    switch ($Action) {
        "install" {
            Assert-PackageInf
            Start-Transaction -DesiredPresent $true
            Invoke-ForwardInstall
        }
        "uninstall" {
            Start-Transaction -DesiredPresent $false
            Invoke-ForwardUninstall
        }
        "remove-feature" {
            if ($TransactionKind -ne "install") {
                throw "Virtual Display feature removal must run inside an install transaction."
            }
            Start-Transaction -DesiredPresent $false
            Invoke-ForwardUninstall
        }
        "rollback" {
            Invoke-Rollback
        }
        "commit" {
            Invoke-Commit
        }
        "resume" {
            Invoke-Resume
        }
    }
} catch {
    if ($Action -in @("install", "uninstall")) {
        try { Invoke-Rollback } catch { Write-Error $_.Exception.Message }
    }
    Write-Error $_.Exception.Message
    exit 1
}

if ($script:RebootRequired) {
    exit 3010
}
exit 0
