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
    [string]$TransactionKind
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

Assert-Administrator
$ProductCode = ConvertTo-NormalizedProductCode -Value $ProductCode
if ($Action -in @("install", "uninstall") -and $Action -ne $TransactionKind) {
    throw "Virtual Display transaction kind does not match the action."
}

$programData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
$rollbackRoot = Join-Path $programData "LumenVirtualDisplayInstallerV1"
$rollbackProduct = Join-Path $rollbackRoot $ProductCode
$rollbackDirectory = Join-Path $rollbackProduct $TransactionKind
$rollbackState = Join-Path $rollbackDirectory "virtual-display-rollback.json"
$rollbackDriver = Join-Path $rollbackDirectory "virtual-display-driver"
$rollbackScript = Join-Path $rollbackDirectory "virtual-display-setup.ps1"
$rollbackHelper = Join-Path $rollbackDirectory "lumen-vddctl.exe"
$packageInf = Join-Path $RootDir "drivers\virtual-display\LumenVirtualDisplay.inf"
$installedHelper = Join-Path $RootDir "tools\lumen-vddctl.exe"
$taskIdentity = $ProductCode.Trim("{}").Replace("-", "")
$resumeTaskName = "Lumen Virtual Display Resume $taskIdentity $TransactionKind"
$rebootMarker = "HKLM:\SOFTWARE\Lumen\Installer\PendingReboot\$taskIdentity\$TransactionKind"

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
        [ValidateSet("forward-remove", "forward-verify", "rollback-remove", "rollback-verify")]
        [string]$Phase
    )
    $State.PendingPhase = $Phase
    $State.PendingBootIdentifier = Get-BootIdentifier
    Save-State -State $State
    Set-RebootMarker
    Register-ResumeTask
    $script:RebootRequired = $true
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
    $infs = @(
        Get-ChildItem -LiteralPath $rollbackDriver -Filter "*.inf" -File -Recurse |
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
    $backupRoot = [IO.Path]::GetFullPath($rollbackDriver) + [IO.Path]::DirectorySeparatorChar
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
            Sha256 = (Get-FileHash -LiteralPath $fullPath -Algorithm SHA256).Hash.ToUpperInvariant()
        }
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $catalog
    if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
        $null -eq $signature.SignerCertificate) {
        throw "The exported Lumen Virtual Display catalog signature is not valid."
    }
    return [pscustomobject]@{
        InfPath = $inf.FullName
        Files = @($files)
        CatalogSignerThumbprint = $signature.SignerCertificate.Thumbprint.ToUpperInvariant()
    }
}

function Save-State {
    param([psobject]$State)
    $pending = Join-Path $rollbackDirectory "virtual-display-rollback.pending"
    $State | ConvertTo-Json | Set-Content -LiteralPath $pending -Encoding UTF8
    Move-Item -LiteralPath $pending -Destination $rollbackState -Force
}

function Read-State {
    Assert-RollbackDirectory
    $state = Get-Content -LiteralPath $rollbackState -Raw | ConvertFrom-Json
    if ([int]$state.Schema -ne 2 -or
        [string]$state.ProductCode -cne $ProductCode -or
        [string]$state.TransactionKind -cne $TransactionKind -or
        -not [IO.Path]::GetFullPath([string]$state.RootDir).Equals(
            [IO.Path]::GetFullPath($RootDir),
            [StringComparison]::OrdinalIgnoreCase) -or
        [string]$state.PendingPhase -notin @(
            "none",
            "forward-remove",
            "forward-verify",
            "rollback-remove",
            "rollback-verify"
        )) {
        throw "Virtual Display rollback state does not match this transaction."
    }
    return $state
}

function Start-Transaction {
    param([bool]$DesiredPresent)
    Initialize-RollbackDirectory
    if ((Test-Path -LiteralPath $rollbackState) -or
        (Test-Path -LiteralPath $rollbackDriver) -or
        (Test-Path -LiteralPath $rollbackHelper)) {
        throw "A pending Virtual Display transaction must be resolved first."
    }
    Copy-Item -LiteralPath $script:CurrentScriptPath -Destination $rollbackScript -Force
    Copy-Item -LiteralPath $installedHelper -Destination $rollbackHelper -Force
    $current = Get-InstalledVirtualDisplay
    $backup = $null
    if ($null -ne $current) {
        $backup = Export-InstalledDriver -InfName $current.InfName
    }
    Save-State -State ([ordered]@{
        Schema = 2
        ProductCode = $ProductCode
        TransactionKind = $TransactionKind
        RootDir = $RootDir
        DriverWasPresent = $null -ne $current
        DesiredPresent = $DesiredPresent
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
    })
}

function Remove-CurrentDriver {
    $current = Get-InstalledVirtualDisplay
    if ($null -eq $current) {
        return $false
    }
    $removeExit = Invoke-PnpUtil `
        -Arguments @("/remove-device", $current.InstanceId) `
        -Description "Removing the Lumen Virtual Display device"
    if ($removeExit -eq 3010) {
        return $true
    }
    $deleteExit = Invoke-PnpUtil `
        -Arguments @("/delete-driver", $current.InfName, "/uninstall", "/force") `
        -Description "Removing the Lumen Virtual Display driver package"
    if ($deleteExit -eq 3010) {
        return $true
    }
    if ($null -ne (Get-InstalledVirtualDisplay)) {
        throw "Lumen Virtual Display is still present after removal."
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
    $State.PendingPhase = "none"
    $State.PendingBootIdentifier = $null
    Save-State -State $State
    Clear-RebootMarker
    Unregister-ResumeTask
    if ([bool]$State.Committed) {
        Remove-RollbackArtifacts
    }
}

function Complete-RollbackOperation {
    param([psobject]$State)
    $State.PendingPhase = "none"
    $State.PendingBootIdentifier = $null
    $State.RollbackComplete = $true
    Save-State -State $State
    Remove-RollbackArtifacts
}

function Invoke-ForwardInstall {
    $state = Read-State
    if ([bool]$state.DriverWasPresent) {
        Resolve-BackupInf -State $state | Out-Null
    }
    $removeNeedsReboot = Remove-CurrentDriver
    if ($removeNeedsReboot) {
        Set-PendingReboot -State $state -Phase "forward-remove"
        return
    }
    $installNeedsReboot = Install-Driver -InfPath $packageInf
    if ($installNeedsReboot) {
        Set-PendingReboot -State $state -Phase "forward-verify"
        return
    }
    Assert-DesiredState -Present $true
    Complete-ForwardOperation -State $state
}

function Invoke-ForwardUninstall {
    $state = Read-State
    if ([bool]$state.DriverWasPresent) {
        Resolve-BackupInf -State $state | Out-Null
    }
    $removeNeedsReboot = Remove-CurrentDriver
    if ($removeNeedsReboot) {
        Set-PendingReboot -State $state -Phase "forward-verify"
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
        if ([string]$state.PendingPhase -ne "none") {
            throw "A committed Virtual Display change is waiting for post-restart verification."
        }
        Remove-RollbackArtifacts
        return
    }
    if (-not [bool]$state.RollbackComplete) {
        if ([bool]$state.DriverWasPresent) {
            $backup = Resolve-BackupInf -State $state
        }
        $removeNeedsReboot = Remove-CurrentDriver
        if ($removeNeedsReboot) {
            Set-PendingReboot -State $state -Phase "rollback-remove"
            return
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
    $state.Committed = $true
    Save-State -State $state
    if ([string]$state.PendingPhase -eq "none") {
        Remove-RollbackArtifacts
    } else {
        $script:RebootRequired = $true
    }
}

function Invoke-Resume {
    if (-not (Test-Path -LiteralPath $rollbackState -PathType Leaf)) {
        return
    }
    $state = Read-State
    $phase = [string]$state.PendingPhase
    if ($phase -eq "none") {
        if ([bool]$state.Committed -or [bool]$state.RollbackComplete) {
            Remove-RollbackArtifacts
        }
        return
    }
    if ([string]$state.PendingBootIdentifier -eq (Get-BootIdentifier)) {
        throw "Virtual Display resume is waiting for Windows to restart."
    }

    if ([bool]$state.Committed) {
        if ($phase -eq "forward-remove") {
            Assert-DesiredState -Present $false
            if ([string]$state.TransactionKind -ne "install") {
                throw "Invalid forward-remove phase for a Virtual Display uninstall."
            }
            $installNeedsReboot = Install-Driver -InfPath $packageInf
            if ($installNeedsReboot) {
                Set-PendingReboot -State $state -Phase "forward-verify"
                return
            }
        } elseif ($phase -ne "forward-verify") {
            throw "Invalid committed Virtual Display resume phase: $phase"
        }
        Assert-DesiredState -Present ([bool]$state.DesiredPresent)
        Complete-ForwardOperation -State $state
        return
    }

    if ($phase -eq "rollback-remove") {
        Assert-DesiredState -Present $false
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
