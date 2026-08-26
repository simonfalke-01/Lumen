# Lumen Setup Script
# This script orchestrates the installation and uninstallation of Lumen.
# The source filename is retained only for build compatibility; packages install it as lumen-setup.ps1.

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet(
            "install",
            "uninstall",
            "rollback",
            "commit",
            "resume"
    )]
    [string]$Action,

    [Parameter(Mandatory=$false)]
    [switch]$Silent,

    [Parameter(Mandatory=$false)]
    [switch]$Msi,

    [Parameter(Mandatory=$false)]
    [string]$ProductCode,

    [Parameter(Mandatory=$false)]
    [ValidateSet("install", "uninstall")]
    [string]$TransactionKind,

    [Parameter(Mandatory=$false)]
    [ValidateSet("0", "1")]
    [string]$InstallVirtualHid,

    [Parameter(Mandatory=$false)]
    [ValidateSet("0", "1")]
    [string]$InstallVirtualMicrophone,

    [Parameter(Mandatory=$false)]
    [ValidateSet("0", "1")]
    [string]$InstallVirtualDisplay,

    [Parameter(Mandatory=$false)]
    [ValidateSet("0", "1")]
    [string]$RemoveVirtualDisplay,

    [Parameter(Mandatory=$false)]
    [ValidateSet("0", "1")]
    [string]$UpgradeOwnedVirtualDisplay = "0",

    [Parameter(Mandatory=$false)]
    [string]$UpgradeVddOwnerProduct,

    [Parameter(Mandatory=$false)]
    [ValidateSet("preserve", "remove")]
    [string]$IdentityDisposition
)

# Constants
$DocsUrl = "https://github.com/simonfalke-01/Lumen"
$virtualHidCertificateSubject = "CN=Lumen Virtual HID Driver"

# Set preference variables for output streams
$InformationPreference = 'Continue'

# Function to write output to both console (with color/stream) and log file (without color)
function Write-LogMessage {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '',
        Justification='Write-Host is required for colored output')]
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string]$Message,

        [Parameter(Mandatory=$false)]
        [ValidateSet(
                'Debug',
                'Error',
                'Information',
                'Step',
                'Success',
                'Verbose',
                'Warning'
        )]
        [string]$Level = 'Information',

        [Parameter(Mandatory=$false)]
        [ValidateSet(
                'Black',
                'Blue',
                'Cyan',
                'DarkGray',
                'Gray',
                'Green',
                'Magenta',
                'Red',
                'White',
                'Yellow'
        )]
        [string]$Color = $null,

        [Parameter(Mandatory=$false)]
        [switch]$NoTimestamp,

        [Parameter(Mandatory=$false)]
        [switch]$NoLogFile
    )

    # Map levels to colors and output streams
    $levelConfig = @{
        'Debug' = @{ DefaultColor = 'DarkGray'; Stream = 'Debug'; Emoji = ''; LogLevel = 'DEBUG' }
        'Error' = @{ DefaultColor = 'Red'; Stream = 'Error'; Emoji = '✗'; LogLevel = 'ERROR' }
        'Information' = @{ DefaultColor = $null; Stream = 'Host'; Emoji = ''; LogLevel = 'INFO' }
        'Step' = @{ DefaultColor = 'Cyan'; Stream = 'Host'; Emoji = '==>'; LogLevel = 'INFO' }
        'Success' = @{ DefaultColor = 'Green'; Stream = 'Host'; Emoji = '✓'; LogLevel = 'INFO' }
        'Verbose' = @{ DefaultColor = 'DarkGray'; Stream = 'Verbose'; Emoji = ''; LogLevel = 'VERBOSE' }
        'Warning' = @{ DefaultColor = 'Yellow'; Stream = 'Warning'; Emoji = '⚠'; LogLevel = 'WARN' }
    }

    $config = $levelConfig[$Level]

    # Use custom color if specified, otherwise use default color for the level
    $displayColor = if ($Color) { $Color } else { $config.DefaultColor }

    # Write to appropriate output stream with color
    switch ($config.Stream) {
        'Debug' {
            Write-Debug $Message
        }
        'Error' {
            Write-Error $Message
        }
        'Host' {
            if ($null -ne $displayColor) {
                Write-Host "$($config.Emoji) $Message" -ForegroundColor $displayColor
            } else {
                Write-Host "$($config.Emoji) $Message"
            }
        }
        'Information' {
            Write-Information $Message
        }
        'Verbose' {
            Write-Verbose $Message
        }
        'Warning' {
            Write-Warning $Message
        }
        default {
            Write-Information $Message
        }
    }

    # Write to log file without color codes (only if LogPath exists and not disabled)
    if ($script:LogPath -and -not $NoLogFile) {
        try {
            # Format log entry with timestamp and level
            if ($NoTimestamp) {
                $logEntry = $Message
            } else {
                $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                $logEntry = "[$timestamp] [$($config.LogLevel)] $Message"
            }

            $logEntry | Out-File `
                -FilePath $script:LogPath `
                -Append `
                -Encoding UTF8
        } catch {
            # Avoid infinite recursion - use Write-Verbose directly
            Write-Verbose "Could not write to log file: $($_.Exception.Message)"
        }
    }
}

# Function to print a separator bar
function Write-Bar {
    param(
        [string]$Level = 'Information',
        [int]$Length = 63,
        [string]$Color = $null,
        [switch]$NoTimestamp
    )
    $bar = "=" * $Length
    if ($Color) {
        Write-LogMessage -Message $bar -Level $Level -Color $Color -NoTimestamp:$NoTimestamp
    } else {
        Write-LogMessage -Message $bar -Level $Level -NoTimestamp:$NoTimestamp
    }
}

# Function to print text framed by bars
function Write-FramedText {
    param(
        [string]$Message,
        [string]$Level = 'Information',
        [int]$BarLength = 63,
        [string]$Color = $null,
        [switch]$NoTimestamp,
        [switch]$NoCenter
    )

    # Center the message if NoCenter is not specified
    $displayMessage = $Message
    if (-not $NoCenter) {
        $messageLength = $Message.Trim().Length

        if ($messageLength -lt $BarLength) {
            $totalPadding = $BarLength - $messageLength
            $leftPadding = [Math]::Floor($totalPadding / 2)
            $displayMessage = (' ' * $leftPadding) + $Message.Trim()
        } else {
            $displayMessage = $Message.Trim()
        }
    }

    if ($Color) {
        Write-Bar -Level $Level -Length $BarLength -Color $Color -NoTimestamp:$NoTimestamp
        Write-LogMessage -Message $displayMessage -Level $Level -Color $Color -NoTimestamp:$NoTimestamp
        Write-Bar -Level $Level -Length $BarLength -Color $Color -NoTimestamp:$NoTimestamp
    } else {
        Write-Bar -Level $Level -Length $BarLength -NoTimestamp:$NoTimestamp
        Write-LogMessage -Message $displayMessage -Level $Level -NoTimestamp:$NoTimestamp
        Write-Bar -Level $Level -Length $BarLength -NoTimestamp:$NoTimestamp
    }
}

# Function to write to log file (helper function)
function Write-LogFile {
    param(
        [string[]]$Lines
    )
    if ($script:LogPath) {
        try {
            foreach ($line in $Lines) {
                $line | Out-File `
                    -FilePath $script:LogPath `
                    -Append `
                    -Encoding UTF8
            }
        } catch {
            Write-Warning "Failed to write to log file: $($_.Exception.Message)"
        }
    }
}

# If Action is not provided, prompt the user
if (-not $Action) {
    Write-Information ""
    Write-FramedText -Message "🔅 Lumen Setup Script" -Level "Information" -Color "Cyan"
    Write-Information ""
    Write-LogMessage -Message "Please select an action:" -Level "Information" -Color "Yellow"
    Write-LogMessage -Message "  1. Install Lumen" -Level "Information" -Color "Green"
    Write-LogMessage -Message "  2. Uninstall Lumen" -Level "Information" -Color "Red"
    Write-Information ""

    $validChoice = $false
    while (-not $validChoice) {
        $choice = Read-Host "Enter your choice (1 or 2)"

        switch ($choice) {
            "1" {
                $Action = "install"
                $validChoice = $true
            }
            "2" {
                $Action = "uninstall"
                $validChoice = $true
            }
            default {
                Write-Warning "Invalid choice. Please select 1 or 2."
                Write-Information ""
            }
        }
    }
    Write-Information ""
}

# Check if running as administrator, if not, relaunch with elevation
$currentPrincipal = New-Object `
        Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Warning "This script requires administrator privileges. Relaunching with elevation..."

    # Build the argument list for the elevated process
    $arguments = "-ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`" -Action $Action"
    if ($Silent) {
        $arguments += " -Silent"
    }
    if ($Msi) {
        $arguments += " -Msi"
    }
    if ($ProductCode) {
        $arguments += " -ProductCode `"$ProductCode`""
    }
    if ($TransactionKind) {
        $arguments += " -TransactionKind $TransactionKind"
    }
    if ($InstallVirtualHid) {
        $arguments += " -InstallVirtualHid $InstallVirtualHid"
    }
    if ($InstallVirtualMicrophone) {
        $arguments += " -InstallVirtualMicrophone $InstallVirtualMicrophone"
    }
    if ($InstallVirtualDisplay) {
        $arguments += " -InstallVirtualDisplay $InstallVirtualDisplay"
    }
    if ($RemoveVirtualDisplay) {
        $arguments += " -RemoveVirtualDisplay $RemoveVirtualDisplay"
    }
    $arguments += " -UpgradeOwnedVirtualDisplay $UpgradeOwnedVirtualDisplay"
    if ($UpgradeVddOwnerProduct) {
        $arguments += " -UpgradeVddOwnerProduct `"$UpgradeVddOwnerProduct`""
    }
    if ($IdentityDisposition) {
        $arguments += " -IdentityDisposition $IdentityDisposition"
    }
    try {
        # Relaunch the script with elevation
        $elevatedProcess = Start-Process `
            -FilePath powershell.exe `
            -Verb RunAs `
            -ArgumentList $arguments `
            -Wait `
            -PassThru
        exit $elevatedProcess.ExitCode
    } catch {
        Write-Error "Failed to elevate privileges: $($_.Exception.Message)"
        exit 1
    }
}

# Get the script directory and root directory
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir

# Set up transcript logging
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logDir = Join-Path $env:TEMP "Lumen\logs\$Action"
$LogPath = Join-Path $logDir "${timestamp}.log"

# Ensure the log directory exists
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

# Store LogPath in script scope for logging functions
$script:LogPath = $LogPath

# Products released before scoped MSI transaction data invoked the installed
# script as `-Action uninstall -Msi` during RemoveExistingProducts. When a new
# product has already installed into the shared directory, that legacy action
# must not remove resources now owned by the new product.
$legacyMajorUpgradeUninstall = $Msi -and $Action -eq "uninstall" -and
    [string]::IsNullOrWhiteSpace($ProductCode) -and
    [string]::IsNullOrWhiteSpace($TransactionKind)
if ($legacyMajorUpgradeUninstall) {
    Write-LogMessage `
        -Message "Skipping the unscoped legacy uninstall action during major upgrade." `
        -Level "Information"
    exit 0
}

# Detect separately installed Sunshine products without mutating them. Lumen
# has its own UpgradeCode and service identity, so official Sunshine remains
# under the user's control even when legacy configuration is available to copy.
function Get-LegacySunshineProducts {
    $products = [System.Collections.Generic.List[object]]::new()
    foreach ($registryRoot in @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )) {
        if (-not (Test-Path -LiteralPath $registryRoot)) {
            continue
        }
        foreach ($productKey in @(Get-ChildItem -LiteralPath $registryRoot -ErrorAction SilentlyContinue)) {
            $product = Get-ItemProperty -LiteralPath $productKey.PSPath -ErrorAction SilentlyContinue
            if ($null -ne $product -and $product.DisplayName -like "Sunshine*") {
                $products.Add($product)
            }
        }
    }
    return $products.ToArray()
}

function Copy-LegacySunshineConfigIfNeeded {
    param(
        [object[]]$Products
    )

    $destination = Join-Path $RootDir "config"
    if ((Test-Path -LiteralPath $destination -PathType Container) -and
        @(Get-ChildItem -LiteralPath $destination -Force).Count -ne 0) {
        return
    }

    foreach ($product in $Products) {
        if ([string]::IsNullOrWhiteSpace($product.InstallLocation)) {
            continue
        }
        $legacyConfig = Join-Path ([string]$product.InstallLocation) "config"
        if (-not (Test-Path -LiteralPath $legacyConfig -PathType Container)) {
            continue
        }
        $legacyItems = @(Get-ChildItem -LiteralPath $legacyConfig -Force -Recurse)
        if ($legacyItems | Where-Object {
                $_.Attributes -band [System.IO.FileAttributes]::ReparsePoint
            }) {
            Write-LogMessage `
                -Message "Skipped legacy Sunshine config containing a reparse point: $legacyConfig" `
                -Level "Warning"
            continue
        }
        New-Item -ItemType Directory -Path $destination -Force | Out-Null
        Get-ChildItem -LiteralPath $legacyConfig -Force | Copy-Item `
            -Destination $destination `
            -Recurse `
            -ErrorAction Stop
        Write-LogMessage `
            -Message "Copied legacy Sunshine configuration from $legacyConfig; the source was not modified." `
            -Level "Information"
        return
    }
}

# Function to execute a batch script if it exists
function Invoke-ScriptIfExist {
    param(
        [string]$ScriptPath,
        [string]$Arguments = "",
        [string]$Description = "",
        [string]$Emoji = "🔧"
    )

    if ($Description) {
        Write-LogMessage -Message "$Emoji $Description" -Level "Step"
    }

    if (Test-Path $ScriptPath) {
        Write-LogMessage -Message "Executing: $ScriptPath $Arguments" -Level "Information"

        # Capture output to suppress it from console but log it
        $stdoutFile = [System.IO.Path]::GetTempFileName()
        $stderrFile = [System.IO.Path]::GetTempFileName()

        try {
            if ($Arguments -ne "") {
                $process = Start-Process `
                    -FilePath $ScriptPath `
                    -ArgumentList $Arguments `
                    -Wait `
                    -PassThru `
                    -NoNewWindow `
                    -RedirectStandardOutput $stdoutFile `
                    -RedirectStandardError $stderrFile
            } else {
                $process = Start-Process `
                    -FilePath $ScriptPath `
                    -Wait `
                    -PassThru `
                    -NoNewWindow `
                    -RedirectStandardOutput $stdoutFile `
                    -RedirectStandardError $stderrFile
            }

            # Log and display the output
            if (Test-Path $stdoutFile) {
                $output = Get-Content $stdoutFile -Raw -ErrorAction SilentlyContinue
                if ($output) {
                    # Display output with indentation
                    $output -split "`r?`n" | ForEach-Object {
                        if ($_.Trim()) {
                            Write-LogMessage -Message "  $_" -Level "Information" -Color "DarkGray"
                        }
                    }
                }
            }
            if (Test-Path $stderrFile) {
                $errors = Get-Content $stderrFile -Raw -ErrorAction SilentlyContinue
                if ($errors) {
                    # Display errors with indentation
                    $errors -split "`r?`n" | ForEach-Object {
                        if ($_.Trim()) {
                            Write-LogMessage -Message "  $_" -Level "Warning"
                        }
                    }
                }
            }

            if ($process.ExitCode -ne 0) {
                Write-LogMessage -Message "  ⚠ Script exited with code $($process.ExitCode): $ScriptPath" -Level "Warning"
                return $process.ExitCode
            } else {
                Write-LogMessage -Message "  ✓ Done" -Level "Success"
                return 0
            }
        } finally {
            # Clean up temp files
            if (Test-Path $stdoutFile) {
                Remove-Item $stdoutFile -Force -ErrorAction SilentlyContinue
            }
            if (Test-Path $stderrFile) {
                Remove-Item $stderrFile -Force -ErrorAction SilentlyContinue
            }
        }
    } else {
        Write-LogMessage -Message "  ⓘ Skipped (script not found)" -Level "Information" -Color "DarkGray"
        return 0
    }
}

# Execute only the current Lumen binary. Legacy Sunshine state may be copied,
# but executable identity never crosses product boundaries.
function Invoke-LumenIfExist {
    param(
        [string]$Arguments,
        [string]$Description = "",
        [string]$Emoji = "🔧"
    )

    if ($Description) {
        Write-LogMessage -Message "$Emoji $Description" -Level "Step"
    }

    $HostPath = Join-Path $RootDir "Lumen.exe"

    if (Test-Path $HostPath -PathType Leaf) {
        Write-LogMessage -Message "Executing: $HostPath $Arguments" -Level "Information"

        # Capture output to suppress it from console but log it
        $stdoutFile = [System.IO.Path]::GetTempFileName()
        $stderrFile = [System.IO.Path]::GetTempFileName()

        try {
            $process = Start-Process `
                -FilePath $HostPath `
                -ArgumentList $Arguments `
                -Wait `
                -PassThru `
                -NoNewWindow `
                -RedirectStandardOutput $stdoutFile `
                -RedirectStandardError $stderrFile

            # Log and display the output
            if (Test-Path $stdoutFile) {
                $output = Get-Content $stdoutFile -Raw -ErrorAction SilentlyContinue
                if ($output) {
                    # Display output with indentation
                    $output -split "`r?`n" | ForEach-Object {
                        if ($_.Trim()) {
                            Write-LogMessage -Message "  $_" -Level "Information" -Color "DarkGray"
                        }
                    }
                }
            }
            if (Test-Path $stderrFile) {
                $errors = Get-Content $stderrFile -Raw -ErrorAction SilentlyContinue
                if ($errors) {
                    # Display errors with indentation
                    $errors -split "`r?`n" | ForEach-Object {
                        if ($_.Trim()) {
                            Write-LogMessage -Message "  $_" -Level "Warning"
                        }
                    }
                }
            }

            if ($process.ExitCode -ne 0) {
                Write-LogMessage -Message "  ⚠ Lumen exited with code $($process.ExitCode)" -Level "Warning"
                return $process.ExitCode
            } else {
                Write-LogMessage -Message "  ✓ Done" -Level "Success"
                return 0
            }
        } finally {
            # Clean up temp files
            if (Test-Path $stdoutFile) {
                Remove-Item $stdoutFile -Force -ErrorAction SilentlyContinue
            }
            if (Test-Path $stderrFile) {
                Remove-Item $stderrFile -Force -ErrorAction SilentlyContinue
            }
        }
    } else {
        Write-LogMessage -Message "  ⓘ Skipped (executable not found)" -Level "Information" -Color "DarkGray"
        return 0
    }
}

# Execute an installation script and fail the active transaction when the
# script exists but reports an error. Optional CPack components may omit some
# scripts, so absence remains an intentional no-op.
function Invoke-SetupScript {
    param(
        [string]$ScriptPath,
        [string]$Arguments = "",
        [string]$Description = "",
        [string]$Emoji = "🔧"
    )

    $exitCode = Invoke-ScriptIfExist `
        -ScriptPath $ScriptPath `
        -Arguments $Arguments `
        -Description $Description `
        -Emoji $Emoji
    if ($exitCode -ne 0) {
        throw "$Description failed with exit code $exitCode."
    }
}

# Invoke the required Virtual HID management helper and preserve its output in
# the installer log. Exit code 3010 means the Plug and Play operation succeeded
# but Windows needs a reboot to finish it.
function Invoke-VirtualHidCtl {
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$Arguments,

        [Parameter(Mandatory=$true)]
        [string]$Description,

        [switch]$AllowNotInstalled
    )

    $persistedVirtualHidCtlPath = Join-Path $rollbackDirectory "lumen-vhidctl.exe"
    $installedVirtualHidCtlPath = Join-Path $RootDir "tools\lumen-vhidctl.exe"
    $virtualHidCtlPath = if (Test-Path -LiteralPath $persistedVirtualHidCtlPath -PathType Leaf) {
        $persistedVirtualHidCtlPath
    } else {
        $installedVirtualHidCtlPath
    }
    if (-not (Test-Path $virtualHidCtlPath -PathType Leaf)) {
        throw "Required Virtual HID helper not found: $virtualHidCtlPath"
    }

    Write-LogMessage -Message "⌨️  $Description" -Level "Step"
    Write-LogMessage `
        -Message "Executing: $virtualHidCtlPath $($Arguments -join ' ')" `
        -Level "Information"

    $stdoutFile = [System.IO.Path]::GetTempFileName()
    $stderrFile = [System.IO.Path]::GetTempFileName()

    try {
        $process = Start-Process `
            -FilePath $virtualHidCtlPath `
            -ArgumentList $Arguments `
            -Wait `
            -PassThru `
            -NoNewWindow `
            -RedirectStandardOutput $stdoutFile `
            -RedirectStandardError $stderrFile

        foreach ($outputFile in @($stdoutFile, $stderrFile)) {
            if (Test-Path $outputFile) {
                Get-Content $outputFile -ErrorAction SilentlyContinue | ForEach-Object {
                    if ($_.Trim()) {
                        Write-LogMessage -Message "  $_" -Level "Information" -Color "DarkGray"
                    }
                }
            }
        }

        if ($process.ExitCode -eq 3010) {
            $script:RebootRequired = $true
            Write-LogMessage `
                -Message "  Windows requires a reboot to finish the driver operation." `
                -Level "Warning"
            return $process.ExitCode
        }

        $isExpectedNotInstalled = $AllowNotInstalled -and $process.ExitCode -eq 2
        $isExpectedUnhealthy = $AllowNotInstalled -and $process.ExitCode -eq 4
        if ($process.ExitCode -ne 0 -and -not $isExpectedNotInstalled) {
            if (-not $isExpectedUnhealthy) {
                throw "$Description failed with exit code $($process.ExitCode)."
            }
        }

        if ($process.ExitCode -eq 0) {
            Write-LogMessage -Message "  ✓ Done" -Level "Success"
        } elseif ($isExpectedNotInstalled) {
            Write-LogMessage -Message "  Lumen Virtual HID driver is not installed." -Level "Information"
        } elseif ($isExpectedUnhealthy) {
            Write-LogMessage -Message "  Lumen Virtual HID driver is installed but unhealthy." -Level "Warning"
        }
        return $process.ExitCode
    } finally {
        Remove-Item $stdoutFile, $stderrFile -Force -ErrorAction SilentlyContinue
    }
}

# Invoke the dedicated virtual microphone lifecycle helper. The same stable
# exit-code contract as lumen-vhidctl is used by MSI and standalone installs.
function Invoke-VirtualMicrophoneCtl {
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$Arguments,

        [Parameter(Mandatory=$true)]
        [string]$Description,

        [switch]$AllowNotInstalled
    )

    $persistedVirtualMicrophoneCtlPath = Join-Path `
        $virtualMicrophoneRollbackDirectory `
        "lumen-vmicctl.exe"
    $installedVirtualMicrophoneCtlPath = Join-Path $RootDir "tools\lumen-vmicctl.exe"
    $virtualMicrophoneCtlPath = if (Test-Path -LiteralPath $persistedVirtualMicrophoneCtlPath -PathType Leaf) {
        $persistedVirtualMicrophoneCtlPath
    } else {
        $installedVirtualMicrophoneCtlPath
    }
    if (-not (Test-Path $virtualMicrophoneCtlPath -PathType Leaf)) {
        throw "Required Virtual Microphone helper not found: $virtualMicrophoneCtlPath"
    }

    Write-LogMessage -Message "🎙️  $Description" -Level "Step"
    Write-LogMessage `
        -Message "Executing: $virtualMicrophoneCtlPath $($Arguments -join ' ')" `
        -Level "Information"

    $stdoutFile = [System.IO.Path]::GetTempFileName()
    $stderrFile = [System.IO.Path]::GetTempFileName()
    try {
        $process = Start-Process `
            -FilePath $virtualMicrophoneCtlPath `
            -ArgumentList $Arguments `
            -Wait `
            -PassThru `
            -NoNewWindow `
            -RedirectStandardOutput $stdoutFile `
            -RedirectStandardError $stderrFile

        foreach ($outputFile in @($stdoutFile, $stderrFile)) {
            if (Test-Path $outputFile) {
                Get-Content $outputFile -ErrorAction SilentlyContinue | ForEach-Object {
                    if ($_.Trim()) {
                        Write-LogMessage -Message "  $_" -Level "Information" -Color "DarkGray"
                    }
                }
            }
        }

        if ($process.ExitCode -eq 3010) {
            $script:RebootRequired = $true
            Write-LogMessage `
                -Message "  Windows requires a reboot to finish the driver operation." `
                -Level "Warning"
            return $process.ExitCode
        }

        $isExpectedAbsent = $AllowNotInstalled -and $process.ExitCode -eq 2
        $isExpectedUnhealthy = $AllowNotInstalled -and $process.ExitCode -in @(3, 4)
        if ($process.ExitCode -ne 0 -and -not $isExpectedAbsent -and -not $isExpectedUnhealthy) {
            throw "$Description failed with exit code $($process.ExitCode)."
        }

        if ($process.ExitCode -eq 0) {
            Write-LogMessage -Message "  ✓ Done" -Level "Success"
        } elseif ($isExpectedAbsent) {
            Write-LogMessage -Message "  Lumen Virtual Microphone driver is not installed." -Level "Information"
        } else {
            Write-LogMessage -Message "  Lumen Virtual Microphone driver is installed but not ready." -Level "Warning"
        }
        return $process.ExitCode
    } finally {
        Remove-Item $stdoutFile, $stderrFile -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-VirtualDisplaySetup {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("install", "remove-feature", "uninstall", "rollback", "commit", "resume")]
        [string]$DriverAction
    )

    $persistedDirectory = Join-Path `
        (Join-Path $programDataDirectory "LumenVirtualDisplayInstallerV1") `
        (Join-Path $ProductCode ($TransactionKind.ToLowerInvariant()))
    $persistedScript = Join-Path $persistedDirectory "virtual-display-setup.ps1"
    $installedScript = Join-Path $RootDir "scripts\virtual-display-setup.ps1"
    $scriptPath = if ($DriverAction -in @("rollback", "commit") -and
        (Test-Path -LiteralPath $persistedScript -PathType Leaf)) {
        $persistedScript
    } else {
        $installedScript
    }
    if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
        if ($DriverAction -in @("rollback", "commit")) {
            if (Test-Path -LiteralPath $persistedDirectory -PathType Container) {
                throw "Virtual Display rollback state exists without its persisted helper."
            }
            return 0
        }
        throw "Required Virtual Display setup helper not found: $scriptPath"
    }

    $stdoutFile = [IO.Path]::GetTempFileName()
    $stderrFile = [IO.Path]::GetTempFileName()
    try {
        $arguments = @(
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy", "Bypass",
            "-File", "`"$scriptPath`"",
            "-Action", $DriverAction,
            "-RootDir", "`"$RootDir`"",
            "-ProductCode", "`"$ProductCode`"",
            "-TransactionKind", $TransactionKind,
            "-UpgradeOwnerProductCode", "`"$UpgradeVddOwnerProduct`""
        )
        $process = Start-Process `
            -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
            -ArgumentList $arguments `
            -Wait `
            -PassThru `
            -NoNewWindow `
            -RedirectStandardOutput $stdoutFile `
            -RedirectStandardError $stderrFile
        foreach ($outputFile in @($stdoutFile, $stderrFile)) {
            if (Test-Path -LiteralPath $outputFile) {
                Get-Content -LiteralPath $outputFile -ErrorAction SilentlyContinue | ForEach-Object {
                    if ($_.Trim()) {
                        Write-LogMessage -Message "  $_" -Level "Information" -Color "DarkGray"
                    }
                }
            }
        }
        if ($process.ExitCode -eq 3010) {
            $script:RebootRequired = $true
            return $process.ExitCode
        }
        if ($process.ExitCode -ne 0) {
            throw "Virtual Display $DriverAction failed with exit code $($process.ExitCode)."
        }
        return 0
    } finally {
        Remove-Item $stdoutFile, $stderrFile -Force -ErrorAction SilentlyContinue
    }
}

# Update the machine PATH without routing the value through cmd.exe. The batch
# implementation corrupts values containing cmd metacharacters and reports the
# wrong exit status when no registry write is required.
function Update-SystemPath {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("add", "remove")]
        [string]$Operation
    )

    $managedPaths = @($RootDir, (Join-Path $RootDir "tools"))
    $normalizePath = {
        param([string]$Path)
        if ([string]::IsNullOrWhiteSpace($Path)) {
            return $null
        }
        $expanded = [System.Environment]::ExpandEnvironmentVariables($Path.Trim().Trim('"'))
        return [System.IO.Path]::GetFullPath($expanded).TrimEnd('\')
    }
    $normalizedManagedPaths = @($managedPaths | ForEach-Object { & $normalizePath $_ })
    $pathTarget = [System.EnvironmentVariableTarget]::Machine
    $currentPath = [System.Environment]::GetEnvironmentVariable("Path", $pathTarget)
    $entries = [System.Collections.Generic.List[string]]::new()
    foreach ($entry in @($currentPath -split ";")) {
        $trimmed = $entry.Trim()
        $normalizedEntry = & $normalizePath $trimmed
        if (-not [string]::IsNullOrWhiteSpace($trimmed) -and
            -not ($normalizedManagedPaths | Where-Object { $_ -ieq $normalizedEntry })) {
            $entries.Add($trimmed)
        }
    }
    if ($Operation -eq "add") {
        foreach ($managedPath in $managedPaths) {
            $entries.Add($managedPath)
        }
    }
    $newPath = $entries -join ";"
    if ($newPath -cne $currentPath) {
        [System.Environment]::SetEnvironmentVariable("Path", $newPath, $pathTarget)
        Add-Type -Namespace Lumen -Name NativeEnvironment -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("user32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
public static extern System.IntPtr SendMessageTimeout(
    System.IntPtr hWnd,
    uint Msg,
    System.IntPtr wParam,
    string lParam,
    uint fuFlags,
    uint uTimeout,
    out System.IntPtr lpdwResult);
'@ -ErrorAction SilentlyContinue
        $result = [IntPtr]::Zero
        [void][Lumen.NativeEnvironment]::SendMessageTimeout(
            [IntPtr]0xffff,
            0x001a,
            [IntPtr]::Zero,
            "Environment",
            0x0002,
            5000,
            [ref]$result
        )
        Write-LogMessage -Message "  ✓ Done" -Level "Success"
    } else {
        Write-LogMessage -Message "  No PATH changes were required." -Level "Information"
    }
}

function Get-VirtualHidInfPath {
    $driverDirectory = Join-Path $RootDir "drivers\virtual-hid"
    if (-not (Test-Path $driverDirectory -PathType Container)) {
        throw "Required Virtual HID driver directory not found: $driverDirectory"
    }

    $infFiles = @(Get-ChildItem -Path $driverDirectory -Filter "*.inf" -File)
    if ($infFiles.Count -ne 1) {
        throw "Expected exactly one Virtual HID INF in $driverDirectory; found $($infFiles.Count)."
    }
    return $infFiles[0].FullName
}

function Get-VirtualMicrophoneInfPath {
    $driverDirectory = Join-Path $RootDir "drivers\virtual-microphone"
    if (-not (Test-Path $driverDirectory -PathType Container)) {
        throw "Required Virtual Microphone driver directory not found: $driverDirectory"
    }

    $infFiles = @(Get-ChildItem -Path $driverDirectory -Filter "*.inf" -File)
    if ($infFiles.Count -ne 1) {
        throw "Expected exactly one Virtual Microphone INF in $driverDirectory; found $($infFiles.Count)."
    }
    if (-not (Select-String `
        -LiteralPath $infFiles[0].FullName `
        -Pattern "ROOT\LumenVirtualMicrophone" `
        -SimpleMatch `
        -Quiet)) {
        throw "The bundled Virtual Microphone INF has an unexpected hardware identity."
    }
    return $infFiles[0].FullName
}

function Get-VirtualHidCertificatePath {
    $driverDirectory = Join-Path $RootDir "drivers\virtual-hid"
    if (-not (Test-Path $driverDirectory -PathType Container)) {
        throw "Required Virtual HID driver directory not found: $driverDirectory"
    }

    $certificateFiles = @(Get-ChildItem -Path $driverDirectory -Filter "*.cer" -File)
    if ($certificateFiles.Count -gt 1) {
        throw "Expected at most one bundled Virtual HID certificate in $driverDirectory; found $($certificateFiles.Count)."
    }
    if ($certificateFiles.Count -eq 0) {
        return $null
    }
    return $certificateFiles[0].FullName
}

function Install-VirtualHidCertificate {
    param(
        [Parameter(Mandatory=$true)]
        [string]$CertificatePath
    )

    if ([string]::IsNullOrWhiteSpace($CertificatePath)) {
        return $null
    }

    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
        $CertificatePath
    )
    if ($certificate.Subject -ne $virtualHidCertificateSubject) {
        throw "Only the exact bundled Lumen Virtual HID certificate may be imported."
    }
    Write-LogMessage -Message "Trusting the exact bundled driver signer" -Level "Step"
    foreach ($storeName in @("Root", "TrustedPublisher")) {
        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
            $storeName,
            [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
        )
        try {
            $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            $store.Add($certificate)
        } finally {
            $store.Close()
        }
    }
    return $certificate.Thumbprint
}

function Get-VirtualHidCertificate {
    param(
        [Parameter(Mandatory=$true)]
        [string]$CertificatePath
    )

    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
        $CertificatePath
    )
    if ($certificate.Subject -ne $virtualHidCertificateSubject) {
        throw "The bundled Virtual HID certificate has an unexpected identity."
    }
    return $certificate
}

function Get-BackedUpVirtualHidCertificate {
    param(
        [string]$DriverDirectory = $rollbackDriverDirectory
    )

    $catalogs = @(Get-ChildItem -LiteralPath $DriverDirectory -Filter "*.cat" -File -Recurse)
    if ($catalogs.Count -ne 1) {
        throw "The previous Virtual HID backup does not contain exactly one signed catalog."
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $catalogs[0].FullName
    $certificate = $signature.SignerCertificate
    if ($null -eq $certificate) {
        throw "The previous Virtual HID catalog does not contain a signer certificate."
    }
    if ($certificate.Subject -notin @(
            $virtualHidCertificateSubject,
            "CN=Lumen Virtual HID Development Driver"
        )) {
        throw "The backed-up Virtual HID signer certificate has an unexpected identity."
    }
    return $certificate
}

function Install-BackedUpVirtualHidCertificate {
    param(
        [string]$DriverDirectory = $rollbackDriverDirectory
    )

    $certificate = Get-BackedUpVirtualHidCertificate -DriverDirectory $DriverDirectory
    foreach ($storeName in @("Root", "TrustedPublisher")) {
        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
            $storeName,
            [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
        )
        try {
            $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            $store.Add($certificate)
        } finally {
            $store.Close()
        }
    }
    return $certificate.Thumbprint
}

function Assert-VirtualHidPackageSignature {
    param(
        [Parameter(Mandatory=$false)]
        [AllowNull()]
        [string]$CertificatePath
    )

    $driverDirectory = Join-Path $RootDir "drivers\virtual-hid"
    $driverDllFiles = @(Get-ChildItem -Path $driverDirectory -Filter "*.dll" -File)
    if ($driverDllFiles.Count -ne 1) {
        throw "Expected exactly one Virtual HID UMDF DLL in $driverDirectory; found $($driverDllFiles.Count)."
    }

    $catalogFiles = @(Get-ChildItem -Path $driverDirectory -Filter "*.cat" -File)
    if ($catalogFiles.Count -ne 1) {
        throw "Expected exactly one Virtual HID catalog in $driverDirectory; found $($catalogFiles.Count)."
    }

    $signature = Get-AuthenticodeSignature -LiteralPath $catalogFiles[0].FullName
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
        $null -eq $signature.SignerCertificate) {
        throw "The Virtual HID catalog does not have a valid trusted signature."
    }
    if (-not [string]::IsNullOrWhiteSpace($CertificatePath)) {
        $expectedCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
            $CertificatePath
        )
        if ($signature.SignerCertificate.Thumbprint -ne $expectedCertificate.Thumbprint) {
            throw "The Virtual HID catalog signer does not match the bundled certificate."
        }
    }
    return $signature.SignerCertificate.Thumbprint
}

function Remove-VirtualHidCertificate {
    param(
        [string]$Thumbprint
    )

    if ([string]::IsNullOrWhiteSpace($Thumbprint)) {
        return
    }
    foreach ($storeName in @("Root", "TrustedPublisher")) {
        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
            $storeName,
            [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
        )
        try {
            $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            foreach ($certificate in @($store.Certificates)) {
                if ($certificate.Subject -in @(
                        $virtualHidCertificateSubject,
                        "CN=Lumen Virtual HID Development Driver"
                    ) -and
                    $certificate.Thumbprint -eq $Thumbprint) {
                    $store.Remove($certificate)
                }
            }
        } finally {
            $store.Close()
        }
    }
}

function Get-InstalledVirtualHidSignerThumbprint {
    foreach ($registryPath in @($installerRegistryPath) + $legacyInstallerRegistryPaths) {
        if (Test-Path -LiteralPath $registryPath) {
            $thumbprint = [string](Get-ItemProperty `
                -LiteralPath $registryPath `
                -Name "SignerThumbprint" `
                -ErrorAction SilentlyContinue).SignerThumbprint
            if (-not [string]::IsNullOrWhiteSpace($thumbprint)) {
                return $thumbprint
            }
        }
    }
    return $null
}

function Set-InstalledVirtualHidSignerThumbprint {
    param(
        [AllowNull()]
        [string]$Thumbprint
    )

    if ([string]::IsNullOrWhiteSpace($Thumbprint)) {
        foreach ($registryPath in @($installerRegistryPath) + $legacyInstallerRegistryPaths) {
            Remove-ItemProperty `
                -LiteralPath $registryPath `
                -Name "SignerThumbprint" `
                -ErrorAction SilentlyContinue
        }
        return
    }
    New-Item -Path $installerRegistryPath -Force | Out-Null
    Set-ItemProperty `
        -LiteralPath $installerRegistryPath `
        -Name "SignerThumbprint" `
        -Type String `
        -Value $Thumbprint `
        -ErrorAction Stop
    foreach ($registryPath in $legacyInstallerRegistryPaths) {
        if (Test-Path -LiteralPath $registryPath) {
            Remove-ItemProperty `
                -LiteralPath $registryPath `
                -Name "SignerThumbprint" `
                -ErrorAction SilentlyContinue
        }
    }
}

$programDataDirectory = [System.Environment]::GetFolderPath(
    [System.Environment+SpecialFolder]::CommonApplicationData
)
$installerRegistryPath = "HKLM:\SOFTWARE\simonfalke\Lumen\VirtualHid"
$legacyInstallerRegistryPaths = @(
    "HKLM:\SOFTWARE\simonfalke-01\Lumen\VirtualHid",
    "HKLM:\SOFTWARE\LizardByte\Lumen\VirtualHid"
)

function ConvertTo-NormalizedProductCode {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Value
    )

    $parsed = [Guid]::Empty
    if (-not [Guid]::TryParseExact($Value, "B", [ref]$parsed)) {
        throw "ProductCode must be an uppercase-braced GUID: $Value"
    }
    $normalized = $parsed.ToString("B").ToUpperInvariant()
    if ($Value -cne $normalized) {
        throw "ProductCode is not normalized: $Value"
    }
    return $normalized
}

if ($Msi -or $ProductCode -or $Action -in @("rollback", "commit", "resume")) {
    if ([string]::IsNullOrWhiteSpace($ProductCode)) {
        throw "ProductCode is required for this installer action."
    }
    if ([string]::IsNullOrWhiteSpace($TransactionKind)) {
        throw "TransactionKind is required for this installer action."
    }
    $ProductCode = ConvertTo-NormalizedProductCode -Value $ProductCode
    if (-not [string]::IsNullOrWhiteSpace($UpgradeVddOwnerProduct)) {
        $UpgradeVddOwnerProduct = ConvertTo-NormalizedProductCode -Value $UpgradeVddOwnerProduct
    }
} else {
    $ProductCode = "{00000000-0000-0000-0000-000000000000}"
    if ([string]::IsNullOrWhiteSpace($TransactionKind)) {
        $TransactionKind = if ($Action -eq "uninstall") { "uninstall" } else { "install" }
    }
}
if ($Action -in @("install", "uninstall") -and $TransactionKind -ne $Action) {
    throw "TransactionKind '$TransactionKind' does not match action '$Action'."
}
if ([string]::IsNullOrWhiteSpace($IdentityDisposition)) {
    $IdentityDisposition = if ($TransactionKind -eq "uninstall") { "remove" } else { "preserve" }
}
if (($TransactionKind -eq "uninstall" -and $IdentityDisposition -ne "remove") -or
    ($TransactionKind -eq "install" -and $IdentityDisposition -ne "preserve")) {
    throw "Identity disposition '$IdentityDisposition' does not match transaction '$TransactionKind'."
}
$upgradeOwnerProvided = -not [string]::IsNullOrWhiteSpace($UpgradeVddOwnerProduct)
$upgradeOwnerRequired = $Msi -and $TransactionKind -eq "install" -and
    $Action -in @("install", "rollback", "commit") -and
    $UpgradeOwnedVirtualDisplay -eq "1"
if ($upgradeOwnerProvided -and -not $upgradeOwnerRequired) {
    throw "UpgradeVddOwnerProduct is valid only for a verified related MSI ownership transaction."
}
if ($upgradeOwnerRequired -and -not $upgradeOwnerProvided) {
    throw "A verified related MSI VDD owner ProductCode is required for ownership transfer."
}
$virtualHidSelected = if ([string]::IsNullOrWhiteSpace($InstallVirtualHid)) {
    $true
} else {
    $InstallVirtualHid -eq "1"
}
$virtualMicrophoneSelected = if ([string]::IsNullOrWhiteSpace($InstallVirtualMicrophone)) {
    $false
} else {
    $InstallVirtualMicrophone -eq "1"
}
$virtualDisplaySelected = if ([string]::IsNullOrWhiteSpace($InstallVirtualDisplay)) {
    Test-Path -LiteralPath (Join-Path $RootDir "drivers\virtual-display\LumenVirtualDisplay.inf") `
        -PathType Leaf
} else {
    $InstallVirtualDisplay -eq "1"
}
$virtualDisplayRemoveSelected = -not [string]::IsNullOrWhiteSpace($RemoveVirtualDisplay) -and
    $RemoveVirtualDisplay -eq "1"
$upgradeOwnedVirtualDisplaySelected = $Msi -and $Action -eq "install" -and
    $UpgradeOwnedVirtualDisplay -eq "1" -and -not $virtualDisplaySelected
$virtualDisplayRemoveSelected = $virtualDisplayRemoveSelected -or
    $upgradeOwnedVirtualDisplaySelected
$virtualDisplayTransactionSelected = $virtualDisplaySelected -or $virtualDisplayRemoveSelected

$rollbackRootDirectory = Join-Path $programDataDirectory "LumenVirtualHidInstallerV2"
$rollbackProductDirectory = Join-Path $rollbackRootDirectory $ProductCode
$rollbackDirectory = Join-Path $rollbackProductDirectory $TransactionKind.ToLowerInvariant()
$rollbackStatePath = Join-Path $rollbackDirectory "virtual-hid-rollback.json"
$rollbackDriverDirectory = Join-Path $rollbackDirectory "virtual-hid-driver"
$rollbackScriptPath = Join-Path $rollbackDirectory "lumen-setup.ps1"
$protectedIdentityRoot = Join-Path $RootDir "config\credentials"
$protectedIdentityBackupDirectory = Join-Path $rollbackDirectory "protocol-v3-identity"
$protectedIdentityRollbackStatePath = Join-Path `
    $rollbackDirectory `
    "protocol-v3-identity-rollback.json"
$protectedIdentityRelativePaths = @(
    "protocol_v3_identity.bin",
    "protocol_v3_identity.journal"
)
$virtualMicrophoneRollbackRootDirectory = Join-Path $programDataDirectory "LumenVirtualMicrophoneInstallerV1"
$virtualMicrophoneRollbackProductDirectory = Join-Path `
    $virtualMicrophoneRollbackRootDirectory `
    $ProductCode
$virtualMicrophoneRollbackDirectory = Join-Path `
    $virtualMicrophoneRollbackProductDirectory `
    $TransactionKind.ToLowerInvariant()
$virtualMicrophoneRollbackStatePath = Join-Path `
    $virtualMicrophoneRollbackDirectory `
    "virtual-microphone-rollback.json"
$virtualMicrophoneRollbackDriverDirectory = Join-Path `
    $virtualMicrophoneRollbackDirectory `
    "virtual-microphone-driver"
$virtualMicrophoneRollbackScriptPath = Join-Path `
    $virtualMicrophoneRollbackDirectory `
    "lumen-setup.ps1"
$script:RebootRequired = $false

function Set-PendingDriverRebootMarker {
    $productToken = $ProductCode.Trim("{}").Replace("-", "")
    if ($productToken -cnotmatch '^[0-9A-F]{32}$') {
        throw "Cannot persist a reboot marker for an invalid ProductCode."
    }
    $marker = "HKLM:\SOFTWARE\Lumen\Installer\PendingReboot\$productToken\$TransactionKind"
    if (-not (Test-Path -LiteralPath $marker -PathType Container)) {
        New-Item -Path $marker -Force | Out-Null
    }
    New-ItemProperty `
        -LiteralPath $marker `
        -Name "Pending" `
        -PropertyType DWord `
        -Value 1 `
        -Force | Out-Null
}

function Clear-PendingDriverRebootMarker {
    $productToken = $ProductCode.Trim("{}").Replace("-", "")
    $marker = "HKLM:\SOFTWARE\Lumen\Installer\PendingReboot\$productToken\$TransactionKind"
    if (Test-Path -LiteralPath $marker -PathType Container) {
        Remove-Item -LiteralPath $marker -Recurse -Force
    }
}

function Get-InstallerBootIdentifier {
    $operatingSystem = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    return $operatingSystem.LastBootUpTime.ToUniversalTime().Ticks.ToString(
        [Globalization.CultureInfo]::InvariantCulture)
}

function Get-DriverResumeTaskName {
    $productToken = $ProductCode.Trim("{}").Replace("-", "")
    return "Lumen Driver Resume $productToken $TransactionKind"
}

function Register-DriverResumeTask {
    $resumeScript = $null
    if (Test-Path -LiteralPath $rollbackStatePath -PathType Leaf) {
        $hidState = Read-RollbackState
        if ([bool]$hidState.DriverPendingReboot) {
            $resumeScript = $rollbackScriptPath
        }
    }
    if ($null -eq $resumeScript -and
        (Test-Path -LiteralPath $virtualMicrophoneRollbackStatePath -PathType Leaf)) {
        $microphoneState = Read-VirtualMicrophoneRollbackState
        if ([bool]$microphoneState.DriverPendingReboot) {
            $resumeScript = $virtualMicrophoneRollbackScriptPath
        }
    }
    if ($null -eq $resumeScript) {
        return
    }
    if (-not (Test-Path -LiteralPath $resumeScript -PathType Leaf)) {
        throw "The persisted driver resume script is missing."
    }
    $powerShell = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
    $arguments = @(
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy", "Bypass",
        "-File", ('"{0}"' -f $resumeScript),
        "-Action", "resume",
        "-Silent",
        "-ProductCode", ('"{0}"' -f $ProductCode),
        "-TransactionKind", $TransactionKind,
        "-InstallVirtualHid", $(if ($virtualHidSelected) { "1" } else { "0" }),
        "-InstallVirtualMicrophone", $(if ($virtualMicrophoneSelected) { "1" } else { "0" }),
        "-InstallVirtualDisplay", $(if ($virtualDisplaySelected) { "1" } else { "0" }),
        "-RemoveVirtualDisplay", $(if ($virtualDisplayRemoveSelected) { "1" } else { "0" }),
        "-UpgradeOwnedVirtualDisplay", $(if ($upgradeOwnedVirtualDisplaySelected) { "1" } else { "0" }),
        "-IdentityDisposition", $IdentityDisposition
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
        -TaskName (Get-DriverResumeTaskName) `
        -Action $action `
        -Trigger $trigger `
        -Principal $principal `
        -Settings $settings `
        -Force | Out-Null
}

function Unregister-DriverResumeTask {
    $taskName = Get-DriverResumeTaskName
    if ($null -ne (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    }
}

function New-InstallRollbackDirectoryAcl {
    $systemSid = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-18")
    $administratorsSid = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-32-544")
    $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `
        [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $acl = [System.Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($administratorsSid)
    foreach ($sid in @($systemSid, $administratorsSid)) {
        $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        ))
    }
    return $acl
}

function Assert-InstallRollbackDirectorySecure {
    param(
        [string]$Path = $rollbackDirectory
    )

    $directory = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not $directory.PSIsContainer -or
        ($directory.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        throw "Installer rollback path is not a physical directory: $Path"
    }

    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    if (-not $acl.AreAccessRulesProtected) {
        throw "Installer rollback directory inherits access rules: $Path"
    }

    $expectedSids = @("S-1-5-18", "S-1-5-32-544")
    $fullControlSids = @{}
    $requiredInheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `
        [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($rule in $acl.Access) {
        $ruleSid = $rule.IdentityReference.Translate(
            [System.Security.Principal.SecurityIdentifier]
        ).Value
        if ($rule.IsInherited -or
            $rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
            $expectedSids -notcontains $ruleSid) {
            throw "Installer rollback directory has an unexpected access rule for $ruleSid."
        }
        $fullControl = [System.Security.AccessControl.FileSystemRights]::FullControl
        if (($rule.FileSystemRights -band $fullControl) -eq $fullControl -and
            ($rule.InheritanceFlags -band $requiredInheritance) -eq $requiredInheritance) {
            $fullControlSids[$ruleSid] = $true
        }
    }
    foreach ($sid in $expectedSids) {
        if (-not $fullControlSids.ContainsKey($sid)) {
            throw "Installer rollback directory does not grant full control to $sid."
        }
    }

    $ownerSid = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if ($expectedSids -notcontains $ownerSid) {
        throw "Installer rollback directory has an unexpected owner: $ownerSid"
    }
}

function Initialize-InstallRollbackDirectory {
    $protectedAcl = New-InstallRollbackDirectoryAcl
    foreach ($directoryPath in @(
        $rollbackRootDirectory,
        $rollbackProductDirectory,
        $rollbackDirectory
    )) {
        if (-not (Test-Path -LiteralPath $directoryPath)) {
            try {
                [System.IO.Directory]::CreateDirectory($directoryPath, $protectedAcl) | Out-Null
            } catch [System.Management.Automation.MethodException] {
                throw "Atomic protected rollback-directory creation is unavailable on this Windows runtime."
            }
        }
        Assert-InstallRollbackDirectorySecure -Path $directoryPath
    }
}

function Assert-NoPendingRollbackTransaction {
    if ((Test-Path -LiteralPath $rollbackStatePath) -or
        (Test-Path -LiteralPath $rollbackDriverDirectory) -or
        (Test-Path -LiteralPath $rollbackScriptPath)) {
        throw "A pending Virtual HID installer rollback transaction must be resolved before continuing."
    }
}

function Get-ProtectedIdentityAclSddl {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )

    $sections = [System.Security.AccessControl.AccessControlSections]::Owner -bor
        [System.Security.AccessControl.AccessControlSections]::Group -bor
        [System.Security.AccessControl.AccessControlSections]::Access
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    return $acl.GetSecurityDescriptorSddlForm($sections)
}

function Get-ProtectedIdentitySha256 {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
}

function Assert-ProtectedIdentityRootSafe {
    param(
        [Parameter(Mandatory=$true)]
        [string]$InstallRoot,
        [Parameter(Mandatory=$true)]
        [string]$IdentityRoot
    )

    $fullInstallRoot = [System.IO.Path]::GetFullPath($InstallRoot)
    $fullIdentityRoot = [System.IO.Path]::GetFullPath($IdentityRoot)
    $expectedIdentityRoot = [System.IO.Path]::GetFullPath(
        (Join-Path $fullInstallRoot "config\credentials")
    )
    if (-not $fullIdentityRoot.Equals(
        $expectedIdentityRoot,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Protected identity root is outside the exact Lumen configuration directory."
    }

    foreach ($directoryPath in @(
        $fullInstallRoot,
        (Join-Path $fullInstallRoot "config"),
        $fullIdentityRoot
    )) {
        if (-not (Test-Path -LiteralPath $directoryPath)) {
            continue
        }
        $directory = Get-Item -LiteralPath $directoryPath -Force -ErrorAction Stop
        if (-not $directory.PSIsContainer -or
            ($directory.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
            throw "Protected identity path contains a non-directory or reparse point: $directoryPath"
        }
    }
}

function Assert-ProtectedIdentityFileMatches {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [Parameter(Mandatory=$true)]
        [psobject]$Record,
        [switch]$VerifyAcl
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Protected identity file is missing: $Path"
    }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        throw "Protected identity file is a reparse point: $Path"
    }
    if ([int64]$item.Length -ne [int64]$Record.Length -or
        (Get-ProtectedIdentitySha256 -Path $Path) -cne [string]$Record.Sha256) {
        throw "Protected identity file bytes do not match the exact transaction snapshot: $Path"
    }
    if ($VerifyAcl -and
        (Get-ProtectedIdentityAclSddl -Path $Path) -cne [string]$Record.AclSddl) {
        throw "Protected identity file ACL metadata does not match the exact transaction snapshot: $Path"
    }
}

function Save-ProtectedIdentityRollbackState {
    param(
        [Parameter(Mandatory=$true)]
        [psobject]$State
    )

    $pendingPath = Join-Path $rollbackDirectory "protocol-v3-identity-rollback.pending"
    $State | ConvertTo-Json -Depth 6 | Set-Content `
        -LiteralPath $pendingPath `
        -Encoding UTF8 `
        -ErrorAction Stop
    Move-Item `
        -LiteralPath $pendingPath `
        -Destination $protectedIdentityRollbackStatePath `
        -Force `
        -ErrorAction Stop
}

function Read-ProtectedIdentityRollbackState {
    $state = Get-Content `
        -LiteralPath $protectedIdentityRollbackStatePath `
        -Raw `
        -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ([int]$state.Schema -ne 1 -or
        [string]$state.OwnerProductCode -cne $ProductCode -or
        [string]$state.TransactionKind -cne "uninstall" -or
        [string]$state.Disposition -cne "remove") {
        throw "Protected identity rollback state has an invalid owner or schema."
    }

    Assert-ProtectedIdentityRootSafe `
        -InstallRoot ([string]$state.InstallRoot) `
        -IdentityRoot ([string]$state.IdentityRoot)
    $records = @($state.Items)
    if ($records.Count -ne $protectedIdentityRelativePaths.Count) {
        throw "Protected identity rollback state has an invalid file count."
    }
    for ($index = 0; $index -lt $protectedIdentityRelativePaths.Count; $index++) {
        $record = $records[$index]
        $expectedBackup = "identity-$index.backup"
        if ([string]$record.RelativePath -cne $protectedIdentityRelativePaths[$index] -or
            [string]$record.BackupFile -cne $expectedBackup) {
            throw "Protected identity rollback state contains an unexpected path."
        }
    }
    return $state
}

function Start-ProtectedIdentityUninstallTransaction {
    if ($IdentityDisposition -eq "preserve") {
        Write-LogMessage `
            -Message "Preserving the protocol-v3 identity for install, repair, feature change, or related upgrade." `
            -Level "Information"
        return $false
    }
    if ((Test-Path -LiteralPath $protectedIdentityRollbackStatePath) -or
        (Test-Path -LiteralPath $protectedIdentityBackupDirectory)) {
        throw "A pending protected identity uninstall transaction must be resolved first."
    }

    Assert-InstallRollbackDirectorySecure
    Assert-ProtectedIdentityRootSafe -InstallRoot $RootDir -IdentityRoot $protectedIdentityRoot
    New-Item `
        -ItemType Directory `
        -Path $protectedIdentityBackupDirectory `
        -Force `
        -ErrorAction Stop | Out-Null

    $records = [System.Collections.Generic.List[object]]::new()
    for ($index = 0; $index -lt $protectedIdentityRelativePaths.Count; $index++) {
        $relativePath = $protectedIdentityRelativePaths[$index]
        $sourcePath = Join-Path $protectedIdentityRoot $relativePath
        $backupFile = "identity-$index.backup"
        $backupPath = Join-Path $protectedIdentityBackupDirectory $backupFile
        if (Test-Path -LiteralPath $sourcePath) {
            if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
                throw "Protected identity path is not a file: $sourcePath"
            }
            $sourceItem = Get-Item -LiteralPath $sourcePath -Force -ErrorAction Stop
            if ($sourceItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                throw "Protected identity path is a reparse point: $sourcePath"
            }
            [System.IO.File]::WriteAllBytes(
                $backupPath,
                [System.IO.File]::ReadAllBytes($sourcePath)
            )
            $record = [pscustomobject][ordered]@{
                RelativePath = $relativePath
                BackupFile = $backupFile
                Present = $true
                Length = [int64]$sourceItem.Length
                Sha256 = Get-ProtectedIdentitySha256 -Path $sourcePath
                AclSddl = Get-ProtectedIdentityAclSddl -Path $sourcePath
            }
            Assert-ProtectedIdentityFileMatches -Path $backupPath -Record $record
        } else {
            $record = [pscustomobject][ordered]@{
                RelativePath = $relativePath
                BackupFile = $backupFile
                Present = $false
                Length = [int64]0
                Sha256 = $null
                AclSddl = $null
            }
        }
        $records.Add($record) | Out-Null
    }

    $state = [pscustomobject][ordered]@{
        Schema = 1
        OwnerProductCode = $ProductCode
        TransactionKind = "uninstall"
        Disposition = "remove"
        InstallRoot = [System.IO.Path]::GetFullPath($RootDir)
        IdentityRoot = [System.IO.Path]::GetFullPath($protectedIdentityRoot)
        RemovalComplete = $false
        RollbackComplete = $false
        Committed = $false
        Items = $records.ToArray()
    }
    Save-ProtectedIdentityRollbackState -State $state
    Write-LogMessage -Message "Backed up the exact protected protocol-v3 identity state." -Level "Success"
    return $true
}

function Assert-ProtectedIdentityRemoved {
    param(
        [Parameter(Mandatory=$true)]
        [psobject]$State
    )

    foreach ($record in @($State.Items)) {
        $path = Join-Path ([string]$State.IdentityRoot) ([string]$record.RelativePath)
        if (Test-Path -LiteralPath $path) {
            throw "Full uninstall did not remove protected identity state: $path"
        }
    }
}

function Invoke-ProtectedIdentityRemoval {
    if ($IdentityDisposition -ne "remove") {
        return $false
    }
    $state = Read-ProtectedIdentityRollbackState
    foreach ($record in @($state.Items)) {
        $path = Join-Path ([string]$state.IdentityRoot) ([string]$record.RelativePath)
        if ([bool]$record.Present) {
            Assert-ProtectedIdentityFileMatches -Path $path -Record $record -VerifyAcl
        } elseif (Test-Path -LiteralPath $path) {
            throw "Protected identity state appeared after the uninstall snapshot: $path"
        }
    }
    foreach ($record in @($state.Items)) {
        $path = Join-Path ([string]$state.IdentityRoot) ([string]$record.RelativePath)
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Force -ErrorAction Stop
        }
    }
    Assert-ProtectedIdentityRemoved -State $state
    $state.RemovalComplete = $true
    Save-ProtectedIdentityRollbackState -State $state
    Write-LogMessage -Message "Removed and verified the protected protocol-v3 identity state." -Level "Success"
    return $true
}

function Invoke-ProtectedIdentityRollback {
    if (-not (Test-Path -LiteralPath $protectedIdentityRollbackStatePath -PathType Leaf)) {
        return $false
    }
    $state = Read-ProtectedIdentityRollbackState
    if ([bool]$state.Committed) {
        Assert-ProtectedIdentityRemoved -State $state
        return $false
    }

    $hasPresentFile = @($state.Items | Where-Object { [bool]$_.Present }).Count -ne 0
    if ($hasPresentFile -and -not (Test-Path -LiteralPath ([string]$state.IdentityRoot))) {
        New-Item `
            -ItemType Directory `
            -Path ([string]$state.IdentityRoot) `
            -Force `
            -ErrorAction Stop | Out-Null
    }
    Assert-ProtectedIdentityRootSafe `
        -InstallRoot ([string]$state.InstallRoot) `
        -IdentityRoot ([string]$state.IdentityRoot)

    foreach ($record in @($state.Items)) {
        $destination = Join-Path ([string]$state.IdentityRoot) ([string]$record.RelativePath)
        if (-not [bool]$record.Present) {
            if (Test-Path -LiteralPath $destination) {
                $unexpected = Get-Item -LiteralPath $destination -Force -ErrorAction Stop
                if ($unexpected.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                    throw "Refusing to remove a reparse point during protected identity rollback."
                }
                Remove-Item -LiteralPath $destination -Force -ErrorAction Stop
            }
            continue
        }

        $backupPath = Join-Path $protectedIdentityBackupDirectory ([string]$record.BackupFile)
        Assert-ProtectedIdentityFileMatches -Path $backupPath -Record $record
        $pendingRestore = "$destination.restore-pending"
        if (Test-Path -LiteralPath $pendingRestore) {
            $pendingItem = Get-Item -LiteralPath $pendingRestore -Force -ErrorAction Stop
            if ($pendingItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                throw "Refusing to replace a reparse-point identity restore file."
            }
            Remove-Item -LiteralPath $pendingRestore -Force -ErrorAction Stop
        }
        [System.IO.File]::WriteAllBytes(
            $pendingRestore,
            [System.IO.File]::ReadAllBytes($backupPath)
        )
        $sections = [System.Security.AccessControl.AccessControlSections]::Owner -bor
            [System.Security.AccessControl.AccessControlSections]::Group -bor
            [System.Security.AccessControl.AccessControlSections]::Access
        $restoredAcl = [System.Security.AccessControl.FileSecurity]::new()
        $restoredAcl.SetSecurityDescriptorSddlForm(
            [string]$record.AclSddl,
            $sections
        )
        Set-Acl -LiteralPath $pendingRestore -AclObject $restoredAcl -ErrorAction Stop
        Assert-ProtectedIdentityFileMatches `
            -Path $pendingRestore `
            -Record $record `
            -VerifyAcl
        Move-Item `
            -LiteralPath $pendingRestore `
            -Destination $destination `
            -Force `
            -ErrorAction Stop
        Assert-ProtectedIdentityFileMatches -Path $destination -Record $record -VerifyAcl
    }
    $state.RollbackComplete = $true
    $state.RemovalComplete = $false
    Save-ProtectedIdentityRollbackState -State $state
    Write-LogMessage `
        -Message "Restored exact protected identity bytes and ACL metadata during rollback." `
        -Level "Success"
    return $true
}

function Invoke-ProtectedIdentityCommit {
    if (-not (Test-Path -LiteralPath $protectedIdentityRollbackStatePath -PathType Leaf)) {
        return $false
    }
    $state = Read-ProtectedIdentityRollbackState
    if (-not [bool]$state.RemovalComplete) {
        throw "Protected identity uninstall cannot commit before verified removal."
    }
    Assert-ProtectedIdentityRemoved -State $state
    if (-not [bool]$state.Committed) {
        $state.Committed = $true
        Save-ProtectedIdentityRollbackState -State $state
    }
    return $true
}

function Get-ServiceSnapshot {
    param(
        [string]$Name = "LumenService"
    )

    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        return @{
            Present = $false
            Running = $false
            StartMode = $null
            DelayedAutoStart = $null
        }
    }
    $serviceConfiguration = Get-CimInstance `
        -ClassName Win32_Service `
        -Filter "Name='$Name'" `
        -ErrorAction Stop
    $delayedAutoStart = $false
    if ($serviceConfiguration.StartMode -eq "Auto") {
        $serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
        $delayedAutoStart = (Get-ItemProperty `
            -LiteralPath $serviceKey `
            -Name DelayedAutoStart `
            -ErrorAction SilentlyContinue).DelayedAutoStart -eq 1
    }
    return @{
        Present = $true
        Running = $service.Status -eq "Running"
        StartMode = [string]$serviceConfiguration.StartMode
        DelayedAutoStart = $delayedAutoStart
    }
}

function Restore-ServiceSnapshot {
    param(
        [Parameter(Mandatory=$true)]
        [string]$StartMode,
        [Nullable[bool]]$DelayedAutoStart,
        [bool]$Running
    )

    $startArgument = switch ($StartMode) {
        "Auto" { if ($DelayedAutoStart -eq $true) { "delayed-auto" } else { "auto" } }
        "Manual" { "demand" }
        "Disabled" { "disabled" }
        default { throw "Unsupported saved service start mode: $StartMode" }
    }
    $scPath = Join-Path $env:SystemRoot "System32\sc.exe"
    $output = & $scPath config LumenService start= $startArgument 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Restoring the Lumen service start mode failed: $($output -join ' ')"
    }
    $service = Get-Service -Name "LumenService" -ErrorAction Stop
    if ($Running) {
        if ($StartMode -eq "Disabled") {
            throw "Saved service state is internally inconsistent: disabled and running."
        }
        if ($service.Status -ne "Running") {
            Start-Service -Name "LumenService" -ErrorAction Stop
        }
        $service.WaitForStatus("Running", [TimeSpan]::FromSeconds(30))
    } else {
        if ($service.Status -ne "Stopped") {
            Stop-Service -Name "LumenService" -Force -ErrorAction Stop
        }
        $service.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
    }
}

function Remove-InstallRollbackArtifacts {
    if (-not (Test-Path -LiteralPath $rollbackDirectory)) {
        return
    }
    Assert-InstallRollbackDirectorySecure
    $leaf = Get-Item -LiteralPath $rollbackDirectory -Force -ErrorAction Stop
    if ($leaf.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        throw "Refusing to commit a reparse-point transaction leaf: $rollbackDirectory"
    }
    Remove-Item -LiteralPath $rollbackDirectory -Recurse -Force -ErrorAction Stop

    foreach ($parent in @($rollbackProductDirectory, $rollbackRootDirectory)) {
        if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
            continue
        }
        Assert-InstallRollbackDirectorySecure -Path $parent
        if (@(Get-ChildItem -LiteralPath $parent -Force -ErrorAction Stop).Count -ne 0) {
            break
        }
        Remove-Item -LiteralPath $parent -Force -ErrorAction Stop
    }
}

function Get-InstalledVirtualHidInfName {
    $devices = @(
        Get-CimInstance Win32_PnPEntity -ErrorAction Stop | Where-Object {
            @($_.HardwareID) -contains "ROOT\LumenVirtualHid"
        }
    )
    if ($devices.Count -ne 1) {
        throw "Expected exactly one active Lumen Virtual HID device; found $($devices.Count)."
    }

    $driverInfProperty = Get-PnpDeviceProperty `
        -InstanceId $devices[0].PNPDeviceID `
        -KeyName "DEVPKEY_Device_DriverInfPath" `
        -ErrorAction Stop
    $driverInfName = [string]$driverInfProperty.Data
    if ($driverInfName -notmatch '^oem\d+\.inf$') {
        throw "Active Lumen Virtual HID device reported an invalid driver INF path: $driverInfName"
    }
    return $driverInfName
}

function Export-VirtualHidDriverBackup {
    param(
        [Parameter(Mandatory=$true)]
        [string]$PublishedInfName
    )

    if (Test-Path -LiteralPath $rollbackDriverDirectory) {
        Remove-Item -LiteralPath $rollbackDriverDirectory -Recurse -Force -ErrorAction Stop
    }
    New-Item -ItemType Directory -Path $rollbackDriverDirectory -Force | Out-Null

    $pnpUtilPath = Join-Path $env:SystemRoot "System32\pnputil.exe"
    if (-not (Test-Path $pnpUtilPath -PathType Leaf)) {
        throw "Required driver package utility not found: $pnpUtilPath"
    }

    Write-LogMessage -Message "Backing up the active Lumen Virtual HID driver" -Level "Step"
    Write-LogMessage `
        -Message "Executing: $pnpUtilPath /export-driver $PublishedInfName `"$rollbackDriverDirectory`"" `
        -Level "Information"

    $output = & $pnpUtilPath /export-driver $PublishedInfName $rollbackDriverDirectory 2>&1
    $exitCode = $LASTEXITCODE
    $output | ForEach-Object {
        if ($_ -and $_.ToString().Trim()) {
            Write-LogMessage -Message "  $_" -Level "Information" -Color "DarkGray"
        }
    }
    if ($exitCode -ne 0) {
        Remove-Item $rollbackDriverDirectory -Recurse -Force -ErrorAction SilentlyContinue
        throw "Backing up the active Lumen Virtual HID driver failed with exit code $exitCode."
    }

    $exportedInfFiles = @(
        Get-ChildItem -Path $rollbackDriverDirectory -Filter "*.inf" -File -Recurse | Where-Object {
            Select-String -Path $_.FullName -Pattern "ROOT\LumenVirtualHid" -SimpleMatch -Quiet
        }
    )
    if ($exportedInfFiles.Count -ne 1) {
        Remove-Item $rollbackDriverDirectory -Recurse -Force -ErrorAction SilentlyContinue
        throw "Expected exactly one exported Lumen Virtual HID INF; found $($exportedInfFiles.Count)."
    }

    Write-LogMessage -Message "  Driver backup created." -Level "Success"
    return $exportedInfFiles[0].FullName
}

function Save-RollbackState {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("Install", "Uninstall")]
        [string]$TransactionKind,
        [bool]$DriverWasPresent,
        [bool]$ServiceWasPresent,
        [bool]$ServiceWasRunning,
        [AllowNull()]
        [string]$ServiceStartMode,
        [AllowNull()]
        [Nullable[bool]]$ServiceDelayedAutoStart,
        [AllowNull()]
        [string]$BackedUpDriverInfPath,
        [AllowNull()]
        [string]$DriverSignerThumbprint,
        [AllowNull()]
        [string]$PreviousDriverSignerThumbprint,
        [bool]$DriverRollbackComplete = $false,
        [bool]$ServiceRollbackComplete = $false,
        [bool]$DriverPendingReboot = $false,
        [AllowNull()]
        [string]$PendingBootIdentifier = $null
    )

    $state = @{
        Schema = 2
        OwnerProductCode = $ProductCode
        TransactionKind = $TransactionKind.ToLowerInvariant()
        DriverWasPresent = $DriverWasPresent
        ServiceWasPresent = $ServiceWasPresent
        ServiceWasRunning = $ServiceWasRunning
        ServiceStartMode = $ServiceStartMode
        ServiceDelayedAutoStart = $ServiceDelayedAutoStart
        BackedUpDriverInfPath = $BackedUpDriverInfPath
        DriverSignerThumbprint = $DriverSignerThumbprint
        PreviousDriverSignerThumbprint = $PreviousDriverSignerThumbprint
        Committed = $false
        DriverRollbackComplete = $DriverRollbackComplete
        ServiceRollbackComplete = $ServiceRollbackComplete
        DriverPendingReboot = $DriverPendingReboot
        PendingBootIdentifier = $PendingBootIdentifier
    }
    $temporaryStatePath = Join-Path $rollbackDirectory "virtual-hid-rollback.pending"
    $state | ConvertTo-Json | Set-Content `
        -LiteralPath $temporaryStatePath `
        -Encoding UTF8 `
        -ErrorAction Stop
    Move-Item `
        -LiteralPath $temporaryStatePath `
        -Destination $rollbackStatePath `
        -Force `
        -ErrorAction Stop
}

function Start-PersistedRollbackTransaction {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("Install", "Uninstall")]
        [string]$TransactionKind,
        [bool]$DriverWasPresent,
        [bool]$ServiceWasPresent,
        [bool]$ServiceWasRunning,
        [AllowNull()]
        [string]$ServiceStartMode,
        [AllowNull()]
        [Nullable[bool]]$ServiceDelayedAutoStart,
        [AllowNull()]
        [string]$DriverSignerThumbprint,
        [AllowNull()]
        [string]$PreviousDriverSignerThumbprint,
        [bool]$DriverRollbackComplete = $false,
        [bool]$ServiceRollbackComplete = $false
    )

    Initialize-InstallRollbackDirectory
    Assert-NoPendingRollbackTransaction

    try {
        $backedUpDriverInfPath = $null
        if ($DriverWasPresent) {
            $installedDriverInfName = Get-InstalledVirtualHidInfName
            $backedUpDriverInfPath = Export-VirtualHidDriverBackup `
                -PublishedInfName $installedDriverInfName
            if ([string]::IsNullOrWhiteSpace($PreviousDriverSignerThumbprint)) {
                $PreviousDriverSignerThumbprint = (
                    Get-BackedUpVirtualHidCertificate
                ).Thumbprint
            }
        }
        Save-RollbackState `
            -TransactionKind $TransactionKind `
            -DriverWasPresent $DriverWasPresent `
            -ServiceWasPresent $ServiceWasPresent `
            -ServiceWasRunning $ServiceWasRunning `
            -ServiceStartMode $ServiceStartMode `
            -ServiceDelayedAutoStart $ServiceDelayedAutoStart `
            -BackedUpDriverInfPath $backedUpDriverInfPath `
            -DriverSignerThumbprint $DriverSignerThumbprint `
            -PreviousDriverSignerThumbprint $PreviousDriverSignerThumbprint `
            -DriverRollbackComplete $DriverRollbackComplete `
            -ServiceRollbackComplete $ServiceRollbackComplete
        Copy-Item `
            -LiteralPath $PSCommandPath `
            -Destination $rollbackScriptPath `
            -Force `
            -ErrorAction Stop
        Copy-Item `
            -LiteralPath (Join-Path $RootDir "tools\lumen-vhidctl.exe") `
            -Destination (Join-Path $rollbackDirectory "lumen-vhidctl.exe") `
            -Force `
            -ErrorAction Stop
    } catch {
        throw "Could not create rollback state; partial protected artifacts were preserved: $($_.Exception.Message)"
    }
}

function Resolve-BackedUpDriverInfPath {
    param(
        [Parameter(Mandatory=$true)]
        [string]$BackedUpDriverInfPath
    )

    if ([string]::IsNullOrWhiteSpace($BackedUpDriverInfPath)) {
        throw "The previous Lumen Virtual HID driver backup path is missing."
    }
    $backupRoot = [System.IO.Path]::GetFullPath($rollbackDriverDirectory) + `
        [System.IO.Path]::DirectorySeparatorChar
    $resolvedBackupInfPath = [System.IO.Path]::GetFullPath($BackedUpDriverInfPath)
    if (-not $resolvedBackupInfPath.StartsWith(
        $backupRoot,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw "The previous Lumen Virtual HID driver backup path is outside the rollback directory."
    }
    if (-not (Test-Path -LiteralPath $resolvedBackupInfPath -PathType Leaf)) {
        throw "The previous Lumen Virtual HID driver backup is missing: $BackedUpDriverInfPath"
    }
    foreach ($item in @(Get-ChildItem -LiteralPath $rollbackDriverDirectory -Force -Recurse)) {
        if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            throw "The previous Lumen Virtual HID driver backup contains a reparse point: $($item.FullName)"
        }
    }
    $backupItem = Get-Item -LiteralPath $resolvedBackupInfPath -Force -ErrorAction Stop
    if ($backupItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        throw "The previous Lumen Virtual HID driver backup is a reparse point."
    }
    if (-not (Select-String `
        -LiteralPath $resolvedBackupInfPath `
        -Pattern "ROOT\LumenVirtualHid" `
        -SimpleMatch `
        -Quiet)) {
        throw "The previous driver backup does not belong to the exact Lumen Virtual HID root."
    }
    return $resolvedBackupInfPath
}

function Save-ParsedRollbackState {
    param(
        [Parameter(Mandatory=$true)]
        [psobject]$State
    )
    $temporaryStatePath = Join-Path $rollbackDirectory "virtual-hid-rollback.pending"
    $State | ConvertTo-Json | Set-Content `
        -LiteralPath $temporaryStatePath `
        -Encoding UTF8 `
        -ErrorAction Stop
    Move-Item `
        -LiteralPath $temporaryStatePath `
        -Destination $rollbackStatePath `
        -Force `
        -ErrorAction Stop
}

function Set-VirtualHidPendingReboot {
    $state = Read-RollbackState
    $state.DriverPendingReboot = $true
    $state.PendingBootIdentifier = Get-InstallerBootIdentifier
    Save-ParsedRollbackState -State $state
    $script:RebootRequired = $true
}

function Read-RollbackState {
    $state = Get-Content -LiteralPath $rollbackStatePath -Raw -ErrorAction Stop | `
        ConvertFrom-Json -ErrorAction Stop
    if ([int]$state.Schema -ne 2) {
        throw "Rollback state has an unsupported schema."
    }
    if ([string]$state.OwnerProductCode -cne $ProductCode) {
        throw "Rollback state is owned by a different ProductCode."
    }
    if ([string]$state.TransactionKind -cne $TransactionKind.ToLowerInvariant()) {
        throw "Rollback state belongs to a different transaction kind."
    }
    if ([string]$state.TransactionKind -notin @("install", "uninstall")) {
        throw "Rollback state has an invalid transaction kind."
    }
    return $state
}

function Invoke-PersistedRollback {
    Write-LogMessage -Message "Rolling back Lumen service and Virtual HID changes" -Level "Step"

    if (-not (Test-Path -LiteralPath $rollbackDirectory -PathType Container)) {
        Write-LogMessage -Message "No pending installer transaction was found." -Level "Information"
        return $false
    }

    Assert-InstallRollbackDirectorySecure

    if (-not (Test-Path -LiteralPath $rollbackStatePath -PathType Leaf)) {
        Write-LogMessage -Message "No pending installer transaction was found." -Level "Information"
        return $false
    }

    try {
        $rollbackState = Read-RollbackState
        $transactionKind = [string]$rollbackState.TransactionKind
        $driverWasPresent = [bool]$rollbackState.DriverWasPresent
        $serviceWasPresent = [bool]$rollbackState.ServiceWasPresent
        $serviceWasRunning = [bool]$rollbackState.ServiceWasRunning
        $serviceStartMode = [string]$rollbackState.ServiceStartMode
        $serviceDelayedAutoStart = if ($null -eq $rollbackState.ServiceDelayedAutoStart) {
            $null
        } else {
            [Nullable[bool]]([bool]$rollbackState.ServiceDelayedAutoStart)
        }
        $backedUpDriverInfPath = [string]$rollbackState.BackedUpDriverInfPath
        $driverSignerThumbprint = [string]$rollbackState.DriverSignerThumbprint
        $previousDriverSignerThumbprint = [string]$rollbackState.PreviousDriverSignerThumbprint
        $driverRollbackComplete = [bool]$rollbackState.DriverRollbackComplete
        $serviceRollbackComplete = [bool]$rollbackState.ServiceRollbackComplete
    } catch {
        throw "Could not read rollback state; protected rollback artifacts were preserved: $($_.Exception.Message)"
    }

    if ([bool]$rollbackState.Committed) {
        Invoke-ProtectedIdentityCommit | Out-Null
        Remove-InstallRollbackArtifacts
        Write-LogMessage -Message "Removed artifacts from an already committed transaction." -Level "Information"
        return $false
    }

    $rollbackErrors = [System.Collections.Generic.List[string]]::new()
    try {
        Invoke-ProtectedIdentityRollback | Out-Null
    } catch {
        $rollbackErrors.Add($_.Exception.Message) | Out-Null
    }
    $driverNeedsRollback = -not $driverRollbackComplete -and (
        $driverWasPresent -or $transactionKind -eq "install"
    )
    if ($driverNeedsRollback) {
        $currentService = Get-Service -Name "LumenService" -ErrorAction SilentlyContinue
        if ($null -ne $currentService -and $currentService.Status -ne "Stopped") {
            try {
                Stop-Service -Name "LumenService" -Force -ErrorAction Stop
                $currentService.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
            } catch {
                $rollbackErrors.Add(
                    "Could not stop the Lumen service before driver rollback: $($_.Exception.Message)"
                ) | Out-Null
            }
        }
    }

    if (-not $driverRollbackComplete -and $driverWasPresent) {
        try {
            $resolvedBackupInfPath = Resolve-BackedUpDriverInfPath `
                -BackedUpDriverInfPath $backedUpDriverInfPath
            if (-not [string]::IsNullOrWhiteSpace($previousDriverSignerThumbprint)) {
                $restoredSignerThumbprint = Install-BackedUpVirtualHidCertificate
                if ($restoredSignerThumbprint -ne $previousDriverSignerThumbprint) {
                    throw "The rollback driver signer does not match the saved exact thumbprint."
                }
            }
            $restoreExit = Invoke-VirtualHidCtl `
                -Arguments @("install-or-update", "`"$resolvedBackupInfPath`"") `
                -Description "Restoring the previous Lumen Virtual HID driver during rollback"
            if ($restoreExit -eq 3010) {
                Set-VirtualHidPendingReboot
                return $true
            }
            $rollbackState.DriverRollbackComplete = $true
            Save-ParsedRollbackState -State $rollbackState
        } catch {
            $rollbackErrors.Add($_.Exception.Message) | Out-Null
        }
    } elseif (-not $driverRollbackComplete -and $transactionKind -eq "install") {
        try {
            $removeExit = Invoke-VirtualHidCtl `
                -Arguments @("uninstall") `
                -Description "Removing newly installed Lumen Virtual HID driver during rollback"
            if ($removeExit -eq 3010) {
                Set-VirtualHidPendingReboot
                return $true
            }
            $rollbackState.DriverRollbackComplete = $true
            Save-ParsedRollbackState -State $rollbackState
        } catch {
            $rollbackErrors.Add($_.Exception.Message) | Out-Null
        }
    }

    if (-not $serviceRollbackComplete -and $serviceWasPresent) {
        $installServiceScript = Join-Path $RootDir "scripts\install-service.bat"
        try {
            if (-not (Test-Path -LiteralPath $installServiceScript -PathType Leaf)) {
                throw "Required service restore script not found: $installServiceScript"
            }
            $serviceExitCode = Invoke-ScriptIfExist `
                -ScriptPath $installServiceScript `
                -Description "Restoring Windows Service during rollback" `
                -Emoji "⚡"
            if ($serviceExitCode -ne 0) {
                throw "Service restore reported exit code $serviceExitCode."
            }

            $restoredService = Get-Service -Name "LumenService" -ErrorAction SilentlyContinue
            if ($null -eq $restoredService) {
                throw "The Lumen service is still absent after rollback."
            }
            if ([string]::IsNullOrWhiteSpace($serviceStartMode)) {
                if ($serviceWasRunning -and $restoredService.Status -ne "Running") {
                    Start-Service -Name "LumenService" -ErrorAction Stop
                    $restoredService.WaitForStatus("Running", [TimeSpan]::FromSeconds(30))
                } elseif (-not $serviceWasRunning -and $restoredService.Status -ne "Stopped") {
                    Stop-Service -Name "LumenService" -Force -ErrorAction Stop
                    $restoredService.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
                }
            } else {
                Restore-ServiceSnapshot `
                    -StartMode $serviceStartMode `
                    -DelayedAutoStart $serviceDelayedAutoStart `
                    -Running $serviceWasRunning
            }
            $rollbackState.ServiceRollbackComplete = $true
            Save-ParsedRollbackState -State $rollbackState
        } catch {
            $rollbackErrors.Add($_.Exception.Message) | Out-Null
        }
    } elseif (-not $serviceRollbackComplete -and $transactionKind -eq "install") {
        try {
            $uninstallServiceScript = Join-Path $RootDir "scripts\uninstall-service.bat"
            if (-not (Test-Path -LiteralPath $uninstallServiceScript -PathType Leaf)) {
                throw "Required service removal script not found: $uninstallServiceScript"
            }
            $serviceExitCode = Invoke-ScriptIfExist `
                -ScriptPath $uninstallServiceScript `
                -Description "Removing newly installed Windows Service during rollback" `
                -Emoji "⚡"
            if ($serviceExitCode -ne 0) {
                throw "Service rollback reported exit code $serviceExitCode."
            }
            if ($null -ne (Get-Service -Name "LumenService" -ErrorAction SilentlyContinue)) {
                throw "The newly installed Lumen service is still present after rollback."
            }
            $rollbackState.ServiceRollbackComplete = $true
            Save-ParsedRollbackState -State $rollbackState
        } catch {
            $rollbackErrors.Add($_.Exception.Message) | Out-Null
        }
    }

    if ($rollbackErrors.Count -ne 0) {
        foreach ($rollbackError in $rollbackErrors) {
            Write-LogMessage -Message $rollbackError -Level "Error"
        }
        throw "Rollback failed; protected rollback artifacts were preserved for retry."
    }

    if ($transactionKind -eq "install" -and
        -not [string]::IsNullOrWhiteSpace($driverSignerThumbprint) -and
        $driverSignerThumbprint -ne $previousDriverSignerThumbprint) {
        Remove-VirtualHidCertificate -Thumbprint $driverSignerThumbprint
    }
    Remove-InstallRollbackArtifacts
    return $true
}

function Invoke-PersistedCommit {
    if (-not (Test-Path -LiteralPath $rollbackDirectory -PathType Container)) {
        Write-LogMessage -Message "No exact transaction leaf required commit cleanup." -Level "Information"
        return $false
    }

    Assert-InstallRollbackDirectorySecure
    if (-not (Test-Path -LiteralPath $rollbackStatePath -PathType Leaf)) {
        throw "The transaction leaf is missing its rollback state."
    }

    $commitState = Read-RollbackState
    if (-not [bool]$commitState.Committed) {
        # Persist this transition first: once MSI invokes a commit action, this
        # transaction must never be interpreted as rollback work on a retry.
        $commitState.Committed = $true
        Save-ParsedRollbackState -State $commitState
    }
    Invoke-ProtectedIdentityCommit | Out-Null
    if ([bool]$commitState.DriverPendingReboot) {
        $script:RebootRequired = $true
        Write-LogMessage `
            -Message "Virtual HID commit is waiting for post-restart verification." `
            -Level "Warning"
        return $true
    }

    $committedSignerThumbprint = [string]$commitState.DriverSignerThumbprint
    $previousSignerThumbprint = [string]$commitState.PreviousDriverSignerThumbprint
    if ($commitState.TransactionKind -eq "install") {
        Set-InstalledVirtualHidSignerThumbprint -Thumbprint $committedSignerThumbprint
        if (-not [string]::IsNullOrWhiteSpace($previousSignerThumbprint) -and
            $previousSignerThumbprint -ne $committedSignerThumbprint) {
            Remove-VirtualHidCertificate -Thumbprint $previousSignerThumbprint
        }
    } elseif ($commitState.TransactionKind -eq "uninstall") {
        Set-InstalledVirtualHidSignerThumbprint -Thumbprint $null
        if (-not [string]::IsNullOrWhiteSpace($previousSignerThumbprint)) {
            Remove-VirtualHidCertificate -Thumbprint $previousSignerThumbprint
        }
    }

    Remove-InstallRollbackArtifacts
    Write-LogMessage -Message "Installer transaction committed." -Level "Success"
    return $true
}

function Invoke-ExactCurrentRecovery {
    if ((Test-Path -LiteralPath $rollbackStatePath) -or
        (Test-Path -LiteralPath $rollbackDriverDirectory) -or
        (Test-Path -LiteralPath $rollbackScriptPath)) {
        Assert-InstallRollbackDirectorySecure
        if (-not (Test-Path -LiteralPath $rollbackStatePath -PathType Leaf)) {
            throw "The exact current installer transaction is incomplete and was preserved."
        }
        $pendingState = Read-RollbackState
        if ([bool]$pendingState.Committed) {
            Write-LogMessage -Message "Finishing committed installer cleanup" -Level "Warning"
            if ([bool]$pendingState.DriverPendingReboot) {
                Invoke-PendingDriverResume
            } else {
                Invoke-PersistedCommit | Out-Null
            }
        } else {
            Write-LogMessage `
                -Message "Recovering the exact current installer transaction before retry" `
                -Level "Warning"
            Invoke-PersistedRollback | Out-Null
        }
    }
}

function Initialize-VirtualMicrophoneRollbackDirectory {
    $protectedAcl = New-InstallRollbackDirectoryAcl
    foreach ($directoryPath in @(
        $virtualMicrophoneRollbackRootDirectory,
        $virtualMicrophoneRollbackProductDirectory,
        $virtualMicrophoneRollbackDirectory
    )) {
        if (-not (Test-Path -LiteralPath $directoryPath)) {
            try {
                [System.IO.Directory]::CreateDirectory($directoryPath, $protectedAcl) | Out-Null
            } catch [System.Management.Automation.MethodException] {
                throw "Atomic protected Virtual Microphone rollback-directory creation is unavailable."
            }
        }
        Assert-InstallRollbackDirectorySecure -Path $directoryPath
    }
}

function Remove-VirtualMicrophoneRollbackArtifacts {
    if (-not (Test-Path -LiteralPath $virtualMicrophoneRollbackDirectory)) {
        return
    }
    Assert-InstallRollbackDirectorySecure -Path $virtualMicrophoneRollbackDirectory
    $leaf = Get-Item -LiteralPath $virtualMicrophoneRollbackDirectory -Force -ErrorAction Stop
    if ($leaf.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        throw "Refusing to remove a reparse-point Virtual Microphone transaction leaf."
    }
    Remove-Item `
        -LiteralPath $virtualMicrophoneRollbackDirectory `
        -Recurse `
        -Force `
        -ErrorAction Stop

    foreach ($parent in @(
        $virtualMicrophoneRollbackProductDirectory,
        $virtualMicrophoneRollbackRootDirectory
    )) {
        if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
            continue
        }
        Assert-InstallRollbackDirectorySecure -Path $parent
        if (@(Get-ChildItem -LiteralPath $parent -Force -ErrorAction Stop).Count -ne 0) {
            break
        }
        Remove-Item -LiteralPath $parent -Force -ErrorAction Stop
    }
}

function Get-InstalledVirtualMicrophoneInfName {
    $devices = @(
        Get-CimInstance Win32_PnPEntity -ErrorAction Stop | Where-Object {
            @($_.HardwareID) -contains "ROOT\LumenVirtualMicrophone"
        }
    )
    if ($devices.Count -ne 1) {
        throw "Expected exactly one active Lumen Virtual Microphone device; found $($devices.Count)."
    }

    $driverInfProperty = Get-PnpDeviceProperty `
        -InstanceId $devices[0].PNPDeviceID `
        -KeyName "DEVPKEY_Device_DriverInfPath" `
        -ErrorAction Stop
    $driverInfName = [string]$driverInfProperty.Data
    if ($driverInfName -notmatch '^oem\d+\.inf$') {
        throw "Active Lumen Virtual Microphone reported an invalid driver INF path: $driverInfName"
    }
    return $driverInfName
}

function Export-VirtualMicrophoneDriverBackup {
    param(
        [Parameter(Mandatory=$true)]
        [string]$PublishedInfName
    )

    if (Test-Path -LiteralPath $virtualMicrophoneRollbackDriverDirectory) {
        Remove-Item `
            -LiteralPath $virtualMicrophoneRollbackDriverDirectory `
            -Recurse `
            -Force `
            -ErrorAction Stop
    }
    New-Item `
        -ItemType Directory `
        -Path $virtualMicrophoneRollbackDriverDirectory `
        -Force | Out-Null

    $pnpUtilPath = Join-Path $env:SystemRoot "System32\pnputil.exe"
    if (-not (Test-Path $pnpUtilPath -PathType Leaf)) {
        throw "Required driver package utility not found: $pnpUtilPath"
    }
    Write-LogMessage -Message "Backing up the active Lumen Virtual Microphone driver" -Level "Step"
    $output = & $pnpUtilPath `
        /export-driver `
        $PublishedInfName `
        $virtualMicrophoneRollbackDriverDirectory 2>&1
    $exitCode = $LASTEXITCODE
    $output | ForEach-Object {
        if ($_ -and $_.ToString().Trim()) {
            Write-LogMessage -Message "  $_" -Level "Information" -Color "DarkGray"
        }
    }
    if ($exitCode -ne 0) {
        throw "Backing up the active Lumen Virtual Microphone driver failed with exit code $exitCode."
    }

    $exportedInfFiles = @(
        Get-ChildItem `
            -Path $virtualMicrophoneRollbackDriverDirectory `
            -Filter "*.inf" `
            -File `
            -Recurse | Where-Object {
                Select-String `
                    -Path $_.FullName `
                    -Pattern "ROOT\LumenVirtualMicrophone" `
                    -SimpleMatch `
                    -Quiet
            }
    )
    if ($exportedInfFiles.Count -ne 1) {
        throw "Expected exactly one exported Lumen Virtual Microphone INF; found $($exportedInfFiles.Count)."
    }
    return $exportedInfFiles[0].FullName
}

function Save-VirtualMicrophoneRollbackState {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("Install", "Uninstall")]
        [string]$TransactionKind,
        [bool]$DriverWasPresent,
        [AllowNull()]
        [string]$BackedUpDriverInfPath,
        [bool]$DriverRollbackComplete = $false,
        [bool]$Committed = $false,
        [bool]$DriverPendingReboot = $false,
        [AllowNull()]
        [string]$PendingBootIdentifier = $null
    )

    $state = @{
        Schema = 1
        OwnerProductCode = $ProductCode
        TransactionKind = $TransactionKind.ToLowerInvariant()
        DriverWasPresent = $DriverWasPresent
        BackedUpDriverInfPath = $BackedUpDriverInfPath
        DriverRollbackComplete = $DriverRollbackComplete
        Committed = $Committed
        DriverPendingReboot = $DriverPendingReboot
        PendingBootIdentifier = $PendingBootIdentifier
    }
    $temporaryStatePath = Join-Path `
        $virtualMicrophoneRollbackDirectory `
        "virtual-microphone-rollback.pending"
    $state | ConvertTo-Json | Set-Content `
        -LiteralPath $temporaryStatePath `
        -Encoding UTF8 `
        -ErrorAction Stop
    Move-Item `
        -LiteralPath $temporaryStatePath `
        -Destination $virtualMicrophoneRollbackStatePath `
        -Force `
        -ErrorAction Stop
}

function Start-PersistedVirtualMicrophoneTransaction {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("Install", "Uninstall")]
        [string]$TransactionKind,
        [bool]$DriverWasPresent,
        [bool]$DriverRollbackComplete = $false
    )

    Initialize-VirtualMicrophoneRollbackDirectory
    if ((Test-Path -LiteralPath $virtualMicrophoneRollbackStatePath) -or
        (Test-Path -LiteralPath $virtualMicrophoneRollbackDriverDirectory) -or
        (Test-Path -LiteralPath $virtualMicrophoneRollbackScriptPath)) {
        throw "A pending Virtual Microphone rollback transaction must be resolved before continuing."
    }

    $backedUpDriverInfPath = $null
    if ($DriverWasPresent) {
        $installedDriverInfName = Get-InstalledVirtualMicrophoneInfName
        $backedUpDriverInfPath = Export-VirtualMicrophoneDriverBackup `
            -PublishedInfName $installedDriverInfName
    }
    Save-VirtualMicrophoneRollbackState `
        -TransactionKind $TransactionKind `
        -DriverWasPresent $DriverWasPresent `
        -BackedUpDriverInfPath $backedUpDriverInfPath `
        -DriverRollbackComplete $DriverRollbackComplete
    Copy-Item `
        -LiteralPath $PSCommandPath `
        -Destination $virtualMicrophoneRollbackScriptPath `
        -Force `
        -ErrorAction Stop
    Copy-Item `
        -LiteralPath (Join-Path $RootDir "tools\lumen-vmicctl.exe") `
        -Destination (Join-Path $virtualMicrophoneRollbackDirectory "lumen-vmicctl.exe") `
        -Force `
        -ErrorAction Stop
}

function Read-VirtualMicrophoneRollbackState {
    $state = Get-Content `
        -LiteralPath $virtualMicrophoneRollbackStatePath `
        -Raw `
        -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ([int]$state.Schema -ne 1) {
        throw "Virtual Microphone rollback state has an unsupported schema."
    }
    if ([string]$state.OwnerProductCode -cne $ProductCode) {
        throw "Virtual Microphone rollback state is owned by a different ProductCode."
    }
    if ([string]$state.TransactionKind -cne $TransactionKind.ToLowerInvariant()) {
        throw "Virtual Microphone rollback state belongs to a different transaction kind."
    }
    return $state
}

function Save-ParsedVirtualMicrophoneRollbackState {
    param(
        [Parameter(Mandatory=$true)]
        [psobject]$State
    )
    $temporaryStatePath = Join-Path `
        $virtualMicrophoneRollbackDirectory `
        "virtual-microphone-rollback.pending"
    $State | ConvertTo-Json | Set-Content `
        -LiteralPath $temporaryStatePath `
        -Encoding UTF8 `
        -ErrorAction Stop
    Move-Item `
        -LiteralPath $temporaryStatePath `
        -Destination $virtualMicrophoneRollbackStatePath `
        -Force `
        -ErrorAction Stop
}

function Set-VirtualMicrophonePendingReboot {
    $state = Read-VirtualMicrophoneRollbackState
    $state.DriverPendingReboot = $true
    $state.PendingBootIdentifier = Get-InstallerBootIdentifier
    Save-ParsedVirtualMicrophoneRollbackState -State $state
    $script:RebootRequired = $true
}

function Resolve-BackedUpVirtualMicrophoneInfPath {
    param(
        [Parameter(Mandatory=$true)]
        [string]$BackedUpDriverInfPath
    )
    $backupRoot = [System.IO.Path]::GetFullPath(
        $virtualMicrophoneRollbackDriverDirectory
    ) + [System.IO.Path]::DirectorySeparatorChar
    $resolvedInf = [System.IO.Path]::GetFullPath($BackedUpDriverInfPath)
    if (-not $resolvedInf.StartsWith(
        $backupRoot,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw "The Virtual Microphone backup INF is outside the rollback directory."
    }
    if (-not (Test-Path -LiteralPath $resolvedInf -PathType Leaf)) {
        throw "The previous Virtual Microphone driver backup is missing."
    }
    foreach ($item in @(
        Get-ChildItem `
            -LiteralPath $virtualMicrophoneRollbackDriverDirectory `
            -Force `
            -Recurse
    )) {
        if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            throw "The Virtual Microphone driver backup contains a reparse point."
        }
    }
    if (-not (Select-String `
        -LiteralPath $resolvedInf `
        -Pattern "ROOT\LumenVirtualMicrophone" `
        -SimpleMatch `
        -Quiet)) {
        throw "The previous driver backup does not belong to the exact Virtual Microphone root."
    }
    return $resolvedInf
}

function Invoke-PersistedVirtualMicrophoneRollback {
    if (-not (Test-Path -LiteralPath $virtualMicrophoneRollbackDirectory -PathType Container)) {
        return $false
    }
    Assert-InstallRollbackDirectorySecure -Path $virtualMicrophoneRollbackDirectory
    if (-not (Test-Path -LiteralPath $virtualMicrophoneRollbackStatePath -PathType Leaf)) {
        throw "The Virtual Microphone transaction leaf is missing rollback state."
    }

    $state = Read-VirtualMicrophoneRollbackState
    if ([bool]$state.Committed) {
        Remove-VirtualMicrophoneRollbackArtifacts
        return $false
    }
    if (-not [bool]$state.DriverRollbackComplete) {
        $service = Get-Service -Name "LumenService" -ErrorAction SilentlyContinue
        if ($null -ne $service -and $service.Status -ne "Stopped") {
            Stop-Service -Name "LumenService" -Force -ErrorAction Stop
            $service.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
        }

        if ([bool]$state.DriverWasPresent) {
            $backupInf = Resolve-BackedUpVirtualMicrophoneInfPath `
                -BackedUpDriverInfPath ([string]$state.BackedUpDriverInfPath)
            $restoreExit = Invoke-VirtualMicrophoneCtl `
                -Arguments @("install-or-update", "`"$backupInf`"") `
                -Description "Restoring the previous Lumen Virtual Microphone driver"
            if ($restoreExit -eq 3010) {
                Set-VirtualMicrophonePendingReboot
                return $true
            }
        } elseif ([string]$state.TransactionKind -eq "install") {
            $removeExit = Invoke-VirtualMicrophoneCtl `
                -Arguments @("uninstall") `
                -Description "Removing the newly installed Lumen Virtual Microphone driver"
            if ($removeExit -eq 3010) {
                Set-VirtualMicrophonePendingReboot
                return $true
            }
        }
        $state.DriverRollbackComplete = $true
        Save-ParsedVirtualMicrophoneRollbackState -State $state
    }
    Remove-VirtualMicrophoneRollbackArtifacts
    return $true
}

function Invoke-PersistedVirtualMicrophoneCommit {
    if (-not (Test-Path -LiteralPath $virtualMicrophoneRollbackDirectory -PathType Container)) {
        return $false
    }
    Assert-InstallRollbackDirectorySecure -Path $virtualMicrophoneRollbackDirectory
    $state = Read-VirtualMicrophoneRollbackState
    if (-not [bool]$state.Committed) {
        $state.Committed = $true
        Save-ParsedVirtualMicrophoneRollbackState -State $state
    }
    if ([bool]$state.DriverPendingReboot) {
        $script:RebootRequired = $true
        return $true
    }
    Remove-VirtualMicrophoneRollbackArtifacts
    return $true
}

function Invoke-ExactCurrentVirtualMicrophoneRecovery {
    if ((Test-Path -LiteralPath $virtualMicrophoneRollbackStatePath) -or
        (Test-Path -LiteralPath $virtualMicrophoneRollbackDriverDirectory)) {
        Assert-InstallRollbackDirectorySecure -Path $virtualMicrophoneRollbackDirectory
        if (-not (Test-Path -LiteralPath $virtualMicrophoneRollbackStatePath -PathType Leaf)) {
            throw "The exact current Virtual Microphone transaction is incomplete and was preserved."
        }
        $state = Read-VirtualMicrophoneRollbackState
        if ([bool]$state.Committed) {
            if ([bool]$state.DriverPendingReboot) {
                Invoke-PendingDriverResume
            } else {
                Invoke-PersistedVirtualMicrophoneCommit | Out-Null
            }
        } else {
            Invoke-PersistedVirtualMicrophoneRollback | Out-Null
        }
    }
}

function Invoke-AllPersistedRollbacks {
    $errors = [System.Collections.Generic.List[string]]::new()
    $applied = $false
    if ($virtualDisplayTransactionSelected) {
        try {
            Invoke-VirtualDisplaySetup -DriverAction "rollback" | Out-Null
            $applied = $true
        } catch {
            $errors.Add($_.Exception.Message) | Out-Null
        }
    }
    try {
        $applied = (Invoke-PersistedVirtualMicrophoneRollback) -or $applied
    } catch {
        $errors.Add($_.Exception.Message) | Out-Null
    }
    try {
        $applied = (Invoke-PersistedRollback) -or $applied
    } catch {
        $errors.Add($_.Exception.Message) | Out-Null
    }
    if ($errors.Count -ne 0) {
        throw ($errors -join " ")
    }
    return $applied
}

function Invoke-AllPersistedCommits {
    Invoke-PersistedVirtualMicrophoneCommit | Out-Null
    Invoke-PersistedCommit | Out-Null
    if ($virtualDisplayTransactionSelected) {
        Invoke-VirtualDisplaySetup -DriverAction "commit" | Out-Null
    }
}

function Invoke-PendingDriverResume {
    $currentBoot = Get-InstallerBootIdentifier
    if (Test-Path -LiteralPath $rollbackStatePath -PathType Leaf) {
        $hidState = Read-RollbackState
        if ([bool]$hidState.DriverPendingReboot) {
            if ([string]$hidState.PendingBootIdentifier -eq $currentBoot) {
                throw "Virtual HID completion is waiting for Windows to restart."
            }
            if ([bool]$hidState.Committed) {
                $status = Invoke-VirtualHidCtl `
                    -Arguments @("status") `
                    -Description "Verifying the post-restart Lumen Virtual HID state" `
                    -AllowNotInstalled
                $expectedPresent = [string]$hidState.TransactionKind -eq "install"
                if (($expectedPresent -and $status -ne 0) -or
                    (-not $expectedPresent -and $status -ne 2)) {
                    throw "The post-restart Lumen Virtual HID state is not complete."
                }
                $hidState.DriverPendingReboot = $false
                $hidState.PendingBootIdentifier = $null
                Save-ParsedRollbackState -State $hidState
                Invoke-PersistedCommit | Out-Null
            } else {
                $hidState.DriverPendingReboot = $false
                $hidState.PendingBootIdentifier = $null
                Save-ParsedRollbackState -State $hidState
                Invoke-PersistedRollback | Out-Null
            }
        }
    }

    if (Test-Path -LiteralPath $virtualMicrophoneRollbackStatePath -PathType Leaf) {
        $microphoneState = Read-VirtualMicrophoneRollbackState
        if ([bool]$microphoneState.DriverPendingReboot) {
            if ([string]$microphoneState.PendingBootIdentifier -eq $currentBoot) {
                throw "Virtual Microphone completion is waiting for Windows to restart."
            }
            if ([bool]$microphoneState.Committed) {
                $status = Invoke-VirtualMicrophoneCtl `
                    -Arguments @("status") `
                    -Description "Verifying the post-restart Lumen Virtual Microphone state" `
                    -AllowNotInstalled
                $expectedPresent = [string]$microphoneState.TransactionKind -eq "install"
                if (($expectedPresent -and $status -ne 0) -or
                    (-not $expectedPresent -and $status -ne 2)) {
                    throw "The post-restart Lumen Virtual Microphone state is not complete."
                }
                $microphoneState.DriverPendingReboot = $false
                $microphoneState.PendingBootIdentifier = $null
                Save-ParsedVirtualMicrophoneRollbackState -State $microphoneState
                Invoke-PersistedVirtualMicrophoneCommit | Out-Null
            } else {
                $microphoneState.DriverPendingReboot = $false
                $microphoneState.PendingBootIdentifier = $null
                Save-ParsedVirtualMicrophoneRollbackState -State $microphoneState
                Invoke-PersistedVirtualMicrophoneRollback | Out-Null
            }
        }
    }
    Unregister-DriverResumeTask
    Clear-PendingDriverRebootMarker
}

# Main script logic
Write-Information ""

try {
if ($Action -eq "install") {
    Invoke-ExactCurrentRecovery
    Invoke-ExactCurrentVirtualMicrophoneRecovery
    if ($virtualDisplayTransactionSelected) {
        Invoke-VirtualDisplaySetup -DriverAction "rollback" | Out-Null
    }
    $legacySunshineProducts = @(Get-LegacySunshineProducts)
    if ($legacySunshineProducts.Count -ne 0) {
        Write-LogMessage `
            -Message "Detected a separate Sunshine installation. Lumen will not replace or uninstall it." `
            -Level "Warning"
        Copy-LegacySunshineConfigIfNeeded -Products $legacySunshineProducts
    }
    Write-FramedText `
        -Message "🔅 Lumen Installation Script" `
        -Level "Information" `
        -Color "Yellow"
    Write-Information ""

    $totalSteps = 7
    $currentStep = 0

    # Reset permissions on the install directory
    $currentStep++
    Write-Progress `
        -Activity "Installing Lumen" `
        -Status "Resetting permissions on installation directory" `
        -PercentComplete (($currentStep / $totalSteps) * 100)
    Write-LogMessage -Message "🔐 Resetting permissions on installation directory" -Level "Step"
    try {
        Write-LogMessage -Message "Executing: icacls.exe `"$RootDir`" /reset" -Level "Information"

        # Capture output to suppress it from console but log it
        $stdoutFile = [System.IO.Path]::GetTempFileName()
        $stderrFile = [System.IO.Path]::GetTempFileName()

        try {
            $icaclsProcess = Start-Process `
                -FilePath "icacls.exe" `
                -ArgumentList "`"$RootDir`" /reset" `
                -Wait `
                -PassThru `
                -NoNewWindow `
                -RedirectStandardOutput $stdoutFile `
                -RedirectStandardError $stderrFile

            # Log and display the output
            if (Test-Path $stdoutFile) {
                $output = Get-Content $stdoutFile -Raw -ErrorAction SilentlyContinue
                if ($output) {
                    # Display output with indentation
                    $output -split "`r?`n" | ForEach-Object {
                        if ($_.Trim()) {
                            Write-LogMessage -Message "  $_" -Level "Information" -Color "DarkGray"
                        }
                    }
                }
            }
            if (Test-Path $stderrFile) {
                $errors = Get-Content $stderrFile -Raw -ErrorAction SilentlyContinue
                if ($errors) {
                    # Display errors with indentation
                    $errors -split "`r?`n" | ForEach-Object {
                        if ($_.Trim()) {
                            Write-LogMessage -Message "  $_" -Level "Warning"
                        }
                    }
                }
            }

            if ($icaclsProcess.ExitCode -eq 0) {
                Write-LogMessage -Message "  ✓ Done" -Level "Success"
            } else {
                Write-LogMessage -Message "  ⚠ Exit code $($icaclsProcess.ExitCode)" -Level "Warning"
            }
        } finally {
            # Clean up temp files
            if (Test-Path $stdoutFile) {
                Remove-Item $stdoutFile -Force -ErrorAction SilentlyContinue
            }
            if (Test-Path $stderrFile) {
                Remove-Item $stderrFile -Force -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-LogMessage -Message "  ⚠ Failed to reset permissions: $($_.Exception.Message)" -Level "Warning"
    }
    Write-Information ""

    # 1. Update PATH (add)
    $currentStep++
    Write-Progress `
        -Activity "Installing Lumen" `
        -Status "Updating system PATH" `
        -PercentComplete (($currentStep / $totalSteps) * 100)
    Write-LogMessage -Message "📁 Adding Lumen directories to PATH" -Level "Step"
    Update-SystemPath -Operation "add"
    Write-Information ""

    # 2. Migrate configuration
    $currentStep++
    Write-Progress `
        -Activity "Installing Lumen" `
        -Status "Migrating configuration" `
        -PercentComplete (($currentStep / $totalSteps) * 100)
    $migrateConfigScript = Join-Path $RootDir "scripts\migrate-config.bat"
    Invoke-ScriptIfExist `
        -ScriptPath $migrateConfigScript `
        -Description "Migrating configuration files" `
        -Emoji "⚙️"
    Write-Information ""

    # 3. Add firewall rules
    $currentStep++
    Write-Progress `
        -Activity "Installing Lumen" `
        -Status "Configuring firewall" `
        -PercentComplete (($currentStep / $totalSteps) * 100)
    if ($Msi) {
        Write-LogMessage -Message "Windows Installer owns the Lumen firewall rules." -Level "Information"
    } else {
        $addFirewallScript = Join-Path $RootDir "scripts\add-firewall-rule.bat"
        Invoke-ScriptIfExist `
            -ScriptPath $addFirewallScript `
            -Description "Adding firewall rules" `
            -Emoji "🛡️"
    }
    Write-Information ""

    # 4. Install or update selected Lumen device drivers. This must complete
    # before the service is installed or started.
    $currentStep++
    Write-Progress `
        -Activity "Installing Lumen" `
        -Status "Installing selected Lumen device drivers" `
        -PercentComplete (($currentStep / $totalSteps) * 100)
    $driverInfPath = $null
    $driverSignerThumbprint = $null
    $driverCertificatePath = $null
    $previousDriverSignerThumbprint = Get-InstalledVirtualHidSignerThumbprint
    $driverStatus = 2
    if ($virtualHidSelected) {
        $driverStatus = Invoke-VirtualHidCtl `
            -Arguments @("status") `
            -Description "Checking Lumen Virtual HID driver status" `
            -AllowNotInstalled
        $driverInfPath = Get-VirtualHidInfPath
        $driverCertificatePath = Get-VirtualHidCertificatePath
        if ([string]::IsNullOrWhiteSpace($driverCertificatePath)) {
            $driverSignerThumbprint = Assert-VirtualHidPackageSignature
        } else {
            $driverSignerThumbprint = (Get-VirtualHidCertificate `
                -CertificatePath $driverCertificatePath).Thumbprint
        }
    } else {
        Write-LogMessage -Message "Lumen Virtual HID feature is not selected." -Level "Information"
    }
    $virtualMicrophoneInfPath = $null
    $virtualMicrophoneStatus = 2
    if ($virtualMicrophoneSelected) {
        $virtualMicrophoneStatus = Invoke-VirtualMicrophoneCtl `
            -Arguments @("status") `
            -Description "Checking Lumen Virtual Microphone driver status" `
            -AllowNotInstalled
        $virtualMicrophoneInfPath = Get-VirtualMicrophoneInfPath
    } else {
        Write-LogMessage `
            -Message "Lumen Virtual Microphone feature is not selected." `
            -Level "Information"
    }
    $serviceSnapshot = if ($Msi) {
        @{ Present = $false; Running = $false; StartMode = $null; DelayedAutoStart = $null }
    } else {
        Get-ServiceSnapshot
    }
    $existingService = if ($Msi) { $null } else { Get-Service -Name "LumenService" -ErrorAction SilentlyContinue }
    $serviceWasPresent = $serviceSnapshot.Present
    $serviceWasRunning = $serviceSnapshot.Running
    $driverWasPresent = $driverStatus -in @(0, 4)
    $virtualMicrophoneWasPresent = $virtualMicrophoneStatus -in @(0, 3, 4)
    $serviceRollbackComplete = [bool]$Msi
    Start-PersistedRollbackTransaction `
        -TransactionKind "install" `
        -DriverWasPresent $driverWasPresent `
        -ServiceWasPresent $serviceWasPresent `
        -ServiceWasRunning $serviceWasRunning `
        -ServiceStartMode $serviceSnapshot.StartMode `
        -ServiceDelayedAutoStart $serviceSnapshot.DelayedAutoStart `
        -DriverSignerThumbprint $driverSignerThumbprint `
        -PreviousDriverSignerThumbprint $previousDriverSignerThumbprint `
        -DriverRollbackComplete (-not $virtualHidSelected) `
        -ServiceRollbackComplete $serviceRollbackComplete
    if ($virtualMicrophoneSelected) {
        Start-PersistedVirtualMicrophoneTransaction `
            -TransactionKind "install" `
            -DriverWasPresent $virtualMicrophoneWasPresent
    }
    if ($virtualHidSelected -and -not [string]::IsNullOrWhiteSpace($driverCertificatePath)) {
        $importedThumbprint = Install-VirtualHidCertificate `
            -CertificatePath $driverCertificatePath
        if ($importedThumbprint -ne $driverSignerThumbprint) {
            throw "The imported Virtual HID signer does not match the bundled certificate."
        }
        Assert-VirtualHidPackageSignature -CertificatePath $driverCertificatePath | Out-Null
    }
    if (-not $Msi -and $serviceWasRunning) {
        Write-LogMessage `
            -Message "Stopping the Lumen service before updating device drivers" `
            -Level "Step"
        Stop-Service -Name "LumenService" -Force -ErrorAction Stop
        $existingService.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
    }
    if ($virtualHidSelected) {
        $virtualHidInstallExit = Invoke-VirtualHidCtl `
            -Arguments @("install-or-update", "`"$driverInfPath`"") `
            -Description "Installing or updating the Lumen Virtual HID driver"
        if ($virtualHidInstallExit -eq 3010) {
            Set-VirtualHidPendingReboot
        } else {
            Invoke-VirtualHidCtl `
                -Arguments @("probe", "--json") `
                -Description "Verifying the Lumen Virtual HID control protocol" | Out-Null
        }
    }
    if ($virtualMicrophoneSelected) {
        $virtualMicrophoneInstallExit = Invoke-VirtualMicrophoneCtl `
            -Arguments @("install-or-update", "`"$virtualMicrophoneInfPath`"") `
            -Description "Installing or updating the Lumen Virtual Microphone driver"
        if ($virtualMicrophoneInstallExit -eq 3010) {
            Set-VirtualMicrophonePendingReboot
        } else {
            Invoke-VirtualMicrophoneCtl `
                -Arguments @("probe", "--json") `
                -Description "Verifying the Lumen Virtual Microphone control ABI" | Out-Null
        }
    }
    if ($virtualDisplaySelected) {
        Invoke-VirtualDisplaySetup -DriverAction "install" | Out-Null
    } elseif ($virtualDisplayRemoveSelected) {
        Invoke-VirtualDisplaySetup -DriverAction "remove-feature" | Out-Null
    } else {
        Write-LogMessage `
            -Message "Lumen Virtual Display feature is not selected." `
            -Level "Information"
    }
    Write-Information ""

    # 5. Install service. MSI owns this through ServiceInstall/ServiceControl;
    # the scripts remain the NSIS path only.
    $currentStep++
    Write-Progress `
        -Activity "Installing Lumen" `
        -Status "Installing service" `
        -PercentComplete (($currentStep / $totalSteps) * 100)
    if (-not $Msi) {
        $installServiceScript = Join-Path $RootDir "scripts\install-service.bat"
        Invoke-SetupScript `
            -ScriptPath $installServiceScript `
            -Description "Installing Windows Service" `
            -Emoji "⚡"
    } else {
        Write-LogMessage -Message "Windows Installer owns the Lumen service." -Level "Information"
    }
    Write-Information ""

    # 6. Configure autostart
    $currentStep++
    Write-Progress `
        -Activity "Installing Lumen" `
        -Status "Configuring autostart" `
        -PercentComplete (($currentStep / $totalSteps) * 100)
    if (-not $Msi) {
        $autostartScript = Join-Path $RootDir "scripts\autostart-service.bat"
        Invoke-SetupScript `
            -ScriptPath $autostartScript `
            -Description "Configuring autostart" `
            -Emoji "🚀"
    } else {
        Write-LogMessage -Message "Windows Installer owns the Lumen service start mode." -Level "Information"
    }
    Write-Information ""

    Write-Progress -Activity "Installing Lumen" -Completed
    if (-not $Msi) {
        Invoke-AllPersistedCommits
    }
    if ($script:RebootRequired) {
        Write-FramedText `
            -Message "✓ Lumen installed. Restart Windows to finish the driver operation." `
            -Level "Warning"
    } else {
        Write-FramedText -Message "✓ Lumen installation completed successfully!" -Level "Success"
    }

    # Open documentation in browser (only if not running silently)
    if (-not $Silent) {
        Write-Information ""
        Write-LogMessage `
            -Message "📖 Opening documentation in your browser: $DocsUrl" `
            -Level "Step"
        try {
            Start-Process $DocsUrl
            Write-LogMessage -Message "  ✓ Done" -Level "Success"
        } catch {
            Write-LogMessage `
                -Message "  ⓘ Could not open browser automatically: $($_.Exception.Message)" `
                -Level "Warning"
        }
    }

} elseif ($Action -eq "uninstall") {
    Invoke-ExactCurrentRecovery
    Invoke-ExactCurrentVirtualMicrophoneRecovery
    if ($virtualDisplaySelected) {
        Invoke-VirtualDisplaySetup -DriverAction "rollback" | Out-Null
    }
    Write-FramedText `
        -Message "🗑️  Lumen Uninstallation Script" `
        -Level "Information" `
        -Color "Yellow"
    Write-Information ""

    $totalSteps = 5
    $currentStep = 0

    $driverStatus = 2
    if ($virtualHidSelected) {
        $driverStatus = Invoke-VirtualHidCtl `
            -Arguments @("status") `
            -Description "Checking Lumen Virtual HID driver status before uninstall" `
            -AllowNotInstalled
    }
    $uninstallDriverWasPresent = $virtualHidSelected -and $driverStatus -in @(0, 4)
    $virtualMicrophoneStatus = 2
    if ($virtualMicrophoneSelected) {
        $virtualMicrophoneStatus = Invoke-VirtualMicrophoneCtl `
            -Arguments @("status") `
            -Description "Checking Lumen Virtual Microphone driver status before uninstall" `
            -AllowNotInstalled
    }
    $uninstallVirtualMicrophoneWasPresent = `
        $virtualMicrophoneSelected -and $virtualMicrophoneStatus -in @(0, 3, 4)
    $serviceSnapshot = Get-ServiceSnapshot
    $existingService = Get-Service -Name "LumenService" -ErrorAction SilentlyContinue
    $uninstallServiceWasPresent = -not $Msi -and $serviceSnapshot.Present
    $uninstallServiceWasRunning = -not $Msi -and `
        $null -ne $existingService -and $existingService.Status -eq "Running"

    Start-PersistedRollbackTransaction `
        -TransactionKind "uninstall" `
        -DriverWasPresent $uninstallDriverWasPresent `
        -ServiceWasPresent $uninstallServiceWasPresent `
        -ServiceWasRunning $uninstallServiceWasRunning `
        -ServiceStartMode $serviceSnapshot.StartMode `
        -ServiceDelayedAutoStart $serviceSnapshot.DelayedAutoStart `
        -DriverSignerThumbprint $null `
        -PreviousDriverSignerThumbprint (Get-InstalledVirtualHidSignerThumbprint) `
        -DriverRollbackComplete (-not $virtualHidSelected) `
        -ServiceRollbackComplete ([bool]$Msi)
    if ($virtualMicrophoneSelected) {
        Start-PersistedVirtualMicrophoneTransaction `
            -TransactionKind "uninstall" `
            -DriverWasPresent $uninstallVirtualMicrophoneWasPresent
    }

    # 1. Stop and remove the service before touching the driver.
    $currentStep++
    Write-Progress `
        -Activity "Uninstalling Lumen" `
        -Status "Uninstalling service" `
        -PercentComplete (($currentStep / $totalSteps) * 100)
    $uninstallServiceScript = Join-Path $RootDir "scripts\uninstall-service.bat"
    if ($Msi) {
        Write-LogMessage -Message "Windows Installer owns Lumen service removal." -Level "Information"
    } elseif ($uninstallServiceWasPresent) {
        Invoke-SetupScript `
            -ScriptPath $uninstallServiceScript `
            -Description "Removing Windows Service" `
            -Emoji "⚡"
    } else {
        Write-LogMessage -Message "Windows Service is already absent." -Level "Information"
    }
    Write-Information ""

    # The service is now stopped or absent. Snapshot both protected identity
    # artifacts into the SYSTEM/Administrators-only transaction directory,
    # then remove and verify them before any later uninstall mutation can fail.
    Start-ProtectedIdentityUninstallTransaction | Out-Null
    Invoke-ProtectedIdentityRemoval | Out-Null

    # 2. Remove the root device and the Lumen-owned driver package. The helper
    # is idempotent and reports reboot-required cleanup as exit code 3010.
    $currentStep++
    Write-Progress `
        -Activity "Uninstalling Lumen" `
        -Status "Removing selected Lumen device drivers" `
        -PercentComplete (($currentStep / $totalSteps) * 100)
    if ($Msi) {
        $msiOwnedService = Get-Service -Name "LumenService" -ErrorAction SilentlyContinue
        if ($null -ne $msiOwnedService -and $msiOwnedService.Status -ne "Stopped") {
            $msiOwnedService.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
            $msiOwnedService.Refresh()
        }
        if ($null -ne $msiOwnedService -and $msiOwnedService.Status -ne "Stopped") {
            throw "Windows Installer did not stop LumenService before driver removal."
        }
    }
    if ($virtualDisplaySelected) {
        Invoke-VirtualDisplaySetup -DriverAction "uninstall" | Out-Null
    } else {
        Write-LogMessage -Message "Lumen Virtual Display feature was not owned by this product." -Level "Information"
    }
    if ($virtualMicrophoneSelected) {
        $virtualMicrophoneUninstallExit = Invoke-VirtualMicrophoneCtl `
            -Arguments @("uninstall") `
            -Description "Removing the Lumen Virtual Microphone device and driver package"
        if ($virtualMicrophoneUninstallExit -eq 3010) {
            Set-VirtualMicrophonePendingReboot
        }
    } else {
        Write-LogMessage `
            -Message "Lumen Virtual Microphone feature was not owned by this product." `
            -Level "Information"
    }
    if ($virtualHidSelected) {
        $virtualHidUninstallExit = Invoke-VirtualHidCtl `
            -Arguments @("uninstall") `
            -Description "Removing the Lumen Virtual HID device and driver package"
        if ($virtualHidUninstallExit -eq 3010) {
            Set-VirtualHidPendingReboot
        }
    } else {
        Write-LogMessage -Message "Lumen Virtual HID feature was not owned by this product." -Level "Information"
    }
    Write-Information ""

    # 3. Delete firewall rules
    $currentStep++
    Write-Progress `
        -Activity "Uninstalling Lumen" `
        -Status "Removing firewall rules" `
        -PercentComplete (($currentStep / $totalSteps) * 100)
    if ($Msi) {
        Write-LogMessage -Message "Windows Installer owns Lumen firewall rule removal." -Level "Information"
    } else {
        $deleteFirewallScript = Join-Path $RootDir "scripts\delete-firewall-rule.bat"
        Invoke-ScriptIfExist `
            -ScriptPath $deleteFirewallScript `
            -Description "Removing firewall rules" `
            -Emoji "🛡️"
    }
    Write-Information ""

    # 4. Restore NVIDIA preferences
    $currentStep++
    Write-Progress `
        -Activity "Uninstalling Lumen" `
        -Status "Restoring NVIDIA settings" `
        -PercentComplete (($currentStep / $totalSteps) * 100)
    Invoke-LumenIfExist `
        -Arguments "--restore-nvprefs-undo" `
        -Description "Restoring NVIDIA preferences" `
        -Emoji "🎮"
    Write-Information ""

    # 5. Update PATH (remove)
    $currentStep++
    Write-Progress `
        -Activity "Uninstalling Lumen" `
        -Status "Cleaning up system PATH" `
        -PercentComplete (($currentStep / $totalSteps) * 100)
    Write-LogMessage -Message "📁 Removing Lumen directories from PATH" -Level "Step"
    Update-SystemPath -Operation "remove"
    Write-Information ""

    Write-Progress -Activity "Uninstalling Lumen" -Completed
    Write-FramedText `
        -Message "✓ Lumen uninstallation completed successfully!" `
        -Level "Success"
    if (-not $Msi) {
        Invoke-AllPersistedCommits
    }
} elseif ($Action -eq "rollback") {
    $rollbackApplied = Invoke-AllPersistedRollbacks
    if ($rollbackApplied) {
        Write-LogMessage -Message "Rollback completed." -Level "Success"
    }
    if (-not $script:RebootRequired) {
        Unregister-DriverResumeTask
        Clear-PendingDriverRebootMarker
    }
} elseif ($Action -eq "commit") {
    Invoke-AllPersistedCommits
    if (-not $script:RebootRequired) {
        Unregister-DriverResumeTask
        Clear-PendingDriverRebootMarker
    }
} elseif ($Action -eq "resume") {
    Invoke-PendingDriverResume
}

} catch {
    Write-Progress -Activity "Lumen Setup" -Completed
    $setupErrorMessage = $_.Exception.Message
    Write-LogMessage -Message $setupErrorMessage -Level "Error"
    if ($Action -in @("install", "uninstall")) {
        try {
            $rollbackApplied = Invoke-AllPersistedRollbacks
            if ($rollbackApplied) {
                Write-LogMessage -Message "Failed setup changes were rolled back." -Level "Success"
            }
        } catch {
            Write-LogMessage -Message $_.Exception.Message -Level "Error"
        }
    }
    Write-LogMessage `
        -Message "Lumen setup failed. See $LogPath for details." `
        -Level "Error"
    exit 1
}

Write-Information ""
if ($script:RebootRequired) {
    Write-LogMessage `
        -Message "Windows must be restarted to finish the driver operation." `
        -Level "Warning"
    # WixQuietExec treats every nonzero child-process result as failure. The
    # persisted VDD transaction records 3010 in HKLM, and the immediately
    # following native deferred custom action calls MsiSetMode(RebootAtEnd).
    # Recovery artifacts remain until the SYSTEM resume task verifies the next
    # boot. Standalone installers receive 3010 directly.
    if ($Msi) {
        Set-PendingDriverRebootMarker
        Register-DriverResumeTask
        exit 0
    }
    Set-PendingDriverRebootMarker
    Register-DriverResumeTask
    exit 3010
}
exit 0
