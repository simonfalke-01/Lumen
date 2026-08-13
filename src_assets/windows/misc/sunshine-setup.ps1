# Sunshine Setup Script
# This script orchestrates the installation and uninstallation of Sunshine
# Usage: sunshine-setup.ps1 -Action <operation> -ProductCode <guid> -TransactionKind <install|uninstall>

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet(
            "install",
            "uninstall",
            "rollback",
            "commit",
            "recover-legacy"
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
    [string]$PreviousProductCode,

    [Parameter(Mandatory=$false)]
    [ValidateSet("0", "1")]
    [string]$InstallVirtualHid
)

# Constants
$DocsUrl = "https://docs.lizardbyte.dev/projects/sunshine"
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
    Write-FramedText -Message "🔅 Sunshine Setup Script" -Level "Information" -Color "Cyan"
    Write-Information ""
    Write-LogMessage -Message "Please select an action:" -Level "Information" -Color "Yellow"
    Write-LogMessage -Message "  1. Install Sunshine" -Level "Information" -Color "Green"
    Write-LogMessage -Message "  2. Uninstall Sunshine" -Level "Information" -Color "Red"
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
    if ($PreviousProductCode) {
        $arguments += " -PreviousProductCode `"$PreviousProductCode`""
    }
    if ($InstallVirtualHid) {
        $arguments += " -InstallVirtualHid $InstallVirtualHid"
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
$logDir = Join-Path $env:TEMP "Sunshine\logs\$Action"
$LogPath = Join-Path $logDir "${timestamp}.log"

# Ensure the log directory exists
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

# Store LogPath in script scope for logging functions
$script:LogPath = $LogPath

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

# Function to execute sunshine.exe with arguments if it exists
function Invoke-SunshineIfExist {
    param(
        [string]$Arguments,
        [string]$Description = "",
        [string]$Emoji = "🔧"
    )

    if ($Description) {
        Write-LogMessage -Message "$Emoji $Description" -Level "Step"
    }

    $SunshinePath = Join-Path $RootDir "sunshine.exe"

    if (Test-Path $SunshinePath) {
        Write-LogMessage -Message "Executing: $SunshinePath $Arguments" -Level "Information"

        # Capture output to suppress it from console but log it
        $stdoutFile = [System.IO.Path]::GetTempFileName()
        $stderrFile = [System.IO.Path]::GetTempFileName()

        try {
            $process = Start-Process `
                -FilePath $SunshinePath `
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
                Write-LogMessage -Message "  ⚠ Sunshine exited with code $($process.ExitCode)" -Level "Warning"
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

    $virtualHidCtlPath = Join-Path $RootDir "tools\lumen-vhidctl.exe"
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
    if (-not (Test-Path -LiteralPath $installerRegistryPath)) {
        return $null
    }
    return [string](Get-ItemProperty `
        -LiteralPath $installerRegistryPath `
        -Name "SignerThumbprint" `
        -ErrorAction SilentlyContinue).SignerThumbprint
}

function Set-InstalledVirtualHidSignerThumbprint {
    param(
        [AllowNull()]
        [string]$Thumbprint
    )

    if ([string]::IsNullOrWhiteSpace($Thumbprint)) {
        if (Test-Path -LiteralPath $installerRegistryPath) {
            Remove-ItemProperty `
                -LiteralPath $installerRegistryPath `
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
}

$programDataDirectory = [System.Environment]::GetFolderPath(
    [System.Environment+SpecialFolder]::CommonApplicationData
)
$legacyProductCode = "{D14220B3-D6E3-40B9-A781-5965FC320AD8}"
$legacyRollbackDirectory = Join-Path $programDataDirectory "LumenVirtualHidInstaller"
$legacyRollbackStatePath = Join-Path $legacyRollbackDirectory "virtual-hid-rollback.json"
$legacyRollbackDriverDirectory = Join-Path $legacyRollbackDirectory "virtual-hid-driver"
$installerRegistryPath = "HKLM:\SOFTWARE\LizardByte\Lumen\VirtualHid"

function ConvertTo-CanonicalProductCode {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Value
    )

    $parsed = [Guid]::Empty
    if (-not [Guid]::TryParseExact($Value, "B", [ref]$parsed)) {
        throw "ProductCode must be an uppercase-braced GUID: $Value"
    }
    $canonical = $parsed.ToString("B").ToUpperInvariant()
    if ($Value -cne $canonical) {
        throw "ProductCode is not canonical: $Value"
    }
    return $canonical
}

$legacyMsiRollback = $Msi -and $Action -eq "rollback" -and
    [string]::IsNullOrWhiteSpace($ProductCode) -and
    [string]::IsNullOrWhiteSpace($TransactionKind)
if ($Action -eq "recover-legacy" -or $legacyMsiRollback) {
    # The exact 0.0.7 MSI did not pass scoped transaction arguments. Keep this
    # one bridge so its rollback action still works if the new script is on disk.
    $ProductCode = $legacyProductCode
    $TransactionKind = "uninstall"
} elseif ($Msi -or $ProductCode -or $Action -in @("rollback", "commit")) {
    if ([string]::IsNullOrWhiteSpace($ProductCode)) {
        throw "ProductCode is required for this installer action."
    }
    if ([string]::IsNullOrWhiteSpace($TransactionKind)) {
        throw "TransactionKind is required for this installer action."
    }
    $ProductCode = ConvertTo-CanonicalProductCode -Value $ProductCode
} else {
    $ProductCode = "{00000000-0000-0000-0000-000000000000}"
    if ([string]::IsNullOrWhiteSpace($TransactionKind)) {
        $TransactionKind = if ($Action -eq "uninstall") { "uninstall" } else { "install" }
    }
}
if ($Action -in @("install", "uninstall") -and $TransactionKind -ne $Action) {
    throw "TransactionKind '$TransactionKind' does not match action '$Action'."
}
if (-not [string]::IsNullOrWhiteSpace($PreviousProductCode)) {
    $PreviousProductCode = ConvertTo-CanonicalProductCode -Value $PreviousProductCode
    if ($PreviousProductCode -cne $legacyProductCode) {
        throw "Only the exact 0.0.7 ProductCode is supported as a legacy upgrade source."
    }
}
$virtualHidSelected = if ([string]::IsNullOrWhiteSpace($InstallVirtualHid)) {
    $true
} else {
    $InstallVirtualHid -eq "1"
}

$rollbackRootDirectory = Join-Path $programDataDirectory "LumenVirtualHidInstallerV2"
$rollbackProductDirectory = Join-Path $rollbackRootDirectory $ProductCode
$rollbackDirectory = Join-Path $rollbackProductDirectory $TransactionKind.ToLowerInvariant()
$rollbackStatePath = Join-Path $rollbackDirectory "virtual-hid-rollback.json"
$rollbackDriverDirectory = Join-Path $rollbackDirectory "virtual-hid-driver"
$script:RebootRequired = $false

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
        (Test-Path -LiteralPath $rollbackDriverDirectory)) {
        throw "A pending Virtual HID installer rollback transaction must be resolved before continuing."
    }
}

function Get-ServiceSnapshot {
    param(
        [string]$Name = "SunshineService"
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
        [bool]$DelayedAutoStart,
        [bool]$Running
    )

    $startArgument = switch ($StartMode) {
        "Auto" { if ($DelayedAutoStart) { "delayed-auto" } else { "auto" } }
        "Manual" { "demand" }
        "Disabled" { "disabled" }
        default { throw "Unsupported saved service start mode: $StartMode" }
    }
    $scPath = Join-Path $env:SystemRoot "System32\sc.exe"
    $output = & $scPath config SunshineService start= $startArgument 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Restoring the Sunshine service start mode failed: $($output -join ' ')"
    }
    $service = Get-Service -Name "SunshineService" -ErrorAction Stop
    if ($Running) {
        if ($StartMode -eq "Disabled") {
            throw "Saved service state is internally inconsistent: disabled and running."
        }
        if ($service.Status -ne "Running") {
            Start-Service -Name "SunshineService" -ErrorAction Stop
        }
        $service.WaitForStatus("Running", [TimeSpan]::FromSeconds(30))
    } else {
        if ($service.Status -ne "Stopped") {
            Stop-Service -Name "SunshineService" -Force -ErrorAction Stop
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
        Get-PnpDevice -ErrorAction Stop | Where-Object {
            $_.InstanceId -match '^ROOT\\LumenVirtualHid\\[^\\]+$'
        }
    )
    if ($devices.Count -ne 1) {
        throw "Expected exactly one active Lumen Virtual HID device; found $($devices.Count)."
    }

    $driverInfProperty = Get-PnpDeviceProperty `
        -InstanceId $devices[0].InstanceId `
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
        [bool]$ServiceDelayedAutoStart,
        [AllowNull()]
        [string]$BackedUpDriverInfPath,
        [AllowNull()]
        [string]$DriverSignerThumbprint,
        [AllowNull()]
        [string]$PreviousDriverSignerThumbprint,
        [bool]$DriverRollbackComplete = $false,
        [bool]$ServiceRollbackComplete = $false
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
        [bool]$ServiceDelayedAutoStart,
        [AllowNull()]
        [string]$DriverSignerThumbprint,
        [AllowNull()]
        [string]$PreviousDriverSignerThumbprint,
        [AllowNull()]
        [string]$DriverBackupSourceDirectory,
        [bool]$ServiceRollbackComplete = $false
    )

    Initialize-InstallRollbackDirectory
    Assert-NoPendingRollbackTransaction

    try {
        $backedUpDriverInfPath = $null
        if ($DriverWasPresent) {
            if ([string]::IsNullOrWhiteSpace($DriverBackupSourceDirectory)) {
                $installedDriverInfName = Get-InstalledVirtualHidInfName
                $backedUpDriverInfPath = Export-VirtualHidDriverBackup `
                    -PublishedInfName $installedDriverInfName
            } else {
                $source = Get-Item -LiteralPath $DriverBackupSourceDirectory -Force -ErrorAction Stop
                if (-not $source.PSIsContainer -or
                    ($source.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
                    throw "The supplied rollback driver backup is not a physical directory."
                }
                foreach ($item in @(Get-ChildItem -LiteralPath $source.FullName -Force -Recurse)) {
                    if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                        throw "The supplied rollback driver backup contains a reparse point."
                    }
                }
                Copy-Item `
                    -LiteralPath $source.FullName `
                    -Destination $rollbackDriverDirectory `
                    -Recurse `
                    -ErrorAction Stop
                $copiedInfFiles = @(
                    Get-ChildItem -LiteralPath $rollbackDriverDirectory -Filter "*.inf" -File -Recurse | `
                        Where-Object {
                            Select-String `
                                -LiteralPath $_.FullName `
                                -Pattern "ROOT\LumenVirtualHid" `
                                -SimpleMatch `
                                -Quiet
                        }
                )
                if ($copiedInfFiles.Count -ne 1) {
                    throw "The supplied rollback backup does not contain exactly one Lumen Virtual HID INF."
                }
                $backedUpDriverInfPath = $copiedInfFiles[0].FullName
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
            -ServiceRollbackComplete $ServiceRollbackComplete
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
    Write-LogMessage -Message "Rolling back Sunshine service and Virtual HID changes" -Level "Step"

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
        $serviceDelayedAutoStart = [bool]$rollbackState.ServiceDelayedAutoStart
        $backedUpDriverInfPath = [string]$rollbackState.BackedUpDriverInfPath
        $driverSignerThumbprint = [string]$rollbackState.DriverSignerThumbprint
        $previousDriverSignerThumbprint = [string]$rollbackState.PreviousDriverSignerThumbprint
        $driverRollbackComplete = [bool]$rollbackState.DriverRollbackComplete
        $serviceRollbackComplete = [bool]$rollbackState.ServiceRollbackComplete
    } catch {
        throw "Could not read rollback state; protected rollback artifacts were preserved: $($_.Exception.Message)"
    }

    if ([bool]$rollbackState.Committed) {
        Remove-InstallRollbackArtifacts
        Write-LogMessage -Message "Removed artifacts from an already committed transaction." -Level "Information"
        return $false
    }

    $rollbackErrors = [System.Collections.Generic.List[string]]::new()
    $driverNeedsRollback = $driverWasPresent -or $transactionKind -eq "install"
    if ($driverNeedsRollback) {
        $currentService = Get-Service -Name "SunshineService" -ErrorAction SilentlyContinue
        if ($null -ne $currentService -and $currentService.Status -ne "Stopped") {
            try {
                Stop-Service -Name "SunshineService" -Force -ErrorAction Stop
                $currentService.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
            } catch {
                $rollbackErrors.Add(
                    "Could not stop the Sunshine service before driver rollback: $($_.Exception.Message)"
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
            Invoke-VirtualHidCtl `
                -Arguments @("install-or-update", "`"$resolvedBackupInfPath`"") `
                -Description "Restoring the previous Lumen Virtual HID driver during rollback" | Out-Null
            $rollbackState.DriverRollbackComplete = $true
            Save-ParsedRollbackState -State $rollbackState
        } catch {
            $rollbackErrors.Add($_.Exception.Message) | Out-Null
        }
    } elseif (-not $driverRollbackComplete -and $transactionKind -eq "install") {
        try {
            Invoke-VirtualHidCtl `
                -Arguments @("uninstall") `
                -Description "Removing newly installed Lumen Virtual HID driver during rollback" | Out-Null
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

            $restoredService = Get-Service -Name "SunshineService" -ErrorAction SilentlyContinue
            if ($null -eq $restoredService) {
                throw "The Sunshine service is still absent after rollback."
            }
            if ([string]::IsNullOrWhiteSpace($serviceStartMode)) {
                if ($serviceWasRunning -and $restoredService.Status -ne "Running") {
                    Start-Service -Name "SunshineService" -ErrorAction Stop
                    $restoredService.WaitForStatus("Running", [TimeSpan]::FromSeconds(30))
                } elseif (-not $serviceWasRunning -and $restoredService.Status -ne "Stopped") {
                    Stop-Service -Name "SunshineService" -Force -ErrorAction Stop
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
            if ($null -ne (Get-Service -Name "SunshineService" -ErrorAction SilentlyContinue)) {
                throw "The newly installed Sunshine service is still present after rollback."
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
        (Test-Path -LiteralPath $rollbackDriverDirectory)) {
        Assert-InstallRollbackDirectorySecure
        if (-not (Test-Path -LiteralPath $rollbackStatePath -PathType Leaf)) {
            throw "The exact current installer transaction is incomplete and was preserved."
        }
        $pendingState = Read-RollbackState
        if ([bool]$pendingState.Committed) {
            Write-LogMessage -Message "Finishing committed installer cleanup" -Level "Warning"
            Invoke-PersistedCommit | Out-Null
        } else {
            Write-LogMessage `
                -Message "Recovering the exact current installer transaction before retry" `
                -Level "Warning"
            Invoke-PersistedRollback | Out-Null
        }
    }
}

function Invoke-LegacyRecovery {
    if ($ProductCode -cne $legacyProductCode) {
        throw "Legacy recovery is available only for the exact 0.0.7 ProductCode."
    }
    if (-not (Test-Path -LiteralPath $legacyRollbackDirectory -PathType Container)) {
        Write-LogMessage -Message "No stale 0.0.7 installer transaction was found." -Level "Information"
        return $false
    }
    Assert-InstallRollbackDirectorySecure -Path $legacyRollbackDirectory
    if (-not (Test-Path -LiteralPath $legacyRollbackStatePath -PathType Leaf)) {
        throw "Legacy rollback artifacts are incomplete and were preserved."
    }
    $legacyState = Get-Content -LiteralPath $legacyRollbackStatePath -Raw -ErrorAction Stop | `
        ConvertFrom-Json -ErrorAction Stop
    if ([string]$legacyState.TransactionKind -notin @("Install", "Uninstall")) {
        throw "Legacy rollback state has an invalid transaction kind."
    }

    $savedDirectory = $rollbackDirectory
    $savedStatePath = $rollbackStatePath
    $savedDriverDirectory = $rollbackDriverDirectory
    try {
        $script:rollbackDirectory = $legacyRollbackDirectory
        $script:rollbackStatePath = $legacyRollbackStatePath
        $script:rollbackDriverDirectory = $legacyRollbackDriverDirectory
        $legacyErrors = [System.Collections.Generic.List[string]]::new()
        if ([bool]$legacyState.DriverWasPresent) {
            try {
                $legacyInf = Resolve-BackedUpDriverInfPath -BackedUpDriverInfPath ([string]$legacyState.BackedUpDriverInfPath)
                Install-BackedUpVirtualHidCertificate | Out-Null
                Invoke-VirtualHidCtl `
                    -Arguments @("install-or-update", "`"$legacyInf`"") `
                    -Description "Recovering the exact 0.0.7 Virtual HID driver" | Out-Null
            } catch {
                $legacyErrors.Add($_.Exception.Message) | Out-Null
            }
        } elseif ([string]$legacyState.TransactionKind -eq "Install") {
            try {
                Invoke-VirtualHidCtl `
                    -Arguments @("uninstall") `
                    -Description "Removing the exact 0.0.7 Virtual HID install" | Out-Null
            } catch {
                $legacyErrors.Add($_.Exception.Message) | Out-Null
            }
        }
        if ([bool]$legacyState.ServiceWasPresent) {
            try {
                Invoke-SetupScript `
                    -ScriptPath (Join-Path $RootDir "scripts\install-service.bat") `
                    -Description "Recovering the 0.0.7 service" `
                    -Emoji "⚡"
                $service = Get-Service -Name "SunshineService" -ErrorAction Stop
                if ([bool]$legacyState.ServiceWasRunning) {
                    if ($service.Status -ne "Running") { Start-Service -Name "SunshineService" -ErrorAction Stop }
                    $service.WaitForStatus("Running", [TimeSpan]::FromSeconds(30))
                } else {
                    if ($service.Status -ne "Stopped") { Stop-Service -Name "SunshineService" -Force -ErrorAction Stop }
                    $service.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
                }
            } catch {
                $legacyErrors.Add($_.Exception.Message) | Out-Null
            }
        }
        if ($legacyErrors.Count -ne 0) {
            throw "Legacy recovery failed; exact 0.0.7 artifacts were preserved: $($legacyErrors -join '; ')"
        }
        Remove-Item -LiteralPath $legacyRollbackDirectory -Recurse -Force -ErrorAction Stop
        return $true
    } finally {
        $script:rollbackDirectory = $savedDirectory
        $script:rollbackStatePath = $savedStatePath
        $script:rollbackDriverDirectory = $savedDriverDirectory
    }
}

# Main script logic
Write-Information ""

try {
if ($Action -eq "install") {
    Invoke-ExactCurrentRecovery
    Write-FramedText `
        -Message "🔅 Sunshine Installation Script" `
        -Level "Information" `
        -Color "Yellow"
    Write-Information ""

    $totalSteps = 7
    $currentStep = 0

    # Reset permissions on the install directory
    $currentStep++
    Write-Progress `
        -Activity "Installing Sunshine" `
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
        -Activity "Installing Sunshine" `
        -Status "Updating system PATH" `
        -PercentComplete (($currentStep / $totalSteps) * 100)
    $updatePathScript = Join-Path $RootDir "scripts\update-path.bat"
    Invoke-ScriptIfExist `
        -ScriptPath $updatePathScript `
        -Arguments "add" `
        -Description "Adding Sunshine directories to PATH" `
        -Emoji "📁"
    Write-Information ""

    # 2. Migrate configuration
    $currentStep++
    Write-Progress `
        -Activity "Installing Sunshine" `
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
        -Activity "Installing Sunshine" `
        -Status "Configuring firewall" `
        -PercentComplete (($currentStep / $totalSteps) * 100)
    $addFirewallScript = Join-Path $RootDir "scripts\add-firewall-rule.bat"
    Invoke-ScriptIfExist `
        -ScriptPath $addFirewallScript `
        -Description "Adding firewall rules" `
        -Emoji "🛡️"
    Write-Information ""

    # 4. Install or update the Lumen Virtual HID driver. This must complete
    # before the service is installed or started.
    $currentStep++
    Write-Progress `
        -Activity "Installing Sunshine" `
        -Status "Installing Lumen Virtual HID driver" `
        -PercentComplete (($currentStep / $totalSteps) * 100)
    $driverInfPath = $null
    $driverSignerThumbprint = $null
    $driverCertificatePath = $null
    $previousDriverSignerThumbprint = Get-InstalledVirtualHidSignerThumbprint
    $legacyUpgradeCertificate = $null
    $legacyUpgradeState = $null
    if (-not [string]::IsNullOrWhiteSpace($PreviousProductCode)) {
        Assert-InstallRollbackDirectorySecure -Path $legacyRollbackDirectory
        if (-not (Test-Path -LiteralPath $legacyRollbackStatePath -PathType Leaf)) {
            throw "The exact 0.0.7 upgrade rollback state is incomplete and was preserved."
        }
        $legacyUpgradeState = Get-Content -LiteralPath $legacyRollbackStatePath -Raw -ErrorAction Stop | `
            ConvertFrom-Json -ErrorAction Stop
        if ([string]$legacyUpgradeState.TransactionKind -ne "Uninstall") {
            throw "The exact 0.0.7 upgrade rollback state is not an uninstall transaction."
        }
        if ([bool]$legacyUpgradeState.DriverWasPresent) {
            $legacyUpgradeCertificate = Get-BackedUpVirtualHidCertificate `
                -DriverDirectory $legacyRollbackDriverDirectory
            $previousDriverSignerThumbprint = $legacyUpgradeCertificate.Thumbprint
        }
    }
    $driverStatus = Invoke-VirtualHidCtl `
        -Arguments @("status") `
        -Description "Checking Lumen Virtual HID driver status" `
        -AllowNotInstalled
    if ($virtualHidSelected) {
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
    $serviceSnapshot = if ($Msi) {
        @{ Present = $false; Running = $false; StartMode = $null; DelayedAutoStart = $null }
    } else {
        Get-ServiceSnapshot
    }
    $existingService = if ($Msi) { $null } else { Get-Service -Name "SunshineService" -ErrorAction SilentlyContinue }
    $serviceWasPresent = $serviceSnapshot.Present
    $serviceWasRunning = $serviceSnapshot.Running
    $driverWasPresent = $driverStatus -in @(0, 4)
    $driverBackupSourceDirectory = $null
    $serviceRollbackComplete = [bool]$Msi
    if ($null -ne $legacyUpgradeState) {
        $driverWasPresent = [bool]$legacyUpgradeState.DriverWasPresent
        if ($driverWasPresent) {
            $driverBackupSourceDirectory = $legacyRollbackDriverDirectory
        }
        $serviceWasPresent = [bool]$legacyUpgradeState.ServiceWasPresent
        $serviceWasRunning = [bool]$legacyUpgradeState.ServiceWasRunning
        $serviceSnapshot.StartMode = [string]$legacyUpgradeState.ServiceStartMode
        $serviceSnapshot.DelayedAutoStart = [bool]$legacyUpgradeState.ServiceDelayedAutoStart
        $serviceRollbackComplete = $false
    }
    Start-PersistedRollbackTransaction `
        -TransactionKind "install" `
        -DriverWasPresent $driverWasPresent `
        -ServiceWasPresent $serviceWasPresent `
        -ServiceWasRunning $serviceWasRunning `
        -ServiceStartMode $serviceSnapshot.StartMode `
        -ServiceDelayedAutoStart $serviceSnapshot.DelayedAutoStart `
        -DriverSignerThumbprint $driverSignerThumbprint `
        -PreviousDriverSignerThumbprint $previousDriverSignerThumbprint `
        -DriverBackupSourceDirectory $driverBackupSourceDirectory `
        -ServiceRollbackComplete $serviceRollbackComplete
    if ($null -ne $legacyUpgradeCertificate) {
        $trustedLegacyThumbprint = Install-BackedUpVirtualHidCertificate `
            -DriverDirectory $legacyRollbackDriverDirectory
        if ($trustedLegacyThumbprint -ne $previousDriverSignerThumbprint) {
            throw "The trusted 0.0.7 signer does not match the saved rollback signer."
        }
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
            -Message "Stopping the Sunshine service before updating the Virtual HID driver" `
            -Level "Step"
        Stop-Service -Name "SunshineService" -Force -ErrorAction Stop
        $existingService.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
    }
    if ($virtualHidSelected) {
        Invoke-VirtualHidCtl `
            -Arguments @("install-or-update", "`"$driverInfPath`"") `
            -Description "Installing or updating the Lumen Virtual HID driver" | Out-Null
    } elseif ($driverStatus -in @(0, 4)) {
        Invoke-VirtualHidCtl `
            -Arguments @("uninstall") `
            -Description "Removing the deselected Lumen Virtual HID driver" | Out-Null
    }
    Write-Information ""

    # 5. Install service. MSI owns this through ServiceInstall/ServiceControl;
    # the scripts remain the NSIS path only.
    $currentStep++
    Write-Progress `
        -Activity "Installing Sunshine" `
        -Status "Installing service" `
        -PercentComplete (($currentStep / $totalSteps) * 100)
    if (-not $Msi) {
        $installServiceScript = Join-Path $RootDir "scripts\install-service.bat"
        Invoke-SetupScript `
            -ScriptPath $installServiceScript `
            -Description "Installing Windows Service" `
            -Emoji "⚡"
    } else {
        Write-LogMessage -Message "Windows Installer owns the Sunshine service." -Level "Information"
    }
    Write-Information ""

    # 6. Configure autostart
    $currentStep++
    Write-Progress `
        -Activity "Installing Sunshine" `
        -Status "Configuring autostart" `
        -PercentComplete (($currentStep / $totalSteps) * 100)
    if (-not $Msi) {
        $autostartScript = Join-Path $RootDir "scripts\autostart-service.bat"
        Invoke-SetupScript `
            -ScriptPath $autostartScript `
            -Description "Configuring autostart" `
            -Emoji "🚀"
    } else {
        Write-LogMessage -Message "Windows Installer owns the Sunshine service start mode." -Level "Information"
    }
    Write-Information ""

    Write-Progress -Activity "Installing Sunshine" -Completed
    if (-not $Msi) {
        Invoke-PersistedCommit | Out-Null
    }
    if ($script:RebootRequired) {
        Write-FramedText `
            -Message "✓ Lumen installed. Restart Windows to finish the Virtual HID driver operation." `
            -Level "Warning"
    } else {
        Write-FramedText -Message "✓ Sunshine installation completed successfully!" -Level "Success"
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
    Write-FramedText `
        -Message "🗑️  Sunshine Uninstallation Script" `
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
    $serviceSnapshot = Get-ServiceSnapshot
    $existingService = Get-Service -Name "SunshineService" -ErrorAction SilentlyContinue
    $legacyService = Get-Service -Name "sunshinesvc" -ErrorAction SilentlyContinue
    $uninstallServiceWasPresent = -not $Msi -and ($serviceSnapshot.Present -or $null -ne $legacyService)
    $uninstallServiceWasRunning = -not $Msi -and (`
        ($null -ne $existingService -and $existingService.Status -eq "Running") -or `
        ($null -ne $legacyService -and $legacyService.Status -eq "Running"))

    Start-PersistedRollbackTransaction `
        -TransactionKind "uninstall" `
        -DriverWasPresent $uninstallDriverWasPresent `
        -ServiceWasPresent $uninstallServiceWasPresent `
        -ServiceWasRunning $uninstallServiceWasRunning `
        -ServiceStartMode $serviceSnapshot.StartMode `
        -ServiceDelayedAutoStart $serviceSnapshot.DelayedAutoStart `
        -DriverSignerThumbprint $null `
        -PreviousDriverSignerThumbprint (Get-InstalledVirtualHidSignerThumbprint) `
        -ServiceRollbackComplete ([bool]$Msi)

    # 1. Stop and remove the service before touching the driver.
    $currentStep++
    Write-Progress `
        -Activity "Uninstalling Sunshine" `
        -Status "Uninstalling service" `
        -PercentComplete (($currentStep / $totalSteps) * 100)
    $uninstallServiceScript = Join-Path $RootDir "scripts\uninstall-service.bat"
    if ($Msi) {
        Write-LogMessage -Message "Windows Installer owns Sunshine service removal." -Level "Information"
    } elseif ($uninstallServiceWasPresent) {
        Invoke-SetupScript `
            -ScriptPath $uninstallServiceScript `
            -Description "Removing Windows Service" `
            -Emoji "⚡"
    } else {
        Write-LogMessage -Message "Windows Service is already absent." -Level "Information"
    }
    Write-Information ""

    # 2. Remove the root device and the Lumen-owned driver package. The helper
    # is idempotent and reports reboot-required cleanup as exit code 3010.
    $currentStep++
    Write-Progress `
        -Activity "Uninstalling Sunshine" `
        -Status "Removing Lumen Virtual HID driver" `
        -PercentComplete (($currentStep / $totalSteps) * 100)
    if ($virtualHidSelected) {
        Invoke-VirtualHidCtl `
            -Arguments @("uninstall") `
            -Description "Removing the Lumen Virtual HID device and driver package" | Out-Null
    } else {
        Write-LogMessage -Message "Lumen Virtual HID feature was not owned by this product." -Level "Information"
    }
    Write-Information ""

    # 3. Delete firewall rules
    $currentStep++
    Write-Progress `
        -Activity "Uninstalling Sunshine" `
        -Status "Removing firewall rules" `
        -PercentComplete (($currentStep / $totalSteps) * 100)
    $deleteFirewallScript = Join-Path $RootDir "scripts\delete-firewall-rule.bat"
    Invoke-ScriptIfExist `
        -ScriptPath $deleteFirewallScript `
        -Description "Removing firewall rules" `
        -Emoji "🛡️"
    Write-Information ""

    # 4. Restore NVIDIA preferences
    $currentStep++
    Write-Progress `
        -Activity "Uninstalling Sunshine" `
        -Status "Restoring NVIDIA settings" `
        -PercentComplete (($currentStep / $totalSteps) * 100)
    Invoke-SunshineIfExist `
        -Arguments "--restore-nvprefs-undo" `
        -Description "Restoring NVIDIA preferences" `
        -Emoji "🎮"
    Write-Information ""

    # 5. Update PATH (remove)
    $currentStep++
    Write-Progress `
        -Activity "Uninstalling Sunshine" `
        -Status "Cleaning up system PATH" `
        -PercentComplete (($currentStep / $totalSteps) * 100)
    $updatePathScript = Join-Path $RootDir "scripts\update-path.bat"
    Invoke-ScriptIfExist `
        -ScriptPath $updatePathScript `
        -Arguments "remove" `
        -Description "Removing from PATH" `
        -Emoji "📁"
    Write-Information ""

    Write-Progress -Activity "Uninstalling Sunshine" -Completed
    Write-FramedText `
        -Message "✓ Sunshine uninstallation completed successfully!" `
        -Level "Success"
    if (-not $Msi) {
        Invoke-PersistedCommit | Out-Null
    }
} elseif ($Action -eq "rollback") {
    $rollbackApplied = if ($legacyMsiRollback) {
        Invoke-LegacyRecovery
    } else {
        Invoke-PersistedRollback
    }
    if ($rollbackApplied) {
        Write-LogMessage -Message "Rollback completed." -Level "Success"
    }
} elseif ($Action -eq "commit") {
    Invoke-PersistedCommit | Out-Null
} elseif ($Action -eq "recover-legacy") {
    $legacyRecoveryApplied = Invoke-LegacyRecovery
    if ($legacyRecoveryApplied) {
        Write-LogMessage -Message "Exact 0.0.7 recovery completed." -Level "Success"
    }
}

} catch {
    Write-Progress -Activity "Sunshine Setup" -Completed
    $setupErrorMessage = $_.Exception.Message
    Write-LogMessage -Message $setupErrorMessage -Level "Error"
    if ($Action -in @("install", "uninstall")) {
        try {
            $rollbackApplied = Invoke-PersistedRollback
            if ($rollbackApplied) {
                Write-LogMessage -Message "Failed setup changes were rolled back." -Level "Success"
            }
        } catch {
            Write-LogMessage -Message $_.Exception.Message -Level "Error"
        }
    }
    Write-LogMessage `
        -Message "Sunshine setup failed. See $LogPath for details." `
        -Level "Error"
    exit 1
}

Write-Information ""
if ($script:RebootRequired) {
    Write-LogMessage `
        -Message "Windows must be restarted to finish the Virtual HID driver operation." `
        -Level "Warning"
    # Windows Installer treats every nonzero executable custom-action result as
    # failure. The driver APIs have already scheduled their reboot work, so MSI
    # receives success while NSIS retains 3010 and sets its reboot flag.
    if ($Msi) {
        exit 0
    }
    exit 3010
}
exit 0
