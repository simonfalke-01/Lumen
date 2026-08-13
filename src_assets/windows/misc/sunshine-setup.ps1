# Sunshine Setup Script
# This script orchestrates the installation and uninstallation of Sunshine
# Usage: sunshine-setup.ps1 -Action [install|uninstall|rollback|commit] [-Silent]

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet(
            "install",
            "install-driver",
            "uninstall",
            "rollback",
            "commit"
    )]
    [string]$Action,

    [Parameter(Mandatory=$false)]
    [switch]$Silent,

    [Parameter(Mandatory=$false)]
    [switch]$Msi
)

# Constants
$DocsUrl = "https://docs.lizardbyte.dev/projects/sunshine"

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
# the installer log. Exit code 3010 means cleanup completed but Windows needs a
# reboot to finish releasing the driver package.
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
                -Message "  Driver cleanup is scheduled and requires a reboot." `
                -Level "Warning"
            return $process.ExitCode
        }

        $isExpectedNotInstalled = $AllowNotInstalled -and $process.ExitCode -eq 1
        if ($process.ExitCode -ne 0 -and -not $isExpectedNotInstalled) {
            throw "$Description failed with exit code $($process.ExitCode)."
        }

        if ($process.ExitCode -eq 0) {
            Write-LogMessage -Message "  ✓ Done" -Level "Success"
        } elseif ($isExpectedNotInstalled) {
            Write-LogMessage -Message "  Lumen Virtual HID driver is not installed." -Level "Information"
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
    if ($certificateFiles.Count -ne 1) {
        throw "Expected exactly one Virtual HID certificate in $driverDirectory; found $($certificateFiles.Count)."
    }
    return $certificateFiles[0].FullName
}

$virtualHidInstallTaskName = "Lumen Virtual HID Driver Install"
$virtualHidTestSigningKey = "HKLM:\SOFTWARE\Lumen\VirtualHid"

function Test-SecureBootEnabled {
    $secureBootState = Get-ItemProperty `
        -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" `
        -Name "UEFISecureBootEnabled" `
        -ErrorAction SilentlyContinue
    return $null -ne $secureBootState -and $secureBootState.UEFISecureBootEnabled -eq 1
}

function Test-TestSigningActive {
    $systemStartOptions = Get-ItemPropertyValue `
        -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control" `
        -Name "SystemStartOptions" `
        -ErrorAction SilentlyContinue
    return [string]$systemStartOptions -match '(^|\s)TESTSIGNING($|\s)'
}

function Install-VirtualHidCertificate {
    param(
        [Parameter(Mandatory=$true)]
        [string]$CertificatePath
    )

    $certUtilPath = Join-Path $env:SystemRoot "System32\certutil.exe"
    if (-not (Test-Path $certUtilPath -PathType Leaf)) {
        throw "Required certificate utility not found: $certUtilPath"
    }

    foreach ($storeName in @("Root", "TrustedPublisher")) {
        Write-LogMessage `
            -Message "Trusting the Lumen Virtual HID development certificate in $storeName" `
            -Level "Step"
        $output = & $certUtilPath -f -addstore $storeName $CertificatePath 2>&1
        $exitCode = $LASTEXITCODE
        $output | ForEach-Object {
            if ($_ -and $_.ToString().Trim()) {
                Write-LogMessage -Message "  $_" -Level "Information" -Color "DarkGray"
            }
        }
        if ($exitCode -ne 0) {
            throw "Installing the Virtual HID certificate in $storeName failed with exit code $exitCode."
        }
    }
}

function Assert-VirtualHidPackageSignature {
    param(
        [Parameter(Mandatory=$true)]
        [string]$CertificatePath
    )

    $driverDirectory = Split-Path -Parent $CertificatePath
    $catalogFiles = @(Get-ChildItem -Path $driverDirectory -Filter "*.cat" -File)
    if ($catalogFiles.Count -ne 1) {
        throw "Expected exactly one Virtual HID catalog in $driverDirectory; found $($catalogFiles.Count)."
    }

    $expectedCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
        $CertificatePath
    )
    $signature = Get-AuthenticodeSignature -LiteralPath $catalogFiles[0].FullName
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
        $null -eq $signature.SignerCertificate -or
        $signature.SignerCertificate.Thumbprint -ne $expectedCertificate.Thumbprint) {
        throw "The Virtual HID catalog is not validly signed by the bundled certificate."
    }
}

function Remove-VirtualHidCertificate {
    param(
        [string]$Thumbprint
    )

    foreach ($storeName in @("Root", "TrustedPublisher")) {
        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
            $storeName,
            [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
        )
        try {
            $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            foreach ($certificate in @($store.Certificates)) {
                $matchesLumenCertificate = `
                    $certificate.Subject -eq "CN=Lumen Virtual HID Development Driver"
                $matchesRequestedCertificate = `
                    [string]::IsNullOrWhiteSpace($Thumbprint) -or `
                    $certificate.Thumbprint -eq $Thumbprint
                if ($matchesLumenCertificate -and $matchesRequestedCertificate) {
                    $store.Remove($certificate)
                }
            }
        } finally {
            $store.Close()
        }
    }
}

function Remove-VirtualHidInstallTask {
    Unregister-ScheduledTask `
        -TaskName $virtualHidInstallTaskName `
        -Confirm:$false `
        -ErrorAction SilentlyContinue
}

function Register-VirtualHidInstallTask {
    $powerShellPath = Join-Path `
        $env:SystemRoot `
        "System32\WindowsPowerShell\v1.0\powershell.exe"
    $setupScriptPath = Join-Path $RootDir "scripts\sunshine-setup.ps1"
    $taskAction = New-ScheduledTaskAction `
        -Execute $powerShellPath `
        -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$setupScriptPath`" -Action install-driver -Silent"
    $taskTrigger = New-ScheduledTaskTrigger -AtStartup
    $taskPrincipal = New-ScheduledTaskPrincipal `
        -UserId "SYSTEM" `
        -LogonType ServiceAccount `
        -RunLevel Highest
    $taskSettings = New-ScheduledTaskSettingsSet `
        -StartWhenAvailable `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 10)

    Register-ScheduledTask `
        -TaskName $virtualHidInstallTaskName `
        -Action $taskAction `
        -Trigger $taskTrigger `
        -Principal $taskPrincipal `
        -Settings $taskSettings `
        -Description "Finishes installing the test-signed Lumen Virtual HID driver after restart." `
        -Force | Out-Null
}

function Enable-VirtualHidTestSigning {
    if (Test-SecureBootEnabled) {
        throw "Secure Boot is enabled. Disable Secure Boot in UEFI firmware, then run the Lumen installer again so Windows can load the test-signed Virtual HID driver."
    }

    $bcdEditPath = Join-Path $env:SystemRoot "System32\bcdedit.exe"
    if (-not (Test-Path $bcdEditPath -PathType Leaf)) {
        throw "Required boot configuration utility not found: $bcdEditPath"
    }

    Write-LogMessage -Message "Enabling Windows test-signing mode" -Level "Step"
    $output = & $bcdEditPath /set testsigning on 2>&1
    $exitCode = $LASTEXITCODE
    $output | ForEach-Object {
        if ($_ -and $_.ToString().Trim()) {
            Write-LogMessage -Message "  $_" -Level "Information" -Color "DarkGray"
        }
    }
    if ($exitCode -ne 0) {
        throw "Enabling Windows test-signing mode failed with exit code $exitCode."
    }

    New-Item -Path $virtualHidTestSigningKey -Force | Out-Null
    New-ItemProperty `
        -Path $virtualHidTestSigningKey `
        -Name "TestSigningEnabledByLumen" `
        -PropertyType DWord `
        -Value 1 `
        -Force | Out-Null

    Register-VirtualHidInstallTask
    $script:RebootRequired = $true
    Write-LogMessage `
        -Message "Restart Windows to activate test-signing mode and finish installing the Virtual HID driver." `
        -Level "Warning"
}

function Disable-VirtualHidTestSigningIfOwned {
    $enabledByLumen = Get-ItemPropertyValue `
        -LiteralPath $virtualHidTestSigningKey `
        -Name "TestSigningEnabledByLumen" `
        -ErrorAction SilentlyContinue
    if ($enabledByLumen -ne 1) {
        return
    }

    $bcdEditPath = Join-Path $env:SystemRoot "System32\bcdedit.exe"
    if (-not (Test-Path $bcdEditPath -PathType Leaf)) {
        throw "Required boot configuration utility not found: $bcdEditPath"
    }

    Write-LogMessage -Message "Disabling Lumen-owned Windows test-signing mode" -Level "Step"
    $output = & $bcdEditPath /set testsigning off 2>&1
    $exitCode = $LASTEXITCODE
    $output | ForEach-Object {
        if ($_ -and $_.ToString().Trim()) {
            Write-LogMessage -Message "  $_" -Level "Information" -Color "DarkGray"
        }
    }
    if ($exitCode -ne 0) {
        throw "Disabling Windows test-signing mode failed with exit code $exitCode."
    }

    Remove-Item -LiteralPath $virtualHidTestSigningKey -Recurse -Force -ErrorAction SilentlyContinue
    $script:RebootRequired = $true
}

$programDataDirectory = [System.Environment]::GetFolderPath(
    [System.Environment+SpecialFolder]::CommonApplicationData
)
$rollbackDirectory = Join-Path $programDataDirectory "LumenVirtualHidInstaller"
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
    $directory = Get-Item -LiteralPath $rollbackDirectory -Force -ErrorAction Stop
    if (-not $directory.PSIsContainer -or
        ($directory.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        throw "Installer rollback path is not a physical directory: $rollbackDirectory"
    }

    $acl = Get-Acl -LiteralPath $rollbackDirectory -ErrorAction Stop
    if (-not $acl.AreAccessRulesProtected) {
        throw "Installer rollback directory inherits access rules: $rollbackDirectory"
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
    if (Test-Path -LiteralPath $rollbackDirectory) {
        Assert-InstallRollbackDirectorySecure
        return
    } else {
        try {
            [System.IO.Directory]::CreateDirectory(
                $rollbackDirectory,
                (New-InstallRollbackDirectoryAcl)
            ) | Out-Null
        } catch [System.Management.Automation.MethodException] {
            throw "Atomic protected rollback-directory creation is unavailable on this Windows runtime."
        }
    }

    Assert-InstallRollbackDirectorySecure
}

function Assert-NoPendingRollbackTransaction {
    if ((Test-Path -LiteralPath $rollbackStatePath) -or
        (Test-Path -LiteralPath $rollbackDriverDirectory)) {
        throw "A pending Virtual HID installer rollback transaction must be resolved before continuing."
    }
}

function Remove-InstallRollbackArtifacts {
    if (Test-Path -LiteralPath $rollbackDriverDirectory) {
        try {
            $backupItem = Get-Item -LiteralPath $rollbackDriverDirectory -Force -ErrorAction Stop
            if ($backupItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                Remove-Item -LiteralPath $rollbackDriverDirectory -Force -ErrorAction Stop
            } else {
                Remove-Item -LiteralPath $rollbackDriverDirectory -Recurse -Force -ErrorAction Stop
            }
        } catch {
            Write-LogMessage `
                -Message "Could not remove the Virtual HID driver backup: $($_.Exception.Message)" `
                -Level "Warning"
        }
    }
    if (Test-Path -LiteralPath $rollbackStatePath) {
        try {
            Remove-Item -LiteralPath $rollbackStatePath -Force -ErrorAction Stop
        } catch {
            Write-LogMessage `
                -Message "Could not remove the installer rollback state: $($_.Exception.Message)" `
                -Level "Warning"
        }
    }
}

function Get-InstalledVirtualHidInfName {
    $devices = @(
        Get-PnpDevice -PresentOnly -ErrorAction Stop | Where-Object {
            $_.InstanceId -like "ROOT\LumenVirtualHid\*"
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
        [string]$BackedUpDriverInfPath
    )

    @{
        TransactionKind = $TransactionKind
        DriverWasPresent = $DriverWasPresent
        ServiceWasPresent = $ServiceWasPresent
        ServiceWasRunning = $ServiceWasRunning
        BackedUpDriverInfPath = $BackedUpDriverInfPath
    } | ConvertTo-Json | Set-Content `
        -LiteralPath $rollbackStatePath `
        -Encoding UTF8 `
        -ErrorAction Stop
}

function Start-PersistedRollbackTransaction {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("Install", "Uninstall")]
        [string]$TransactionKind,
        [bool]$DriverWasPresent,
        [bool]$ServiceWasPresent,
        [bool]$ServiceWasRunning
    )

    Initialize-InstallRollbackDirectory
    Assert-NoPendingRollbackTransaction

    try {
        $backedUpDriverInfPath = $null
        if ($DriverWasPresent) {
            $installedDriverInfName = Get-InstalledVirtualHidInfName
            $backedUpDriverInfPath = Export-VirtualHidDriverBackup `
                -PublishedInfName $installedDriverInfName
        }
        Save-RollbackState `
            -TransactionKind $TransactionKind `
            -DriverWasPresent $DriverWasPresent `
            -ServiceWasPresent $ServiceWasPresent `
            -ServiceWasRunning $ServiceWasRunning `
            -BackedUpDriverInfPath $backedUpDriverInfPath
    } catch {
        Remove-InstallRollbackArtifacts
        throw
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
    return $resolvedBackupInfPath
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
        $rollbackState = Get-Content -LiteralPath $rollbackStatePath -Raw -ErrorAction Stop | `
            ConvertFrom-Json -ErrorAction Stop
        $transactionKind = [string]$rollbackState.TransactionKind
        if ($transactionKind -notin @("Install", "Uninstall")) {
            throw "Rollback state has an invalid transaction kind: $transactionKind"
        }
        $driverWasPresent = [bool]$rollbackState.DriverWasPresent
        $serviceWasPresent = [bool]$rollbackState.ServiceWasPresent
        $serviceWasRunning = [bool]$rollbackState.ServiceWasRunning
        $backedUpDriverInfPath = [string]$rollbackState.BackedUpDriverInfPath
    } catch {
        throw "Could not read rollback state; protected rollback artifacts were preserved: $($_.Exception.Message)"
    }

    $rollbackErrors = [System.Collections.Generic.List[string]]::new()
    $driverNeedsRollback = $driverWasPresent -or $transactionKind -eq "Install"
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

    if ($driverWasPresent) {
        try {
            $resolvedBackupInfPath = Resolve-BackedUpDriverInfPath `
                -BackedUpDriverInfPath $backedUpDriverInfPath
            Invoke-VirtualHidCtl `
                -Arguments @("install-or-update", "`"$resolvedBackupInfPath`"") `
                -Description "Restoring the previous Lumen Virtual HID driver during rollback" | Out-Null
        } catch {
            $rollbackErrors.Add($_.Exception.Message) | Out-Null
        }
    } elseif ($transactionKind -eq "Install") {
        try {
            Invoke-VirtualHidCtl `
                -Arguments @("uninstall") `
                -Description "Removing newly installed Lumen Virtual HID driver during rollback" | Out-Null
        } catch {
            $rollbackErrors.Add($_.Exception.Message) | Out-Null
        }
    }

    if ($serviceWasPresent) {
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
            if ($serviceWasRunning) {
                if ($restoredService.Status -ne "Running") {
                    Start-Service -Name "SunshineService" -ErrorAction Stop
                }
                $restoredService.WaitForStatus("Running", [TimeSpan]::FromSeconds(30))
            } else {
                if ($restoredService.Status -ne "Stopped") {
                    Stop-Service -Name "SunshineService" -Force -ErrorAction Stop
                }
                $restoredService.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
            }
        } catch {
            $rollbackErrors.Add($_.Exception.Message) | Out-Null
        }
    } elseif ($transactionKind -eq "Install") {
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

    Remove-InstallRollbackArtifacts
    return $true
}

# Main script logic
Write-Information ""

try {
if ($Action -eq "install-driver") {
    $driverInfPath = Get-VirtualHidInfPath
    $driverCertificatePath = Get-VirtualHidCertificatePath
    Install-VirtualHidCertificate -CertificatePath $driverCertificatePath
    Assert-VirtualHidPackageSignature -CertificatePath $driverCertificatePath

    if (-not (Test-TestSigningActive)) {
        throw "Windows test-signing mode is not active after restart; the Virtual HID driver cannot be loaded."
    }

    Invoke-VirtualHidCtl `
        -Arguments @("install-or-update", "`"$driverInfPath`"") `
        -Description "Finishing Lumen Virtual HID driver installation" | Out-Null
    Remove-VirtualHidInstallTask

    $installedService = Get-Service -Name "SunshineService" -ErrorAction SilentlyContinue
    if ($null -ne $installedService) {
        if ($installedService.Status -ne "Stopped") {
            Stop-Service -Name "SunshineService" -Force -ErrorAction Stop
            $installedService.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
        }
        Start-Service -Name "SunshineService" -ErrorAction Stop
        $installedService.WaitForStatus("Running", [TimeSpan]::FromSeconds(30))
    }
    Write-FramedText `
        -Message "✓ Lumen Virtual HID driver installation completed successfully!" `
        -Level "Success"
} elseif ($Action -eq "install") {
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
    $driverInfPath = Get-VirtualHidInfPath
    $driverCertificatePath = Get-VirtualHidCertificatePath
    Install-VirtualHidCertificate -CertificatePath $driverCertificatePath
    Assert-VirtualHidPackageSignature -CertificatePath $driverCertificatePath
    $driverStatus = Invoke-VirtualHidCtl `
        -Arguments @("status") `
        -Description "Checking Lumen Virtual HID driver status" `
        -AllowNotInstalled
    $existingService = Get-Service -Name "SunshineService" -ErrorAction SilentlyContinue
    $serviceWasPresent = $null -ne $existingService
    $serviceWasRunning = $serviceWasPresent -and $existingService.Status -eq "Running"
    Start-PersistedRollbackTransaction `
        -TransactionKind "Install" `
        -DriverWasPresent ($driverStatus -eq 0) `
        -ServiceWasPresent $serviceWasPresent `
        -ServiceWasRunning $serviceWasRunning
    if ($serviceWasRunning) {
        Write-LogMessage `
            -Message "Stopping the Sunshine service before updating the Virtual HID driver" `
            -Level "Step"
        Stop-Service -Name "SunshineService" -Force -ErrorAction Stop
        $existingService.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
    }
    if (Test-TestSigningActive) {
        Invoke-VirtualHidCtl `
            -Arguments @("install-or-update", "`"$driverInfPath`"") `
            -Description "Installing or updating the Lumen Virtual HID driver" | Out-Null
        Remove-VirtualHidInstallTask
    } else {
        Enable-VirtualHidTestSigning
    }
    Write-Information ""

    # 5. Install service
    $currentStep++
    Write-Progress `
        -Activity "Installing Sunshine" `
        -Status "Installing service" `
        -PercentComplete (($currentStep / $totalSteps) * 100)
    $installServiceScript = Join-Path $RootDir "scripts\install-service.bat"
    Invoke-SetupScript `
        -ScriptPath $installServiceScript `
        -Description "Installing Windows Service" `
        -Emoji "⚡"
    Write-Information ""

    # 6. Configure autostart
    $currentStep++
    Write-Progress `
        -Activity "Installing Sunshine" `
        -Status "Configuring autostart" `
        -PercentComplete (($currentStep / $totalSteps) * 100)
    $autostartScript = Join-Path $RootDir "scripts\autostart-service.bat"
    Invoke-SetupScript `
        -ScriptPath $autostartScript `
        -Description "Configuring autostart" `
        -Emoji "🚀"
    Write-Information ""

    Write-Progress -Activity "Installing Sunshine" -Completed
    if (-not $Msi) {
        Remove-InstallRollbackArtifacts
    }
    if ($script:RebootRequired) {
        Write-FramedText `
            -Message "✓ Lumen installed. Restart Windows to activate the Virtual HID driver." `
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
    Write-FramedText `
        -Message "🗑️  Sunshine Uninstallation Script" `
        -Level "Information" `
        -Color "Yellow"
    Write-Information ""

    $totalSteps = 5
    $currentStep = 0

    Remove-VirtualHidInstallTask

    $driverStatus = Invoke-VirtualHidCtl `
        -Arguments @("status") `
        -Description "Checking Lumen Virtual HID driver status before uninstall" `
        -AllowNotInstalled
    $uninstallDriverWasPresent = $driverStatus -eq 0
    $existingService = Get-Service -Name "SunshineService" -ErrorAction SilentlyContinue
    $legacyService = Get-Service -Name "sunshinesvc" -ErrorAction SilentlyContinue
    $uninstallServiceWasPresent = $null -ne $existingService -or $null -ne $legacyService
    $uninstallServiceWasRunning = `
        ($null -ne $existingService -and $existingService.Status -eq "Running") -or `
        ($null -ne $legacyService -and $legacyService.Status -eq "Running")

    Start-PersistedRollbackTransaction `
        -TransactionKind "Uninstall" `
        -DriverWasPresent $uninstallDriverWasPresent `
        -ServiceWasPresent $uninstallServiceWasPresent `
        -ServiceWasRunning $uninstallServiceWasRunning

    # 1. Stop and remove the service before touching the driver.
    $currentStep++
    Write-Progress `
        -Activity "Uninstalling Sunshine" `
        -Status "Uninstalling service" `
        -PercentComplete (($currentStep / $totalSteps) * 100)
    $uninstallServiceScript = Join-Path $RootDir "scripts\uninstall-service.bat"
    if ($uninstallServiceWasPresent) {
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
    Invoke-VirtualHidCtl `
        -Arguments @("uninstall") `
        -Description "Removing the Lumen Virtual HID device and driver package" | Out-Null
    Remove-VirtualHidCertificate
    Disable-VirtualHidTestSigningIfOwned
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
        Remove-InstallRollbackArtifacts
    }
} elseif ($Action -eq "rollback") {
    $rollbackApplied = Invoke-PersistedRollback
    if ($rollbackApplied) {
        Write-LogMessage -Message "Rollback completed." -Level "Success"
    }
} elseif ($Action -eq "commit") {
    Assert-InstallRollbackDirectorySecure
    Remove-InstallRollbackArtifacts
    Write-LogMessage -Message "Installer transaction committed." -Level "Success"
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
            if ($Action -eq "install") {
                Remove-VirtualHidInstallTask
                try {
                    $bundledCertificatePath = Get-VirtualHidCertificatePath
                    $bundledCertificate = `
                        [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
                            $bundledCertificatePath
                        )
                    Remove-VirtualHidCertificate -Thumbprint $bundledCertificate.Thumbprint
                } catch {
                    Write-LogMessage `
                        -Message "Could not remove the bundled Virtual HID certificate: $($_.Exception.Message)" `
                        -Level "Warning"
                }
                Disable-VirtualHidTestSigningIfOwned
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
