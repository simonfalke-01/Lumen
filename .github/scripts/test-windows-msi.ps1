param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('install-no-vhid', 'install-vhid', 'install-vmic', 'upgrade', 'legacy-import')]
    [string]$Scenario
)

$ErrorActionPreference = 'Stop'
$msiTimeoutMilliseconds = 15 * 60 * 1000
$artifactDirectory = (Resolve-Path 'artifacts').Path
$msiCandidates = @(Get-ChildItem 'artifacts/Lumen-*-Windows-AMD64-installer.msi' -File)
if ($msiCandidates.Count -ne 1) {
    throw 'Expected exactly one versioned Lumen Windows MSI artifact.'
}
$msiPath = (Resolve-Path $msiCandidates[0].FullName).Path
$productCode = [string]$env:MSI_PRODUCT_CODE
if ([string]::IsNullOrWhiteSpace($productCode)) {
    throw 'MSI_PRODUCT_CODE was not populated by MSI table validation.'
}

function Invoke-Msi {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,
        [Parameter(Mandatory = $true)]
        [string]$LogName,
        [Parameter(Mandatory = $true)]
        [string]$FailureMessage
    )

    $logPath = Join-Path $artifactDirectory $LogName
    $msiArguments = $Arguments + @('/L*V', "`"$logPath`"")
    $process = Start-Process msiexec.exe -PassThru -ArgumentList $msiArguments
    if (-not $process.WaitForExit($msiTimeoutMilliseconds)) {
        & taskkill.exe /PID $process.Id /T /F | Out-Null
        $process.WaitForExit()
        if (Test-Path -LiteralPath $logPath -PathType Leaf) {
            Get-Content $logPath
        }
        throw "$FailureMessage Timed out after 15 minutes."
    }
    if ($process.ExitCode -notin @(0, 3010)) {
        Get-Content $logPath
        throw "$FailureMessage Exit code: $($process.ExitCode)."
    }
    return $process.ExitCode
}

function Assert-ServiceRunning {
    $service = Get-Service LumenService -ErrorAction Stop
    if ($service.Status -ne 'Running') {
        throw 'LumenService is not running after MSI installation.'
    }
    $deadline = (Get-Date).AddSeconds(30)
    do {
        $hostProcess = Get-Process Lumen -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($null -ne $hostProcess) {
            return
        }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $deadline)
    throw 'LumenService is running but did not launch Lumen.exe.'
}

function Assert-VirtualHidHealthy {
    param([string]$FailureLog)

    $helper = 'C:\Program Files\Lumen\tools\lumen-vhidctl.exe'
    $vigemInstaller = 'C:\Program Files\Lumen\third-party\vigembus_installer.exe'
    if (-not (Test-Path -LiteralPath $vigemInstaller -PathType Leaf)) {
        throw "Bundled ViGEmBus installer is missing: $vigemInstaller"
    }
    $vigemInstall = Start-Process `
        -FilePath $vigemInstaller `
        -ArgumentList @('/install', '/quiet', '/norestart') `
        -Wait `
        -PassThru
    if ($vigemInstall.ExitCode -eq 3010) {
        throw 'ViGEmBus installation requires a reboot; XInput validation cannot continue.'
    }
    if ($vigemInstall.ExitCode -ne 0) {
        throw "ViGEmBus installation failed with exit code $($vigemInstall.ExitCode)."
    }
    Restart-Service -Name LumenService -Force
    Assert-ServiceRunning
    $statusOutput = @(& $helper status --json)
    $statusExitCode = $LASTEXITCODE
    $statusText = ($statusOutput -join [Environment]::NewLine).Trim()
    Write-Host $statusText
    try {
        $status = $statusText | ConvertFrom-Json -ErrorAction Stop
    } catch {
        Get-Content (Join-Path $artifactDirectory $FailureLog)
        throw "Virtual HID status did not return valid JSON: $($_.Exception.Message)"
    }
    if ($statusExitCode -ne 0 -or
        $status.state -ne 'installed' -or
        [int]$status.rootDevices -ne 1 -or
        [int]$status.keyboards -ne 1 -or
        [int]$status.mice -ne 2 -or
        [int]$status.consumers -ne 1 -or
        $status.control -ne 'inaccessible' -or
        [int]$status.controlWin32 -ne 5) {
        Get-Content (Join-Path $artifactDirectory $FailureLog)
        throw (
            'Virtual HID runneradmin status contract mismatch: ' +
            "exit=$statusExitCode state='$($status.state)' roots=$($status.rootDevices) " +
            "keyboards=$($status.keyboards) mice=$($status.mice) consumers=$($status.consumers) " +
            "control='$($status.control)' win32=$($status.controlWin32)."
        )
    }
    $taskName = "Lumen-VHID-Probe-$([Guid]::NewGuid().ToString('N'))"
    $probeScript = Join-Path $artifactDirectory 'lumen-vhid-probe.ps1'
    $probeOutput = Join-Path $artifactDirectory 'lumen-vhid-probe.json'
    $probeExit = Join-Path $artifactDirectory 'lumen-vhid-probe.exit'
    $smokeOutput = Join-Path $artifactDirectory 'lumen-vhid-gamepad-smoke.json'
    $smokeExit = Join-Path $artifactDirectory 'lumen-vhid-gamepad-smoke.exit'
    $vigemOutput = Join-Path $artifactDirectory 'lumen-vigem-smoke.json'
    $vigemExit = Join-Path $artifactDirectory 'lumen-vigem-smoke.exit'
    $escapedHelper = $helper.Replace("'", "''")
    $escapedProbeOutput = $probeOutput.Replace("'", "''")
    $escapedProbeExit = $probeExit.Replace("'", "''")
    $escapedSmokeOutput = $smokeOutput.Replace("'", "''")
    $escapedSmokeExit = $smokeExit.Replace("'", "''")
    $escapedVigemOutput = $vigemOutput.Replace("'", "''")
    $escapedVigemExit = $vigemExit.Replace("'", "''")
    Remove-Item $probeOutput, $probeExit, $smokeOutput, $smokeExit, $vigemOutput, $vigemExit -Force -ErrorAction SilentlyContinue
    @"
& '$escapedHelper' probe --json | Set-Content -LiteralPath '$escapedProbeOutput' -Encoding UTF8
`$probeExitCode = `$LASTEXITCODE
Set-Content -LiteralPath '$escapedProbeExit' -Value `$probeExitCode -NoNewline
& '$escapedHelper' smoke-gamepad --json | Set-Content -LiteralPath '$escapedSmokeOutput' -Encoding UTF8
`$smokeExitCode = `$LASTEXITCODE
Set-Content -LiteralPath '$escapedSmokeExit' -Value `$smokeExitCode -NoNewline
& '$escapedHelper' smoke-vigem --json | Set-Content -LiteralPath '$escapedVigemOutput' -Encoding UTF8
`$vigemExitCode = `$LASTEXITCODE
Set-Content -LiteralPath '$escapedVigemExit' -Value `$vigemExitCode -NoNewline
"@ | Set-Content -LiteralPath $probeScript -Encoding UTF8

    $action = New-ScheduledTaskAction `
        -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$probeScript`""
    $principal = New-ScheduledTaskPrincipal `
        -UserId 'SYSTEM' `
        -LogonType ServiceAccount `
        -RunLevel Highest
    try {
        Register-ScheduledTask `
            -TaskName $taskName `
            -Action $action `
            -Principal $principal `
            -Force | Out-Null
        Start-ScheduledTask -TaskName $taskName
        $deadline = (Get-Date).AddSeconds(300)
        while (-not (Test-Path -LiteralPath $vigemExit -PathType Leaf) -and
            (Get-Date) -lt $deadline) {
            Start-Sleep -Milliseconds 100
        }
        if (-not (Test-Path -LiteralPath $vigemExit -PathType Leaf)) {
            throw 'Virtual HID protocol, gamepad, or ViGEm/XInput smoke timed out.'
        }
        $probeText = (Get-Content -LiteralPath $probeOutput -Raw).Trim()
        Write-Host $probeText
        $probeExitCode = [int](Get-Content -LiteralPath $probeExit -Raw)
        if ($probeExitCode -ne 0) {
            Get-Content (Join-Path $artifactDirectory $FailureLog)
            throw "Virtual HID protocol probe failed with exit code $probeExitCode."
        }
        try {
            $probe = $probeText | ConvertFrom-Json -ErrorAction Stop
        } catch {
            throw "Virtual HID SYSTEM probe did not return valid JSON: $($_.Exception.Message)"
        }
        if ($probe.state -ne 'compatible' -or
            [int]$probe.protocolGeneration -ne 3 -or
            [int]$probe.abiVersion -ne 2 -or
            [int]$probe.gamepadAbiVersion -ne 1 -or
            (([int]$probe.gamepadCapabilityFlags -band 15) -ne 15) -or
            (([int64]$probe.supportedGamepadProfiles -band 125) -ne 125) -or
            (([int64]$probe.supportedGamepadProfiles -band 2) -ne 0) -or
            [int]$probe.maxGamepads -ne 16 -or
            [int]$probe.activeGamepads -ne 0) {
            throw "Virtual HID SYSTEM capability contract mismatch: $probeText"
        }

        $smokeText = (Get-Content -LiteralPath $smokeOutput -Raw).Trim()
        Write-Host $smokeText
        $smokeExitCode = [int](Get-Content -LiteralPath $smokeExit -Raw)
        if ($smokeExitCode -ne 0) {
            Get-Content (Join-Path $artifactDirectory $FailureLog)
            throw "Virtual HID dynamic-gamepad smoke failed with exit code $smokeExitCode."
        }
        try {
            $smoke = $smokeText | ConvertFrom-Json -ErrorAction Stop
        } catch {
            throw "Virtual HID gamepad smoke did not return valid JSON: $($_.Exception.Message)"
        }
        if ($smoke.state -ne 'passed' -or
            [int]$smoke.protocolGeneration -ne 3 -or
            [int]$smoke.gamepadAbiVersion -ne 1 -or
            $smoke.profile -ne 'generic' -or
            $smoke.enumerated -ne $true -or
            $smoke.tokenRejected -ne $true -or
            $smoke.deviceRejected -ne $true -or
            $smoke.crossFileRejected -ne $true -or
            $smoke.ownerCleanup -ne $true -or
            [int]$smoke.profilesValidated -ne 6 -or
            [int]$smoke.capacity -ne 16 -or
            $smoke.overflowRejected -ne $true -or
            $smoke.submitted -ne $true -or
            $smoke.input -ne 'received' -or
            $smoke.output -ne 'received' -or
            $smoke.destroyed -ne $true -or
            [int]$smoke.activeGamepads -ne 0) {
            throw "Virtual HID dynamic-gamepad smoke contract mismatch: $smokeText"
        }

        $vigemText = (Get-Content -LiteralPath $vigemOutput -Raw).Trim()
        Write-Host $vigemText
        $vigemExitCode = [int](Get-Content -LiteralPath $vigemExit -Raw)
        if ($vigemExitCode -ne 0) {
            Get-Content (Join-Path $artifactDirectory $FailureLog)
            throw "ViGEm/XInput smoke failed with exit code $vigemExitCode."
        }
        try {
            $vigem = $vigemText | ConvertFrom-Json -ErrorAction Stop
        } catch {
            throw "ViGEm/XInput smoke did not return valid JSON: $($_.Exception.Message)"
        }
        if ($vigem.state -ne 'passed' -or
            $vigem.backend -ne 'vigem' -or
            $vigem.profile -ne 'x360' -or
            [int]$vigem.xinputIndex -lt 0 -or
            [int]$vigem.xinputIndex -ge 4) {
            throw "ViGEm/XInput smoke contract mismatch: $vigemText"
        }
    } finally {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Item $probeScript, $probeExit, $smokeExit, $vigemExit -Force -ErrorAction SilentlyContinue
    }
}

function Assert-VirtualHidRemoved {
    $helper = 'C:\Program Files\Lumen\tools\lumen-vhidctl.exe'
    $dynamicIdentities = @(
        'VID_1209&PID_0001',
        'VID_045E&PID_02EA',
        'VID_045E&PID_0B12',
        'VID_054C&PID_05C4',
        'VID_054C&PID_0CE6',
        'VID_057E&PID_2009'
    )
    $deadline = (Get-Date).AddSeconds(30)
    do {
        $roots = @(Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object {
            $_.InstanceId -like 'ROOT\LUMENVIRTUALHID*'
        })
        $hidCollections = @(Get-PnpDevice -PresentOnly -Class HIDClass -ErrorAction SilentlyContinue | Where-Object {
            $instanceId = $_.InstanceId
            $instanceId -match 'VID_4C42&PID_0001' -or
                @($dynamicIdentities | Where-Object { $instanceId -match [regex]::Escape($_) }).Count -ne 0
        })
        $driverStoreText = (& pnputil.exe /enum-drivers /files 2>&1 | Out-String)
        if ($LASTEXITCODE -ne 0) {
            throw "pnputil failed while verifying Virtual HID removal: $driverStoreText"
        }
        $packagePresent = $driverStoreText -match '(?im)LumenVirtualHid\.inf'
        $helperPresent = Test-Path -LiteralPath $helper -PathType Leaf
        if ($roots.Count -eq 0 -and
            $hidCollections.Count -eq 0 -and
            -not $packagePresent -and
            -not $helperPresent) {
            return
        }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $deadline)

    throw (
        'Virtual HID uninstall left owned resources behind: ' +
        "roots=$($roots.InstanceId -join ',') " +
        "hidCollections=$($hidCollections.InstanceId -join ',') " +
        "packagePresent=$packagePresent helperPresent=$helperPresent."
    )
}

function Get-MsiProperty {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $installer = New-Object -ComObject WindowsInstaller.Installer
    $database = $installer.GetType().InvokeMember(
        'OpenDatabase',
        'InvokeMethod',
        $null,
        $installer,
        @($Path, 0)
    )
    $view = $database.OpenView("SELECT `Value` FROM `Property` WHERE `Property`='$Name'")
    [void]$view.Execute()
    $record = $view.Fetch()
    if ($null -eq $record) {
        throw "MSI property '$Name' was not found in $Path."
    }
    $value = $record.StringData(1)
    [void]$view.Close()
    return $value
}

switch ($Scenario) {
    'install-no-vhid' {
        [void](Invoke-Msi `
            -Arguments @('/i', "`"$msiPath`"", '/qn', '/norestart', 'LUMEN_INSTALL_VHID=0') `
            -LogName 'lumen-msi-install-no-vhid.log' `
            -FailureMessage 'MSI install without Virtual HID failed.')
        Assert-ServiceRunning
        if (Test-Path 'C:\Program Files\Lumen\drivers\virtual-hid') {
            throw 'Virtual HID files were installed despite LUMEN_INSTALL_VHID=0.'
        }
        [void](Invoke-Msi `
            -Arguments @('/x', $productCode, '/qn', '/norestart') `
            -LogName 'lumen-msi-uninstall-no-vhid.log' `
            -FailureMessage 'MSI uninstall without Virtual HID failed.')
    }
    'install-vhid' {
        [void](Invoke-Msi `
            -Arguments @('/i', "`"$msiPath`"", '/qn', '/norestart', 'LUMEN_INSTALL_VHID=1') `
            -LogName 'lumen-msi-install-vhid.log' `
            -FailureMessage 'MSI install with Virtual HID failed.')
        Assert-VirtualHidHealthy -FailureLog 'lumen-msi-install-vhid.log'
        [void](Invoke-Msi `
            -Arguments @('/x', $productCode, '/qn', '/norestart') `
            -LogName 'lumen-msi-uninstall-vhid.log' `
            -FailureMessage 'MSI uninstall with Virtual HID failed.')
        Assert-VirtualHidRemoved
    }
    'install-vmic' {
        [void](Invoke-Msi `
            -Arguments @(
                '/i',
                "`"$msiPath`"",
                '/qn',
                '/norestart',
                'LUMEN_INSTALL_VHID=0',
                'LUMEN_INSTALL_VMIC=1'
            ) `
            -LogName 'lumen-msi-install-vmic.log' `
            -FailureMessage 'MSI install with Virtual Microphone failed.')
        $helper = 'C:\Program Files\Lumen\tools\lumen-vmicctl.exe'
        $statusOutput = @(& $helper status --json)
        $statusExitCode = $LASTEXITCODE
        $statusText = ($statusOutput -join [Environment]::NewLine).Trim()
        Write-Host $statusText
        try {
            $status = $statusText | ConvertFrom-Json -ErrorAction Stop
        } catch {
            Get-Content (Join-Path $artifactDirectory 'lumen-msi-install-vmic.log')
            throw "Virtual Microphone status did not return valid JSON: $($_.Exception.Message)"
        }
        if ($statusExitCode -ne 3 -or
            $status.state -ne 'unhealthy' -or
            [int]$status.rootDevices -ne 1 -or
            [int]$status.activeCaptureEndpoints -lt 1 -or
            [int]$status.captureEndpoints -ne 1 -or
            $status.control -ne 'inaccessible') {
            Get-Content (Join-Path $artifactDirectory 'lumen-msi-install-vmic.log')
            throw (
                'Virtual Microphone runneradmin status contract mismatch: ' +
                "exit=$statusExitCode state='$($status.state)' " +
                "rootDevices=$($status.rootDevices) " +
                "activeCaptureEndpoints=$($status.activeCaptureEndpoints) " +
                "captureEndpoints=$($status.captureEndpoints) " +
                "control='$($status.control)'."
            )
        }

        $probeOutput = @(& $helper probe --json)
        $probeExitCode = $LASTEXITCODE
        $probeText = ($probeOutput -join [Environment]::NewLine).Trim()
        Write-Host $probeText
        try {
            $probe = $probeText | ConvertFrom-Json -ErrorAction Stop
        } catch {
            Get-Content (Join-Path $artifactDirectory 'lumen-msi-install-vmic.log')
            throw "Virtual Microphone probe did not return valid JSON: $($_.Exception.Message)"
        }
        if ($probeExitCode -ne 3 -or $probe.state -ne 'inaccessible') {
            Get-Content (Join-Path $artifactDirectory 'lumen-msi-install-vmic.log')
            throw (
                'Virtual Microphone runneradmin probe contract mismatch: ' +
                "exit=$probeExitCode state='$($probe.state)'."
            )
        }
        $global:LASTEXITCODE = 0
        [void](Invoke-Msi `
            -Arguments @('/x', $productCode, '/qn', '/norestart') `
            -LogName 'lumen-msi-uninstall-vmic.log' `
            -FailureMessage 'MSI uninstall with Virtual Microphone failed.')
        if (Test-Path $helper) {
            throw 'Virtual Microphone helper remains after MSI uninstall.'
        }
        $remainingDevices = @(
            Get-CimInstance Win32_PnPEntity -ErrorAction Stop | Where-Object {
                @($_.HardwareID) -contains 'ROOT\LumenVirtualMicrophone'
            }
        )
        if ($remainingDevices.Count -ne 0) {
            throw "Virtual Microphone device remains after MSI uninstall: $($remainingDevices.Count)."
        }
    }
    'upgrade' {
        $headers = @{
            Accept = 'application/vnd.github+json'
            Authorization = "Bearer $env:GITHUB_TOKEN"
            'X-GitHub-Api-Version' = '2022-11-28'
        }
        $releases = @(Invoke-RestMethod `
            -Uri "https://api.github.com/repos/$env:GITHUB_REPOSITORY/releases?per_page=20" `
            -Headers $headers)
        $previousRelease = $releases |
            Where-Object {
                -not $_.draft -and
                @($_.assets | Where-Object {
                    $_.name -like 'Lumen-*-Windows-AMD64-installer.msi'
                }).Count -ne 0
            } |
            Select-Object -First 1
        if ($null -eq $previousRelease) {
            Write-Warning 'No prior Lumen release exists; Lumen-to-Lumen upgrade validation starts with the next prerelease.'
            break
        }
        $previousAsset = $previousRelease.assets |
            Where-Object { $_.name -like 'Lumen-*-Windows-AMD64-installer.msi' } |
            Select-Object -First 1
        $checksumAsset = $previousRelease.assets |
            Where-Object { $_.name -eq 'SHA256SUMS' } |
            Select-Object -First 1
        if ($null -eq $checksumAsset) {
            throw "Previous Lumen release $($previousRelease.tag_name) has no SHA256SUMS asset."
        }

        $previousMsi = Join-Path $env:RUNNER_TEMP $previousAsset.name
        $previousChecksums = Join-Path $env:RUNNER_TEMP 'Lumen-previous-SHA256SUMS'
        Invoke-WebRequest `
            -Uri $previousAsset.browser_download_url `
            -Headers $headers `
            -OutFile $previousMsi
        Invoke-WebRequest `
            -Uri $checksumAsset.browser_download_url `
            -Headers $headers `
            -OutFile $previousChecksums
        $expectedHashLine = Get-Content -LiteralPath $previousChecksums |
            Where-Object { $_ -match "\s$([regex]::Escape($previousAsset.name))$" } |
            Select-Object -First 1
        if (-not $expectedHashLine) {
            throw "SHA256SUMS does not contain $($previousAsset.name)."
        }
        $expectedHash = ($expectedHashLine -split '\s+')[0].ToUpperInvariant()
        $actualHash = (Get-FileHash -LiteralPath $previousMsi -Algorithm SHA256).Hash
        if ($actualHash -ne $expectedHash) {
            throw "Checksum mismatch for $($previousAsset.name)."
        }
        $previousProductCode = Get-MsiProperty -Path $previousMsi -Name 'ProductCode'

        [void](Invoke-Msi `
            -Arguments @('/i', "`"$previousMsi`"", '/qn', '/norestart', 'LUMEN_INSTALL_VHID=0') `
            -LogName 'lumen-msi-install-previous-release.log' `
            -FailureMessage 'Installing the previous Lumen release failed.')
        $sentinel = 'C:\Program Files\Lumen\config\upgrade-ci-sentinel.txt'
        Set-Content -LiteralPath $sentinel -Value 'preserve-me' -NoNewline

        [void](Invoke-Msi `
            -Arguments @('/i', "`"$msiPath`"", '/qn', '/norestart', 'LUMEN_INSTALL_VHID=0') `
            -LogName 'lumen-msi-upgrade-from-previous-release.log' `
            -FailureMessage 'Lumen-to-Lumen MSI upgrade failed.')
        if ((Get-Content -LiteralPath $sentinel -Raw) -ne 'preserve-me') {
            throw 'Lumen-to-Lumen upgrade did not preserve configuration state.'
        }
        if ($previousProductCode -ne $productCode) {
            $previousProduct = Get-ItemProperty `
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$previousProductCode" `
                -ErrorAction SilentlyContinue
            if ($null -ne $previousProduct) {
                throw 'The previous Lumen MSI product remains registered after upgrade.'
            }
        }
        $lumenProducts = @(Get-ChildItem `
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' |
            Get-ItemProperty |
            Where-Object { $_.DisplayName -eq 'Lumen' })
        if ($lumenProducts.Count -ne 1) {
            throw "Expected one registered Lumen product after upgrade; found $($lumenProducts.Count)."
        }
        Assert-ServiceRunning

        [void](Invoke-Msi `
            -Arguments @('/x', $productCode, '/qn', '/norestart') `
            -LogName 'lumen-msi-upgrade-uninstall.log' `
            -FailureMessage 'Uninstall after Lumen-to-Lumen upgrade failed.')
    }
    'legacy-import' {
        $fixtureId = '{A6C1CA63-42B6-4F83-AEC7-BCAC48E43CC8}'
        $fixtureRegistry = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$fixtureId"
        $fixtureRoot = Join-Path $env:RUNNER_TEMP 'SunshineMigrationFixture'
        $fixtureConfig = Join-Path $fixtureRoot 'config'
        $fixtureSentinel = Join-Path $fixtureConfig 'migration-ci-sentinel.txt'
        try {
            New-Item -ItemType Directory -Path $fixtureConfig -Force | Out-Null
            Set-Content -LiteralPath $fixtureSentinel -Value 'preserve-me' -NoNewline
            New-Item -Path $fixtureRegistry -Force | Out-Null
            Set-ItemProperty -Path $fixtureRegistry -Name DisplayName -Value 'Sunshine Migration Fixture'
            Set-ItemProperty -Path $fixtureRegistry -Name InstallLocation -Value $fixtureRoot

            [void](Invoke-Msi `
                -Arguments @('/i', "`"$msiPath`"", '/qn', '/norestart', 'LUMEN_INSTALL_VHID=0') `
                -LogName 'lumen-msi-legacy-import.log' `
                -FailureMessage 'Lumen legacy configuration import failed.')

            $lumenSentinel = 'C:\Program Files\Lumen\config\migration-ci-sentinel.txt'
            if ((Get-Content -LiteralPath $lumenSentinel -Raw) -ne 'preserve-me') {
                throw 'Lumen did not copy the legacy Sunshine configuration fixture.'
            }
            if ((Get-Content -LiteralPath $fixtureSentinel -Raw) -ne 'preserve-me') {
                throw 'Lumen modified the legacy Sunshine configuration fixture.'
            }
            if (-not (Test-Path -LiteralPath $fixtureRegistry)) {
                throw 'Lumen removed the legacy Sunshine product fixture.'
            }
            if ($null -ne (Get-Service SunshineService -ErrorAction SilentlyContinue)) {
                throw 'Lumen created or claimed the SunshineService identity.'
            }
            Assert-ServiceRunning

            [void](Invoke-Msi `
                -Arguments @('/x', $productCode, '/qn', '/norestart') `
                -LogName 'lumen-msi-legacy-import-uninstall.log' `
                -FailureMessage 'Uninstall after legacy import failed.')
        } finally {
            Remove-Item -LiteralPath $fixtureRegistry -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $fixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
