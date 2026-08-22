param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('install-no-vhid', 'install-vhid', 'upgrade', 'legacy-import')]
    [string]$Scenario
)

$ErrorActionPreference = 'Stop'
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
    $process = Start-Process msiexec.exe -Wait -PassThru -ArgumentList $msiArguments
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
    & $helper status --json
    if ($LASTEXITCODE -ne 0) {
        Get-Content (Join-Path $artifactDirectory $FailureLog)
        throw "Virtual HID status failed with exit code $LASTEXITCODE."
    }
    $taskName = "Lumen-VHID-Probe-$([Guid]::NewGuid().ToString('N'))"
    $probeScript = Join-Path $artifactDirectory 'lumen-vhid-probe.ps1'
    $probeOutput = Join-Path $artifactDirectory 'lumen-vhid-probe.json'
    $probeExit = Join-Path $artifactDirectory 'lumen-vhid-probe.exit'
    $escapedHelper = $helper.Replace("'", "''")
    $escapedOutput = $probeOutput.Replace("'", "''")
    $escapedExit = $probeExit.Replace("'", "''")
    Remove-Item $probeOutput, $probeExit -Force -ErrorAction SilentlyContinue
    @"
& '$escapedHelper' probe --json | Set-Content -LiteralPath '$escapedOutput' -Encoding UTF8
`$probeExitCode = `$LASTEXITCODE
Set-Content -LiteralPath '$escapedExit' -Value `$probeExitCode -NoNewline
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
        $deadline = (Get-Date).AddSeconds(30)
        while (-not (Test-Path -LiteralPath $probeExit -PathType Leaf) -and
            (Get-Date) -lt $deadline) {
            Start-Sleep -Milliseconds 100
        }
        if (-not (Test-Path -LiteralPath $probeExit -PathType Leaf)) {
            throw 'Virtual HID protocol probe timed out.'
        }
        Get-Content -LiteralPath $probeOutput
        $probeExitCode = [int](Get-Content -LiteralPath $probeExit -Raw)
        if ($probeExitCode -ne 0) {
            Get-Content (Join-Path $artifactDirectory $FailureLog)
            throw "Virtual HID protocol probe failed with exit code $probeExitCode."
        }
    } finally {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Item $probeScript, $probeExit -Force -ErrorAction SilentlyContinue
    }
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
        if (Test-Path 'C:\Program Files\Lumen\tools\lumen-vhidctl.exe') {
            throw 'Virtual HID helper remains after MSI uninstall.'
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
