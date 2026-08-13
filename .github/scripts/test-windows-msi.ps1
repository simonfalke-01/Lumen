param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('install-no-vhid', 'install-vhid', 'upgrade')]
    [string]$Scenario
)

$ErrorActionPreference = 'Stop'
$artifactDirectory = (Resolve-Path 'artifacts').Path
$msiPath = (Resolve-Path 'artifacts/Sunshine-Windows-AMD64-installer.msi').Path
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
    $service = Get-Service SunshineService -ErrorAction Stop
    if ($service.Status -ne 'Running') {
        throw 'SunshineService is not running after MSI installation.'
    }
}

function Assert-VirtualHidHealthy {
    param([string]$FailureLog)

    $helper = 'C:\Program Files\Sunshine\tools\lumen-vhidctl.exe'
    & $helper status --json
    if ($LASTEXITCODE -ne 0) {
        Get-Content (Join-Path $artifactDirectory $FailureLog)
        throw "Virtual HID status failed with exit code $LASTEXITCODE."
    }
}

switch ($Scenario) {
    'install-no-vhid' {
        [void](Invoke-Msi `
            -Arguments @('/i', "`"$msiPath`"", '/qn', '/norestart', 'LUMEN_INSTALL_VHID=0') `
            -LogName 'lumen-msi-install-no-vhid.log' `
            -FailureMessage 'MSI install without Virtual HID failed.')
        Assert-ServiceRunning
        if (Test-Path 'C:\Program Files\Sunshine\drivers\virtual-hid') {
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
        if (Test-Path 'C:\Program Files\Sunshine\tools\lumen-vhidctl.exe') {
            throw 'Virtual HID helper remains after MSI uninstall.'
        }
    }
    'upgrade' {
        $oldArtifactId = 9136389283
        $oldArtifactZip = Join-Path $env:RUNNER_TEMP 'lumen-0.0.9.zip'
        $oldArtifactDir = Join-Path $env:RUNNER_TEMP 'lumen-0.0.9'
        $headers = @{
            Accept = 'application/vnd.github+json'
            Authorization = "Bearer $env:GITHUB_TOKEN"
            'X-GitHub-Api-Version' = '2022-11-28'
        }
        Invoke-WebRequest `
            -Uri "https://api.github.com/repos/$env:GITHUB_REPOSITORY/actions/artifacts/$oldArtifactId/zip" `
            -Headers $headers `
            -OutFile $oldArtifactZip
        Expand-Archive -LiteralPath $oldArtifactZip -DestinationPath $oldArtifactDir
        $oldMsi = (Get-ChildItem $oldArtifactDir -Filter '*.msi' -File -Recurse |
            Select-Object -First 1).FullName
        if (-not $oldMsi) {
            throw 'The 0.0.9 regression artifact does not contain an MSI.'
        }

        [void](Invoke-Msi `
            -Arguments @('/i', "`"$oldMsi`"", '/qn', '/norestart') `
            -LogName 'lumen-msi-install-0.0.9.log' `
            -FailureMessage 'Installing the 0.0.9 MSI fixture failed.')
        $sentinel = 'C:\Program Files\Sunshine\config\upgrade-ci-sentinel.txt'
        Set-Content -LiteralPath $sentinel -Value 'preserve-me' -NoNewline

        [void](Invoke-Msi `
            -Arguments @('/i', "`"$msiPath`"", '/qn', '/norestart', 'LUMEN_INSTALL_VHID=1') `
            -LogName 'lumen-msi-upgrade.log' `
            -FailureMessage 'MSI upgrade from 0.0.9 failed.')
        if ((Get-Content -LiteralPath $sentinel -Raw) -ne 'preserve-me') {
            throw 'MSI upgrade did not preserve the existing configuration sentinel.'
        }
        Assert-ServiceRunning
        Assert-VirtualHidHealthy -FailureLog 'lumen-msi-upgrade.log'

        $oldProduct = Get-ItemProperty `
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{77391323-4F4F-4189-9ABA-151A7F048675}' `
            -ErrorAction SilentlyContinue
        if ($null -ne $oldProduct) {
            throw 'The 0.0.9 product is still registered after the major upgrade.'
        }
        [void](Invoke-Msi `
            -Arguments @('/x', $productCode, '/qn', '/norestart') `
            -LogName 'lumen-msi-upgrade-uninstall.log' `
            -FailureMessage 'Uninstall after MSI upgrade failed.')
    }
}
