$ErrorActionPreference = 'Stop'

$msiCandidates = @(Get-ChildItem 'artifacts/Lumen-*-Windows-AMD64-installer.msi' -File)
if ($msiCandidates.Count -ne 1) {
    throw 'Expected exactly one versioned Lumen Windows MSI artifact.'
}
$msiPath = Resolve-Path $msiCandidates[0].FullName
$installer = New-Object -ComObject WindowsInstaller.Installer
$database = $installer.GetType().InvokeMember(
    'OpenDatabase',
    'InvokeMethod',
    $null,
    $installer,
    @($msiPath.Path, 0)
)

function Read-MsiRows([string]$Query, [int]$Columns) {
    $view = $database.OpenView($Query)
    [void]$view.Execute()
    $rows = [Collections.Generic.List[object[]]]::new()
    while ($record = $view.Fetch()) {
        $row = [object[]]@(1..$Columns | ForEach-Object { $record.StringData($_) })
        $rows.Add($row)
    }
    [void]$view.Close()
    return ,$rows.ToArray()
}

$actions = Read-MsiRows `
    'SELECT `Action`,`Type`,`Source`,`Target` FROM `CustomAction`' 4
$sequence = Read-MsiRows `
    'SELECT `Action`,`Condition`,`Sequence` FROM `InstallExecuteSequence`' 3
$services = Read-MsiRows `
    'SELECT `ServiceInstall`,`Name`,`StartType`,`Component_` FROM `ServiceInstall`' 4
$features = Read-MsiRows `
    'SELECT `Feature`,`Level` FROM `Feature`' 2
$properties = Read-MsiRows `
    'SELECT `Property`,`Value` FROM `Property`' 2

$requiredActions = @(
    'CA_LumenInstall',
    'CA_LumenInstallRollback',
    'CA_LumenInstallCommit',
    'CA_LumenUninstall',
    'CA_LumenUninstallRollback',
    'CA_LumenUninstallCommit'
)
$actionNames = @($actions | ForEach-Object { $_[0] })
$sequenceNames = @($sequence | ForEach-Object { $_[0] })
foreach ($action in $requiredActions) {
    if ($actionNames -notcontains $action -or $sequenceNames -notcontains $action) {
        throw "Generated MSI is missing custom action or sequence row: $action"
    }
}

if ($services.Count -ne 1 -or $services[0][1] -ne 'LumenService') {
    throw 'Generated MSI does not contain the declarative LumenService row.'
}
if ($sequenceNames -notcontains 'RemoveExistingProducts') {
    throw 'Generated MSI is missing RemoveExistingProducts.'
}

$setterNames = @(
    'SetLumenInstallRollbackData',
    'SetLumenInstallData',
    'SetLumenInstallCommitData',
    'SetLumenUninstallRollbackData',
    'SetLumenUninstallData',
    'SetLumenUninstallCommitData'
)
foreach ($setterName in $setterNames) {
    $setter = @($actions | Where-Object { $_[0] -eq $setterName })
    if ($setter.Count -ne 1) {
        throw "Generated MSI is missing a command setter: $setterName"
    }
    $command = $setter[0][3]
    $expectedScript = if ($setterName -eq 'SetLumenUninstallCommitData') {
        ' -File "\[CommonAppDataFolder\]LumenVirtualHidInstallerV2\\\[ProductCode\]\\uninstall\\lumen-setup\.ps1" '
    } else {
        ' -File "\[INSTALL_ROOT\]scripts\\lumen-setup\.ps1" '
    }
    if ($command -notmatch '^"\[System64Folder\]WindowsPowerShell\\v1\.0\\powershell\.exe" ' -or
        $command -notmatch $expectedScript -or
        $command -notmatch ' -Msi ' -or
        $command -notmatch ' -ProductCode "\[ProductCode\]" ' -or
        $command -notmatch ' -TransactionKind (install|uninstall) ' -or
        $command -notmatch ' -InstallVirtualHid \[LUMEN_INSTALL_VHID\]$') {
        throw "Generated MSI has an invalid deferred command: $setterName"
    }
    if ($command -match '&(?:amp;)?quot;|\[CustomActionData\]|-MsiData') {
        throw "Generated MSI has escaped or nested deferred command data: $setterName"
    }
}

$deferredActions = @($actions | Where-Object { $_[0] -in $requiredActions })
foreach ($deferredAction in $deferredActions) {
    if ($deferredAction[2] -ne 'Wix4UtilCA_X64' -or
        $deferredAction[3] -ne 'WixQuietExec64') {
        throw "Deferred MSI action does not use WixQuietExec64: $($deferredAction[0])"
    }
}

foreach ($commitAction in @('CA_LumenInstallCommit', 'CA_LumenUninstallCommit')) {
    $commit = @($actions | Where-Object { $_[0] -eq $commitAction })
    if ($commit.Count -ne 1 -or ([int]$commit[0][1] -band 0x40) -ne 0) {
        throw "MSI commit cleanup must fail the transaction when cleanup fails: $commitAction"
    }
}

$installSetterRows = @($sequence | Where-Object { $_[0] -eq 'SetLumenInstallData' })
if ($installSetterRows.Count -ne 1) {
    throw 'Generated MSI must set CA_LumenInstall CustomActionData exactly once.'
}
$removeExistingProducts = @($sequence | Where-Object { $_[0] -eq 'RemoveExistingProducts' })
$installDeferred = @($sequence | Where-Object { $_[0] -eq 'CA_LumenInstall' })
if ([int]$removeExistingProducts[0][2] -le [int]$installDeferred[0][2]) {
    throw 'The new product must finish its install action before removing the old product.'
}

$vhidFeature = @($features | Where-Object { $_[0] -eq 'CM_C_virtual_hid_driver' })
if ($vhidFeature.Count -ne 1) {
    throw 'Generated MSI is missing the Virtual HID feature.'
}
$vhidDefault = @($properties | Where-Object { $_[0] -eq 'LUMEN_INSTALL_VHID' })
if ($vhidDefault.Count -ne 1 -or $vhidDefault[0][1] -ne '0') {
    throw 'The Virtual HID feature must remain explicit opt-in.'
}
$productCode = @($properties | Where-Object { $_[0] -eq 'ProductCode' })
if ($productCode.Count -ne 1 -or
    $productCode[0][1] -notmatch '^\{[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}\}$') {
    throw 'Generated MSI has an invalid ProductCode.'
}
$upgradeCode = @($properties | Where-Object { $_[0] -eq 'UpgradeCode' })
if ($upgradeCode.Count -ne 1 -or
    $upgradeCode[0][1] -ne '{89721553-C582-4D70-8BBF-1E6C5431C8D5}') {
    throw 'Generated MSI does not use the permanent Lumen UpgradeCode.'
}
$productName = @($properties | Where-Object { $_[0] -eq 'ProductName' })
if ($productName.Count -ne 1 -or $productName[0][1] -ne 'Lumen') {
    throw 'Generated MSI ProductName is not Lumen.'
}
"MSI_PRODUCT_CODE=$($productCode[0][1])" >> $env:GITHUB_ENV
