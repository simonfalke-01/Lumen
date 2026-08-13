$ErrorActionPreference = 'Stop'

$msiPath = Resolve-Path 'artifacts/Sunshine-Windows-AMD64-installer.msi'
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
    'CA_SunshineInstall',
    'CA_SunshineInstallRollback',
    'CA_SunshineInstallCommit',
    'CA_SunshineUninstall',
    'CA_SunshineUninstallRollback',
    'CA_SunshineUninstallCommit'
)
$actionNames = @($actions | ForEach-Object { $_[0] })
$sequenceNames = @($sequence | ForEach-Object { $_[0] })
foreach ($action in $requiredActions) {
    if ($actionNames -notcontains $action -or $sequenceNames -notcontains $action) {
        throw "Generated MSI is missing custom action or sequence row: $action"
    }
}

if ($services.Count -ne 1 -or $services[0][1] -ne 'SunshineService') {
    throw 'Generated MSI does not contain the declarative SunshineService row.'
}
if ($sequenceNames -notcontains 'RemoveExistingProducts') {
    throw 'Generated MSI is missing RemoveExistingProducts.'
}

$setterNames = @(
    'SetSunshineInstallRollbackData',
    'SetSunshineInstallData',
    'SetSunshineInstallCommitData',
    'SetSunshineUninstallRollbackData',
    'SetSunshineUninstallData',
    'SetSunshineUninstallCommitData'
)
foreach ($setterName in $setterNames) {
    $setter = @($actions | Where-Object { $_[0] -eq $setterName })
    if ($setter.Count -ne 1) {
        throw "Generated MSI is missing a command setter: $setterName"
    }
    $command = $setter[0][3]
    if ($command -notmatch '^"\[SystemFolder\]WindowsPowerShell\\v1\.0\\powershell\.exe" ' -or
        $command -notmatch ' -File "\[INSTALL_ROOT\]scripts\\sunshine-setup\.ps1" ' -or
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

foreach ($commitAction in @('CA_SunshineInstallCommit', 'CA_SunshineUninstallCommit')) {
    $commit = @($actions | Where-Object { $_[0] -eq $commitAction })
    if ($commit.Count -ne 1 -or ([int]$commit[0][1] -band 0x40) -ne 0) {
        throw "MSI commit cleanup must fail the transaction when cleanup fails: $commitAction"
    }
}

$installSetterRows = @($sequence | Where-Object { $_[0] -eq 'SetSunshineInstallData' })
if ($installSetterRows.Count -ne 1) {
    throw 'Generated MSI must set CA_SunshineInstall CustomActionData exactly once.'
}
$removeExistingProducts = @($sequence | Where-Object { $_[0] -eq 'RemoveExistingProducts' })
$installDeferred = @($sequence | Where-Object { $_[0] -eq 'CA_SunshineInstall' })
if ([int]$removeExistingProducts[0][2] -le [int]$installDeferred[0][2]) {
    throw 'The new product must finish its install action before removing the old product.'
}

$vhidFeature = @($features | Where-Object { $_[0] -eq 'CM_C_virtual_hid_driver' })
if ($vhidFeature.Count -ne 1) {
    throw 'Generated MSI is missing the Virtual HID feature.'
}
$productCode = @($properties | Where-Object { $_[0] -eq 'ProductCode' })
if ($productCode.Count -ne 1 -or
    $productCode[0][1] -notmatch '^\{[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}\}$') {
    throw 'Generated MSI has an invalid ProductCode.'
}
"MSI_PRODUCT_CODE=$($productCode[0][1])" >> $env:GITHUB_ENV
