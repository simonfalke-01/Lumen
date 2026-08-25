$ErrorActionPreference = 'Stop'

$msiCandidates = if ([string]::IsNullOrWhiteSpace($env:LUMEN_MSI_PATH)) {
    @(Get-ChildItem 'artifacts/Lumen-*-Windows-AMD64-installer.msi' -File)
} elseif (Test-Path -LiteralPath $env:LUMEN_MSI_PATH -PathType Leaf) {
    @(Get-Item -LiteralPath $env:LUMEN_MSI_PATH)
} else {
    @()
}
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
    'SELECT `ServiceInstall`,`Name`,`StartType`,`Component_`,`StartName` FROM `ServiceInstall`' 5
$features = Read-MsiRows `
    'SELECT `Feature`,`Level` FROM `Feature`' 2
$upgrades = Read-MsiRows `
    'SELECT `UpgradeCode`,`ActionProperty` FROM `Upgrade`' 2
$properties = Read-MsiRows `
    'SELECT `Property`,`Value` FROM `Property`' 2
$files = Read-MsiRows `
    'SELECT `File`,`FileName`,`Component_` FROM `File`' 3
$firewallExceptions = Read-MsiRows `
    'SELECT `Name`,`Protocol`,`Program`,`Profile`,`Component_`,`Direction` FROM `Wix4FirewallException`' 6

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
$rebootActions = @('CA_LumenReadPendingDriverReboot')
foreach ($action in $rebootActions) {
    if ($actionNames -notcontains $action -or $sequenceNames -notcontains $action) {
        throw "Generated MSI is missing the VDD reboot bridge action: $action"
    }
    $row = @($actions | Where-Object { $_[0] -eq $action })
    if ($row.Count -ne 1 -or
        $row[0][2] -ne 'LumenMsiCA' -or
        $row[0][3] -ne 'LumenReadPendingDriverReboot') {
        throw "Generated MSI has an invalid VDD reboot bridge action: $action"
    }
}
$upgradeOwnershipAction = @($actions | Where-Object { $_[0] -eq 'CA_LumenResolveUpgradeVddOwnership' })
if ($upgradeOwnershipAction.Count -ne 1 -or
    $upgradeOwnershipAction[0][2] -ne 'LumenMsiCA' -or
    $upgradeOwnershipAction[0][3] -ne 'LumenResolveUpgradeVddOwnership' -or
    $sequenceNames -notcontains 'CA_LumenResolveUpgradeVddOwnership') {
    throw 'Generated MSI is missing the upgrade-aware Virtual Display ownership resolver.'
}
$lumenUpgradeRows = @($upgrades | Where-Object {
    $_[0] -eq '{89721553-C582-4D70-8BBF-1E6C5431C8D5}' -and
    $_[1] -eq 'WIX_UPGRADE_DETECTED'
})
if ($lumenUpgradeRows.Count -eq 0) {
    throw 'Generated MSI does not expose detected Lumen products to the VDD ownership resolver.'
}

if ($services.Count -ne 1 -or
    $services[0][1] -ne 'LumenService' -or
    $services[0][2] -ne '2' -or
    $services[0][4] -ne 'LocalSystem') {
    throw 'Generated MSI does not contain an automatic LocalSystem LumenService row.'
}
$expectedFirewallProtocols = @{
    'Lumen TCP' = '6'
    'Lumen UDP' = '17'
}
if ($firewallExceptions.Count -ne $expectedFirewallProtocols.Count) {
    throw 'Generated MSI does not contain exactly two Lumen firewall rules.'
}
foreach ($firewallException in $firewallExceptions) {
    $ruleName = $firewallException[0]
    if (-not $expectedFirewallProtocols.ContainsKey($ruleName) -or
        $firewallException[1] -ne $expectedFirewallProtocols[$ruleName] -or
        $firewallException[2] -ne '[#CM_FP_application.Lumen.exe]' -or
        $firewallException[3] -ne '2147483647' -or
        $firewallException[4] -ne 'CM_CP_application.Lumen.exe' -or
        $firewallException[5] -ne '1') {
        throw "Generated MSI has an invalid Lumen firewall row: $($firewallException -join ', ')"
    }
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
    $expectedUpgradeOwnership = if ($setterName -like 'SetLumenInstall*') {
        ' -UpgradeOwnedVirtualDisplay \[LUMEN_UPGRADE_OWNED_VDD\] ' +
            '-UpgradeVddOwnerProduct "\[LUMEN_UPGRADE_VDD_OWNER_PRODUCT\]"$'
    } else {
        ' -UpgradeOwnedVirtualDisplay 0 -UpgradeVddOwnerProduct ""$'
    }
    $expectedIdentityDisposition = if ($setterName -like 'SetLumenInstall*') {
        ' -IdentityDisposition preserve '
    } else {
        ' -IdentityDisposition remove '
    }
    if ($command -notmatch '^"\[System64Folder\]WindowsPowerShell\\v1\.0\\powershell\.exe" ' -or
        $command -notmatch $expectedScript -or
        $command -notmatch ' -Msi ' -or
        $command -notmatch ' -ProductCode "\[ProductCode\]" ' -or
        $command -notmatch ' -TransactionKind (install|uninstall) ' -or
        $command -notmatch ' -InstallVirtualHid \[LUMEN_INSTALL_VHID\] ' -or
        $command -notmatch ' -InstallVirtualMicrophone \[LUMEN_INSTALL_VMIC\] ' -or
        $command -notmatch ' -InstallVirtualDisplay \[LUMEN_INSTALL_VDD\] ' -or
        $command -notmatch ' -RemoveVirtualDisplay \[LUMEN_REMOVE_VDD\] ' -or
        $command -notmatch $expectedIdentityDisposition -or
        $command -notmatch $expectedUpgradeOwnership) {
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
$upgradeOwnershipSequence = @($sequence | Where-Object {
    $_[0] -eq 'CA_LumenResolveUpgradeVddOwnership'
})
if ($upgradeOwnershipSequence.Count -ne 1 -or
    [int]$upgradeOwnershipSequence[0][2] -ge [int]$installSetterRows[0][2]) {
    throw 'VDD upgrade ownership must resolve before deferred install data is frozen.'
}
$removeExistingProducts = @($sequence | Where-Object { $_[0] -eq 'RemoveExistingProducts' })
$installDeferred = @($sequence | Where-Object { $_[0] -eq 'CA_LumenInstall' })
if ([int]$removeExistingProducts[0][2] -le [int]$installDeferred[0][2]) {
    throw 'The new product must finish its install action before removing the old product.'
}
$stopServices = @($sequence | Where-Object { $_[0] -eq 'StopServices' })
$uninstallSetter = @($sequence | Where-Object { $_[0] -eq 'SetLumenUninstallRollbackData' })
$uninstallDeferred = @($sequence | Where-Object { $_[0] -eq 'CA_LumenUninstall' })
if ($stopServices.Count -ne 1 -or $uninstallSetter.Count -ne 1 -or $uninstallDeferred.Count -ne 1 -or
    [int]$uninstallSetter[0][2] -le [int]$stopServices[0][2] -or
    [int]$uninstallDeferred[0][2] -le [int]$stopServices[0][2]) {
    throw 'VDD driver uninstall must be sequenced after StopServices.'
}
$installDispositionRows = @($sequence | Where-Object {
    $_[0] -in @('CA_LumenInstallRollback', 'CA_LumenInstall', 'CA_LumenInstallCommit')
})
$uninstallDispositionRows = @($sequence | Where-Object {
    $_[0] -in @('CA_LumenUninstallRollback', 'CA_LumenUninstall', 'CA_LumenUninstallCommit')
})
if (@($installDispositionRows | Where-Object { $_[1] -ne 'NOT (REMOVE="ALL")' }).Count -ne 0 -or
    @($uninstallDispositionRows | Where-Object {
        $_[1] -ne 'REMOVE="ALL" AND NOT UPGRADINGPRODUCTCODE'
    }).Count -ne 0) {
    throw 'Identity disposition must preserve repair/feature/related-upgrade and remove only full uninstall.'
}
$installExecute = @($sequence | Where-Object { $_[0] -eq 'InstallExecute' })
$installFinalize = @($sequence | Where-Object { $_[0] -eq 'InstallFinalize' })
$readReboot = @($sequence | Where-Object { $_[0] -eq 'CA_LumenReadPendingDriverReboot' })
$scheduleReboot = @($sequence | Where-Object { $_[0] -eq 'ScheduleReboot' })
if ($installExecute.Count -ne 1 -or $installFinalize.Count -ne 1 -or
    $readReboot.Count -ne 1 -or $scheduleReboot.Count -ne 1 -or
    [int]$installDeferred[0][2] -ge [int]$installExecute[0][2] -or
    [int]$uninstallDeferred[0][2] -ge [int]$installExecute[0][2] -or
    [int]$readReboot[0][2] -le [int]$installExecute[0][2] -or
    [int]$readReboot[0][2] -ge [int]$installFinalize[0][2] -or
    [int]$scheduleReboot[0][2] -le [int]$readReboot[0][2] -or
    [int]$scheduleReboot[0][2] -ge [int]$installFinalize[0][2] -or
    $scheduleReboot[0][1] -ne 'LUMEN_DRIVER_REBOOT_REQUIRED = 1') {
    throw 'Driver reboot detection must bridge InstallExecute to ScheduleReboot before InstallFinalize.'
}

$vhidFeature = @($features | Where-Object { $_[0] -eq 'CM_C_virtual_hid_driver' })
$vhidDefault = @($properties | Where-Object { $_[0] -eq 'LUMEN_INSTALL_VHID' })
if ($vhidDefault.Count -ne 1 -or $vhidDefault[0][1] -ne '0') {
    throw 'The Virtual HID feature must remain explicit opt-in.'
}
$vhidFiles = @($files | Where-Object {
    $_[1] -match '(?i)LumenVirtualHid\.(inf|cat|dll|cer)|lumen-vhidctl\.exe'
})
$expectVhidFeature = if ([string]::IsNullOrWhiteSpace($env:EXPECT_VHID_FEATURE)) {
    $true
} else {
    $env:EXPECT_VHID_FEATURE -eq 'true'
}
if ($expectVhidFeature) {
    if ($vhidFeature.Count -ne 1) {
        throw 'Generated MSI is missing the Virtual HID feature.'
    }
    foreach ($requiredVhidFile in @(
        'LumenVirtualHid.inf',
        'LumenVirtualHid.cat',
        'LumenVirtualHid.dll',
        'lumen-vhidctl.exe'
    )) {
        if (-not ($vhidFiles | Where-Object { $_[1] -match "(?i)$([regex]::Escape($requiredVhidFile))" })) {
            throw "Generated MSI is missing $requiredVhidFile."
        }
    }
} elseif ($vhidFeature.Count -ne 0 -or $vhidFiles.Count -ne 0) {
    throw 'Generated MSI unexpectedly contains Virtual HID files or features.'
}
$vmicFeature = @($features | Where-Object { $_[0] -eq 'CM_C_virtual_microphone_driver' })
$vmicDefault = @($properties | Where-Object { $_[0] -eq 'LUMEN_INSTALL_VMIC' })
if ($vmicDefault.Count -ne 1 -or $vmicDefault[0][1] -ne '0') {
    throw 'The Virtual Microphone feature must remain explicit opt-in.'
}
$vmicFiles = @($files | Where-Object {
    $_[1] -match '(?i)LumenVirtualMicrophone\.(inf|sys|cat)|lumen-vmicctl\.exe'
})
$expectVmicFeature = $env:EXPECT_VMIC_FEATURE -eq 'true'
if ($expectVmicFeature) {
    if ($vmicFeature.Count -ne 1) {
        throw 'Generated development MSI is missing the Virtual Microphone feature.'
    }
    foreach ($requiredVmicFile in @(
        'LumenVirtualMicrophone.inf',
        'LumenVirtualMicrophone.sys',
        'LumenVirtualMicrophone.cat',
        'lumen-vmicctl.exe'
    )) {
        if (-not ($vmicFiles | Where-Object { $_[1] -match "(?i)$([regex]::Escape($requiredVmicFile))" })) {
            throw "Generated development MSI is missing $requiredVmicFile."
        }
    }
} elseif ($vmicFeature.Count -ne 0 -or $vmicFiles.Count -ne 0) {
    throw 'Generated tagged MSI unexpectedly contains Virtual Microphone files or features.'
}
$vddFeature = @($features | Where-Object { $_[0] -eq 'CM_C_virtual_display_driver' })
$vddDefault = @($properties | Where-Object { $_[0] -eq 'LUMEN_INSTALL_VDD' })
$vddRemoveDefault = @($properties | Where-Object { $_[0] -eq 'LUMEN_REMOVE_VDD' })
if ($vddRemoveDefault.Count -ne 1 -or $vddRemoveDefault[0][1] -ne '0') {
    throw 'The Virtual Display removal selector must default to disabled.'
}
$vddFiles = @($files | Where-Object {
    $_[1] -match '(?i)LumenVirtualDisplay\.(inf|cat|dll)'
})
$vddHelpers = @($files | Where-Object { $_[1] -match '(?i)lumen-vddctl\.exe' })
if ($vddHelpers.Count -ne 1) {
    throw 'Every Windows MSI must carry exactly one VDD lifecycle helper for upgrade cleanup.'
}
$expectVddFeature = $env:EXPECT_VDD_FEATURE -eq 'true'
if ($expectVddFeature) {
    if ($vddDefault.Count -ne 1 -or $vddDefault[0][1] -ne '1') {
        throw 'An MSI containing Lumen Virtual Display must select it by default.'
    }
    if ($vddFeature.Count -ne 1) {
        throw 'Generated MSI is missing the Virtual Display feature.'
    }
    foreach ($requiredVddFile in @(
        'LumenVirtualDisplay.inf',
        'LumenVirtualDisplay.cat',
        'LumenVirtualDisplay.dll'
    )) {
        if (-not ($vddFiles | Where-Object { $_[1] -match "(?i)$([regex]::Escape($requiredVddFile))" })) {
            throw "Generated MSI is missing $requiredVddFile."
        }
    }
    if (-not ($files | Where-Object { $_[1] -match '(?i)virtual-display-setup\.ps1' })) {
        throw 'Generated MSI is missing the Virtual Display transaction helper.'
    }
} else {
    if ($vddDefault.Count -ne 1 -or $vddDefault[0][1] -ne '0') {
        throw 'An MSI without a Virtual Display package must disable its driver transaction.'
    }
    if ($vddFeature.Count -ne 0 -or $vddFiles.Count -ne 0) {
        throw 'Generated MSI unexpectedly contains a Virtual Display feature or driver payload.'
    }
}

$msquicFiles = @($files | Where-Object {
    $_[1] -match '(?i)(^|\|)(msquic|lumen_msquic_shim)\.dll$|MsQuic-LICENSE\.txt'
})
$expectMsQuic = $env:EXPECT_MSQUIC -eq 'true'
if ($expectMsQuic) {
    foreach ($requiredMsQuicFile in @(
        'msquic.dll',
        'lumen_msquic_shim.dll',
        'MsQuic-LICENSE.txt'
    )) {
        if (-not ($msquicFiles | Where-Object { $_[1] -match "(?i)$([regex]::Escape($requiredMsQuicFile))" })) {
            throw "Generated MSI is missing $requiredMsQuicFile."
        }
    }
} elseif ($msquicFiles.Count -ne 0) {
    throw 'Generated MSI unexpectedly contains MsQuic runtime files.'
}
$localTestMarkers = @($files | Where-Object {
    $_[1] -match '(?i)LOCAL-TEST-SIGNED\.json'
})
$expectLocalTestMarker = $env:EXPECT_LOCAL_TEST_SIGNED -eq 'true'
if ($expectLocalTestMarker -and $localTestMarkers.Count -ne 1) {
    throw 'Local-test full profile is missing its explicit signing marker.'
}
if (-not $expectLocalTestMarker -and $localTestMarkers.Count -ne 0) {
    throw 'Public MSI unexpectedly contains a local-test signing marker.'
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
