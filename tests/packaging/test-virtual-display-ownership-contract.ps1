[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$lumenRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "../.."))
$setupPath = Join-Path $lumenRoot "src_assets/windows/misc/virtual-display-setup.ps1"
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $setupPath,
    [ref]$tokens,
    [ref]$parseErrors)
if ($parseErrors.Count -ne 0) {
    throw "Virtual Display setup has PowerShell parse errors: $($parseErrors -join '; ')"
}

$requiredFunctions = @(
    "ConvertTo-NormalizedProductCode",
    "Resolve-VirtualDisplayOwnership",
    "New-VirtualDisplayTransactionIdentity",
    "Resolve-OwnershipCommitAction",
    "Resolve-OwnershipRollbackAction",
    "Assert-VirtualDisplayResumeAfterRestart",
    "Assert-DriverIdentityFields",
    "Assert-OwnedDriverManifestSchema"
)
$definitions = @($ast.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -in $requiredFunctions
        }, $true))
if ($definitions.Count -ne $requiredFunctions.Count) {
    throw "Could not load the production Virtual Display ownership functions."
}
Invoke-Expression (($definitions | ForEach-Object { $_.Extent.Text }) -join "`n")

function Assert-Equal {
    param(
        [object]$Actual,
        [object]$Expected,
        [string]$Description
    )
    if ($Actual -cne $Expected) {
        throw "$Description Expected '$Expected', got '$Actual'."
    }
}

function Assert-ThrowsMessage {
    param(
        [scriptblock]$Operation,
        [string]$ExpectedMessage,
        [string]$Description
    )
    try {
        & $Operation
    } catch {
        if ($_.Exception.Message -cne $ExpectedMessage) {
            throw "$Description Expected '$ExpectedMessage', got '$($_.Exception.Message)'."
        }
        return
    }
    throw "$Description Expected a refusal."
}

$current = "{11111111-1111-1111-1111-111111111111}"
$foreign = "{22222222-2222-2222-2222-222222222222}"
$other = "{33333333-3333-3333-3333-333333333333}"

$unowned = Resolve-VirtualDisplayOwnership `
    -OwnedProductCode $null `
    -CurrentProductCode $current `
    -RelatedUpgradeOwnerProductCode $null `
    -InstalledDevicePresent $false
Assert-Equal $unowned.Disposition "unowned" "A clean install must start unowned."
Assert-Equal $unowned.PreviousOwnerProductCode $null "A clean install must not invent an owner."

Assert-ThrowsMessage {
    Resolve-VirtualDisplayOwnership `
        -OwnedProductCode $null `
        -CurrentProductCode $current `
        -RelatedUpgradeOwnerProductCode $null `
        -InstalledDevicePresent $true
} "Refusing to adopt a Virtual Display device without durable ProductCode ownership or verified related-upgrade ownership." `
    "Hardware ID alone must not establish ownership."

$retained = Resolve-VirtualDisplayOwnership `
    -OwnedProductCode $current `
    -CurrentProductCode $current `
    -RelatedUpgradeOwnerProductCode $null `
    -InstalledDevicePresent $true
Assert-Equal $retained.Disposition "current-product" "The owning ProductCode must retain ownership."
Assert-Equal $retained.PreviousOwnerProductCode $current "The current owner must be persisted."

Assert-ThrowsMessage {
    Resolve-VirtualDisplayOwnership `
        -OwnedProductCode $foreign `
        -CurrentProductCode $current `
        -RelatedUpgradeOwnerProductCode $null `
        -InstalledDevicePresent $true
} "Refusing to mutate a Virtual Display owned by another ProductCode: $foreign" `
    "A foreign manifest plus present device must fail closed."

Assert-ThrowsMessage {
    Resolve-VirtualDisplayOwnership `
        -OwnedProductCode $foreign `
        -CurrentProductCode $current `
        -RelatedUpgradeOwnerProductCode $other `
        -InstalledDevicePresent $false
} "Refusing to mutate a Virtual Display owned by another ProductCode: $foreign" `
    "A foreign package-only owner must not transfer through a different related product."

$transfer = Resolve-VirtualDisplayOwnership `
    -OwnedProductCode $foreign `
    -CurrentProductCode $current `
    -RelatedUpgradeOwnerProductCode $foreign `
    -InstalledDevicePresent $true
Assert-Equal $transfer.Disposition "related-upgrade-transfer" "A verified related product may transfer ownership."
Assert-Equal $transfer.PreviousOwnerProductCode $foreign "A transfer must retain the prior owner until commit."

$legacyTransfer = Resolve-VirtualDisplayOwnership `
    -OwnedProductCode $null `
    -CurrentProductCode $current `
    -RelatedUpgradeOwnerProductCode $foreign `
    -InstalledDevicePresent $true
Assert-Equal $legacyTransfer.Disposition "related-upgrade-transfer" `
    "Verified MSI feature ownership may migrate a pre-manifest related product."
Assert-Equal $legacyTransfer.PreviousOwnerProductCode $foreign `
    "A pre-manifest transfer must persist its MSI-proven prior owner."

Assert-ThrowsMessage {
    Resolve-VirtualDisplayOwnership `
        -OwnedProductCode $current `
        -CurrentProductCode $current `
        -RelatedUpgradeOwnerProductCode $foreign `
        -InstalledDevicePresent $true
} "The related-upgrade VDD owner conflicts with the durable ProductCode ownership manifest." `
    "Multiple conflicting ownership proofs must be refused."

Assert-ThrowsMessage {
    Resolve-VirtualDisplayOwnership `
        -OwnedProductCode "not-a-product-code" `
        -CurrentProductCode $current `
        -RelatedUpgradeOwnerProductCode $null `
        -InstalledDevicePresent $true
} "ProductCode must be an uppercase-braced GUID." `
    "A tampered ownership ProductCode must be refused."

$installIdentity = New-VirtualDisplayTransactionIdentity `
    -CurrentProductCode $current `
    -CurrentTransactionKind "install"
$uninstallIdentity = New-VirtualDisplayTransactionIdentity `
    -CurrentProductCode $current `
    -CurrentTransactionKind "uninstall"
$foreignIdentity = New-VirtualDisplayTransactionIdentity `
    -CurrentProductCode $foreign `
    -CurrentTransactionKind "install"
Assert-Equal $installIdentity.RebootMarkerSuffix `
    "11111111111111111111111111111111\install" `
    "The reboot journal must be ProductCode plus transaction scoped."
Assert-Equal $uninstallIdentity.RebootMarkerSuffix `
    "11111111111111111111111111111111\uninstall" `
    "Install and uninstall resume journals must not collide."
if ($installIdentity.ResumeTaskName -ceq $uninstallIdentity.ResumeTaskName -or
    $installIdentity.ResumeTaskName -ceq $foreignIdentity.ResumeTaskName) {
    throw "Resume tasks are not scoped by exact ProductCode and transaction."
}
Assert-ThrowsMessage {
    New-VirtualDisplayTransactionIdentity `
        -CurrentProductCode $current `
        -CurrentTransactionKind "repair"
} "Virtual Display transaction kind is invalid." `
    "Unknown resume transaction kinds must be refused."

$hashA = "A" * 64
$hashB = "B" * 64
Assert-Equal (Resolve-OwnershipCommitAction `
        -OwnershipCommitted $false `
        -PreviousManifestSha256 $hashA `
        -CurrentManifestSha256 $hashA `
        -IntendedOwnershipMatches $false) `
    "apply" `
    "An unchanged prior manifest may advance to the atomic ownership write."
Assert-Equal (Resolve-OwnershipCommitAction `
        -OwnershipCommitted $false `
        -PreviousManifestSha256 $hashA `
        -CurrentManifestSha256 $hashB `
        -IntendedOwnershipMatches $true) `
    "record-committed" `
    "A crash after the atomic ownership move must resume without rewriting it."
Assert-Equal (Resolve-OwnershipCommitAction `
        -OwnershipCommitted $true `
        -PreviousManifestSha256 $hashA `
        -CurrentManifestSha256 $hashB `
        -IntendedOwnershipMatches $true) `
    "already-committed" `
    "Ownership commit replay must be idempotent."
Assert-ThrowsMessage {
    Resolve-OwnershipCommitAction `
        -OwnershipCommitted $false `
        -PreviousManifestSha256 $hashA `
        -CurrentManifestSha256 $hashB `
        -IntendedOwnershipMatches $false
} "The durable Virtual Display ownership manifest changed during the transaction." `
    "A well-formed manifest replacement must fail compare-and-swap."
Assert-ThrowsMessage {
    Resolve-OwnershipCommitAction `
        -OwnershipCommitted $true `
        -PreviousManifestSha256 $hashA `
        -CurrentManifestSha256 $hashB `
        -IntendedOwnershipMatches $false
} "Committed Virtual Display ownership no longer matches the transaction result." `
    "Committed ownership tampering must fail closed."

Assert-Equal (Resolve-OwnershipRollbackAction `
        -TransactionCommitted $false `
        -OwnershipCommitted $false `
        -PreviousManifestSha256 $hashA `
        -CurrentManifestSha256 $hashA) `
    "retain-previous" `
    "Rollback before ownership commit must preserve the prior owner."
Assert-Equal (Resolve-OwnershipRollbackAction `
        -TransactionCommitted $true `
        -OwnershipCommitted $true `
        -PreviousManifestSha256 $hashA `
        -CurrentManifestSha256 $hashB) `
    "complete-commit" `
    "Rollback after ownership commit must finish rather than restore foreign ownership."
Assert-ThrowsMessage {
    Resolve-OwnershipRollbackAction `
        -TransactionCommitted $false `
        -OwnershipCommitted $false `
        -PreviousManifestSha256 $hashA `
        -CurrentManifestSha256 $hashB
} "The durable Virtual Display ownership manifest changed before rollback." `
    "Rollback must not overwrite a concurrently changed manifest."

Assert-ThrowsMessage {
    Assert-VirtualDisplayResumeAfterRestart `
        -PendingBootIdentifier "638917200000000000" `
        -CurrentBootIdentifier "638917200000000000"
} "Virtual Display resume is waiting for Windows to restart." `
    "A reboot-pending transaction must refuse same-boot resume."
Assert-VirtualDisplayResumeAfterRestart `
    -PendingBootIdentifier "638917200000000000" `
    -CurrentBootIdentifier "638918064000000000"
Assert-ThrowsMessage {
    Assert-VirtualDisplayResumeAfterRestart `
        -PendingBootIdentifier "tampered" `
        -CurrentBootIdentifier "638918064000000000"
} "Virtual Display resume state has an invalid boot identifier." `
    "A tampered reboot journal must fail closed."

$validIdentity = [pscustomobject]@{
    PublishedInfName = "oem42.inf"
    InfSha256 = "C" * 64
    ManifestSha256 = "D" * 64
    CatalogSignerThumbprint = "E" * 40
}
Assert-DriverIdentityFields -Identity $validIdentity
$validManifest = [pscustomobject]@{
    Schema = 1
    ProductCode = $current
    PublishedInfName = $validIdentity.PublishedInfName
    InfSha256 = $validIdentity.InfSha256
    ManifestSha256 = $validIdentity.ManifestSha256
    CatalogSignerThumbprint = $validIdentity.CatalogSignerThumbprint
}
Assert-OwnedDriverManifestSchema -Manifest $validManifest
$extraFieldManifest = $validManifest.PSObject.Copy()
$extraFieldManifest | Add-Member -NotePropertyName AdoptByHardwareId -NotePropertyValue $true
Assert-ThrowsMessage {
    Assert-OwnedDriverManifestSchema -Manifest $extraFieldManifest
} "The Lumen Virtual Display ownership manifest schema is invalid." `
    "Tampered ownership manifests with extra authority fields must be refused."
$tamperedIdentity = $validIdentity.PSObject.Copy()
$tamperedIdentity.ManifestSha256 = "not-a-sha256"
Assert-ThrowsMessage {
    Assert-DriverIdentityFields -Identity $tamperedIdentity
} "The saved Lumen Virtual Display ownership identity is invalid." `
    "Tampered manifest identity fields must be refused."

Write-Output "PASS: Virtual Display ProductCode ownership transfer/refusal contract"
