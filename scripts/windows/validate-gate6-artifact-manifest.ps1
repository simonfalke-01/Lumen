[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ManifestPath,

    [Parameter(Mandatory = $true)]
    [string]$EvidenceRoot,

    [string]$PolicyPath = (Join-Path $PSScriptRoot 'gate6-artifact-inventory.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'gate6-artifact-manifest.ps1')

$result = Assert-Gate6ArtifactManifest `
    -ManifestPath $ManifestPath `
    -EvidenceRoot $EvidenceRoot `
    -PolicyPath $PolicyPath

Write-Output "PASS: Gate6 artifact manifest validates $($result.FileCount) exact files."
