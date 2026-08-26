[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$FragmentRoot,

    [string]$ManifestPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'gate6-evidence.ps1')

if ([string]::IsNullOrWhiteSpace($ManifestPath)) {
    $ManifestPath = Join-Path $FragmentRoot 'lumen-gate6-assembly-fragment.json'
}
$result = Assert-Gate6AssemblyFragment `
    -FragmentRoot $FragmentRoot `
    -ManifestPath $ManifestPath
Write-Output (
    "PASS: Lumen Gate6 assembly fragment retains {0} files and {1} mandatory runs." -f
        $result.FileCount,
        $result.MandatoryRunCount
)
