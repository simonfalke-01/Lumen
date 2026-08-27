Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "../..")).Path
$workflowPath = Join-Path $root ".github/workflows/ci-windows.yml"
$workflowLines = @(Get-Content -LiteralPath $workflowPath)
$invocations = [Collections.Generic.List[string]]::new()

for ($index = 0; $index -lt $workflowLines.Count; $index++) {
    if ($workflowLines[$index].Trim() -ne '& .\scripts\windows\build-full-profile.ps1 `') {
        continue
    }

    $invocationLines = [Collections.Generic.List[string]]::new()
    do {
        $line = $workflowLines[$index].Trim()
        $invocationLines.Add($line)
        $continues = $line.EndsWith('`', [StringComparison]::Ordinal)
        $index++
    } while ($continues -and $index -lt $workflowLines.Count)
    $invocations.Add(($invocationLines -join "`n"))
    $index--
}

if ($invocations.Count -ne 3) {
    throw "Expected exactly three full-profile Windows build invocations, found $($invocations.Count)."
}
foreach ($invocation in $invocations) {
    if ($invocation -notmatch '(?m)^-BuildOnly(?: `)?$') {
        throw "Every CI full-profile invocation must remain build-only.`n$invocation"
    }
    if ($invocation -notmatch '(?m)^-SkipSourceArchive(?: `)?$') {
        throw "Build-only CI must use direct source provenance instead of creating another archive.`n$invocation"
    }
}

Write-Output "PASS: Windows CI build-only invocations skip redundant source archives"
