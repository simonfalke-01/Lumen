Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "../..")).Path
$workflowPath = Join-Path $root ".github/workflows/ci-windows.yml"
$workflowLines = @(Get-Content -LiteralPath $workflowPath)
$workflow = $workflowLines -join "`n"
$buildScriptPath = Join-Path $root "scripts/windows/build-full-profile.ps1"
$buildScript = Get-Content -LiteralPath $buildScriptPath -Raw
$artifactInventoryPath = Join-Path $root "scripts/windows/gate6-artifact-inventory.json"
$artifactInventoryText = Get-Content -LiteralPath $artifactInventoryPath -Raw
$artifactInventoryText | ConvertFrom-Json | Out-Null
$windowsTargets = Get-Content -LiteralPath (Join-Path $root "cmake/targets/windows.cmake") -Raw
$packagingCommon = Get-Content -LiteralPath (Join-Path $root "cmake/packaging/common.cmake") -Raw
$testProject = Get-Content -LiteralPath (Join-Path $root "tests/CMakeLists.txt") -Raw
$viteConfig = Get-Content -LiteralPath (Join-Path $root "vite.config.js") -Raw
$invocations = [Collections.Generic.List[string]]::new()

function Assert-ContainsLiteral {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text,

        [Parameter(Mandatory = $true)]
        [string]$Literal,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if (-not $Text.Contains($Literal, [StringComparison]::Ordinal)) {
        throw $Message
    }
}

$buildStepIndex = [Array]::IndexOf($workflowLines, "      - name: Build complete Windows profile")
if ($buildStepIndex -lt 0) {
    throw "Windows CI is missing the full-profile build step."
}
$runIndex = $buildStepIndex + 1
while ($runIndex -lt $workflowLines.Count -and $workflowLines[$runIndex].Trim() -ne 'run: |') {
    $runIndex++
}
if ($runIndex -ge $workflowLines.Count) {
    throw "Windows full-profile build step is missing its PowerShell run block."
}
$runLines = [Collections.Generic.List[string]]::new()
for ($index = $runIndex + 1; $index -lt $workflowLines.Count; $index++) {
    $line = $workflowLines[$index]
    if ($line -match '^      - name: ') {
        break
    }
    if ($line.Length -eq 0) {
        $runLines.Add('')
        continue
    }
    if ($line.Length -lt 10 -or $line.Substring(0, 10).Trim().Length -ne 0) {
        throw "Windows full-profile run block contains an invalid indentation boundary: $line"
    }
    $runLines.Add($line.Substring(10))
}
$runParseErrors = $null
[System.Management.Automation.Language.Parser]::ParseInput(
    ($runLines -join "`n"),
    [ref]$null,
    [ref]$runParseErrors
) | Out-Null
if ($runParseErrors.Count -ne 0) {
    $messages = $runParseErrors | ForEach-Object Message
    throw "Windows full-profile workflow PowerShell does not parse: $($messages -join '; ')"
}

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
    if ($invocation -notmatch '(?m)^-SccachePath \$sccache `?$') {
        throw "Every full-profile invocation must wire the hosted compiler cache.`n$invocation"
    }
}

foreach ($path in @(
        "src/platform/windows/virtual_hid_driver/LumenVirtualHid.vcxproj",
        "src/platform/windows/virtual_hid_driver/LumenVirtualHid.inf",
        "src/platform/windows/virtual_microphone_driver/LumenVirtualMicrophone.vcxproj",
        "src/platform/windows/virtual_microphone_driver/LumenVirtualMicrophone.inf",
        "src/platform/windows/virtual_display_driver/LumenVirtualDisplay.vcxproj",
        "src/platform/windows/virtual_display_driver/LumenVirtualDisplay.inf",
        "src/platform/windows/msquic_shim/LumenMsQuicShim.vcxproj",
        ".github/scripts/validate-windows-msi.ps1"
    )) {
    if (-not (Test-Path -LiteralPath (Join-Path $root $path) -PathType Leaf)) {
        throw "Windows full-profile input is missing: $path"
    }
}

foreach ($runId in @(
        "lumen-full-application-build",
        "lumen-full-nonhardware-tests",
        "lumen-full-msi-zip-package",
        "lumen-msi-table-validation",
        "lumen-msi-administrative-extraction",
        "lumen-zip-extraction"
    )) {
    Assert-ContainsLiteral $buildScript "-RunId '$runId'" "Missing downstream recorded command: $runId"
}

Assert-ContainsLiteral `
    $workflow `
    'path: cmake-build-windows/_deps' `
    "Windows CI must restore the CMake dependency tree."
Assert-ContainsLiteral `
    $workflow `
    '$sccache = (Get-Command sccache -ErrorAction Stop).Source' `
    "Windows CI must resolve the executable path rather than the extensionless SCCACHE_PATH hint."
Assert-ContainsLiteral `
    $buildScript `
    'Join-Path $SourceRoot "cmake-build-windows\_deps"' `
    "The full-profile configure must consume the restored CMake dependency tree."
Assert-ContainsLiteral `
    $buildScript `
    "-DFETCHCONTENT_BASE_DIR='`$dependencyCacheCmake'" `
    "The full-profile configure must bind FetchContent to the restored dependency tree."
Assert-ContainsLiteral `
    $buildScript `
    "-DCMAKE_C_COMPILER_LAUNCHER='`$sccacheCmake'" `
    "The full-profile C compiler must use the hosted sccache executable."
Assert-ContainsLiteral `
    $buildScript `
    "-DCMAKE_CXX_COMPILER_LAUNCHER='`$sccacheCmake'" `
    "The full-profile C++ compiler must use the hosted sccache executable."

$msquicCachePath = '${{ runner.temp }}/lumen-full-profile/downloads/Microsoft.Native.Quic.MsQuic.Schannel.2.6.0.nupkg'
Assert-ContainsLiteral $workflow "path: $msquicCachePath" "Windows CI must cache the pinned MsQuic package."
Assert-ContainsLiteral `
    $workflow `
    'if (-not (Test-Path -LiteralPath $nupkg -PathType Leaf)) {' `
    "Windows CI must reuse the cached MsQuic package before downloading it."
Assert-ContainsLiteral `
    $workflow `
    "Copy-Item (Join-Path `$staging 'artifacts\*') artifacts -Recurse -Force" `
    "Windows artifact staging must recursively preserve nested drivers, shim, and identity manifests."
$uploadBlock = [regex]::Match(
    $workflow,
    '(?s)- name: Upload Windows artifacts(?<body>.*?)\n\s{2}publish_reused_windows_artifacts:'
)
if (-not $uploadBlock.Success -or
    -not $uploadBlock.Groups['body'].Value.Contains('compression-level: 0', [StringComparison]::Ordinal)) {
    throw "Windows artifact upload must avoid recompressing the MSI and ZIP payloads."
}

$serviceMatch = [regex]::Match(
    $windowsTargets,
    '(?s)set_target_properties\(sunshinesvc\s+PROPERTIES\s+OUTPUT_NAME\s+"(?<name>[^"]+)"\)'
)
if (-not $serviceMatch.Success) {
    throw "Unable to resolve the installed Windows service executable name."
}
$servicePackagePath = "tools/$($serviceMatch.Groups['name'].Value).exe"
Assert-ContainsLiteral `
    $buildScript `
    "'$servicePackagePath'" `
    "Full-profile package validation must use the configured service executable name."
Assert-ContainsLiteral `
    $artifactInventoryText `
    "`"path`": `"$servicePackagePath`"" `
    "Gate6 artifact inventories must use the configured service executable name."
if ($buildScript.Contains('tools/sunshinesvc.exe', [StringComparison]::Ordinal) -or
    $artifactInventoryText.Contains('tools/sunshinesvc.exe', [StringComparison]::Ordinal)) {
    throw "Windows package contracts retain the pre-rename service executable path."
}

$webInputs = @(
    [regex]::Matches($viteConfig, "resolve\(assetsSrcPath, '([^']+\.html)'\)") |
        ForEach-Object { $_.Groups[1].Value } |
        Sort-Object -Unique
)
if ($webInputs.Count -ne 10) {
    throw "Expected ten production Vite HTML entries, found $($webInputs.Count)."
}
foreach ($webInput in $webInputs) {
    $packagePath = "assets/web/$webInput"
    Assert-ContainsLiteral `
        $buildScript `
        "'$packagePath'" `
        "Full-profile package validation is missing the Vite entry: $packagePath"
}

Assert-ContainsLiteral `
    $testProject `
    'project(test_sunshine)' `
    "The downstream nonhardware test executable target was renamed or removed."
Assert-ContainsLiteral `
    $buildScript `
    "'`$buildMsys/tests/test_sunshine.exe'" `
    "The full-profile preflight must execute the built gtest binary."
Assert-ContainsLiteral `
    $packagingCommon `
    'set(CPACK_PACKAGE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/cpack_artifacts)' `
    "The CPack artifact output directory contract changed."
Assert-ContainsLiteral `
    $buildScript `
    'Join-Path $buildRoot "cpack_artifacts"' `
    "The full-profile packager must collect MSI and ZIP outputs from CPack's configured directory."

Write-Output "PASS: cached Windows CI downstream build, test, package, and upload contracts are aligned"
