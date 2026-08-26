Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "../..")).Path
. (Join-Path $root "scripts/windows/full-profile-source-provenance.ps1")

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ("lumen-source-provenance-" + [Guid]::NewGuid().ToString("N"))
$sourceRoot = Join-Path $testRoot "mutable-source"
$freezeRoot = Join-Path $testRoot "freeze"
$verifiedRoot = Join-Path $testRoot "verified-source"
$tamperRoot = Join-Path $testRoot "tamper-output"

try {
    $shimRoot = Join-Path $sourceRoot "src/platform/windows/msquic_shim"
    $vddRoot = Join-Path $sourceRoot "src/platform/windows/virtual_display_driver"
    New-Item -ItemType Directory -Path $shimRoot, $vddRoot -Force | Out-Null
    [IO.File]::WriteAllText(
        (Join-Path $shimRoot "manifest.json"),
        '{"abi":3,"header_sha256":"header","source_sha256":"source","project_sha256":"project"}',
        [Text.UTF8Encoding]::new($false)
    )
    [IO.File]::WriteAllText(
        (Join-Path $vddRoot "LumenVirtualDisplayProtocol.h"),
        "#define LUMEN_VDD_ABI_VERSION 3u`n",
        [Text.UTF8Encoding]::new($false)
    )
    [IO.File]::WriteAllText(
        (Join-Path $sourceRoot "product-source.txt"),
        "frozen-content",
        [Text.UTF8Encoding]::new($false)
    )
    $shaderRoot = Join-Path $sourceRoot "src_assets/windows/assets/shaders/directx"
    foreach ($shader in @(
            'convert_yuv420_packed_uv_type0_ps_vdd_color_transform.hlsl',
            'convert_yuv420_packed_uv_type0s_ps_vdd_color_transform.hlsl',
            'convert_yuv420_planar_y_ps_vdd_color_transform.hlsl',
            'convert_yuv444_packed_ayuv_ps_vdd_color_transform.hlsl',
            'convert_yuv444_packed_y410_ps_vdd_color_transform.hlsl',
            'convert_yuv444_planar_ps_vdd_color_transform.hlsl',
            'include/convert_vdd_color_transform_base.hlsl'
        )) {
        $shaderPath = Join-Path $shaderRoot $shader
        New-Item -ItemType Directory -Path (Split-Path -Parent $shaderPath) -Force | Out-Null
        [IO.File]::WriteAllText(
            $shaderPath,
            "fixture:$shader",
            [Text.UTF8Encoding]::new($false)
        )
    }
    $scriptsRoot = Join-Path $sourceRoot "scripts/windows"
    New-Item -ItemType Directory -Path $scriptsRoot -Force | Out-Null
    [IO.File]::WriteAllText(
        (Join-Path $scriptsRoot "build-full-profile.ps1"),
        "build-entry-point",
        [Text.UTF8Encoding]::new($false)
    )
    foreach ($generatedDirectory in @("build-generated", "cmake-build-generated", ".venv")) {
        $generatedRoot = Join-Path $sourceRoot $generatedDirectory
        New-Item -ItemType Directory -Path $generatedRoot -Force | Out-Null
        [IO.File]::WriteAllText(
            (Join-Path $generatedRoot "ignored.txt"),
            "generated-content",
            [Text.UTF8Encoding]::new($false)
        )
    }
    $checkedInBuildRoot = Join-Path $sourceRoot "src_assets/macos/build"
    New-Item -ItemType Directory -Path $checkedInBuildRoot -Force | Out-Null
    [IO.File]::WriteAllText(
        (Join-Path $checkedInBuildRoot "Info.plist.in"),
        "checked-in-build-asset",
        [Text.UTF8Encoding]::new($false)
    )

    $sharedSourceFreezeManifestSha256 = 'd' * 64
    & (Join-Path $root "scripts/windows/freeze-full-profile-source.ps1") `
        -SourceRoot $sourceRoot `
        -OutputDirectory $freezeRoot `
        -SharedSourceFreezeManifestSha256 $sharedSourceFreezeManifestSha256 | Out-Null
    [IO.File]::WriteAllText(
        (Join-Path $sourceRoot "product-source.txt"),
        "mutable-content",
        [Text.UTF8Encoding]::new($false)
    )

    $provenance = Expand-VerifiedFullProfileSource `
        -FreezeDirectory $freezeRoot `
        -DestinationDirectory $verifiedRoot `
        -MutableSourceRoot $sourceRoot `
        -ExpectedSharedSourceFreezeManifestSha256 $sharedSourceFreezeManifestSha256
    $verifiedContent = Get-Content -LiteralPath (Join-Path $verifiedRoot "product-source.txt") -Raw
    if ($verifiedContent -cne "frozen-content") {
        throw "Verified build source was read from the mutable source tree."
    }
    $buildEntryPoint = Join-Path $verifiedRoot "scripts/windows/build-full-profile.ps1"
    if (-not (Test-Path -LiteralPath $buildEntryPoint -PathType Leaf)) {
        throw "Source freeze treated a build-prefixed file as a generated build directory."
    }
    foreach ($generatedDirectory in @("build-generated", "cmake-build-generated", ".venv")) {
        if (Test-Path -LiteralPath (Join-Path $verifiedRoot $generatedDirectory)) {
            throw "Source freeze retained generated directory: $generatedDirectory"
        }
    }
    if (-not (Test-Path -LiteralPath (Join-Path $verifiedRoot "src_assets/macos/build/Info.plist.in"))) {
        throw "Source freeze removed a checked-in nested build asset directory."
    }
    if ($provenance.SourceRoot -cne (Resolve-Path -LiteralPath $verifiedRoot).Path -or
        $provenance.FileCount -ne 12 -or
        $provenance.FilesManifestSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $provenance.ArchiveSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw "Verified source provenance result is incomplete."
    }

    Add-Content -LiteralPath (Join-Path $freezeRoot "full-profile-files.json") -Value " " -NoNewline
    $tamperRejected = $false
    try {
        Expand-VerifiedFullProfileSource `
            -FreezeDirectory $freezeRoot `
            -DestinationDirectory $tamperRoot `
            -MutableSourceRoot $sourceRoot `
            -ExpectedSharedSourceFreezeManifestSha256 $sharedSourceFreezeManifestSha256 | Out-Null
    } catch {
        $tamperRejected = $_.Exception.Message -eq
            "Source file manifest hash does not match the source-freeze manifest."
    }
    if (-not $tamperRejected) {
        throw "Tampered source metadata was not rejected."
    }

    Write-Output "PASS: frozen source is isolated, verified, and tamper-evident"
} finally {
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}
