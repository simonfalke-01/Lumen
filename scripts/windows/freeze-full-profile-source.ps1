[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SourceRoot,

    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$SourceRoot = (Resolve-Path -LiteralPath $SourceRoot).Path
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
if ($OutputDirectory -eq $SourceRoot -or
    $OutputDirectory.StartsWith(
        $SourceRoot + [IO.Path]::DirectorySeparatorChar,
        [StringComparison]::OrdinalIgnoreCase
    ) -or
    $SourceRoot.StartsWith(
        $OutputDirectory + [IO.Path]::DirectorySeparatorChar,
        [StringComparison]::OrdinalIgnoreCase
    )) {
    throw "OutputDirectory and SourceRoot must be disjoint."
}
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$excludedDirectoryNames = @(
    ".git",
    ".omx",
    ".venv",
    ".wix",
    "node_modules"
)
function Test-ExcludedPath {
    param([string]$RelativePath)
    $segments = $RelativePath -split '[/\\]'
    for ($index = 0; $index -lt $segments.Count - 1; $index++) {
        $segment = $segments[$index]
        if ($segment -in $excludedDirectoryNames -or
            $segment -like "cmake-build-*" -or
            ($index -eq 0 -and (
                $segment -eq "build" -or
                $segment -eq "build-deps" -or
                $segment -like "build-*"
            ))) {
            return $true
        }
    }
    $name = $segments[-1]
    return $name -eq ".git" -or
        $name -eq ".DS_Store" -or
        $name -eq "sunshine_state.json" -or
        $name -like "test_sunshine.log*" -or
        $name -like "write_file_test_*.txt" -or
        $name -like "*.gcda" -or
        $name -like "*.gcno"
}

$files = @(
    Get-ChildItem -LiteralPath $SourceRoot -File -Recurse -Force | ForEach-Object {
        if (-not $_.FullName.StartsWith(
                $SourceRoot + [IO.Path]::DirectorySeparatorChar,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "Source enumeration escaped SourceRoot."
        }
        $relative = $_.FullName.Substring($SourceRoot.Length).TrimStart(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar
        ) -replace '\\', '/'
        if (-not (Test-ExcludedPath $relative)) {
            if ($relative.Contains("`n") -or $relative.Contains("`r")) {
                throw "Source bundle does not support newline characters in paths."
            }
            [pscustomobject]@{
                RelativePath = $relative
                FullName = $_.FullName
            }
        }
    } | Sort-Object RelativePath
)
if ($files.Count -eq 0) {
    throw "Source freeze selected no files."
}

$hashRows = @(
    $files | ForEach-Object {
        $file = $_
        [ordered]@{
            path = $file.RelativePath
            sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            bytes = ([IO.FileInfo]::new($file.FullName)).Length
        }
    }
)
$fileManifestPath = Join-Path $OutputDirectory "full-profile-files.json"
$hashRows | ConvertTo-Json -Depth 4 | Set-Content $fileManifestPath -Encoding UTF8

$listPath = Join-Path $OutputDirectory "full-profile-files.txt"
[IO.File]::WriteAllLines(
    $listPath,
    [string[]]$files.RelativePath,
    [Text.UTF8Encoding]::new($false)
)
$archivePath = Join-Path $OutputDirectory "lumen-full-profile-source.tar.gz"
& tar -czhf $archivePath -C $SourceRoot -T $listPath
if ($LASTEXITCODE -ne 0) {
    throw "tar failed with exit code $LASTEXITCODE."
}

$msquicManifestPath = Join-Path $SourceRoot "src/platform/windows/msquic_shim/manifest.json"
$msquicManifest = Get-Content $msquicManifestPath -Raw | ConvertFrom-Json
$vddProtocolPath = Join-Path $SourceRoot "src/platform/windows/virtual_display_driver/LumenVirtualDisplayProtocol.h"
$vddProtocol = Get-Content $vddProtocolPath -Raw
$vddMatch = [regex]::Match($vddProtocol, '#define\s+LUMEN_VDD_ABI_VERSION\s+(\d+)u')
if (-not $vddMatch.Success) {
    throw "Unable to read LUMEN_VDD_ABI_VERSION."
}

$freeze = [ordered]@{
    schema = 1
    fileCount = $files.Count
    filesManifest = [ordered]@{
        name = [IO.Path]::GetFileName($fileManifestPath)
        sha256 = (Get-FileHash $fileManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    archive = [ordered]@{
        name = [IO.Path]::GetFileName($archivePath)
        bytes = (Get-Item $archivePath).Length
        sha256 = (Get-FileHash $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    identities = [ordered]@{
        msquicShimAbi = [int]$msquicManifest.abi
        msquicHeaderSha256 = [string]$msquicManifest.header_sha256
        msquicSourceSha256 = [string]$msquicManifest.source_sha256
        msquicProjectSha256 = [string]$msquicManifest.project_sha256
        virtualDisplayAbi = [int]$vddMatch.Groups[1].Value
        virtualDisplayProtocolSha256 = (Get-FileHash $vddProtocolPath -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    pendingRuntimePins = @(
        "LUMEN_MSQUIC_SHIM_DLL_SHA256",
        "LUMEN_MSQUIC_SHIM_LIB_SHA256",
        "Microsoft-signed virtual-hid package",
        "Microsoft-signed virtual-microphone package",
        "Microsoft-signed virtual-display package"
    )
}
$freezePath = Join-Path $OutputDirectory "full-profile-source-freeze.json"
$freeze | ConvertTo-Json -Depth 8 | Set-Content $freezePath -Encoding UTF8
Remove-Item -LiteralPath $listPath -Force

Write-Output "SOURCE_ARCHIVE=$archivePath"
Write-Output "SOURCE_ARCHIVE_SHA256=$($freeze.archive.sha256)"
Write-Output "SOURCE_FREEZE=$freezePath"
