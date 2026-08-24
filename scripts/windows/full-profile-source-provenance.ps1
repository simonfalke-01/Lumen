Set-StrictMode -Version Latest

function Test-FullProfilePathsDisjoint {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FirstPath,

        [Parameter(Mandatory = $true)]
        [string]$SecondPath
    )

    $first = [IO.Path]::GetFullPath($FirstPath).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    )
    $second = [IO.Path]::GetFullPath($SecondPath).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    )
    $separator = [IO.Path]::DirectorySeparatorChar
    return -not (
        $first.Equals($second, [StringComparison]::OrdinalIgnoreCase) -or
        $first.StartsWith($second + $separator, [StringComparison]::OrdinalIgnoreCase) -or
        $second.StartsWith($first + $separator, [StringComparison]::OrdinalIgnoreCase)
    )
}

function Expand-VerifiedFullProfileSource {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FreezeDirectory,

        [Parameter(Mandatory = $true)]
        [string]$DestinationDirectory,

        [Parameter(Mandatory = $true)]
        [string]$MutableSourceRoot
    )

    $FreezeDirectory = (Resolve-Path -LiteralPath $FreezeDirectory).Path
    $MutableSourceRoot = (Resolve-Path -LiteralPath $MutableSourceRoot).Path
    $DestinationDirectory = [IO.Path]::GetFullPath($DestinationDirectory)
    if (-not (Test-FullProfilePathsDisjoint $DestinationDirectory $MutableSourceRoot)) {
        throw "Verified source destination and mutable SourceRoot must be disjoint."
    }
    if (-not (Test-FullProfilePathsDisjoint $DestinationDirectory $FreezeDirectory)) {
        throw "Verified source destination and freeze directory must be disjoint."
    }

    $freezeManifestPath = Join-Path $FreezeDirectory "full-profile-source-freeze.json"
    if (-not (Test-Path -LiteralPath $freezeManifestPath -PathType Leaf)) {
        throw "Source-freeze manifest is missing: $freezeManifestPath"
    }
    $freezeManifest = Get-Content -LiteralPath $freezeManifestPath -Raw | ConvertFrom-Json
    if ([int]$freezeManifest.schema -ne 1 -or [int64]$freezeManifest.fileCount -le 0) {
        throw "Source-freeze manifest is invalid."
    }
    if ([string]$freezeManifest.filesManifest.name -cne "full-profile-files.json" -or
        [string]$freezeManifest.archive.name -cne "lumen-full-profile-source.tar.gz") {
        throw "Source-freeze manifest contains unexpected artifact names."
    }

    $filesManifestPath = Join-Path $FreezeDirectory "full-profile-files.json"
    $archivePath = Join-Path $FreezeDirectory "lumen-full-profile-source.tar.gz"
    foreach ($path in @($filesManifestPath, $archivePath)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Source-freeze artifact is missing: $path"
        }
    }
    $filesManifestHash = (Get-FileHash -LiteralPath $filesManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $archiveHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ([string]$freezeManifest.filesManifest.sha256 -cne $filesManifestHash) {
        throw "Source file manifest hash does not match the source-freeze manifest."
    }
    if ([string]$freezeManifest.archive.sha256 -cne $archiveHash -or
        [int64]$freezeManifest.archive.bytes -ne ([IO.FileInfo]::new($archivePath)).Length) {
        throw "Source archive identity does not match the source-freeze manifest."
    }

    # Windows PowerShell 5.1 preserves a top-level JSON array as one pipeline
    # object. The explicit object-array cast gives both 5.1 and PowerShell 7
    # the same row collection.
    $fileRows = [object[]](Get-Content -LiteralPath $filesManifestPath -Raw | ConvertFrom-Json)
    if ($fileRows.Count -ne [int]$freezeManifest.fileCount) {
        throw "Source file manifest count $($fileRows.Count) does not match the source-freeze manifest count $($freezeManifest.fileCount)."
    }

    $expectedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $expectedPathsIgnoreCase = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($row in $fileRows) {
        $relativePath = [string]$row.path
        $sha256 = [string]$row.sha256
        $segments = @($relativePath -split '/')
        if ([string]::IsNullOrWhiteSpace($relativePath) -or
            [IO.Path]::IsPathRooted($relativePath) -or
            $relativePath.Contains('\') -or
            $segments.Count -eq 0 -or
            @($segments | Where-Object { $_ -eq "" -or $_ -eq "." -or $_ -eq ".." }).Count -ne 0) {
            throw "Source file manifest contains an unsafe path: $relativePath"
        }
        if ($sha256 -cnotmatch '^[0-9a-f]{64}$' -or [int64]$row.bytes -lt 0) {
            throw "Source file manifest contains invalid metadata for: $relativePath"
        }
        if (-not $expectedPaths.Add($relativePath) -or
            -not $expectedPathsIgnoreCase.Add($relativePath)) {
            throw "Source file manifest contains a duplicate path: $relativePath"
        }
    }

    $archiveEntries = @(& tar -tzf $archivePath)
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to list the frozen source archive."
    }
    if ($archiveEntries.Count -ne $fileRows.Count) {
        throw "Source archive entry count does not match the source file manifest."
    }
    $archivePaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($entry in $archiveEntries) {
        if (-not $archivePaths.Add([string]$entry) -or -not $expectedPaths.Contains([string]$entry)) {
            throw "Source archive contains an unexpected or duplicate entry: $entry"
        }
    }

    if (Test-Path -LiteralPath $DestinationDirectory) {
        Remove-Item -LiteralPath $DestinationDirectory -Recurse -Force
    }
    New-Item -ItemType Directory -Path $DestinationDirectory -Force | Out-Null
    & tar -xzf $archivePath -C $DestinationDirectory
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to extract the frozen source archive."
    }
    $DestinationDirectory = (Resolve-Path -LiteralPath $DestinationDirectory).Path

    $reparsePoints = @(
        Get-ChildItem -LiteralPath $DestinationDirectory -Recurse -Force |
            Where-Object { ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 }
    )
    if ($reparsePoints.Count -ne 0) {
        throw "Extracted source contains a reparse point: $($reparsePoints[0].FullName)"
    }
    $actualFiles = @(Get-ChildItem -LiteralPath $DestinationDirectory -File -Recurse -Force)
    if ($actualFiles.Count -ne $fileRows.Count) {
        throw "Extracted source file count does not match the source file manifest."
    }
    foreach ($row in $fileRows) {
        $relativePath = [string]$row.path
        $path = Join-Path $DestinationDirectory ($relativePath -replace '/', [IO.Path]::DirectorySeparatorChar)
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Extracted source file is missing: $relativePath"
        }
        $fileInfo = [IO.FileInfo]::new($path)
        if ($fileInfo.Length -ne [int64]$row.bytes -or
            (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string]$row.sha256) {
            throw "Extracted source file identity mismatch: $relativePath"
        }
    }

    $msquicManifestPath = Join-Path $DestinationDirectory "src/platform/windows/msquic_shim/manifest.json"
    $vddProtocolPath = Join-Path $DestinationDirectory "src/platform/windows/virtual_display_driver/LumenVirtualDisplayProtocol.h"
    $msquicManifest = Get-Content -LiteralPath $msquicManifestPath -Raw | ConvertFrom-Json
    $vddProtocol = Get-Content -LiteralPath $vddProtocolPath -Raw
    $vddMatch = [regex]::Match($vddProtocol, '#define\s+LUMEN_VDD_ABI_VERSION\s+(\d+)u')
    if (-not $vddMatch.Success -or
        [int]$freezeManifest.identities.msquicShimAbi -ne [int]$msquicManifest.abi -or
        [string]$freezeManifest.identities.msquicHeaderSha256 -cne [string]$msquicManifest.header_sha256 -or
        [string]$freezeManifest.identities.msquicSourceSha256 -cne [string]$msquicManifest.source_sha256 -or
        [string]$freezeManifest.identities.msquicProjectSha256 -cne [string]$msquicManifest.project_sha256 -or
        [int]$freezeManifest.identities.virtualDisplayAbi -ne [int]$vddMatch.Groups[1].Value -or
        [string]$freezeManifest.identities.virtualDisplayProtocolSha256 -cne
            (Get-FileHash -LiteralPath $vddProtocolPath -Algorithm SHA256).Hash.ToLowerInvariant()) {
        throw "Source-freeze identity claims do not match the extracted build source."
    }

    return [pscustomobject]@{
        SourceRoot = $DestinationDirectory
        FileCount = $fileRows.Count
        FilesManifestSha256 = $filesManifestHash
        ArchiveSha256 = $archiveHash
        FreezeManifestSha256 = (Get-FileHash -LiteralPath $freezeManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}
