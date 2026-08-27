Set-StrictMode -Version Latest

if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw 'Full-profile source provenance requires PowerShell 7 or newer.'
}

$script:FullProfileExcludedDirectoryNames = @(
    '.git',
    '.omx',
    '.venv',
    '.wix',
    'node_modules'
)

function Write-FullProfileTarList {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Paths,

        [Parameter(Mandatory = $true)]
        [string]$ListPath
    )

    if ($Paths.Count -eq 0 -or @($Paths | Where-Object { $_ -eq '' }).Count -ne 0) {
        throw 'Full-profile tar list requires nonempty paths.'
    }
    [IO.File]::WriteAllText(
        $ListPath,
        [string]::Join("`n", $Paths),
        [Text.UTF8Encoding]::new($false)
    )
}

function Test-FullProfileExcludedPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RelativePath
    )

    $segments = @($RelativePath -split '[/\\]')
    for ($index = 0; $index -lt $segments.Count - 1; $index++) {
        $segment = $segments[$index]
        if ($segment -in $script:FullProfileExcludedDirectoryNames -or
            $segment -like 'cmake-build-*' -or
            ($index -eq 0 -and (
                $segment -eq 'build' -or
                $segment -eq 'build-deps' -or
                $segment -like 'build-*'
            ))) {
            return $true
        }
    }
    $name = $segments[-1]
    return $name -eq '.git' -or
        $name -eq '.DS_Store' -or
        $name -eq 'sunshine_state.json' -or
        $name -like 'test_sunshine.log*' -or
        $name -like 'write_file_test_*.txt' -or
        $name -like '*.gcda' -or
        $name -like '*.gcno'
}

function Get-FullProfileSourceFiles {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourceRoot
    )

    $SourceRoot = (Resolve-Path -LiteralPath $SourceRoot).Path
    $rootPrefix = $SourceRoot + [IO.Path]::DirectorySeparatorChar
    $resolvedFileReparseTargets = [Collections.Generic.Dictionary[string, IO.FileInfo]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    $reparsePoints = @(Get-ChildItem -LiteralPath $SourceRoot -Recurse -Force | Where-Object {
            ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
        })
    foreach ($reparsePoint in $reparsePoints) {
        $relative = $reparsePoint.FullName.Substring($SourceRoot.Length).TrimStart(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar
        ) -replace '\\', '/'
        if (Test-FullProfileExcludedPath $relative) {
            continue
        }
        if ($reparsePoint -is [IO.DirectoryInfo]) {
            throw "Full-profile source contains a directory reparse point: $($reparsePoint.FullName)"
        }
        if ([string]$reparsePoint.LinkType -cne 'SymbolicLink') {
            throw "Full-profile source contains an unsupported file reparse point: $($reparsePoint.FullName)"
        }
        try {
            $resolvedTarget = $reparsePoint.ResolveLinkTarget($true)
        } catch {
            throw "Full-profile source contains an unresolvable file reparse point: $($reparsePoint.FullName)"
        }
        if ($null -eq $resolvedTarget -or
            $resolvedTarget -isnot [IO.FileInfo] -or
            -not $resolvedTarget.Exists) {
            throw "Full-profile source contains a broken file reparse point: $($reparsePoint.FullName)"
        }
        $resolvedTargetPath = [IO.Path]::GetFullPath($resolvedTarget.FullName)
        if (-not $resolvedTargetPath.StartsWith(
                $rootPrefix,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "Full-profile source file reparse point escapes SourceRoot: $($reparsePoint.FullName)"
        }
        $resolvedFileReparseTargets.Add($reparsePoint.FullName, $resolvedTarget)
    }

    $files = @(
        Get-ChildItem -LiteralPath $SourceRoot -File -Recurse -Force | ForEach-Object {
            if (-not $_.FullName.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
                throw 'Source enumeration escaped SourceRoot.'
            }
            $relative = $_.FullName.Substring($SourceRoot.Length).TrimStart(
                [IO.Path]::DirectorySeparatorChar,
                [IO.Path]::AltDirectorySeparatorChar
            ) -replace '\\', '/'
            if (-not (Test-FullProfileExcludedPath $relative)) {
                if ($relative.Contains("`n") -or $relative.Contains("`r")) {
                    throw 'Source bundle does not support newline characters in paths.'
                }
                $identityFile = if ($resolvedFileReparseTargets.ContainsKey($_.FullName)) {
                    $resolvedFileReparseTargets[$_.FullName]
                } else {
                    $_
                }
                [pscustomobject]@{
                    RelativePath = $relative
                    FullName = $_.FullName
                    Bytes = $identityFile.Length
                    Sha256 = (Get-FileHash -LiteralPath $identityFile.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
                }
            }
        } | Sort-Object RelativePath
    )
    if ($files.Count -eq 0) {
        throw 'Full-profile source selected no files.'
    }
    $paths = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $pathsIgnoreCase = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($file in $files) {
        if (-not $paths.Add([string]$file.RelativePath) -or
            -not $pathsIgnoreCase.Add([string]$file.RelativePath)) {
            throw "Full-profile source contains a duplicate or case-colliding path: $($file.RelativePath)"
        }
    }
    return $files
}

function Read-FullProfileFilesManifest {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilesManifestPath
    )

    if (-not (Test-Path -LiteralPath $FilesManifestPath -PathType Leaf)) {
        throw "Source files manifest is missing: $FilesManifestPath"
    }
    $rows = [object[]](Get-Content -LiteralPath $FilesManifestPath -Raw | ConvertFrom-Json)
    $paths = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $pathsIgnoreCase = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($row in $rows) {
        $relativePath = [string]$row.path
        $segments = @($relativePath -split '/')
        if ([string]::IsNullOrWhiteSpace($relativePath) -or
            [IO.Path]::IsPathRooted($relativePath) -or
            $relativePath.Contains('\\') -or
            $segments.Count -eq 0 -or
            @($segments | Where-Object { $_ -eq '' -or $_ -eq '.' -or $_ -eq '..' }).Count -ne 0) {
            throw "Source file manifest contains an unsafe path: $relativePath"
        }
        if ([string]$row.sha256 -cnotmatch '^[0-9a-f]{64}$' -or [int64]$row.bytes -lt 0) {
            throw "Source file manifest contains invalid metadata for: $relativePath"
        }
        if (-not $paths.Add($relativePath) -or -not $pathsIgnoreCase.Add($relativePath)) {
            throw "Source file manifest contains a duplicate path: $relativePath"
        }
    }
    return $rows
}

function Assert-FullProfileSourceSnapshot {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourceRoot,

        [Parameter(Mandatory = $true)]
        [string]$FilesManifestPath,

        [Parameter(Mandatory = $true)]
        [string]$Boundary
    )

    $expectedRows = @(Read-FullProfileFilesManifest $FilesManifestPath)
    $actualFiles = @(Get-FullProfileSourceFiles $SourceRoot)
    if ($actualFiles.Count -ne $expectedRows.Count) {
        throw "Full-profile source changed before ${Boundary}: expected $($expectedRows.Count) files, found $($actualFiles.Count)."
    }
    $actualByPath = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
    foreach ($file in $actualFiles) {
        $actualByPath.Add([string]$file.RelativePath, $file)
    }
    foreach ($row in $expectedRows) {
        $relativePath = [string]$row.path
        if (-not $actualByPath.ContainsKey($relativePath)) {
            throw "Full-profile source changed before ${Boundary}: missing $relativePath"
        }
        $actual = $actualByPath[$relativePath]
        if ([int64]$actual.Bytes -ne [int64]$row.bytes -or
            [string]$actual.Sha256 -cne [string]$row.sha256) {
            throw "Full-profile source changed before ${Boundary}: identity mismatch for $relativePath"
        }
    }
    return [pscustomobject]@{
        Boundary = $Boundary
        FileCount = $actualFiles.Count
        FilesManifestSha256 = (Get-FileHash -LiteralPath $FilesManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

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
        [string]$MutableSourceRoot,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedSharedSourceFreezeManifestSha256
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
    if ([int]$freezeManifest.schema -ne 1 -or
        [int64]$freezeManifest.fileCount -le 0 -or
        [string]$freezeManifest.sharedSourceFreezeSchema -cne
            'umbra-lumen/source-freeze-manifest/1' -or
        [string]$freezeManifest.sharedSourceFreezeManifestSha256 -cne
            $ExpectedSharedSourceFreezeManifestSha256) {
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
    $fileRows = @(Read-FullProfileFilesManifest $filesManifestPath)
    if ($fileRows.Count -ne [int]$freezeManifest.fileCount) {
        throw "Source file manifest count $($fileRows.Count) does not match the source-freeze manifest count $($freezeManifest.fileCount)."
    }

    $expectedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($row in $fileRows) { [void]$expectedPaths.Add([string]$row.path) }

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

    [void](Assert-FullProfileSourceSnapshot `
        -SourceRoot $DestinationDirectory `
        -FilesManifestPath $filesManifestPath `
        -Boundary 'verified-source extraction')

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
        FilesManifestPath = $filesManifestPath
        FreezeManifestPath = $freezeManifestPath
        ArchivePath = $archivePath
        SharedSourceFreezeManifestSha256 = $ExpectedSharedSourceFreezeManifestSha256
    }
}
