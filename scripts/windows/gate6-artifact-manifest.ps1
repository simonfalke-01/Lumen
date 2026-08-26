Set-StrictMode -Version Latest

function Get-Gate6Sha256 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-Gate6Properties {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Value,

        [Parameter(Mandatory = $true)]
        [string[]]$Required,

        [string[]]$Optional = @(),

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    if ($null -eq $Value) {
        throw "$Description is missing."
    }
    $names = @($Value.PSObject.Properties.Name)
    foreach ($name in $Required) {
        if ($name -notin $names) {
            throw "$Description is missing property: $name"
        }
    }
    $allowed = @($Required) + @($Optional)
    $unexpected = @($names | Where-Object { $_ -notin $allowed })
    if ($unexpected.Count -ne 0) {
        throw "$Description contains an unexpected property: $($unexpected[0])"
    }
}

function Assert-Gate6Sha256 {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    if ($Value -cnotmatch '^[0-9a-f]{64}$') {
        throw "$Description must be a lowercase SHA-256 value."
    }
}

function Assert-Gate6RelativePath {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Description,

        [switch]$AllowEmpty
    )

    if (($Path.Length -eq 0 -and -not $AllowEmpty) -or
        [IO.Path]::IsPathRooted($Path) -or
        $Path.Contains('\') -or
        $Path.Contains(':') -or
        $Path.Contains("`n") -or
        $Path.Contains("`r") -or
        $Path -match '[\x00-\x1f\x7f]') {
        throw "$Description is unsafe: $Path"
    }
    if ($Path.Length -eq 0) {
        return
    }
    $segments = @($Path -split '/')
    if (@($segments | Where-Object {
                $_ -eq '' -or $_ -eq '.' -or $_ -eq '..' -or
                $_.EndsWith('.') -or $_.EndsWith(' ')
            }).Count -ne 0) {
        throw "$Description is unsafe: $Path"
    }
}

function Resolve-Gate6EvidencePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$EvidenceRoot,

        [Parameter(Mandatory = $true)]
        [string]$RelativePath
    )

    Assert-Gate6RelativePath $RelativePath 'Evidence path'
    $root = [IO.Path]::GetFullPath($EvidenceRoot).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    )
    $nativeRelative = $RelativePath.Replace('/', [IO.Path]::DirectorySeparatorChar)
    $candidate = [IO.Path]::GetFullPath((Join-Path $root $nativeRelative))
    $prefix = $root + [IO.Path]::DirectorySeparatorChar
    if (-not $candidate.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Evidence path escaped the evidence root: $RelativePath"
    }
    return $candidate
}

function Get-Gate6RelativeEvidencePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$EvidenceRoot,

        [Parameter(Mandatory = $true)]
        [string]$FullPath
    )

    $root = [IO.Path]::GetFullPath($EvidenceRoot).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    )
    $candidate = [IO.Path]::GetFullPath($FullPath)
    $prefix = $root + [IO.Path]::DirectorySeparatorChar
    if (-not $candidate.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Evidence enumeration escaped the evidence root: $candidate"
    }
    return $candidate.Substring($prefix.Length).Replace('\', '/')
}

function Read-Gate6Json {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Description is missing: $Path"
    }
    try {
        return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    } catch {
        throw "$Description is not valid JSON: $Path"
    }
}

function Join-Gate6PolicyPath {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Root,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    Assert-Gate6RelativePath $Root 'Policy scope root' -AllowEmpty
    Assert-Gate6RelativePath $Path 'Policy file path'
    if ($Root.Length -eq 0) {
        return $Path
    }
    return "$Root/$Path"
}

function Test-Gate6Regex {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value,

        [Parameter(Mandatory = $true)]
        [string]$Pattern
    )

    try {
        return [regex]::IsMatch(
            $Value,
            $Pattern,
            [Text.RegularExpressions.RegexOptions]::CultureInvariant
        )
    } catch {
        throw "Gate6 policy contains an invalid regular expression: $Pattern"
    }
}

function Get-Gate6InventoryRowsSha256 {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Rows,

        [Parameter(Mandatory = $true)]
        [string]$InventoryRoot
    )

    Assert-Gate6RelativePath $InventoryRoot 'Gate6 package inventory root'
    $prefix = "$InventoryRoot/"
    $lines = @(
        $Rows | Where-Object {
            ([string]$_.path).StartsWith($prefix, [StringComparison]::Ordinal)
        } | Sort-Object { [string]$_.path } | ForEach-Object {
            $relativePath = ([string]$_.path).Substring($prefix.Length)
            "$relativePath`t$([string]$_.kind)`t$([int64]$_.bytes)`t$([string]$_.sha256)"
        }
    )
    $payload = [Text.UTF8Encoding]::new($false).GetBytes(($lines -join "`n") + "`n")
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = $sha256.ComputeHash($payload)
        return (($digest | ForEach-Object { '{0:x2}' -f $_ }) -join '')
    } finally {
        $sha256.Dispose()
    }
}

function Assert-Gate6InventoryPolicy {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Policy
    )

    Assert-Gate6Properties $Policy `
        @(
            'schema',
            'manifestSchema',
            'allowedKinds',
            'driverSubmissionBoundPatterns',
            'packageInventories',
            'scopes'
        ) `
        @() `
        'Gate6 inventory policy'
    if ([string]$Policy.schema -cne 'lumen-gate6-artifact-inventory-policy/1' -or
        [string]$Policy.manifestSchema -cne 'lumen-gate6-artifact-manifest/1') {
        throw 'Gate6 inventory policy schema is unsupported.'
    }

    $allowedKinds = @($Policy.allowedKinds)
    if ($allowedKinds.Count -eq 0 -or @($allowedKinds | Where-Object {
                [string]::IsNullOrWhiteSpace([string]$_)
            }).Count -ne 0) {
        throw 'Gate6 inventory policy has no usable file kinds.'
    }
    $kindSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($kind in $allowedKinds) {
        if (-not $kindSet.Add([string]$kind)) {
            throw "Gate6 inventory policy contains a duplicate file kind: $kind"
        }
    }

    foreach ($pattern in @($Policy.driverSubmissionBoundPatterns)) {
        [void](Test-Gate6Regex '' ([string]$pattern))
    }

    $scopeNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $scopeRoots = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::Ordinal)
    $policyPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($scope in @($Policy.scopes)) {
        Assert-Gate6Properties $scope `
            @('name', 'root', 'exactFiles', 'requiredPatterns', 'forbiddenPatterns') `
            @() `
            'Gate6 inventory scope'
        $scopeName = [string]$scope.name
        $scopeRoot = [string]$scope.root
        if ([string]::IsNullOrWhiteSpace($scopeName) -or -not $scopeNames.Add($scopeName)) {
            throw "Gate6 inventory policy contains an invalid or duplicate scope: $scopeName"
        }
        Assert-Gate6RelativePath $scopeRoot 'Policy scope root' -AllowEmpty
        $scopeRoots.Add($scopeName, $scopeRoot)

        foreach ($entry in @($scope.exactFiles)) {
            Assert-Gate6Properties $entry @('path', 'kind') @() 'Gate6 exact-file rule'
            $fullPath = Join-Gate6PolicyPath $scopeRoot ([string]$entry.path)
            $kind = [string]$entry.kind
            if ($kind -notin $allowedKinds) {
                throw "Gate6 exact-file rule has an unknown kind: $kind"
            }
            if (-not $policyPaths.Add($fullPath)) {
                throw "Gate6 inventory policy contains a duplicate or case-colliding path: $fullPath"
            }
        }

        foreach ($rule in @($scope.requiredPatterns)) {
            Assert-Gate6Properties $rule @('regex', 'kind', 'minimum') @('maximum') 'Gate6 pattern rule'
            $kind = [string]$rule.kind
            if ($kind -notin $allowedKinds -or [int64]$rule.minimum -lt 0) {
                throw "Gate6 pattern rule is invalid in scope: $scopeName"
            }
            if ($null -ne $rule.PSObject.Properties['maximum'] -and
                [int64]$rule.maximum -lt [int64]$rule.minimum) {
                throw "Gate6 pattern maximum is lower than its minimum in scope: $scopeName"
            }
            [void](Test-Gate6Regex '' ([string]$rule.regex))
        }
        foreach ($pattern in @($scope.forbiddenPatterns)) {
            [void](Test-Gate6Regex '' ([string]$pattern))
        }
    }
    if ($scopeNames.Count -eq 0) {
        throw 'Gate6 inventory policy has no scopes.'
    }

    $packageNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($package in @($Policy.packageInventories)) {
        Assert-Gate6Properties $package `
            @('name', 'root', 'packageKind') `
            @() `
            'Gate6 package-inventory policy'
        $name = [string]$package.name
        $root = [string]$package.root
        $kind = [string]$package.packageKind
        Assert-Gate6RelativePath $root 'Gate6 package inventory root'
        if (-not $packageNames.Add($name) -or
            -not $scopeRoots.ContainsKey($name) -or
            $scopeRoots[$name] -cne $root -or
            $kind -notin $allowedKinds) {
            throw "Gate6 package-inventory policy is invalid: $name"
        }
    }
    if ($packageNames.Count -eq 0) {
        throw 'Gate6 inventory policy has no package inventories.'
    }
}

function Assert-Gate6SourceFreezeReference {
    param(
        [Parameter(Mandatory = $true)]
        [object]$SourceFreeze,

        [Parameter(Mandatory = $true)]
        [string]$EvidenceRoot
    )

    Assert-Gate6Properties $SourceFreeze `
        @(
            'manifestPath',
            'manifestSha256',
            'filesManifestPath',
            'filesManifestSha256',
            'archivePath',
            'archiveSha256'
        ) `
        @() `
        'Gate6 source-freeze reference'
    foreach ($property in @('manifestSha256', 'filesManifestSha256', 'archiveSha256')) {
        Assert-Gate6Sha256 ([string]$SourceFreeze.$property) "Gate6 source-freeze $property"
    }
    if ([string]$SourceFreeze.manifestPath -cne 'source-freeze/full-profile-source-freeze.json' -or
        [string]$SourceFreeze.filesManifestPath -cne 'source-freeze/full-profile-files.json' -or
        [string]$SourceFreeze.archivePath -cne 'source-freeze/lumen-full-profile-source.tar.gz') {
        throw 'Gate6 source-freeze reference contains unexpected artifact paths.'
    }

    $manifestPath = Resolve-Gate6EvidencePath $EvidenceRoot ([string]$SourceFreeze.manifestPath)
    $filesManifestPath = Resolve-Gate6EvidencePath $EvidenceRoot ([string]$SourceFreeze.filesManifestPath)
    $archivePath = Resolve-Gate6EvidencePath $EvidenceRoot ([string]$SourceFreeze.archivePath)
    foreach ($path in @($manifestPath, $filesManifestPath, $archivePath)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Gate6 source-freeze artifact is missing: $path"
        }
    }
    if ((Get-Gate6Sha256 $manifestPath) -cne [string]$SourceFreeze.manifestSha256) {
        throw 'Gate6 source-freeze manifest hash does not match its reference.'
    }
    if ((Get-Gate6Sha256 $filesManifestPath) -cne [string]$SourceFreeze.filesManifestSha256) {
        throw 'Gate6 source files manifest hash does not match its reference.'
    }
    if ((Get-Gate6Sha256 $archivePath) -cne [string]$SourceFreeze.archiveSha256) {
        throw 'Gate6 source archive hash does not match its reference.'
    }

    $freeze = Read-Gate6Json $manifestPath 'Gate6 source-freeze manifest'
    if ([int]$freeze.schema -ne 1 -or [int64]$freeze.fileCount -le 0) {
        throw 'Gate6 source-freeze manifest is invalid.'
    }
    if ([string]$freeze.filesManifest.name -cne [IO.Path]::GetFileName($filesManifestPath) -or
        [string]$freeze.filesManifest.sha256 -cne [string]$SourceFreeze.filesManifestSha256) {
        throw 'Gate6 source files manifest does not match the source-freeze manifest.'
    }
    if ([string]$freeze.archive.name -cne [IO.Path]::GetFileName($archivePath) -or
        [string]$freeze.archive.sha256 -cne [string]$SourceFreeze.archiveSha256 -or
        [int64]$freeze.archive.bytes -ne ([IO.FileInfo]::new($archivePath)).Length) {
        throw 'Gate6 source archive does not match the source-freeze manifest.'
    }
}

function Assert-Gate6DriverSubmissionReference {
    param(
        [Parameter(Mandatory = $true)]
        [object]$DriverSubmission,

        [Parameter(Mandatory = $true)]
        [object]$SourceFreeze,

        [Parameter(Mandatory = $true)]
        [string]$EvidenceRoot
    )

    Assert-Gate6Properties $DriverSubmission `
        @('manifestPath', 'manifestSha256', 'sourceFilesManifestSha256') `
        @() `
        'Gate6 driver-submission reference'
    Assert-Gate6Sha256 ([string]$DriverSubmission.manifestSha256) 'Gate6 driver-submission manifest hash'
    Assert-Gate6Sha256 `
        ([string]$DriverSubmission.sourceFilesManifestSha256) `
        'Gate6 driver-submission source-files hash'
    if ([string]$DriverSubmission.manifestPath -cne 'full-profile-driver-manifest.json') {
        throw 'Gate6 driver-submission reference contains an unexpected manifest path.'
    }
    $manifestPath = Resolve-Gate6EvidencePath $EvidenceRoot ([string]$DriverSubmission.manifestPath)
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf) -or
        (Get-Gate6Sha256 $manifestPath) -cne [string]$DriverSubmission.manifestSha256) {
        throw 'Gate6 driver-submission manifest hash does not match its reference.'
    }
    $driverManifest = Read-Gate6Json $manifestPath 'Gate6 driver-submission manifest'
    if ([int]$driverManifest.schema -ne 1 -or
        $null -eq $driverManifest.PSObject.Properties['sourceArchiveSha256'] -or
        $null -eq $driverManifest.PSObject.Properties['sourceFreezeManifestSha256'] -or
        [string]$driverManifest.sourceFilesManifestSha256 -cne
            [string]$DriverSubmission.sourceFilesManifestSha256 -or
        [string]$DriverSubmission.sourceFilesManifestSha256 -cne
            [string]$SourceFreeze.filesManifestSha256 -or
        [string]$driverManifest.sourceArchiveSha256 -cne [string]$SourceFreeze.archiveSha256 -or
        [string]$driverManifest.sourceFreezeManifestSha256 -cne
            [string]$SourceFreeze.manifestSha256) {
        throw 'Gate6 driver submission was not produced from the referenced source freeze.'
    }
}

function Assert-Gate6ArtifactManifest {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ManifestPath,

        [Parameter(Mandatory = $true)]
        [string]$EvidenceRoot,

        [string]$PolicyPath = (Join-Path $PSScriptRoot 'gate6-artifact-inventory.json')
    )

    $ManifestPath = (Resolve-Path -LiteralPath $ManifestPath).Path
    $EvidenceRoot = (Resolve-Path -LiteralPath $EvidenceRoot).Path
    $PolicyPath = (Resolve-Path -LiteralPath $PolicyPath).Path
    $policy = Read-Gate6Json $PolicyPath 'Gate6 inventory policy'
    Assert-Gate6InventoryPolicy $policy
    $manifest = Read-Gate6Json $ManifestPath 'Gate6 artifact manifest'
    Assert-Gate6Properties $manifest `
        @(
            'schema',
            'policySha256',
            'fileCount',
            'sourceFreeze',
            'driverSubmission',
            'packageInventories',
            'files'
        ) `
        @() `
        'Gate6 artifact manifest'

    if ([string]$manifest.schema -cne [string]$policy.manifestSchema) {
        throw 'Gate6 artifact manifest schema is unsupported.'
    }
    Assert-Gate6Sha256 ([string]$manifest.policySha256) 'Gate6 inventory policy hash'
    if ([string]$manifest.policySha256 -cne (Get-Gate6Sha256 $PolicyPath)) {
        throw 'Gate6 artifact manifest does not reference the exact inventory policy.'
    }
    if ([int64]$manifest.fileCount -lt 1) {
        throw 'Gate6 artifact manifest file count is invalid.'
    }

    Assert-Gate6SourceFreezeReference $manifest.sourceFreeze $EvidenceRoot
    Assert-Gate6DriverSubmissionReference `
        $manifest.driverSubmission `
        $manifest.sourceFreeze `
        $EvidenceRoot

    $rows = @($manifest.files)
    if ($rows.Count -ne [int64]$manifest.fileCount) {
        throw 'Gate6 artifact manifest file count does not match its rows.'
    }
    $allowedKinds = @($policy.allowedKinds)
    $paths = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $pathsIgnoreCase = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $rowByPath = [Collections.Generic.Dictionary[string, object]]::new(
        [StringComparer]::Ordinal
    )
    foreach ($row in $rows) {
        Assert-Gate6Properties $row `
            @(
                'path',
                'kind',
                'bytes',
                'sha256',
                'sourceFreezeManifestSha256',
                'driverSubmissionManifestSha256'
            ) `
            @() `
            'Gate6 artifact row'
        $relativePath = [string]$row.path
        $kind = [string]$row.kind
        Assert-Gate6RelativePath $relativePath 'Gate6 artifact row path'
        if (-not $paths.Add($relativePath)) {
            throw "Gate6 artifact manifest contains a duplicate path: $relativePath"
        }
        if (-not $pathsIgnoreCase.Add($relativePath)) {
            throw "Gate6 artifact manifest contains a case-colliding path: $relativePath"
        }
        if ($kind -notin $allowedKinds) {
            throw "Gate6 artifact row has an unknown kind: $relativePath"
        }
        if ([int64]$row.bytes -lt 0) {
            throw "Gate6 artifact row has an invalid byte count: $relativePath"
        }
        Assert-Gate6Sha256 ([string]$row.sha256) "Gate6 artifact hash for $relativePath"
        Assert-Gate6Sha256 `
            ([string]$row.sourceFreezeManifestSha256) `
            "Gate6 source-freeze binding for $relativePath"
        if ([string]$row.sourceFreezeManifestSha256 -cne
            [string]$manifest.sourceFreeze.manifestSha256) {
            throw "Gate6 artifact row refers to a foreign source freeze: $relativePath"
        }

        $driverBound = $false
        foreach ($pattern in @($policy.driverSubmissionBoundPatterns)) {
            if (Test-Gate6Regex $relativePath ([string]$pattern)) {
                $driverBound = $true
                break
            }
        }
        $driverBinding = [string]$row.driverSubmissionManifestSha256
        if ($driverBound) {
            Assert-Gate6Sha256 $driverBinding "Gate6 driver-submission binding for $relativePath"
            if ($driverBinding -cne [string]$manifest.driverSubmission.manifestSha256) {
                throw "Gate6 artifact row refers to a foreign driver submission: $relativePath"
            }
        } elseif ($driverBinding.Length -ne 0) {
            throw "Gate6 non-driver artifact carries a driver-submission binding: $relativePath"
        }

        $path = Resolve-Gate6EvidencePath $EvidenceRoot $relativePath
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Gate6 manifested artifact is missing: $relativePath"
        }
        $fileInfo = [IO.FileInfo]::new($path)
        if (($fileInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Gate6 evidence contains a reparse point: $relativePath"
        }
        if ($fileInfo.Length -ne [int64]$row.bytes -or
            (Get-Gate6Sha256 $path) -cne [string]$row.sha256) {
            throw "Gate6 artifact identity mismatch: $relativePath"
        }
        $rowByPath[$relativePath] = $row
    }

    $excludedFullPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    [void]$excludedFullPaths.Add([IO.Path]::GetFullPath($ManifestPath))
    [void]$excludedFullPaths.Add([IO.Path]::GetFullPath($PolicyPath))
    $actualFiles = @(
        Get-ChildItem -LiteralPath $EvidenceRoot -File -Recurse -Force | Where-Object {
            -not $excludedFullPaths.Contains([IO.Path]::GetFullPath($_.FullName))
        }
    )
    foreach ($file in $actualFiles) {
        if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Gate6 evidence contains a reparse point: $($file.FullName)"
        }
        $relativePath = Get-Gate6RelativeEvidencePath $EvidenceRoot $file.FullName
        if (-not $paths.Contains($relativePath)) {
            throw "Gate6 evidence contains an unmanifested file: $relativePath"
        }
    }
    if ($actualFiles.Count -ne $rows.Count) {
        throw 'Gate6 evidence file count does not match the artifact manifest.'
    }

    $packageInventories = @($manifest.packageInventories)
    if ($packageInventories.Count -ne @($policy.packageInventories).Count) {
        throw 'Gate6 artifact manifest has an unexpected package-inventory count.'
    }
    $packageByName = [Collections.Generic.Dictionary[string, object]]::new(
        [StringComparer]::Ordinal
    )
    foreach ($inventory in $packageInventories) {
        Assert-Gate6Properties $inventory `
            @(
                'name',
                'packagePath',
                'packageSha256',
                'inventoryRoot',
                'fileCount',
                'inventorySha256'
            ) `
            @() `
            'Gate6 package inventory'
        $name = [string]$inventory.name
        if ([string]::IsNullOrWhiteSpace($name) -or $packageByName.ContainsKey($name)) {
            throw "Gate6 artifact manifest contains a duplicate package inventory: $name"
        }
        Assert-Gate6RelativePath ([string]$inventory.packagePath) 'Gate6 package path'
        Assert-Gate6RelativePath ([string]$inventory.inventoryRoot) 'Gate6 package inventory root'
        Assert-Gate6Sha256 ([string]$inventory.packageSha256) "Gate6 package hash for $name"
        Assert-Gate6Sha256 ([string]$inventory.inventorySha256) "Gate6 inventory hash for $name"
        if ([int64]$inventory.fileCount -lt 1) {
            throw "Gate6 package inventory has an invalid file count: $name"
        }
        $packageByName.Add($name, $inventory)
    }
    foreach ($expected in @($policy.packageInventories)) {
        $name = [string]$expected.name
        if (-not $packageByName.ContainsKey($name)) {
            throw "Gate6 artifact manifest is missing package inventory: $name"
        }
        $inventory = $packageByName[$name]
        $packagePath = [string]$inventory.packagePath
        if ([string]$inventory.inventoryRoot -cne [string]$expected.root -or
            -not $rowByPath.ContainsKey($packagePath) -or
            [string]$rowByPath[$packagePath].kind -cne [string]$expected.packageKind -or
            [string]$rowByPath[$packagePath].sha256 -cne [string]$inventory.packageSha256) {
            throw "Gate6 package inventory is not bound to the expected package: $name"
        }
        $inventoryPrefix = [string]$expected.root + '/'
        $inventoryRows = @($rows | Where-Object {
            ([string]$_.path).StartsWith($inventoryPrefix, [StringComparison]::Ordinal)
        })
        if ($inventoryRows.Count -ne [int64]$inventory.fileCount -or
            (Get-Gate6InventoryRowsSha256 $rows ([string]$expected.root)) -cne
                [string]$inventory.inventorySha256) {
            throw "Gate6 package inventory identity mismatch: $name"
        }
    }

    foreach ($scope in @($policy.scopes)) {
        $scopeRoot = [string]$scope.root
        $prefix = if ($scopeRoot.Length -eq 0) { '' } else { "$scopeRoot/" }
        foreach ($entry in @($scope.exactFiles)) {
            $path = Join-Gate6PolicyPath $scopeRoot ([string]$entry.path)
            if (-not $rowByPath.ContainsKey($path) -or
                [string]$rowByPath[$path].kind -cne [string]$entry.kind) {
                throw "Gate6 evidence is missing required $($scope.name) file: $path"
            }
        }

        $scopeRows = @($rows | Where-Object {
            $prefix.Length -eq 0 -or ([string]$_.path).StartsWith($prefix, [StringComparison]::Ordinal)
        })
        foreach ($rule in @($scope.requiredPatterns)) {
            $matches = @($scopeRows | Where-Object {
                $relative = if ($prefix.Length -eq 0) {
                    [string]$_.path
                } else {
                    ([string]$_.path).Substring($prefix.Length)
                }
                (Test-Gate6Regex $relative ([string]$rule.regex)) -and
                    [string]$_.kind -ceq [string]$rule.kind
            })
            if ($matches.Count -lt [int]$rule.minimum -or
                ($null -ne $rule.PSObject.Properties['maximum'] -and
                    $matches.Count -gt [int]$rule.maximum)) {
                throw "Gate6 evidence does not satisfy required pattern in scope $($scope.name): $($rule.regex)"
            }
        }
        foreach ($pattern in @($scope.forbiddenPatterns)) {
            $forbidden = @($scopeRows | Where-Object {
                $relative = ([string]$_.path).Substring($prefix.Length)
                Test-Gate6Regex $relative ([string]$pattern)
            })
            if ($forbidden.Count -ne 0) {
                throw "Gate6 evidence contains forbidden $($scope.name) file: $($forbidden[0].path)"
            }
        }
    }

    return [pscustomobject]@{
        Schema = [string]$manifest.schema
        FileCount = $rows.Count
        SourceFreezeManifestSha256 = [string]$manifest.sourceFreeze.manifestSha256
        DriverSubmissionManifestSha256 = [string]$manifest.driverSubmission.manifestSha256
    }
}
