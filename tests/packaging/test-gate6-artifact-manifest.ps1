[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$lumenRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '../..')).Path
$policyPath = Join-Path $lumenRoot 'scripts/windows/gate6-artifact-inventory.json'
$helperPath = Join-Path $lumenRoot 'scripts/windows/gate6-artifact-manifest.ps1'
. $helperPath

function Write-Utf8File {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value
    )

    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    [IO.File]::WriteAllText($Path, $Value, [Text.UTF8Encoding]::new($false))
}

function Save-Json {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [object]$Value
    )

    Write-Utf8File $Path ($Value | ConvertTo-Json -Depth 20)
}

function Get-PolicyKind {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Policy,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    foreach ($scope in @($Policy.scopes)) {
        $root = [string]$scope.root
        $prefix = if ($root.Length -eq 0) { '' } else { "$root/" }
        foreach ($entry in @($scope.exactFiles)) {
            if ((Join-Gate6PolicyPath $root ([string]$entry.path)) -ceq $Path) {
                return [string]$entry.kind
            }
        }
        if ($prefix.Length -ne 0 -and
            -not $Path.StartsWith($prefix, [StringComparison]::Ordinal)) {
            continue
        }
        $relative = if ($prefix.Length -eq 0) { $Path } else { $Path.Substring($prefix.Length) }
        foreach ($rule in @($scope.requiredPatterns)) {
            if (Test-Gate6Regex $relative ([string]$rule.regex)) {
                return [string]$rule.kind
            }
        }
    }
    throw "Fixture path has no Gate6 policy kind: $Path"
}

function Test-DriverBoundPath {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Policy,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    foreach ($pattern in @($Policy.driverSubmissionBoundPatterns)) {
        if (Test-Gate6Regex $Path ([string]$pattern)) {
            return $true
        }
    }
    return $false
}

function New-PackageInventoryReferences {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Policy,

        [Parameter(Mandatory = $true)]
        [object[]]$Rows
    )

    return @(
        foreach ($expected in @($Policy.packageInventories)) {
            $packageRows = @($Rows | Where-Object {
                [string]$_.kind -ceq [string]$expected.packageKind -and
                    ([string]$_.path).StartsWith('artifacts/', [StringComparison]::Ordinal)
            })
            if ($packageRows.Count -ne 1) {
                throw "Fixture expected exactly one $($expected.packageKind) package row."
            }
            $prefix = [string]$expected.root + '/'
            $inventoryRows = @($Rows | Where-Object {
                ([string]$_.path).StartsWith($prefix, [StringComparison]::Ordinal)
            })
            [ordered]@{
                name = [string]$expected.name
                packagePath = [string]$packageRows[0].path
                packageSha256 = [string]$packageRows[0].sha256
                inventoryRoot = [string]$expected.root
                fileCount = $inventoryRows.Count
                inventorySha256 = Get-Gate6InventoryRowsSha256 $Rows ([string]$expected.root)
            }
        }
    )
}

function Update-PackageInventoryReferences {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Manifest,

        [Parameter(Mandatory = $true)]
        [object]$Policy
    )

    $Manifest.packageInventories = New-PackageInventoryReferences $Policy @($Manifest.files)
}

function New-Gate6Fixture {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Root
    )

    $policy = Get-Content -LiteralPath $policyPath -Raw | ConvertFrom-Json
    $evidenceRoot = Join-Path $Root 'evidence'
    $manifestPath = Join-Path $Root 'artifact-manifest.json'
    New-Item -ItemType Directory -Path $evidenceRoot -Force | Out-Null

    $paths = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($scope in @($policy.scopes)) {
        foreach ($entry in @($scope.exactFiles)) {
            [void]$paths.Add((Join-Gate6PolicyPath ([string]$scope.root) ([string]$entry.path)))
        }
    }
    foreach ($path in @(
            'artifacts/Lumen-0.1.0-Gate6-Windows-AMD64-installer.msi',
            'artifacts/Lumen-0.1.0-Gate6-Windows-AMD64-lite.zip',
            'inventories/msi/assets/web/index.fixture.js',
            'inventories/zip/assets/web/index.fixture.js'
        )) {
        [void]$paths.Add($path)
    }

    foreach ($path in @($paths | Sort-Object)) {
        $fullPath = Resolve-Gate6EvidencePath $evidenceRoot $path
        Write-Utf8File $fullPath "fixture:$path"
    }

    $filesManifestPath = Resolve-Gate6EvidencePath `
        $evidenceRoot `
        'source-freeze/full-profile-files.json'
    Save-Json $filesManifestPath @(
        [ordered]@{
            path = 'fixture-source.txt'
            sha256 = ('a' * 64)
            bytes = 1
        }
    )
    $archivePath = Resolve-Gate6EvidencePath `
        $evidenceRoot `
        'source-freeze/lumen-full-profile-source.tar.gz'
    Write-Utf8File $archivePath 'fixture-source-archive'
    $filesManifestSha256 = Get-Gate6Sha256 $filesManifestPath
    $archiveSha256 = Get-Gate6Sha256 $archivePath

    $sharedSourceFreezePath = Resolve-Gate6EvidencePath `
        $evidenceRoot `
        'source-freeze/umbra-lumen-source-freeze-manifest.json'
    Save-Json $sharedSourceFreezePath ([ordered]@{
        schema = 'umbra-lumen/source-freeze-manifest/1'
        kind = 'source_freeze'
        release_id = 'fixture'
        digest_algorithm = 'sha256'
        repositories = @()
    })
    $sharedSourceFreezeSha256 = Get-Gate6Sha256 $sharedSourceFreezePath

    $sourceFreezePath = Resolve-Gate6EvidencePath `
        $evidenceRoot `
        'source-freeze/full-profile-source-freeze.json'
    Save-Json $sourceFreezePath ([ordered]@{
        schema = 1
        sharedSourceFreezeSchema = 'umbra-lumen/source-freeze-manifest/1'
        sharedSourceFreezeManifestSha256 = $sharedSourceFreezeSha256
        fileCount = 1
        filesManifest = [ordered]@{
            name = 'full-profile-files.json'
            sha256 = $filesManifestSha256
        }
        archive = [ordered]@{
            name = 'lumen-full-profile-source.tar.gz'
            bytes = ([IO.FileInfo]::new($archivePath)).Length
            sha256 = $archiveSha256
        }
        identities = [ordered]@{}
        pendingRuntimePins = @()
    })
    $sourceFreezeSha256 = Get-Gate6Sha256 $sourceFreezePath

    $driverManifestPath = Resolve-Gate6EvidencePath `
        $evidenceRoot `
        'full-profile-driver-manifest.json'
    Save-Json $driverManifestPath ([ordered]@{
        schema = 1
        sourceFilesManifestSha256 = $filesManifestSha256
        sourceArchiveSha256 = $archiveSha256
        sourceFreezeManifestSha256 = $sourceFreezeSha256
        unsignedDriverSubmissions = [ordered]@{}
    })
    $driverManifestSha256 = Get-Gate6Sha256 $driverManifestPath

    $rows = @(
        Get-ChildItem -LiteralPath $evidenceRoot -File -Recurse -Force | ForEach-Object {
            $path = Get-Gate6RelativeEvidencePath $evidenceRoot $_.FullName
            [ordered]@{
                path = $path
                kind = Get-PolicyKind $policy $path
                bytes = $_.Length
                sha256 = Get-Gate6Sha256 $_.FullName
                sourceFreezeManifestSha256 = $sourceFreezeSha256
                driverSubmissionManifestSha256 = if (Test-DriverBoundPath $policy $path) {
                    $driverManifestSha256
                } else {
                    ''
                }
            }
        } | Sort-Object path
    )
    Save-Json $manifestPath ([ordered]@{
        schema = [string]$policy.manifestSchema
        policySha256 = Get-Gate6Sha256 $policyPath
        fileCount = $rows.Count
        sourceFreeze = [ordered]@{
            manifestPath = 'source-freeze/full-profile-source-freeze.json'
            manifestSha256 = $sourceFreezeSha256
            filesManifestPath = 'source-freeze/full-profile-files.json'
            filesManifestSha256 = $filesManifestSha256
            archivePath = 'source-freeze/lumen-full-profile-source.tar.gz'
            archiveSha256 = $archiveSha256
        }
        driverSubmission = [ordered]@{
            manifestPath = 'full-profile-driver-manifest.json'
            manifestSha256 = $driverManifestSha256
            sourceFilesManifestSha256 = $filesManifestSha256
        }
        packageInventories = New-PackageInventoryReferences $policy $rows
        files = $rows
    })

    return [pscustomobject]@{
        EvidenceRoot = $evidenceRoot
        ManifestPath = $manifestPath
        Policy = $policy
    }
}

function Get-FixtureManifest {
    param([object]$Fixture)
    return Get-Content -LiteralPath $Fixture.ManifestPath -Raw | ConvertFrom-Json
}

function Get-FixtureRow {
    param([object]$Manifest, [string]$Path)
    $rows = @($Manifest.files | Where-Object { [string]$_.path -ceq $Path })
    if ($rows.Count -ne 1) {
        throw "Fixture expected exactly one manifest row: $Path"
    }
    return $rows[0]
}

function Assert-ThrowsLike {
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$Operation,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedPattern,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    try {
        & $Operation
    } catch {
        if ($_.Exception.Message -notmatch $ExpectedPattern) {
            throw "$Description expected '$ExpectedPattern', got '$($_.Exception.Message)'."
        }
        return
    }
    throw "$Description expected a refusal."
}

function Invoke-HostileFixture {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [scriptblock]$Mutate,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedPattern
    )

    $root = Join-Path $testRoot $Name
    $fixture = New-Gate6Fixture $root
    & $Mutate $fixture
    Assert-ThrowsLike {
        Assert-Gate6ArtifactManifest `
            -ManifestPath $fixture.ManifestPath `
            -EvidenceRoot $fixture.EvidenceRoot `
            -PolicyPath $policyPath | Out-Null
    } $ExpectedPattern $Name
}

$testRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'lumen-gate6-artifact-manifest-' + [Guid]::NewGuid().ToString('N')
)
try {
    $policy = Get-Content -LiteralPath $policyPath -Raw | ConvertFrom-Json
    Assert-Gate6InventoryPolicy $policy
    $scopes = @($policy.scopes)
    if (($scopes.name -join ',') -cne 'evidence,msi,zip') {
        throw 'Gate6 policy must retain evidence, MSI, and ZIP scopes.'
    }
    $msi = @($scopes | Where-Object name -ceq 'msi')[0]
    $zip = @($scopes | Where-Object name -ceq 'zip')[0]
    $evidence = @($scopes | Where-Object name -ceq 'evidence')[0]
    if (@($msi.exactFiles | Where-Object kind -ceq 'shader').Count -ne 41 -or
        @($zip.exactFiles | Where-Object kind -ceq 'shader').Count -ne 41 -or
        @($evidence.exactFiles | Where-Object kind -ceq 'vector').Count -ne 3 -or
        @($msi.exactFiles | Where-Object kind -ceq 'driver').Count -ne 9 -or
        @($zip.exactFiles | Where-Object kind -ceq 'driver').Count -ne 0) {
        throw 'Gate6 policy does not contain the exact shader/vector/driver boundary.'
    }

    $valid = New-Gate6Fixture (Join-Path $testRoot 'valid')
    $summary = Assert-Gate6ArtifactManifest `
        -ManifestPath $valid.ManifestPath `
        -EvidenceRoot $valid.EvidenceRoot `
        -PolicyPath $policyPath
    if ($summary.FileCount -lt 100) {
        throw 'Gate6 baseline fixture did not exercise the complete inventory policy.'
    }

    Invoke-HostileFixture 'missing-required-shader' {
        param($fixture)
        $path = 'inventories/msi/assets/shaders/directx/cursor_ps.hlsl'
        Remove-Item -LiteralPath (Resolve-Gate6EvidencePath $fixture.EvidenceRoot $path) -Force
        $manifest = Get-FixtureManifest $fixture
        $manifest.files = @($manifest.files | Where-Object { [string]$_.path -cne $path })
        $manifest.fileCount = @($manifest.files).Count
        Update-PackageInventoryReferences $manifest $fixture.Policy
        Save-Json $fixture.ManifestPath $manifest
    } 'missing required msi file'

    Invoke-HostileFixture 'extra-unmanifested-file' {
        param($fixture)
        Write-Utf8File `
            (Resolve-Gate6EvidencePath $fixture.EvidenceRoot 'inventories/msi/foreign.dll') `
            'foreign'
    } 'unmanifested file'

    Invoke-HostileFixture 'duplicate-path' {
        param($fixture)
        $manifest = Get-FixtureManifest $fixture
        $copy = (Get-FixtureRow $manifest 'app/Lumen.exe').PSObject.Copy()
        $manifest.files = @($manifest.files) + @($copy)
        $manifest.fileCount = @($manifest.files).Count
        Save-Json $fixture.ManifestPath $manifest
    } 'duplicate path'

    Invoke-HostileFixture 'case-collision' {
        param($fixture)
        $manifest = Get-FixtureManifest $fixture
        $copy = (Get-FixtureRow $manifest 'app/Lumen.exe').PSObject.Copy()
        $copy.path = 'App/Lumen.exe'
        $manifest.files = @($manifest.files) + @($copy)
        $manifest.fileCount = @($manifest.files).Count
        Save-Json $fixture.ManifestPath $manifest
    } 'case-colliding path'

    foreach ($swap in @(
            @('swapped-shim', 'shim/lumen_msquic_shim.dll'),
            @('swapped-shader', 'inventories/msi/assets/shaders/directx/convert_yuv420_planar_y_ps.hlsl'),
            @('swapped-driver', 'drivers/virtual-display/LumenVirtualDisplay.dll'),
            @('stale-vector', 'vectors/quic_v3_vectors.json')
        )) {
        Invoke-HostileFixture $swap[0] {
            param($fixture)
            Write-Utf8File `
                (Resolve-Gate6EvidencePath $fixture.EvidenceRoot $swap[1]) `
                "mutated:$($swap[1])"
        }.GetNewClosure() 'artifact identity mismatch'
    }

    Invoke-HostileFixture 'foreign-driver-input' {
        param($fixture)
        $manifest = Get-FixtureManifest $fixture
        $row = Get-FixtureRow $manifest 'drivers/virtual-hid/LumenVirtualHid.dll'
        $row.driverSubmissionManifestSha256 = 'f' * 64
        Save-Json $fixture.ManifestPath $manifest
    } 'foreign driver submission'

    Invoke-HostileFixture 'foreign-driver-manifest' {
        param($fixture)
        $driverPath = Resolve-Gate6EvidencePath `
            $fixture.EvidenceRoot `
            'full-profile-driver-manifest.json'
        $driverManifest = Get-Content -LiteralPath $driverPath -Raw | ConvertFrom-Json
        $driverManifest.sourceFreezeManifestSha256 = 'f' * 64
        Save-Json $driverPath $driverManifest
        $driverHash = Get-Gate6Sha256 $driverPath

        $manifest = Get-FixtureManifest $fixture
        $manifest.driverSubmission.manifestSha256 = $driverHash
        $driverManifestRow = Get-FixtureRow $manifest 'full-profile-driver-manifest.json'
        $driverManifestRow.bytes = ([IO.FileInfo]::new($driverPath)).Length
        $driverManifestRow.sha256 = $driverHash
        foreach ($row in @($manifest.files)) {
            if (Test-DriverBoundPath $fixture.Policy ([string]$row.path)) {
                $row.driverSubmissionManifestSha256 = $driverHash
            }
        }
        Save-Json $fixture.ManifestPath $manifest
    } 'driver submission was not produced from the referenced source freeze'

    Invoke-HostileFixture 'manifest-schema' {
        param($fixture)
        $manifest = Get-FixtureManifest $fixture
        $manifest.schema = 'lumen-gate6-artifact-manifest/0'
        Save-Json $fixture.ManifestPath $manifest
    } 'manifest schema is unsupported'

    Invoke-HostileFixture 'manifest-extra-property' {
        param($fixture)
        $manifest = Get-FixtureManifest $fixture
        $manifest | Add-Member -NotePropertyName allowForeignInput -NotePropertyValue $true
        Save-Json $fixture.ManifestPath $manifest
    } 'unexpected property'

    Invoke-HostileFixture 'manifest-policy-hash' {
        param($fixture)
        $manifest = Get-FixtureManifest $fixture
        $manifest.policySha256 = '0' * 64
        Save-Json $fixture.ManifestPath $manifest
    } 'exact inventory policy'

    Invoke-HostileFixture 'manifest-file-hash' {
        param($fixture)
        $manifest = Get-FixtureManifest $fixture
        (Get-FixtureRow $manifest 'app/Lumen.exe').sha256 = '0' * 64
        Save-Json $fixture.ManifestPath $manifest
    } 'artifact identity mismatch'

    Invoke-HostileFixture 'manifest-count' {
        param($fixture)
        $manifest = Get-FixtureManifest $fixture
        $manifest.fileCount = [int]$manifest.fileCount + 1
        Save-Json $fixture.ManifestPath $manifest
    } 'file count does not match its rows'

    Invoke-HostileFixture 'package-inventory-hash' {
        param($fixture)
        $manifest = Get-FixtureManifest $fixture
        @($manifest.packageInventories | Where-Object name -ceq 'msi')[0].inventorySha256 = '0' * 64
        Save-Json $fixture.ManifestPath $manifest
    } 'package inventory identity mismatch'

    Invoke-HostileFixture 'source-freeze-reference' {
        param($fixture)
        $manifest = Get-FixtureManifest $fixture
        $manifest.sourceFreeze.filesManifestSha256 = '0' * 64
        Save-Json $fixture.ManifestPath $manifest
    } 'source files manifest hash does not match its reference'

    Invoke-HostileFixture 'foreign-source-input' {
        param($fixture)
        $manifest = Get-FixtureManifest $fixture
        (Get-FixtureRow $manifest 'app/Lumen.exe').sourceFreezeManifestSha256 = 'e' * 64
        Save-Json $fixture.ManifestPath $manifest
    } 'foreign source freeze'

    Invoke-HostileFixture 'foreign-shared-source-freeze' {
        param($fixture)
        $path = 'source-freeze/umbra-lumen-source-freeze-manifest.json'
        $fullPath = Resolve-Gate6EvidencePath $fixture.EvidenceRoot $path
        Save-Json $fullPath ([ordered]@{
            schema = 'umbra-lumen/source-freeze-manifest/1'
            kind = 'source_freeze'
            release_id = 'foreign'
            digest_algorithm = 'sha256'
            repositories = @()
        })
        $manifest = Get-FixtureManifest $fixture
        $row = Get-FixtureRow $manifest $path
        $row.bytes = ([IO.FileInfo]::new($fullPath)).Length
        $row.sha256 = Get-Gate6Sha256 $fullPath
        Save-Json $fixture.ManifestPath $manifest
    } 'not bound to the shared Gate6 Source Freeze Manifest'

    Invoke-HostileFixture 'zip-driver-payload' {
        param($fixture)
        $path = 'inventories/zip/drivers/foreign.sys'
        $fullPath = Resolve-Gate6EvidencePath $fixture.EvidenceRoot $path
        Write-Utf8File $fullPath 'foreign-driver'
        $manifest = Get-FixtureManifest $fixture
        $manifest.files = @($manifest.files) + @([pscustomobject][ordered]@{
            path = $path
            kind = 'driver'
            bytes = ([IO.FileInfo]::new($fullPath)).Length
            sha256 = Get-Gate6Sha256 $fullPath
            sourceFreezeManifestSha256 = [string]$manifest.sourceFreeze.manifestSha256
            driverSubmissionManifestSha256 = ''
        })
        $manifest.fileCount = @($manifest.files).Count
        Update-PackageInventoryReferences $manifest $fixture.Policy
        Save-Json $fixture.ManifestPath $manifest
    } 'forbidden zip file'

    $finalMutation = New-Gate6Fixture (Join-Path $testRoot 'final-mutation')
    Assert-Gate6ArtifactManifest `
        -ManifestPath $finalMutation.ManifestPath `
        -EvidenceRoot $finalMutation.EvidenceRoot `
        -PolicyPath $policyPath | Out-Null
    Write-Utf8File `
        (Resolve-Gate6EvidencePath $finalMutation.EvidenceRoot 'app/Lumen.exe') `
        'post-validation-mutation'
    Assert-ThrowsLike {
        Assert-Gate6ArtifactManifest `
            -ManifestPath $finalMutation.ManifestPath `
            -EvidenceRoot $finalMutation.EvidenceRoot `
            -PolicyPath $policyPath | Out-Null
    } 'artifact identity mismatch' 'final mutation'

    Write-Output 'PASS: Gate6 artifact policy rejects missing/extra/duplicate/case-collision, swapped inputs, stale vectors, foreign inputs, manifest/SFM mismatches, forbidden ZIP drivers, and final mutation.'
} finally {
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}
