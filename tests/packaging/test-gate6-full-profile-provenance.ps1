[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$lumenRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '../..')).Path
. (Join-Path $lumenRoot 'scripts/windows/full-profile-source-provenance.ps1')
. (Join-Path $lumenRoot 'scripts/windows/gate6-evidence.ps1')

function Write-TestFile {
    param([string]$Path, [string]$Value)
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    [IO.File]::WriteAllText($Path, $Value, [Text.UTF8Encoding]::new($false))
}

function Assert-ThrowsLike {
    param([scriptblock]$Operation, [string]$Pattern, [string]$Description)
    try {
        & $Operation
    } catch {
        if ($_.Exception.Message -notmatch $Pattern) {
            throw "$Description threw an unexpected error: $($_.Exception.Message)"
        }
        return
    }
    throw "$Description did not fail."
}

$root = Join-Path ([IO.Path]::GetTempPath()) ("lumen-gate6-provenance-" + [Guid]::NewGuid())
$source = Join-Path $root 'source'
$freeze = Join-Path $root 'freeze'
$expanded = Join-Path $root 'expanded'
$runs = Join-Path $root 'runs'
try {
    New-Item -ItemType Directory -Path $source -Force | Out-Null
    Write-TestFile (Join-Path $source 'src/platform/windows/msquic_shim/manifest.json') `
        '{"abi":3,"header_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","source_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","project_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}'
    Write-TestFile `
        (Join-Path $source 'src/platform/windows/virtual_display_driver/LumenVirtualDisplayProtocol.h') `
        '#define LUMEN_VDD_ABI_VERSION 5u'
    $shaderPaths = @(
        'convert_yuv420_packed_uv_type0_ps_vdd_color_transform.hlsl',
        'convert_yuv420_packed_uv_type0s_ps_vdd_color_transform.hlsl',
        'convert_yuv420_planar_y_ps_vdd_color_transform.hlsl',
        'convert_yuv444_packed_ayuv_ps_vdd_color_transform.hlsl',
        'convert_yuv444_packed_y410_ps_vdd_color_transform.hlsl',
        'convert_yuv444_planar_ps_vdd_color_transform.hlsl',
        'include/convert_vdd_color_transform_base.hlsl'
    )
    foreach ($path in $shaderPaths) {
        Write-TestFile `
            (Join-Path $source "src_assets/windows/assets/shaders/directx/$path") `
            "shader:$path"
    }
    Write-TestFile (Join-Path $source 'README.md') 'fixture'
    Write-TestFile (Join-Path $source 'node_modules/generated.txt') 'ignored-build-output'

    $sharedHash = 'd' * 64
    & (Join-Path $lumenRoot 'scripts/windows/freeze-full-profile-source.ps1') `
        -SourceRoot $source `
        -OutputDirectory $freeze `
        -SharedSourceFreezeManifestSha256 $sharedHash | Out-Null
    $freezeManifest = Get-Content `
        (Join-Path $freeze 'full-profile-source-freeze.json') `
        -Raw | ConvertFrom-Json
    if ([string]$freezeManifest.sharedSourceFreezeManifestSha256 -cne $sharedHash -or
        [int]$freezeManifest.identities.vddShaderCount -ne 7 -or
        [string]$freezeManifest.identities.vddShaderInventorySha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'Portable freeze did not bind the shared SFM and exact seven-shader inventory.'
    }

    $provenance = Expand-VerifiedFullProfileSource `
        -FreezeDirectory $freeze `
        -DestinationDirectory $expanded `
        -MutableSourceRoot $source `
        -ExpectedSharedSourceFreezeManifestSha256 $sharedHash
    [void](Assert-FullProfileSourceSnapshot `
        -SourceRoot $expanded `
        -FilesManifestPath $provenance.FilesManifestPath `
        -Boundary 'portable test')
    Write-TestFile (Join-Path $expanded 'README.md') 'mutated'
    Assert-ThrowsLike {
        [void](Assert-FullProfileSourceSnapshot `
            -SourceRoot $expanded `
            -FilesManifestPath $provenance.FilesManifestPath `
            -Boundary 'mutation test')
    } 'identity mismatch' 'Post-freeze source mutation'

    $sharedManifestPath = Join-Path $root 'shared-sfm.json'
    Write-Gate6Json $sharedManifestPath ([ordered]@{
            schema = 'umbra-lumen/source-freeze-manifest/1'
            kind = 'source_freeze'
            release_id = 'fixture'
            digest_algorithm = 'sha256'
            repositories = @(
                [ordered]@{
                    name = 'Lumen'
                    commit = '1' * 40
                    upstream_commit = '1' * 40
                    clean = $true
                    pushed = $true
                    submodules = @()
                }
            )
        })
    $shared = Assert-Gate6SharedSourceFreezeManifest `
        -ManifestPath $sharedManifestPath `
        -RepositoryName Lumen `
        -ExpectedCommit ('1' * 40)
    if ($shared.Sha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'Shared SFM validation did not return its exact hash.'
    }

    $pwsh = (Get-Process -Id $PID).Path
    $passing = Invoke-Gate6RecordedCommand `
        -RunId passing `
        -FilePath $pwsh `
        -Arguments @('-NoProfile', '-Command', '[Console]::Out.Write("out"); [Console]::Error.Write("err")') `
        -WorkingDirectory $root `
        -RunEvidenceRoot $runs `
        -ToolchainIds @('portable-pwsh')
    if ([string]$passing.Record.result -cne 'pass' -or
        [int64]$passing.Record.monotonic_duration_ns -lt 0 -or
        [int64]$passing.Record.stdout.bytes -ne 3 -or
        [int64]$passing.Record.stderr.bytes -ne 3) {
        throw 'Binary-safe passing run evidence is incomplete.'
    }
    Assert-Gate6MandatoryRunsPassed @($passing)
    Write-TestFile $passing.StdoutPath 'mutated'
    Assert-ThrowsLike {
        Assert-Gate6MandatoryRunsPassed @($passing)
    } 'stream identity mismatch' 'Post-validation run-log mutation'
    Write-TestFile $passing.StdoutPath 'out'

    $failing = Invoke-Gate6RecordedCommand `
        -RunId failing `
        -FilePath $pwsh `
        -Arguments @('-NoProfile', '-Command', 'exit 7') `
        -WorkingDirectory $root `
        -RunEvidenceRoot $runs `
        -ToolchainIds @('portable-pwsh')
    Assert-ThrowsLike {
        Assert-Gate6MandatoryRunsPassed @($passing, $failing)
    } 'Mandatory Gate6 run failed: failing' 'Artifact-manifest mandatory-run gate'

    Write-Output 'PASS: Gate6 full-profile provenance integration rejects mutation and incomplete mandatory evidence.'
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
