[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SourceRoot,

    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$SharedSourceFreezeManifestSha256
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

. (Join-Path $PSScriptRoot 'full-profile-source-provenance.ps1')
$files = @(Get-FullProfileSourceFiles $SourceRoot)

$hashRows = @(
    $files | ForEach-Object {
        $file = $_
        [ordered]@{
            path = $file.RelativePath
            sha256 = $file.Sha256
            bytes = $file.Bytes
        }
    }
)
$fileManifestPath = Join-Path $OutputDirectory "full-profile-files.json"
$hashRows | ConvertTo-Json -Depth 4 | Set-Content $fileManifestPath -Encoding UTF8

$listPath = Join-Path $OutputDirectory "full-profile-files.txt"
Write-FullProfileTarList -Paths ([string[]]$files.RelativePath) -ListPath $listPath
$archivePath = Join-Path $OutputDirectory "lumen-full-profile-source.tar.gz"
$tarCommand = Get-Command tar.exe, tar -CommandType Application -ErrorAction SilentlyContinue |
    Select-Object -First 1
if ($null -eq $tarCommand) {
    throw 'tar is required for full-profile source freezing.'
}
$tarStartInfo = [Diagnostics.ProcessStartInfo]::new()
$tarStartInfo.FileName = $tarCommand.Source
$tarStartInfo.UseShellExecute = $false
$tarStartInfo.RedirectStandardOutput = $true
$tarStartInfo.RedirectStandardError = $true
foreach ($argument in @('-czh', '-f', '-', '-C', $SourceRoot, '-T', $listPath)) {
    $tarStartInfo.ArgumentList.Add($argument)
}
$tarProcess = [Diagnostics.Process]::new()
$tarProcess.StartInfo = $tarStartInfo
$archiveStream = $null
$stderrTask = $null
$tarStarted = $false
$tarExitCode = $null
$tarError = $null
$tarFailure = $null
try {
    $archiveStream = [IO.File]::Open(
        $archivePath,
        [IO.FileMode]::Create,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None
    )
    $tarStarted = $tarProcess.Start()
    if (-not $tarStarted) {
        throw 'tar did not start.'
    }
    $stderrTask = $tarProcess.StandardError.ReadToEndAsync()
    $tarProcess.StandardOutput.BaseStream.CopyTo($archiveStream)
    $archiveStream.Flush()
    $tarProcess.WaitForExit()
    $tarExitCode = $tarProcess.ExitCode
    $tarError = $stderrTask.GetAwaiter().GetResult()
} catch {
    $tarFailure = $_
    $tarExitedAfterFailure = $false
    if ($tarStarted) {
        try {
            if (-not $tarProcess.HasExited) {
                $tarProcess.Kill($true)
                [void]$tarProcess.WaitForExit(5000)
            }
            $tarExitedAfterFailure = $tarProcess.HasExited
        } catch {
            # The original archive failure remains authoritative.
        }
    }
    if ($null -ne $stderrTask -and $tarExitedAfterFailure) {
        try { $tarError = $stderrTask.GetAwaiter().GetResult() } catch {}
    }
} finally {
    if ($null -ne $archiveStream) { $archiveStream.Dispose() }
    $tarProcess.Dispose()
}
if (-not [string]::IsNullOrWhiteSpace([string]$tarError)) {
    [Console]::Error.Write([string]$tarError)
}
if ($null -ne $tarFailure -or $tarExitCode -ne 0) {
    Remove-Item -LiteralPath $archivePath -Force -ErrorAction SilentlyContinue
    if ($null -ne $tarFailure) {
        throw "tar failed while streaming the source archive: $($tarFailure.Exception.Message)"
    }
    throw "tar failed with exit code $tarExitCode."
}
if (-not (Test-Path -LiteralPath $archivePath -PathType Leaf) -or
    (Get-Item -LiteralPath $archivePath).Length -le 0) {
    Remove-Item -LiteralPath $archivePath -Force -ErrorAction SilentlyContinue
    throw 'tar produced an empty source archive.'
}

$msquicManifestPath = Join-Path $SourceRoot "src/platform/windows/msquic_shim/manifest.json"
$msquicManifest = Get-Content $msquicManifestPath -Raw | ConvertFrom-Json
$vddProtocolPath = Join-Path $SourceRoot "src/platform/windows/virtual_display_driver/LumenVirtualDisplayProtocol.h"
$vddProtocol = Get-Content $vddProtocolPath -Raw
$vddMatch = [regex]::Match($vddProtocol, '#define\s+LUMEN_VDD_ABI_VERSION\s+(\d+)u')
if (-not $vddMatch.Success) {
    throw "Unable to read LUMEN_VDD_ABI_VERSION."
}

$vddShaderPaths = @(
    'src_assets/windows/assets/shaders/directx/convert_yuv420_packed_uv_type0_ps_vdd_color_transform.hlsl',
    'src_assets/windows/assets/shaders/directx/convert_yuv420_packed_uv_type0s_ps_vdd_color_transform.hlsl',
    'src_assets/windows/assets/shaders/directx/convert_yuv420_planar_y_ps_vdd_color_transform.hlsl',
    'src_assets/windows/assets/shaders/directx/convert_yuv444_packed_ayuv_ps_vdd_color_transform.hlsl',
    'src_assets/windows/assets/shaders/directx/convert_yuv444_packed_y410_ps_vdd_color_transform.hlsl',
    'src_assets/windows/assets/shaders/directx/convert_yuv444_planar_ps_vdd_color_transform.hlsl',
    'src_assets/windows/assets/shaders/directx/include/convert_vdd_color_transform_base.hlsl'
)
$vddShaderRows = @(
    foreach ($path in $vddShaderPaths) {
        $matches = @($hashRows | Where-Object { [string]$_.path -ceq $path })
        if ($matches.Count -ne 1) {
            throw "The Gate6 source freeze is missing exact VDD shader source: $path"
        }
        $matches[0]
    }
)
$vddShaderInventoryText = (($vddShaderRows | ForEach-Object {
            "$([string]$_.path)`t$([int64]$_.bytes)`t$([string]$_.sha256)"
        }) -join "`n") + "`n"
$vddShaderInventoryBytes = [Text.UTF8Encoding]::new($false).GetBytes($vddShaderInventoryText)
$sha256 = [Security.Cryptography.SHA256]::Create()
try {
    $vddShaderInventorySha256 = (($sha256.ComputeHash($vddShaderInventoryBytes) |
        ForEach-Object { '{0:x2}' -f $_ }) -join '')
} finally {
    $sha256.Dispose()
}

$freeze = [ordered]@{
    schema = 1
    sharedSourceFreezeSchema = 'umbra-lumen/source-freeze-manifest/1'
    sharedSourceFreezeManifestSha256 = $SharedSourceFreezeManifestSha256
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
        vddShaderCount = $vddShaderRows.Count
        vddShaderInventorySha256 = $vddShaderInventorySha256
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
