[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SourceRoot,

    [Parameter(Mandatory = $true)]
    [string]$StagingRoot,

    [Parameter(Mandatory = $true)]
    [string]$Msys2Root,

    [Parameter(Mandatory = $true)]
    [string]$MsQuicPackageRoot,

    [Parameter(Mandatory = $true)]
    [string]$BuildVersion,

    [Parameter(Mandatory = $true)]
    [string]$SharedSourceFreezeManifestPath,

    [Parameter(Mandatory = $true)]
    [string]$Gate6EvidenceRoot,

    [string]$PythonPath,

    [string]$DotNetRoot,

    [string]$NodeRoot,

    [string]$SignedDriverRoot,

    [switch]$AllowTestSignedDrivers,

    [string]$Configuration = "Release"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-ExistingDirectory {
    param([string]$Path, [string]$Name)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "$Name directory is missing: $Path"
    }
    return (Resolve-Path -LiteralPath $Path).Path
}

function Resolve-Tool {
    param([string]$Path, [string]$Name)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Name is missing: $Path"
    }
    return (Resolve-Path -LiteralPath $Path).Path
}

$SourceRoot = Resolve-ExistingDirectory $SourceRoot "Source"
$Msys2Root = Resolve-ExistingDirectory $Msys2Root "MSYS2"
$MsQuicPackageRoot = Resolve-ExistingDirectory $MsQuicPackageRoot "MsQuic package"
$StagingRoot = [IO.Path]::GetFullPath($StagingRoot)
$Gate6EvidenceRoot = [IO.Path]::GetFullPath($Gate6EvidenceRoot)
if ($StagingRoot -eq $SourceRoot -or
    $SourceRoot.StartsWith(
        $StagingRoot + [IO.Path]::DirectorySeparatorChar,
        [StringComparison]::OrdinalIgnoreCase
    ) -or
    $StagingRoot.StartsWith(
        $SourceRoot + [IO.Path]::DirectorySeparatorChar,
        [StringComparison]::OrdinalIgnoreCase
    )) {
    throw "StagingRoot and SourceRoot must be disjoint."
}
New-Item -ItemType Directory -Path $StagingRoot -Force | Out-Null
$runEvidenceRoot = Join-Path $StagingRoot 'gate6-runs'
if (Test-Path -LiteralPath $runEvidenceRoot) {
    Remove-Item -LiteralPath $runEvidenceRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $runEvidenceRoot -Force | Out-Null
$powerShellExecutable = (Get-Process -Id $PID).Path
$pendingManifestPath = Join-Path $StagingRoot "full-profile-driver-manifest.json"
if (Test-Path -LiteralPath $pendingManifestPath) {
    Remove-Item -LiteralPath $pendingManifestPath -Force
}

. (Join-Path $SourceRoot "scripts\windows\full-profile-source-provenance.ps1")
. (Join-Path $SourceRoot "scripts\windows\gate6-evidence.ps1")

if (-not (Test-FullProfilePathsDisjoint $Gate6EvidenceRoot $SourceRoot) -or
    -not (Test-FullProfilePathsDisjoint $Gate6EvidenceRoot $StagingRoot)) {
    throw 'Gate6EvidenceRoot must be disjoint from both source and staging/build roots.'
}

$gitCommand = Get-Command git.exe, git -CommandType Application -ErrorAction SilentlyContinue |
    Select-Object -First 1
if ($null -eq $gitCommand) {
    throw 'Git is required for exact Gate6 source eligibility checks.'
}
$gitExecutable = Resolve-Tool $gitCommand.Source 'Git'
$sourceCommit = (& $gitExecutable -C $SourceRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $sourceCommit -cnotmatch '^(?:[0-9a-f]{40}|[0-9a-f]{64})$') {
    throw 'The mutable Lumen source must be an exact Git commit before Gate6 freezing.'
}
$sourceStatus = @(& $gitExecutable -C $SourceRoot status --porcelain=v1 --untracked-files=all)
if ($LASTEXITCODE -ne 0 -or $sourceStatus.Count -ne 0) {
    throw 'The mutable Lumen source must be clean before Gate6 freezing.'
}
$submoduleStatus = @(& $gitExecutable -C $SourceRoot submodule status --recursive)
if ($LASTEXITCODE -ne 0 -or @($submoduleStatus | Where-Object {
            -not ([string]$_).StartsWith(' ', [StringComparison]::Ordinal)
        }).Count -ne 0) {
    throw 'Every recursive Lumen submodule must be initialized at its exact clean gitlink before Gate6 freezing.'
}
$sharedSourceFreeze = Assert-Gate6SharedSourceFreezeManifest `
    -ManifestPath $SharedSourceFreezeManifestPath `
    -RepositoryName 'Lumen' `
    -ExpectedCommit $sourceCommit
$sharedSourceFreezeManifestSha256 = $sharedSourceFreeze.Sha256
$gate6Runs = [Collections.Generic.List[object]]::new()

function Invoke-MandatoryGate6Command {
    param(
        [string]$RunId,
        [string]$FilePath,
        [string[]]$Arguments,
        [string]$WorkingDirectory,
        [string[]]$ToolchainIds,
        [hashtable]$Environment = @{}
    )

    $result = Invoke-Gate6RecordedCommand `
        -RunId $RunId `
        -FilePath $FilePath `
        -Arguments $Arguments `
        -WorkingDirectory $WorkingDirectory `
        -RunEvidenceRoot $runEvidenceRoot `
        -ToolchainIds $ToolchainIds `
        -Environment $Environment
    $gate6Runs.Add($result)
    if ([int]$result.Record.exit_code -ne 0) {
        Write-Host "===== $RunId stdout ====="
        Get-Content -LiteralPath $result.StdoutPath -Raw | Write-Host
        Write-Host "===== $RunId stderr ====="
        Get-Content -LiteralPath $result.StderrPath -Raw | Write-Host
        throw "Mandatory Gate6 run failed: $RunId"
    }
    return $result
}

$vswhere = Resolve-Tool `
    (Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe") `
    "vswhere"
$vsRoot = & $vswhere -latest -products "*" -requires Microsoft.Component.MSBuild -property installationPath |
    Select-Object -First 1
if ([string]::IsNullOrWhiteSpace($vsRoot)) {
    throw "Visual Studio 2022 Build Tools with MSBuild is required."
}
$msbuild = Resolve-Tool (Join-Path $vsRoot "MSBuild\Current\Bin\amd64\MSBuild.exe") "x64 MSBuild"
$kitsRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10"
$infVerif = Get-ChildItem (Join-Path $kitsRoot "Tools") -Recurse -File -Filter InfVerif.exe |
    Where-Object { $_.FullName -match '\\x64\\InfVerif\.exe$' } |
    Sort-Object FullName -Descending | Select-Object -First 1
$inf2Cat = Get-ChildItem (Join-Path $kitsRoot "bin") -Recurse -File -Filter Inf2Cat.exe |
    Sort-Object FullName -Descending | Select-Object -First 1
$signTool = Get-ChildItem (Join-Path $kitsRoot "bin") -Recurse -File -Filter signtool.exe |
    Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
    Sort-Object FullName -Descending | Select-Object -First 1
$apiValidator = Get-ChildItem (Join-Path $kitsRoot 'bin') -Recurse -File -Filter ApiValidator.exe |
    Where-Object { $_.FullName -match '\\x64\\ApiValidator\.exe$' } |
    Sort-Object FullName -Descending | Select-Object -First 1
$universalDdis = Get-ChildItem (Join-Path $kitsRoot 'build\universalDDIs') `
    -Recurse -File -Filter UniversalDDIs.xml |
    Where-Object { $_.FullName -match '\\x64\\UniversalDDIs\.xml$' } |
    Sort-Object FullName -Descending | Select-Object -First 1
if ($null -eq $infVerif -or $null -eq $inf2Cat -or $null -eq $signTool -or
    $null -eq $apiValidator -or $null -eq $universalDdis) {
    throw 'The x64 WDK InfVerif, Inf2Cat, SignTool, ApiValidator, and UniversalDDIs.xml tools are required.'
}
$msysShell = Resolve-Tool (Join-Path $Msys2Root "msys2_shell.cmd") "MSYS2 shell"

if ([string]::IsNullOrWhiteSpace($PythonPath)) {
    $pythonCommand = Get-Command python.exe -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -eq $pythonCommand) {
        $pythonCommand = Get-Command python -CommandType Application -ErrorAction SilentlyContinue |
            Select-Object -First 1
    }
    if ($null -eq $pythonCommand) {
        throw "Python is required. Pass -PythonPath or add python.exe to PATH."
    }
    $PythonPath = $pythonCommand.Source
}
$PythonPath = Resolve-Tool $PythonPath "Python"

if ([string]::IsNullOrWhiteSpace($DotNetRoot)) {
    $dotnetCommand = Get-Command dotnet.exe -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -eq $dotnetCommand) {
        $dotnetCommand = Get-Command dotnet -CommandType Application -ErrorAction SilentlyContinue |
            Select-Object -First 1
    }
    if ($null -eq $dotnetCommand) {
        throw ".NET is required. Pass -DotNetRoot or add dotnet.exe to PATH."
    }
    $DotNetRoot = Split-Path -Parent $dotnetCommand.Source
}
$DotNetRoot = Resolve-ExistingDirectory $DotNetRoot ".NET"
$dotnetExecutable = Resolve-Tool (Join-Path $DotNetRoot "dotnet.exe") ".NET executable"

if ([string]::IsNullOrWhiteSpace($NodeRoot)) {
    $nodeCommand = Get-Command node.exe -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -ne $nodeCommand) {
        $NodeRoot = Split-Path -Parent $nodeCommand.Source
    } else {
        $msysNodeRoot = Join-Path $Msys2Root "ucrt64\bin"
        if (Test-Path -LiteralPath (Join-Path $msysNodeRoot "node.exe") -PathType Leaf) {
            $NodeRoot = $msysNodeRoot
        }
    }
}
if ([string]::IsNullOrWhiteSpace($NodeRoot)) {
    throw "Node.js is required. Pass -NodeRoot or add node.exe to PATH."
}
$NodeRoot = Resolve-ExistingDirectory $NodeRoot "Node.js"
Resolve-Tool (Join-Path $NodeRoot "node.exe") "Node.js executable" | Out-Null
$npmExecutablePath = Join-Path $NodeRoot "npm.cmd"
if (-not (Test-Path -LiteralPath $npmExecutablePath -PathType Leaf)) {
    $npmExecutablePath = Join-Path $NodeRoot "npm.exe"
}
$npmExecutable = Resolve-Tool $npmExecutablePath "npm"

$uvExecutablePath = $null
$uvCommand = Get-Command uv.exe -CommandType Application -ErrorAction SilentlyContinue |
    Select-Object -First 1
if ($null -eq $uvCommand) {
    $uvCandidate = Join-Path $Msys2Root "ucrt64\bin\uv.exe"
    if (Test-Path -LiteralPath $uvCandidate -PathType Leaf) {
        $uvExecutablePath = $uvCandidate
    }
} else {
    $uvExecutablePath = $uvCommand.Source
}
if ([string]::IsNullOrWhiteSpace($uvExecutablePath)) {
    throw "uv is required. Install it in MSYS2 UCRT64 or add uv.exe to PATH."
}
$uvExecutable = Resolve-Tool $uvExecutablePath "uv"

$freezeDirectory = Join-Path $StagingRoot "source-freeze"
if (Test-Path -LiteralPath $freezeDirectory) {
    Remove-Item -LiteralPath $freezeDirectory -Recurse -Force
}
[void](Invoke-MandatoryGate6Command `
    -RunId 'lumen-source-freeze' `
    -FilePath $powerShellExecutable `
    -Arguments @(
        '-NoLogo',
        '-NoProfile',
        '-NonInteractive',
        '-File',
        (Join-Path $SourceRoot 'scripts\windows\freeze-full-profile-source.ps1'),
        '-SourceRoot',
        $SourceRoot,
        '-OutputDirectory',
        $freezeDirectory,
        '-SharedSourceFreezeManifestSha256',
        $sharedSourceFreezeManifestSha256
    ) `
    -WorkingDirectory $SourceRoot `
    -ToolchainIds @('windows-powershell'))
$mutableSourceRoot = $SourceRoot
$sourceProvenance = Expand-VerifiedFullProfileSource `
    -FreezeDirectory $freezeDirectory `
    -DestinationDirectory (Join-Path $StagingRoot "verified-source") `
    -MutableSourceRoot $mutableSourceRoot `
    -ExpectedSharedSourceFreezeManifestSha256 $sharedSourceFreezeManifestSha256
$SourceRoot = $sourceProvenance.SourceRoot
$sourceFilesManifestSha256 = $sourceProvenance.FilesManifestSha256

$requiredMsQuicHashes = @{
    "build\native\include\msquic.h" = "EBD3499686C2B3008ED0EE5B06DAE1A62A50192816ABFE9A67BBBBA97CABB861"
    "build\native\lib\x64\msquic.lib" = "AA08808C1CA29166EA476A66410B73C7D0D85A34459EA59A30DE63CCA7AD7327"
    "build\native\bin\x64\msquic.dll" = "C981E61CD207F42D46B54EF7DBF1049F1F836424C3BA981F4469AC2B2BEA9610"
    "LICENSE" = "903DF5512F7D02609FED0C780A9B704F5A3EEB6E4D84EBE42A29845C81899A3C"
}
foreach ($entry in $requiredMsQuicHashes.GetEnumerator()) {
    $path = Join-Path $MsQuicPackageRoot $entry.Key
    if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or
        (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $entry.Value) {
        throw "MsQuic 2.6.0 package identity mismatch: $($entry.Key)"
    }
}

function Invoke-DriverBuild {
    param(
        [string]$Name,
        [string]$Project,
        [string]$BinaryName,
        [string]$InfName,
        [string]$PackageDirectory
    )
    [void](Assert-FullProfileSourceSnapshot `
        -SourceRoot $SourceRoot `
        -FilesManifestPath $sourceProvenance.FilesManifestPath `
        -Boundary "$Name driver build")
    $buildRoot = Join-Path $StagingRoot "drivers\$Name"
    if (Test-Path -LiteralPath $buildRoot) {
        Remove-Item -LiteralPath $buildRoot -Recurse -Force
    }
    if (Test-Path -LiteralPath $PackageDirectory) {
        Remove-Item -LiteralPath $PackageDirectory -Recurse -Force
    }
    $bin = Join-Path $buildRoot "bin"
    $obj = Join-Path $buildRoot "obj"
    New-Item -ItemType Directory -Path $bin, $obj, $PackageDirectory -Force | Out-Null
    $msbuildArguments = @(
        $Project,
        "/m",
        "/restore",
        "/t:Rebuild",
        "/p:Configuration=$Configuration",
        "/p:Platform=x64",
        "/p:OutDir=$bin\",
        "/p:IntDir=$obj\",
        "/p:EnableInf2Cat=false",
        "/p:SkipPackageVerification=true",
        "/p:SignMode=Off",
        "/p:RunCodeAnalysis=true",
        "/p:EnableCppCodeAnalysis=true",
        "/p:CodeAnalysisTreatWarningsAsErrors=true"
    )
    $msbuildArguments += "/warnaserror"
    [void](Invoke-MandatoryGate6Command `
        -RunId "driver-$Name-msbuild" `
        -FilePath $msbuild `
        -Arguments $msbuildArguments `
        -WorkingDirectory $SourceRoot `
        -ToolchainIds @('windows-msbuild-wdk'))
    $binary = Get-ChildItem $bin -Recurse -File -Filter $BinaryName | Select-Object -First 1
    if ($null -eq $binary) {
        throw "$Name did not produce $BinaryName."
    }
    $infSource = Join-Path (Split-Path -Parent $Project) $InfName
    Copy-Item -LiteralPath $binary.FullName, $infSource -Destination $PackageDirectory -Force
    $inf = Join-Path $PackageDirectory $InfName
    [void](Invoke-MandatoryGate6Command `
        -RunId "driver-$Name-infverif" `
        -FilePath $infVerif.FullName `
        -Arguments @('/v', '/w', $inf) `
        -WorkingDirectory $PackageDirectory `
        -ToolchainIds @('windows-msbuild-wdk'))
    [void](Invoke-MandatoryGate6Command `
        -RunId "driver-$Name-apivalidator" `
        -FilePath $apiValidator.FullName `
        -Arguments @(
            "-DriverPackagePath:$PackageDirectory",
            "-SupportedApiXmlFiles:$($universalDdis.FullName)"
        ) `
        -WorkingDirectory $PackageDirectory `
        -ToolchainIds @('windows-msbuild-wdk'))
    [void](Invoke-MandatoryGate6Command `
        -RunId "driver-$Name-inf2cat" `
        -FilePath $inf2Cat.FullName `
        -Arguments @("/driver:$PackageDirectory", '/os:10_X64', '/verbose') `
        -WorkingDirectory $PackageDirectory `
        -ToolchainIds @('windows-msbuild-wdk'))
    $catalogs = @(Get-ChildItem $PackageDirectory -File -Filter "*.cat")
    if ($catalogs.Count -ne 1) {
        throw "$Name did not produce exactly one catalog."
    }
}

$rawDriverRoot = Join-Path $StagingRoot "unsigned-driver-submissions"
$vhidRaw = Join-Path $rawDriverRoot "virtual-hid"
$vmicRaw = Join-Path $rawDriverRoot "virtual-microphone"
$vddRaw = Join-Path $rawDriverRoot "virtual-display"
Invoke-DriverBuild `
    -Name "virtual-hid" `
    -Project (Join-Path $SourceRoot "src\platform\windows\virtual_hid_driver\LumenVirtualHid.vcxproj") `
    -BinaryName "LumenVirtualHid.dll" `
    -InfName "LumenVirtualHid.inf" `
    -PackageDirectory $vhidRaw
Invoke-DriverBuild `
    -Name "virtual-microphone" `
    -Project (Join-Path $SourceRoot "src\platform\windows\virtual_microphone_driver\LumenVirtualMicrophone.vcxproj") `
    -BinaryName "LumenVirtualMicrophone.sys" `
    -InfName "LumenVirtualMicrophone.inf" `
    -PackageDirectory $vmicRaw
Invoke-DriverBuild `
    -Name "virtual-display" `
    -Project (Join-Path $SourceRoot "src\platform\windows\virtual_display_driver\LumenVirtualDisplay.vcxproj") `
    -BinaryName "LumenVirtualDisplay.dll" `
    -InfName "LumenVirtualDisplay.inf" `
    -PackageDirectory $vddRaw

$shimProject = Join-Path $SourceRoot "src\platform\windows\msquic_shim\LumenMsQuicShim.vcxproj"
[void](Assert-FullProfileSourceSnapshot `
    -SourceRoot $SourceRoot `
    -FilesManifestPath $sourceProvenance.FilesManifestPath `
    -Boundary 'MsQuic shim build')
$shimOutput = Join-Path $StagingRoot "msquic-shim"
if (Test-Path -LiteralPath $shimOutput) {
    Remove-Item -LiteralPath $shimOutput -Recurse -Force
}
New-Item -ItemType Directory -Path $shimOutput -Force | Out-Null
[void](Invoke-MandatoryGate6Command `
    -RunId 'msquic-shim-msbuild' `
    -FilePath $msbuild `
    -Arguments @(
        $shimProject,
        '/m',
        '/t:Rebuild',
        '/warnaserror',
        '/p:Configuration=Release',
        '/p:Platform=x64',
        "/p:MsQuicRoot=$MsQuicPackageRoot",
        "/p:OutDir=$shimOutput\"
    ) `
    -WorkingDirectory $SourceRoot `
    -ToolchainIds @('windows-msbuild-wdk'))
$shimDll = Join-Path $shimOutput "lumen_msquic_shim.dll"
$shimLib = Join-Path $shimOutput "lumen_msquic_shim.lib"
$shimManifest = Join-Path $shimOutput "manifest.json"
foreach ($path in @($shimDll, $shimLib, $shimManifest)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "MsQuic ABI3 shim output is incomplete: $path"
    }
}
$manifest = Get-Content -LiteralPath $shimManifest -Raw | ConvertFrom-Json
$shimDllHash = (Get-FileHash $shimDll -Algorithm SHA256).Hash.ToLowerInvariant()
$shimLibHash = (Get-FileHash $shimLib -Algorithm SHA256).Hash.ToLowerInvariant()
if ([int]$manifest.abi -ne 3 -or
    [string]$manifest.architecture -cne "x64" -or
    [string]$manifest.toolset -cne "v143" -or
    [string]$manifest.shim_dll_sha256 -cne $shimDllHash -or
    [string]$manifest.shim_import_library_sha256 -cne $shimLibHash) {
    throw "MsQuic ABI3 shim manifest does not match the built artifacts."
}

$sourceFreezeManifest = Get-Content $sourceProvenance.FreezeManifestPath -Raw | ConvertFrom-Json
$pendingManifest = [ordered]@{
    schema = 1
    sourceRoot = $SourceRoot
    sourceFileCount = $sourceProvenance.FileCount
    sourceFilesManifestSha256 = $sourceFilesManifestSha256
    sourceArchiveSha256 = $sourceProvenance.ArchiveSha256
    sourceFreezeManifestSha256 = $sourceProvenance.FreezeManifestSha256
    sharedSourceFreezeManifestSha256 = $sharedSourceFreezeManifestSha256
    vddShaderCount = 7
    vddShaderInventorySha256 = [string]$sourceFreezeManifest.identities.vddShaderInventorySha256
    msquicShim = @{
        abi = 3
        dllSha256 = $shimDllHash
        libSha256 = $shimLibHash
    }
    unsignedDriverSubmissions = @{}
}
foreach ($directory in @($vhidRaw, $vmicRaw, $vddRaw)) {
    $pendingManifest.unsignedDriverSubmissions[(Split-Path -Leaf $directory)] = @(
        Get-ChildItem $directory -File | Sort-Object Name | ForEach-Object {
            @{ name = $_.Name; sha256 = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
        }
    )
}
$pendingManifest | ConvertTo-Json -Depth 8 | Set-Content $pendingManifestPath -Encoding UTF8

if ([string]::IsNullOrWhiteSpace($SignedDriverRoot)) {
    throw "SignedDriverRoot is required to finish the full profile. Submit the three packages under '$rawDriverRoot' for Microsoft driver signing, then rerun with signed subdirectories virtual-hid, virtual-microphone, and virtual-display. Manifest: $pendingManifestPath"
}
$SignedDriverRoot = Resolve-ExistingDirectory $SignedDriverRoot "Signed driver package"
$signedSubmissionManifestPath = Join-Path $SignedDriverRoot "full-profile-driver-manifest.json"
if (-not (Test-Path -LiteralPath $signedSubmissionManifestPath -PathType Leaf)) {
    throw "SignedDriverRoot must retain full-profile-driver-manifest.json from the submitted build."
}
$signedSubmissionManifest = Get-Content $signedSubmissionManifestPath -Raw | ConvertFrom-Json
if ([int]$signedSubmissionManifest.schema -ne 1 -or
    [string]$signedSubmissionManifest.sourceFilesManifestSha256 -cne $sourceFilesManifestSha256) {
    throw "Signed driver packages were not built from this exact source freeze."
}
if ((Get-FileHash -LiteralPath $signedSubmissionManifestPath -Algorithm SHA256).Hash -ne
    (Get-FileHash -LiteralPath $pendingManifestPath -Algorithm SHA256).Hash) {
    throw 'The returned driver submission manifest is not byte-identical to the submitted manifest.'
}

$signaturePolicy = "/kp"
$localTestMarkerCmake = "-DLUMEN_WINDOWS_LOCAL_TEST_SIGNING_MARKER="
if ($AllowTestSignedDrivers) {
    $testMarkerPath = Join-Path $SignedDriverRoot "LOCAL-TEST-SIGNED.json"
    $testCertificatePath = Join-Path $SignedDriverRoot "local-test-signing.cer"
    if (-not (Test-Path -LiteralPath $testMarkerPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $testCertificatePath -PathType Leaf)) {
        throw "Local test signing requires LOCAL-TEST-SIGNED.json and local-test-signing.cer."
    }
    $testMarker = Get-Content $testMarkerPath -Raw | ConvertFrom-Json
    $certificateHash = (Get-FileHash $testCertificatePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ([int]$testMarker.schema -ne 1 -or
        [string]$testMarker.purpose -cne "local-test-only" -or
        [string]$testMarker.sourceFilesManifestSha256 -cne $sourceFilesManifestSha256 -or
        [string]$testMarker.certificateSha256 -cne $certificateHash) {
        throw "Local test signing marker does not match the source freeze and certificate."
    }
    foreach ($store in @("Root", "TrustedPublisher")) {
        & certutil.exe -addstore -f $store $testCertificatePath | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Adding the local test certificate to $store failed."
        }
    }
    $signaturePolicy = "/pa"
    $testMarkerCmakePath = [IO.Path]::GetFullPath($testMarkerPath) -replace '\\', '/'
    $localTestMarkerCmake = "-DLUMEN_WINDOWS_LOCAL_TEST_SIGNING_MARKER='$testMarkerCmakePath'"
} elseif (Test-Path -LiteralPath (Join-Path $SignedDriverRoot "LOCAL-TEST-SIGNED.json")) {
    throw "Local-test-signed drivers require explicit -AllowTestSignedDrivers."
}

$signedReturnPackages = [ordered]@{}
function Assert-SignedDriverPackage {
    param(
        [string]$Name,
        [string]$RawDirectory,
        [string]$BinaryName,
        [string]$InfName
    )
    $directory = Resolve-ExistingDirectory (Join-Path $SignedDriverRoot $Name) "$Name signed package"
    $expectedNames = @($BinaryName, $InfName, [IO.Path]::ChangeExtension($InfName, ".cat"))
    $expectedNamesNormalized = @($expectedNames | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object)
    $actualNames = @(Get-ChildItem $directory -File | Select-Object -ExpandProperty Name)
    $actualNamesNormalized = @($actualNames | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object)
    if (($actualNamesNormalized -join "|") -cne ($expectedNamesNormalized -join "|")) {
        throw "$Name signed package must contain exactly: $($expectedNames -join ', ')"
    }
    $signedInf = Join-Path $directory $InfName
    $rawInf = Join-Path $RawDirectory $InfName
    $rawBinary = Join-Path $RawDirectory $BinaryName
    if ((Get-FileHash $signedInf -Algorithm SHA256).Hash -ne
        (Get-FileHash $rawInf -Algorithm SHA256).Hash) {
        throw "$Name signed package changed its INF after validation."
    }
    $submittedRows = @($signedSubmissionManifest.unsignedDriverSubmissions.$Name)
    $submittedInf = @($submittedRows | Where-Object { $_.name -ceq $InfName })
    $submittedBinary = @($submittedRows | Where-Object { $_.name -ceq $BinaryName })
    if ($submittedInf.Count -ne 1 -or
        $submittedBinary.Count -ne 1 -or
        [string]$submittedInf[0].sha256 -cne
            (Get-FileHash $rawInf -Algorithm SHA256).Hash.ToLowerInvariant() -or
        [string]$submittedBinary[0].sha256 -cne
            (Get-FileHash $rawBinary -Algorithm SHA256).Hash.ToLowerInvariant()) {
        throw "$Name signed package manifest does not match its submitted bytes."
    }
    $catalog = Join-Path $directory ([IO.Path]::ChangeExtension($InfName, ".cat"))
    $binary = Join-Path $directory $BinaryName
    [void](Invoke-MandatoryGate6Command `
        -RunId "driver-$Name-signature-catalog" `
        -FilePath $signTool.FullName `
        -Arguments @('verify', $signaturePolicy, '/v', $catalog) `
        -WorkingDirectory $directory `
        -ToolchainIds @('windows-msbuild-wdk'))
    [void](Invoke-MandatoryGate6Command `
        -RunId "driver-$Name-signature-inf" `
        -FilePath $signTool.FullName `
        -Arguments @('verify', $signaturePolicy, '/v', '/c', $catalog, $signedInf) `
        -WorkingDirectory $directory `
        -ToolchainIds @('windows-msbuild-wdk'))
    [void](Invoke-MandatoryGate6Command `
        -RunId "driver-$Name-signature-binary" `
        -FilePath $signTool.FullName `
        -Arguments @('verify', $signaturePolicy, '/v', '/c', $catalog, $binary) `
        -WorkingDirectory $directory `
        -ToolchainIds @('windows-msbuild-wdk'))
    $script:signedReturnPackages[$Name] = [ordered]@{
        submitted = @(
            $submittedRows | Sort-Object name | ForEach-Object {
                [ordered]@{ name = [string]$_.name; sha256 = [string]$_.sha256 }
            }
        )
        returned = @(
            Get-ChildItem -LiteralPath $directory -File | Sort-Object Name | ForEach-Object {
                [ordered]@{
                    name = $_.Name
                    bytes = $_.Length
                    sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
                }
            }
        )
        signaturePolicy = $signaturePolicy
    }
    return $directory
}

$vhidSigned = Assert-SignedDriverPackage "virtual-hid" $vhidRaw "LumenVirtualHid.dll" "LumenVirtualHid.inf"
$vmicSigned = Assert-SignedDriverPackage "virtual-microphone" $vmicRaw "LumenVirtualMicrophone.sys" "LumenVirtualMicrophone.inf"
$vddSigned = Assert-SignedDriverPackage "virtual-display" $vddRaw "LumenVirtualDisplay.dll" "LumenVirtualDisplay.inf"
$signedReturnReceiptPath = Join-Path $StagingRoot 'signed-return-receipt.json'
[ordered]@{
    schema = 'lumen-gate6-signed-driver-return/1'
    sourceFilesManifestSha256 = $sourceFilesManifestSha256
    sourceArchiveSha256 = $sourceProvenance.ArchiveSha256
    sourceFreezeManifestSha256 = $sourceProvenance.FreezeManifestSha256
    sharedSourceFreezeManifestSha256 = $sharedSourceFreezeManifestSha256
    submissionManifestSha256 = (Get-FileHash $pendingManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    packages = $signedReturnPackages
} | ConvertTo-Json -Depth 12 | ForEach-Object {
    [IO.File]::WriteAllText($signedReturnReceiptPath, $_, [Text.UTF8Encoding]::new($false))
}

function Convert-ToMsysPath {
    param([string]$Path)
    if ($Path.Contains("'")) { throw "MSYS2 paths may not contain a single quote." }
    $result = & (Join-Path $Msys2Root "usr\bin\cygpath.exe") -u $Path
    if ($LASTEXITCODE -ne 0) { throw "cygpath failed for $Path" }
    return $result.Trim()
}

function Convert-ToCMakePath {
    param([string]$Path)
    return ([IO.Path]::GetFullPath($Path) -replace '\\', '/')
}

$sourceMsys = Convert-ToMsysPath $SourceRoot
$buildRoot = Join-Path $StagingRoot "cmake-build-full"
if (Test-Path -LiteralPath $buildRoot) {
    Remove-Item -LiteralPath $buildRoot -Recurse -Force
}
$artifacts = Join-Path $StagingRoot "artifacts"
if (Test-Path -LiteralPath $artifacts) {
    Remove-Item -LiteralPath $artifacts -Recurse -Force
}
New-Item -ItemType Directory -Path $artifacts -Force | Out-Null
$buildMsys = Convert-ToMsysPath $buildRoot
$pythonCmake = Convert-ToCMakePath $PythonPath
$pythonMsys = Convert-ToMsysPath $PythonPath
$dotnetMsys = Convert-ToMsysPath $DotNetRoot
$dotnetExecutableMsys = Convert-ToMsysPath $dotnetExecutable
$dotnetRootCmake = Convert-ToCMakePath $DotNetRoot
$dotnetCmake = Convert-ToCMakePath $dotnetExecutable
$nodeMsys = Convert-ToMsysPath $NodeRoot
$nodeExecutableMsys = Convert-ToMsysPath (Join-Path $NodeRoot 'node.exe')
$npmCmake = Convert-ToCMakePath $npmExecutable
$npmMsys = Convert-ToMsysPath $npmExecutable
$uvMsys = Convert-ToMsysPath $uvExecutable
$pythonEnvironment = Join-Path $StagingRoot 'python-environment'
$pythonEnvironmentMsys = Convert-ToMsysPath $pythonEnvironment
$shimMsys = Convert-ToMsysPath $shimOutput
$msquicRuntimeMsys = Convert-ToMsysPath (Join-Path $MsQuicPackageRoot "build\native\bin\x64")
$msquicCmake = Convert-ToCMakePath $MsQuicPackageRoot
$shimCmake = Convert-ToCMakePath $shimOutput
$vhidCmake = Convert-ToCMakePath $vhidSigned
$vmicCmake = Convert-ToCMakePath $vmicSigned
$vddCmake = Convert-ToCMakePath $vddSigned
[void](Invoke-MandatoryGate6Command `
    -RunId 'tool-msbuild-version' `
    -FilePath $msbuild `
    -Arguments @('/version', '/nologo') `
    -WorkingDirectory $SourceRoot `
    -ToolchainIds @('windows-msbuild-wdk'))
$toolVersionCommand = @"
set -euo pipefail
git --version
cmake --version
ninja --version
gcc --version
'$pythonMsys' --version
'$uvMsys' --version
'$dotnetExecutableMsys' --version
'$nodeExecutableMsys' --version
'$npmMsys' --version
"@
$toolVersionScript = Join-Path $StagingRoot 'gate6-tool-versions.sh'
[IO.File]::WriteAllText(
    $toolVersionScript,
    $toolVersionCommand,
    [Text.UTF8Encoding]::new($false)
)
[void](Invoke-MandatoryGate6Command `
    -RunId 'toolchain-runtime-versions' `
    -FilePath $msysShell `
    -Arguments @('-defterm', '-no-start', '-ucrt64', '-c', "bash '$(Convert-ToMsysPath $toolVersionScript)'") `
    -WorkingDirectory $SourceRoot `
    -ToolchainIds @('windows-mingw', 'windows-cmake-ninja', 'windows-wix'))

[void](Assert-FullProfileSourceSnapshot `
    -SourceRoot $SourceRoot `
    -FilesManifestPath $sourceProvenance.FilesManifestPath `
    -Boundary 'full application build')
$buildCommand = @"
set -euo pipefail
cd '$sourceMsys'
export UV_PYTHON='$pythonCmake'
export UV_PROJECT_ENVIRONMENT='$pythonEnvironmentMsys'
export DOTNET_ROOT='$dotnetRootCmake'
export PATH='$shimMsys':'$msquicRuntimeMsys':'$dotnetMsys':'$nodeMsys':"`$PATH"
'$uvMsys' sync --locked --no-python-downloads --no-install-project
cmake -S . -B '$buildMsys' -G Ninja \
  -DBUILD_DOCS=OFF -DBUILD_TESTS=ON -DBUILD_WERROR=ON -DCMAKE_BUILD_TYPE=Release \
  -DDOTNET_EXECUTABLE='$dotnetCmake' \
  -DNPM='$npmCmake' \
  -DLUMEN_WINDOWS_FULL_PROFILE=ON -DLUMEN_EXPERIMENTAL_MSQUIC=ON \
  -DLUMEN_MSQUIC_VERSION=2.6.0 -DLUMEN_MSQUIC_ROOT='$msquicCmake' \
  -DLUMEN_MSQUIC_SHIM_ROOT='$shimCmake' \
  -DLUMEN_MSQUIC_SHIM_DLL_SHA256='$shimDllHash' \
  -DLUMEN_MSQUIC_SHIM_LIB_SHA256='$shimLibHash' \
  $localTestMarkerCmake \
  -DSUNSHINE_VIRTUAL_HID_DRIVER_PACKAGE_DIR='$vhidCmake' \
  -DSUNSHINE_VIRTUAL_HID_BUNDLED_CERTIFICATE=OFF \
  -DSUNSHINE_VIRTUAL_MICROPHONE_DRIVER_PACKAGE_DIR='$vmicCmake' \
  -DSUNSHINE_VIRTUAL_DISPLAY_DRIVER_PACKAGE_DIR='$vddCmake'
ninja -C '$buildMsys'
"@
$buildScript = Join-Path $StagingRoot 'build-full-profile-app.sh'
[IO.File]::WriteAllText($buildScript, $buildCommand, [Text.UTF8Encoding]::new($false))
[void](Invoke-MandatoryGate6Command `
    -RunId 'lumen-full-application-build' `
    -FilePath $msysShell `
    -Arguments @('-defterm', '-no-start', '-ucrt64', '-c', "bash '$(Convert-ToMsysPath $buildScript)'") `
    -WorkingDirectory $SourceRoot `
    -ToolchainIds @('windows-mingw', 'windows-cmake-ninja'))

$testCommand = @"
set -euo pipefail
# Physical encoder probes run on the RTX hardware gate. The disposable builder
# runs the complete nonhardware suite so virtualized DXGI drivers cannot crash
# the packaging preflight before artifacts are validated.
'$buildMsys/tests/test_sunshine.exe' --gtest_filter='-EncoderVariants/EncoderTest.*'
"@
$testScript = Join-Path $StagingRoot 'test-full-profile-nonhardware.sh'
[IO.File]::WriteAllText($testScript, $testCommand, [Text.UTF8Encoding]::new($false))
[void](Invoke-MandatoryGate6Command `
    -RunId 'lumen-full-nonhardware-tests' `
    -FilePath $msysShell `
    -Arguments @('-defterm', '-no-start', '-ucrt64', '-c', "bash '$(Convert-ToMsysPath $testScript)'") `
    -WorkingDirectory $SourceRoot `
    -ToolchainIds @('windows-mingw'))

[void](Assert-FullProfileSourceSnapshot `
    -SourceRoot $SourceRoot `
    -FilesManifestPath $sourceProvenance.FilesManifestPath `
    -Boundary 'MSI and ZIP packaging')
$packageCommand = @"
set -euo pipefail
cd '$buildMsys'
cpack -G WIX
cpack -G ZIP
"@
$packageScript = Join-Path $StagingRoot 'package-full-profile.sh'
[IO.File]::WriteAllText($packageScript, $packageCommand, [Text.UTF8Encoding]::new($false))
[void](Invoke-MandatoryGate6Command `
    -RunId 'lumen-full-msi-zip-package' `
    -FilePath $msysShell `
    -Arguments @('-defterm', '-no-start', '-ucrt64', '-c', "bash '$(Convert-ToMsysPath $packageScript)'") `
    -WorkingDirectory $buildRoot `
    -ToolchainIds @('windows-cmake-ninja', 'windows-wix'))

$msi = @(Get-ChildItem (Join-Path $buildRoot "cpack_artifacts") -File -Filter "*.msi")
$zip = @(Get-ChildItem (Join-Path $buildRoot "cpack_artifacts") -File -Filter "*.zip")
if ($msi.Count -ne 1 -or $zip.Count -ne 1) {
    throw "Full-profile CPack did not produce exactly one MSI and one ZIP."
}
$versionedMsi = Join-Path $artifacts "Lumen-$BuildVersion-Windows-AMD64-installer.msi"
$versionedZip = Join-Path $artifacts "Lumen-$BuildVersion-Windows-AMD64-lite.zip"
Copy-Item $msi[0].FullName $versionedMsi -Force
Copy-Item $zip[0].FullName $versionedZip -Force
$env:EXPECT_VHID_FEATURE = "true"
$env:EXPECT_VMIC_FEATURE = "true"
$env:EXPECT_VDD_FEATURE = "true"
$env:EXPECT_MSQUIC = "true"
$env:EXPECT_LOCAL_TEST_SIGNED = if ($AllowTestSignedDrivers) { "true" } else { "false" }
$env:GITHUB_ENV = Join-Path $StagingRoot "full-profile-validator.env"
$env:LUMEN_MSI_PATH = $versionedMsi
[void](Invoke-MandatoryGate6Command `
    -RunId 'lumen-msi-table-validation' `
    -FilePath $powerShellExecutable `
    -Arguments @(
        '-NoLogo',
        '-NoProfile',
        '-NonInteractive',
        '-File',
        (Join-Path $SourceRoot '.github\scripts\validate-windows-msi.ps1')
    ) `
    -WorkingDirectory $SourceRoot `
    -ToolchainIds @('windows-wix'))

$toolIdentityPath = Join-Path $runEvidenceRoot 'toolchain-identities.json'
$nativeTools = @(
    [ordered]@{ id = 'git'; path = $gitExecutable },
    [ordered]@{ id = 'vswhere'; path = $vswhere },
    [ordered]@{ id = 'msbuild'; path = $msbuild },
    [ordered]@{ id = 'infverif'; path = $infVerif.FullName },
    [ordered]@{ id = 'inf2cat'; path = $inf2Cat.FullName },
    [ordered]@{ id = 'apivalidator'; path = $apiValidator.FullName },
    [ordered]@{ id = 'universal-ddis'; path = $universalDdis.FullName },
    [ordered]@{ id = 'signtool'; path = $signTool.FullName },
    [ordered]@{ id = 'msys2-shell'; path = $msysShell },
    [ordered]@{ id = 'python'; path = $PythonPath },
    [ordered]@{ id = 'dotnet'; path = $dotnetExecutable },
    [ordered]@{ id = 'npm'; path = $npmExecutable },
    [ordered]@{ id = 'uv'; path = $uvExecutable }
)
$toolIdentities = @(
    foreach ($tool in $nativeTools) {
        $item = Get-Item -LiteralPath $tool.path
        [ordered]@{
            id = $tool.id
            path = $item.FullName
            bytes = $item.Length
            sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            fileVersion = [string]$item.VersionInfo.FileVersion
            productVersion = [string]$item.VersionInfo.ProductVersion
        }
    }
)
Write-Gate6Json $toolIdentityPath ([ordered]@{
        schema = 'lumen-gate6-toolchain-identities/1'
        sourceCommit = $sourceCommit
        sharedSourceFreezeManifestSha256 = $sharedSourceFreezeManifestSha256
        tools = $toolIdentities
    })

function Copy-Gate6EvidenceFile {
    param([string]$Source, [string]$RelativeDestination)
    $destination = Resolve-Gate6EvidencePath $Gate6EvidenceRoot $RelativeDestination
    $parent = Split-Path -Parent $destination
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    if (Test-Path -LiteralPath $destination) {
        throw "Gate6 evidence destination already exists: $RelativeDestination"
    }
    Copy-Item -LiteralPath $Source -Destination $destination
}

function Copy-Gate6EvidenceTree {
    param([string]$SourceRoot, [string]$RelativeDestination)
    $destination = Resolve-Gate6EvidencePath $Gate6EvidenceRoot $RelativeDestination
    New-Item -ItemType Directory -Path $destination -Force | Out-Null
    foreach ($child in @(Get-ChildItem -LiteralPath $SourceRoot -Force)) {
        Copy-Item -LiteralPath $child.FullName -Destination $destination -Recurse
    }
}

function Get-Gate6PackageContentRoot {
    param([string]$ExtractionRoot, [string]$Name)
    $executables = @(Get-ChildItem -LiteralPath $ExtractionRoot -File -Recurse -Filter Lumen.exe)
    if ($executables.Count -ne 1) {
        throw "$Name extraction must contain exactly one Lumen.exe; found $($executables.Count)."
    }
    return $executables[0].Directory.FullName
}

if (Test-Path -LiteralPath $Gate6EvidenceRoot) {
    if (@(Get-ChildItem -LiteralPath $Gate6EvidenceRoot -Force).Count -ne 0) {
        throw "Gate6EvidenceRoot must be absent or empty: $Gate6EvidenceRoot"
    }
} else {
    New-Item -ItemType Directory -Path $Gate6EvidenceRoot -Force | Out-Null
}

$packageExtractionRoot = Join-Path $StagingRoot 'gate6-package-extraction'
if (Test-Path -LiteralPath $packageExtractionRoot) {
    Remove-Item -LiteralPath $packageExtractionRoot -Recurse -Force
}
$msiExtractionRoot = Join-Path $packageExtractionRoot 'msi'
$zipExtractionRoot = Join-Path $packageExtractionRoot 'zip'
New-Item -ItemType Directory -Path $msiExtractionRoot, $zipExtractionRoot -Force | Out-Null
$msiexec = Resolve-Tool (Join-Path $env:SystemRoot 'System32\msiexec.exe') 'Windows Installer'
[void](Invoke-MandatoryGate6Command `
    -RunId 'lumen-msi-administrative-extraction' `
    -FilePath $msiexec `
    -Arguments @('/a', $versionedMsi, '/qn', "TARGETDIR=$msiExtractionRoot") `
    -WorkingDirectory $StagingRoot `
    -ToolchainIds @('windows-wix'))
$zipExtractionScript = Join-Path $StagingRoot 'extract-gate6-zip.ps1'
[IO.File]::WriteAllText(
    $zipExtractionScript,
    "param([string]`$Archive,[string]`$Destination) Expand-Archive -LiteralPath `$Archive -DestinationPath `$Destination -Force",
    [Text.UTF8Encoding]::new($false)
)
[void](Invoke-MandatoryGate6Command `
    -RunId 'lumen-zip-extraction' `
    -FilePath $powerShellExecutable `
    -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $zipExtractionScript,
        '-Archive', $versionedZip, '-Destination', $zipExtractionRoot) `
    -WorkingDirectory $StagingRoot `
    -ToolchainIds @('windows-wix'))
$msiContentRoot = Get-Gate6PackageContentRoot $msiExtractionRoot 'MSI'
$zipContentRoot = Get-Gate6PackageContentRoot $zipExtractionRoot 'ZIP'

Copy-Gate6EvidenceTree $freezeDirectory 'source-freeze'
Copy-Gate6EvidenceFile $sharedSourceFreeze.Path 'source-freeze/umbra-lumen-source-freeze-manifest.json'
Copy-Gate6EvidenceFile $signedSubmissionManifestPath 'full-profile-driver-manifest.json'
Copy-Gate6EvidenceFile $signedReturnReceiptPath 'signed-return-receipt.json'
Copy-Gate6EvidenceFile $shimDll 'shim/lumen_msquic_shim.dll'
Copy-Gate6EvidenceFile $shimLib 'shim/lumen_msquic_shim.lib'
Copy-Gate6EvidenceFile $shimManifest 'shim/manifest.json'
foreach ($path in @(
        'Lumen.exe',
        'zlib1.dll',
        'msquic.dll',
        'lumen_msquic_shim.dll',
        'MsQuic-LICENSE.txt',
        'tools/sunshinesvc.exe',
        'tools/lumen-vddctl.exe'
    )) {
    Copy-Gate6EvidenceFile (Join-Path $msiContentRoot $path) "app/$($path -replace '\\', '/')"
}
foreach ($driver in @(
        @{ Name = 'virtual-hid'; Root = $vhidSigned },
        @{ Name = 'virtual-microphone'; Root = $vmicSigned },
        @{ Name = 'virtual-display'; Root = $vddSigned }
    )) {
    Copy-Gate6EvidenceTree $driver.Root "drivers/$($driver.Name)"
}
foreach ($vector in @('quic_v3_vectors.json', 'start_mode_vectors.json', 'vdd_gate5_contract.json')) {
    Copy-Gate6EvidenceFile `
        (Join-Path $SourceRoot "docs\protocols\vectors\$vector") `
        "vectors/$vector"
}
Copy-Gate6EvidenceFile $versionedMsi "artifacts/$([IO.Path]::GetFileName($versionedMsi))"
Copy-Gate6EvidenceFile $versionedZip "artifacts/$([IO.Path]::GetFileName($versionedZip))"
Copy-Gate6EvidenceTree $msiContentRoot 'inventories/msi'
Copy-Gate6EvidenceTree $zipContentRoot 'inventories/zip'

[void](Assert-FullProfileSourceSnapshot `
    -SourceRoot $SourceRoot `
    -FilesManifestPath $sourceProvenance.FilesManifestPath `
    -Boundary 'Gate6 artifact manifest generation')
Assert-Gate6MandatoryRunsPassed @($gate6Runs)
$gate6ArtifactManifestPath = Join-Path $StagingRoot 'lumen-gate6-artifact-manifest.json'
$gate6ArtifactManifest = New-Gate6ArtifactManifest `
    -EvidenceRoot $Gate6EvidenceRoot `
    -ManifestPath $gate6ArtifactManifestPath `
    -Runs @($gate6Runs)

Write-Output "FULL_PROFILE_MSI=$versionedMsi"
Write-Output "FULL_PROFILE_MSI_SHA256=$((Get-FileHash $versionedMsi -Algorithm SHA256).Hash)"
Write-Output "FULL_PROFILE_ZIP=$versionedZip"
Write-Output "FULL_PROFILE_ZIP_SHA256=$((Get-FileHash $versionedZip -Algorithm SHA256).Hash)"
Write-Output "GATE6_RUN_EVIDENCE=$runEvidenceRoot"
Write-Output "GATE6_TOOLCHAIN_IDENTITIES=$toolIdentityPath"
Write-Output "GATE6_ARTIFACT_EVIDENCE=$Gate6EvidenceRoot"
Write-Output "GATE6_ARTIFACT_MANIFEST=$gate6ArtifactManifestPath"
Write-Output "GATE6_ARTIFACT_FILE_COUNT=$($gate6ArtifactManifest.FileCount)"
