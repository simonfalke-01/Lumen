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
$pendingManifestPath = Join-Path $StagingRoot "full-profile-driver-manifest.json"
if (Test-Path -LiteralPath $pendingManifestPath) {
    Remove-Item -LiteralPath $pendingManifestPath -Force
}

. (Join-Path $SourceRoot "scripts\windows\full-profile-source-provenance.ps1")

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
if ($null -eq $infVerif -or $null -eq $inf2Cat -or $null -eq $signTool) {
    throw "The x64 WDK InfVerif, Inf2Cat, and SignTool tools are required."
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
& (Join-Path $SourceRoot "scripts\windows\freeze-full-profile-source.ps1") `
    -SourceRoot $SourceRoot `
    -OutputDirectory $freezeDirectory
$mutableSourceRoot = $SourceRoot
$sourceProvenance = Expand-VerifiedFullProfileSource `
    -FreezeDirectory $freezeDirectory `
    -DestinationDirectory (Join-Path $StagingRoot "verified-source") `
    -MutableSourceRoot $mutableSourceRoot
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
        "/p:EnableCppCodeAnalysis=true"
    )
    $msbuildArguments += "/warnaserror"
    & $msbuild @msbuildArguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Name MSBuild failed with exit code $LASTEXITCODE."
    }
    $binary = Get-ChildItem $bin -Recurse -File -Filter $BinaryName | Select-Object -First 1
    if ($null -eq $binary) {
        throw "$Name did not produce $BinaryName."
    }
    $infSource = Join-Path (Split-Path -Parent $Project) $InfName
    Copy-Item -LiteralPath $binary.FullName, $infSource -Destination $PackageDirectory -Force
    $inf = Join-Path $PackageDirectory $InfName
    & $infVerif.FullName /v /w $inf
    if ($LASTEXITCODE -ne 0) {
        throw "$Name InfVerif failed with exit code $LASTEXITCODE."
    }
    & $inf2Cat.FullName "/driver:$PackageDirectory" /os:10_X64 /verbose
    if ($LASTEXITCODE -ne 0) {
        throw "$Name Inf2Cat failed with exit code $LASTEXITCODE."
    }
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
$shimOutput = Join-Path $StagingRoot "msquic-shim"
if (Test-Path -LiteralPath $shimOutput) {
    Remove-Item -LiteralPath $shimOutput -Recurse -Force
}
New-Item -ItemType Directory -Path $shimOutput -Force | Out-Null
& $msbuild `
    $shimProject `
    /m `
    /t:Rebuild `
    /warnaserror `
    /p:Configuration=Release `
    /p:Platform=x64 `
    /p:MsQuicRoot="$MsQuicPackageRoot" `
    /p:OutDir="$shimOutput\"
if ($LASTEXITCODE -ne 0) {
    throw "MsQuic ABI2 shim build failed with exit code $LASTEXITCODE."
}
$shimDll = Join-Path $shimOutput "lumen_msquic_shim.dll"
$shimLib = Join-Path $shimOutput "lumen_msquic_shim.lib"
$shimManifest = Join-Path $shimOutput "manifest.json"
foreach ($path in @($shimDll, $shimLib, $shimManifest)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "MsQuic ABI2 shim output is incomplete: $path"
    }
}
$manifest = Get-Content -LiteralPath $shimManifest -Raw | ConvertFrom-Json
$shimDllHash = (Get-FileHash $shimDll -Algorithm SHA256).Hash.ToLowerInvariant()
$shimLibHash = (Get-FileHash $shimLib -Algorithm SHA256).Hash.ToLowerInvariant()
if ([int]$manifest.abi -ne 2 -or
    [string]$manifest.architecture -cne "x64" -or
    [string]$manifest.toolset -cne "v143" -or
    [string]$manifest.shim_dll_sha256 -cne $shimDllHash -or
    [string]$manifest.shim_import_library_sha256 -cne $shimLibHash) {
    throw "MsQuic ABI2 shim manifest does not match the built artifacts."
}

$pendingManifest = [ordered]@{
    schema = 1
    sourceRoot = $SourceRoot
    sourceFileCount = $sourceProvenance.FileCount
    sourceFilesManifestSha256 = $sourceFilesManifestSha256
    sourceArchiveSha256 = $sourceProvenance.ArchiveSha256
    sourceFreezeManifestSha256 = $sourceProvenance.FreezeManifestSha256
    msquicShim = @{
        abi = 2
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
    if ((Get-FileHash $signedInf -Algorithm SHA256).Hash -ne
        (Get-FileHash $rawInf -Algorithm SHA256).Hash) {
        throw "$Name signed package changed its INF after validation."
    }
    $submittedRows = @($signedSubmissionManifest.unsignedDriverSubmissions.$Name)
    $submittedInf = @($submittedRows | Where-Object { $_.name -ceq $InfName })
    if ($submittedInf.Count -ne 1 -or
        [string]$submittedInf[0].sha256 -cne
            (Get-FileHash $rawInf -Algorithm SHA256).Hash.ToLowerInvariant()) {
        throw "$Name signed package manifest does not match its submitted INF."
    }
    $catalog = Join-Path $directory ([IO.Path]::ChangeExtension($InfName, ".cat"))
    $binary = Join-Path $directory $BinaryName
    & $signTool.FullName verify $signaturePolicy /v $catalog | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "$Name catalog does not pass kernel-policy signature verification." }
    & $signTool.FullName verify $signaturePolicy /v /c $catalog $signedInf | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "$Name catalog does not cover its INF." }
    & $signTool.FullName verify $signaturePolicy /v /c $catalog $binary | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "$Name catalog does not cover its binary." }
    return $directory
}

$vhidSigned = Assert-SignedDriverPackage "virtual-hid" $vhidRaw "LumenVirtualHid.dll" "LumenVirtualHid.inf"
$vmicSigned = Assert-SignedDriverPackage "virtual-microphone" $vmicRaw "LumenVirtualMicrophone.sys" "LumenVirtualMicrophone.inf"
$vddSigned = Assert-SignedDriverPackage "virtual-display" $vddRaw "LumenVirtualDisplay.dll" "LumenVirtualDisplay.inf"

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
$dotnetMsys = Convert-ToMsysPath $DotNetRoot
$dotnetRootCmake = Convert-ToCMakePath $DotNetRoot
$dotnetCmake = Convert-ToCMakePath $dotnetExecutable
$nodeMsys = Convert-ToMsysPath $NodeRoot
$npmCmake = Convert-ToCMakePath $npmExecutable
$uvMsys = Convert-ToMsysPath $uvExecutable
$shimMsys = Convert-ToMsysPath $shimOutput
$msquicRuntimeMsys = Convert-ToMsysPath (Join-Path $MsQuicPackageRoot "build\native\bin\x64")
$msquicCmake = Convert-ToCMakePath $MsQuicPackageRoot
$shimCmake = Convert-ToCMakePath $shimOutput
$vhidCmake = Convert-ToCMakePath $vhidSigned
$vmicCmake = Convert-ToCMakePath $vmicSigned
$vddCmake = Convert-ToCMakePath $vddSigned
$command = @"
set -euo pipefail
cd '$sourceMsys'
export UV_PYTHON='$pythonCmake'
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
'$buildMsys/tests/test_sunshine.exe'
cd '$buildMsys'
cpack -G WIX
cpack -G ZIP
"@
$bashScript = Join-Path $StagingRoot "build-full-profile.sh"
[IO.File]::WriteAllText($bashScript, $command, [Text.UTF8Encoding]::new($false))
& $msysShell -defterm -no-start -ucrt64 -c "bash '$(Convert-ToMsysPath $bashScript)'"
if ($LASTEXITCODE -ne 0) {
    throw "Full-profile MSYS2 build failed with exit code $LASTEXITCODE."
}

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
Push-Location $SourceRoot
try {
    & (Join-Path $SourceRoot ".github\scripts\validate-windows-msi.ps1")
} finally {
    Pop-Location
}
Write-Output "FULL_PROFILE_MSI=$versionedMsi"
Write-Output "FULL_PROFILE_MSI_SHA256=$((Get-FileHash $versionedMsi -Algorithm SHA256).Hash)"
Write-Output "FULL_PROFILE_ZIP=$versionedZip"
Write-Output "FULL_PROFILE_ZIP_SHA256=$((Get-FileHash $versionedZip -Algorithm SHA256).Hash)"
