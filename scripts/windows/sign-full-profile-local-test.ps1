[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$StagingRoot,

    [Parameter(Mandatory = $true)]
    [string]$OutputRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$StagingRoot = (Resolve-Path -LiteralPath $StagingRoot).Path
$OutputRoot = [IO.Path]::GetFullPath($OutputRoot)
$submissionRoot = Join-Path $StagingRoot "unsigned-driver-submissions"
$submissionManifest = Join-Path $StagingRoot "full-profile-driver-manifest.json"
if (-not (Test-Path -LiteralPath $submissionManifest -PathType Leaf)) {
    throw "Full-profile submission manifest is missing: $submissionManifest"
}
$manifest = Get-Content $submissionManifest -Raw | ConvertFrom-Json
if ([int]$manifest.schema -ne 1 -or
    [string]::IsNullOrWhiteSpace([string]$manifest.sourceFilesManifestSha256)) {
    throw "Full-profile submission manifest is invalid."
}

$kitsRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10"
$inf2Cat = Get-ChildItem (Join-Path $kitsRoot "bin") -Recurse -File -Filter Inf2Cat.exe |
    Sort-Object FullName -Descending | Select-Object -First 1
$signTool = Get-ChildItem (Join-Path $kitsRoot "bin") -Recurse -File -Filter signtool.exe |
    Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
    Sort-Object FullName -Descending | Select-Object -First 1
if ($null -eq $inf2Cat -or $null -eq $signTool) {
    throw "Inf2Cat and x64 SignTool are required."
}

if (Test-Path -LiteralPath $OutputRoot) {
    Remove-Item -LiteralPath $OutputRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null

$certificate = New-SelfSignedCertificate `
    -Subject "CN=Lumen Local Test Drivers" `
    -FriendlyName "Lumen Local Test Drivers - not for release" `
    -Type CodeSigningCert `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyAlgorithm RSA `
    -KeyLength 3072 `
    -HashAlgorithm SHA256 `
    -KeyExportPolicy Exportable `
    -NotAfter (Get-Date).AddDays(30)
$certificatePath = Join-Path $OutputRoot "local-test-signing.cer"
$pfxPath = Join-Path $StagingRoot "local-test-signing.pfx"
$passwordText = [Guid]::NewGuid().ToString("N")
$password = ConvertTo-SecureString $passwordText -AsPlainText -Force
Export-Certificate -Cert $certificate -FilePath $certificatePath -Force | Out-Null
Export-PfxCertificate -Cert $certificate -FilePath $pfxPath -Password $password -Force | Out-Null
foreach ($store in @("Root", "TrustedPublisher")) {
    & certutil.exe -addstore -f $store $certificatePath | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Adding the local test certificate to $store failed."
    }
}

function New-TestSignedPackage {
    param(
        [string]$Name,
        [string]$BinaryName,
        [string]$InfName
    )
    $source = Join-Path $submissionRoot $Name
    $destination = Join-Path $OutputRoot $Name
    if (-not (Test-Path -LiteralPath $source -PathType Container)) {
        throw "Unsigned $Name submission is missing."
    }
    New-Item -ItemType Directory -Path $destination -Force | Out-Null
    $sourceInf = Join-Path $source $InfName
    $sourceBinary = Join-Path $source $BinaryName
    Copy-Item -LiteralPath $sourceInf, $sourceBinary -Destination $destination
    $binary = Join-Path $destination $BinaryName
    $inf = Join-Path $destination $InfName

    & $signTool.FullName sign /f $pfxPath /p $passwordText /fd SHA256 /v $binary
    if ($LASTEXITCODE -ne 0) { throw "Signing $BinaryName failed." }
    & $inf2Cat.FullName "/driver:$destination" /os:10_X64 /verbose
    if ($LASTEXITCODE -ne 0) { throw "Inf2Cat failed for $Name." }
    $catalogs = @(Get-ChildItem $destination -File -Filter "*.cat")
    if ($catalogs.Count -ne 1) { throw "$Name did not produce exactly one catalog." }
    & $signTool.FullName sign /f $pfxPath /p $passwordText /fd SHA256 /v $catalogs[0].FullName
    if ($LASTEXITCODE -ne 0) { throw "Signing the $Name catalog failed." }
    & $signTool.FullName verify /pa /v $binary
    if ($LASTEXITCODE -ne 0) { throw "$BinaryName signature validation failed." }
    & $signTool.FullName verify /pa /v $catalogs[0].FullName
    if ($LASTEXITCODE -ne 0) { throw "$Name catalog signature validation failed." }
    & $signTool.FullName verify /pa /v /c $catalogs[0].FullName $inf
    if ($LASTEXITCODE -ne 0) { throw "$Name catalog does not cover its INF." }
    & $signTool.FullName verify /pa /v /c $catalogs[0].FullName $binary
    if ($LASTEXITCODE -ne 0) { throw "$Name catalog does not cover its binary." }
}

try {
    New-TestSignedPackage "virtual-hid" "LumenVirtualHid.dll" "LumenVirtualHid.inf"
    New-TestSignedPackage "virtual-microphone" "LumenVirtualMicrophone.sys" "LumenVirtualMicrophone.inf"
    New-TestSignedPackage "virtual-display" "LumenVirtualDisplay.dll" "LumenVirtualDisplay.inf"
    Copy-Item $submissionManifest (Join-Path $OutputRoot "full-profile-driver-manifest.json")
    $marker = [ordered]@{
        schema = 1
        purpose = "local-test-only"
        sourceFilesManifestSha256 = [string]$manifest.sourceFilesManifestSha256
        certificateSha256 = (Get-FileHash $certificatePath -Algorithm SHA256).Hash.ToLowerInvariant()
        certificateThumbprint = $certificate.Thumbprint
        expiresUtc = $certificate.NotAfter.ToUniversalTime().ToString("o")
    }
    $marker | ConvertTo-Json | Set-Content `
        (Join-Path $OutputRoot "LOCAL-TEST-SIGNED.json") `
        -Encoding UTF8
} finally {
    Remove-Item -LiteralPath $pfxPath -Force -ErrorAction SilentlyContinue
}

Write-Output "LOCAL_TEST_SIGNED_DRIVER_ROOT=$OutputRoot"
