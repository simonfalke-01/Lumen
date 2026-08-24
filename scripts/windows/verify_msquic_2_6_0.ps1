# Verify an extracted official Microsoft.Native.Quic.MsQuic.Schannel 2.6.0
# x64 NuGet package without installing, building, or launching Lumen.
param(
    [Parameter(Mandatory = $true)]
    [string]$PackageRoot
)

$ErrorActionPreference = "Stop"
$Expected = @{
    "build/native/include/msquic.h" = "EBD3499686C2B3008ED0EE5B06DAE1A62A50192816ABFE9A67BBBBA97CABB861"
    "build/native/lib/x64/msquic.lib" = "AA08808C1CA29166EA476A66410B73C7D0D85A34459EA59A30DE63CCA7AD7327"
    "build/native/bin/x64/msquic.dll" = "C981E61CD207F42D46B54EF7DBF1049F1F836424C3BA981F4469AC2B2BEA9610"
    "LICENSE" = "903DF5512F7D02609FED0C780A9B704F5A3EEB6E4D84EBE42A29845C81899A3C"
}

foreach ($RelativePath in $Expected.Keys) {
    $Path = Join-Path $PackageRoot $RelativePath
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Missing MsQuic artifact: $Path"
    }
    $Actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    if ($Actual -ne $Expected[$RelativePath]) {
        throw "Hash mismatch for $RelativePath. Expected $($Expected[$RelativePath]); got $Actual"
    }
}

Write-Output "PASS MsQuic 2.6.0 x64 Schannel artifact and license hashes"
