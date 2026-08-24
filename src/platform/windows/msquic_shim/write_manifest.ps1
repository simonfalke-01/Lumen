param([string]$OutputMarker, [string]$ProjectMarker)
$ErrorActionPreference = "Stop"
$OutputDirectory = Split-Path -Parent $OutputMarker
$ProjectDirectory = Split-Path -Parent $ProjectMarker
$manifest = Get-Content -LiteralPath (Join-Path $ProjectDirectory "manifest.json") -Raw | ConvertFrom-Json
$manifest.abi = 3
$manifest.header_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $ProjectDirectory "lumen_msquic_shim.h")).Hash.ToLowerInvariant()
$manifest.source_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $ProjectDirectory "lumen_msquic_shim.cpp")).Hash.ToLowerInvariant()
$manifest.project_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $ProjectDirectory "LumenMsQuicShim.vcxproj")).Hash.ToLowerInvariant()
$manifest | Add-Member -NotePropertyName shim_dll_sha256 -NotePropertyValue ((Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $OutputDirectory "lumen_msquic_shim.dll")).Hash.ToLowerInvariant())
$manifest | Add-Member -NotePropertyName shim_import_library_sha256 -NotePropertyValue ((Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $OutputDirectory "lumen_msquic_shim.lib")).Hash.ToLowerInvariant())
$outputPath = Join-Path $OutputDirectory "manifest.json"
$encoding = [System.Text.UTF8Encoding]::new($false)
[System.IO.File]::WriteAllText($outputPath, ($manifest | ConvertTo-Json), $encoding)
