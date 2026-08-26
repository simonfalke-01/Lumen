Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot 'gate6-artifact-manifest.ps1')

function Write-Gate6Json {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [object]$Value
    )

    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    [IO.File]::WriteAllText(
        $Path,
        ($Value | ConvertTo-Json -Depth 30),
        [Text.UTF8Encoding]::new($false)
    )
}

function Assert-Gate6SharedSourceFreezeManifest {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ManifestPath,

        [Parameter(Mandatory = $true)]
        [string]$RepositoryName,

        [Parameter(Mandatory = $true)]
        [ValidatePattern('^(?:[0-9a-f]{40}|[0-9a-f]{64})$')]
        [string]$ExpectedCommit
    )

    $ManifestPath = (Resolve-Path -LiteralPath $ManifestPath).Path
    $manifest = Read-Gate6Json $ManifestPath 'Shared Gate6 Source Freeze Manifest'
    if ([string]$manifest.schema -cne 'umbra-lumen/source-freeze-manifest/1' -or
        [string]$manifest.kind -cne 'source_freeze' -or
        [string]$manifest.digest_algorithm -cne 'sha256') {
        throw 'Shared Gate6 Source Freeze Manifest has an unsupported schema.'
    }
    $repositories = @($manifest.repositories | Where-Object {
            [string]$_.name -ceq $RepositoryName
        })
    if ($repositories.Count -ne 1) {
        throw "Shared Gate6 Source Freeze Manifest must contain exactly one $RepositoryName repository."
    }
    $repository = $repositories[0]
    if ([string]$repository.commit -cne $ExpectedCommit -or
        [string]$repository.upstream_commit -cne $ExpectedCommit -or
        [bool]$repository.clean -ne $true -or
        [bool]$repository.pushed -ne $true) {
        throw "Shared Gate6 Source Freeze Manifest does not authorize exact $RepositoryName commit $ExpectedCommit."
    }
    if (@($repository.submodules | Where-Object {
                [bool]$_.clean -ne $true -or
                [bool]$_.remote_reachable -ne $true -or
                [string]$_.gitlink_commit -cne [string]$_.checked_out_commit
            }).Count -ne 0) {
        throw "Shared Gate6 Source Freeze Manifest contains an invalid $RepositoryName submodule."
    }
    return [pscustomobject]@{
        Path = $ManifestPath
        Sha256 = Get-Gate6Sha256 $ManifestPath
        ReleaseId = [string]$manifest.release_id
        RepositoryCommit = [string]$repository.commit
    }
}

function Invoke-Gate6RecordedCommand {
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]*$')]
        [string]$RunId,

        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [string[]]$Arguments = @(),

        [Parameter(Mandatory = $true)]
        [string]$WorkingDirectory,

        [Parameter(Mandatory = $true)]
        [string]$RunEvidenceRoot,

        [Parameter(Mandatory = $true)]
        [string[]]$ToolchainIds,

        [ValidateSet('mandatory', 'capability_conditional')]
        [string]$Classification = 'mandatory',

        [hashtable]$Environment = @{}
    )

    $FilePath = (Resolve-Path -LiteralPath $FilePath).Path
    $WorkingDirectory = (Resolve-Path -LiteralPath $WorkingDirectory).Path
    if ($ToolchainIds.Count -eq 0) {
        throw "Gate6 run $RunId must reference at least one toolchain."
    }
    $runDirectory = Join-Path ([IO.Path]::GetFullPath($RunEvidenceRoot)) $RunId
    if (Test-Path -LiteralPath $runDirectory) {
        throw "Gate6 run evidence already exists: $RunId"
    }
    New-Item -ItemType Directory -Path $runDirectory -Force | Out-Null
    $stdoutPath = Join-Path $runDirectory 'stdout.bin'
    $stderrPath = Join-Path $runDirectory 'stderr.bin'
    $recordPath = Join-Path $runDirectory 'run.json'

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in $Arguments) {
        [void]$startInfo.ArgumentList.Add([string]$argument)
    }
    $recordedEnvironment = [ordered]@{}
    foreach ($name in @($Environment.Keys | Sort-Object)) {
        $value = [string]$Environment[$name]
        $startInfo.Environment[[string]$name] = $value
        $recordedEnvironment[[string]$name] = $value
    }

    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $startedAt = [DateTime]::UtcNow
    $startedTicks = [Diagnostics.Stopwatch]::GetTimestamp()
    $stdout = [IO.File]::Open($stdoutPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
    $stderr = [IO.File]::Open($stderrPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
    try {
        if (-not $process.Start()) {
            throw "Unable to start Gate6 command: $FilePath"
        }
        $stdoutCopy = $process.StandardOutput.BaseStream.CopyToAsync($stdout)
        $stderrCopy = $process.StandardError.BaseStream.CopyToAsync($stderr)
        $process.WaitForExit()
        [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdoutCopy, $stderrCopy))
        $stdout.Flush()
        $stderr.Flush()
        $exitCode = $process.ExitCode
    } finally {
        $stdout.Dispose()
        $stderr.Dispose()
        $process.Dispose()
    }
    $endedTicks = [Diagnostics.Stopwatch]::GetTimestamp()
    $endedAt = [DateTime]::UtcNow
    $durationNs = [int64](
        (($endedTicks - $startedTicks) * 1000000000.0) / [Diagnostics.Stopwatch]::Frequency
    )
    $stdoutInfo = [IO.FileInfo]::new($stdoutPath)
    $stderrInfo = [IO.FileInfo]::new($stderrPath)
    $stdoutSha256 = Get-Gate6Sha256 $stdoutPath
    $stderrSha256 = Get-Gate6Sha256 $stderrPath
    $record = [ordered]@{
        schema = 'umbra-lumen/run-evidence/1'
        run_id = $RunId
        classification = $Classification
        argv = @($FilePath) + @($Arguments)
        cwd = $WorkingDirectory
        environment = $recordedEnvironment
        toolchain_ids = @($ToolchainIds)
        started_at_utc = $startedAt.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
        ended_at_utc = $endedAt.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
        monotonic_duration_ns = $durationNs
        exit_code = $exitCode
        stdout = [ordered]@{
            id = "sha256:$stdoutSha256"
            sha256 = $stdoutSha256
            bytes = $stdoutInfo.Length
            media_type = 'application/octet-stream'
            complete = $true
        }
        stderr = [ordered]@{
            id = "sha256:$stderrSha256"
            sha256 = $stderrSha256
            bytes = $stderrInfo.Length
            media_type = 'application/octet-stream'
            complete = $true
        }
        result = if ($exitCode -eq 0) { 'pass' } else { 'fail' }
    }
    Write-Gate6Json $recordPath $record
    return [pscustomobject]@{
        Record = [pscustomobject]$record
        RecordPath = $recordPath
        StdoutPath = $stdoutPath
        StderrPath = $stderrPath
    }
}

function Assert-Gate6MandatoryRunsPassed {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Runs
    )

    if ($Runs.Count -eq 0) {
        throw 'Gate6 artifact manifest requires mandatory run evidence.'
    }
    $ids = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($runWrapper in $Runs) {
        $run = if ($null -ne $runWrapper.PSObject.Properties['Record']) {
            $runWrapper.Record
        } else {
            $runWrapper
        }
        if ([string]$run.schema -cne 'umbra-lumen/run-evidence/1' -or
            -not $ids.Add([string]$run.run_id) -or
            [bool]$run.stdout.complete -ne $true -or
            [bool]$run.stderr.complete -ne $true) {
            throw 'Gate6 run evidence is invalid or duplicated.'
        }
        if ($null -ne $runWrapper.PSObject.Properties['StdoutPath'] -and
            $null -ne $runWrapper.PSObject.Properties['StderrPath']) {
            foreach ($stream in @(
                    @{ Name = 'stdout'; Path = [string]$runWrapper.StdoutPath },
                    @{ Name = 'stderr'; Path = [string]$runWrapper.StderrPath }
                )) {
                if (-not (Test-Path -LiteralPath $stream.Path -PathType Leaf)) {
                    throw "Gate6 run evidence stream is missing: $($run.run_id) $($stream.Name)"
                }
                $expected = $run.($stream.Name)
                $file = [IO.FileInfo]::new($stream.Path)
                if ($file.Length -ne [int64]$expected.bytes -or
                    (Get-Gate6Sha256 $stream.Path) -cne [string]$expected.sha256) {
                    throw "Gate6 run evidence stream identity mismatch: $($run.run_id) $($stream.Name)"
                }
            }
        }
        if ([string]$run.classification -ceq 'mandatory' -and
            ([int]$run.exit_code -ne 0 -or [string]$run.result -cne 'pass')) {
            throw "Mandatory Gate6 run failed: $($run.run_id)"
        }
    }
}

function Get-Gate6PolicyKind {
    param([object]$Policy, [string]$Path)

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
    throw "Gate6 evidence path has no inventory policy kind: $Path"
}

function Test-Gate6DriverBoundEvidencePath {
    param([object]$Policy, [string]$Path)

    foreach ($pattern in @($Policy.driverSubmissionBoundPatterns)) {
        if (Test-Gate6Regex $Path ([string]$pattern)) { return $true }
    }
    return $false
}

function New-Gate6ArtifactManifest {
    param(
        [Parameter(Mandatory = $true)]
        [string]$EvidenceRoot,

        [Parameter(Mandatory = $true)]
        [string]$ManifestPath,

        [Parameter(Mandatory = $true)]
        [object[]]$Runs,

        [string]$PolicyPath = (Join-Path $PSScriptRoot 'gate6-artifact-inventory.json')
    )

    Assert-Gate6MandatoryRunsPassed $Runs
    $EvidenceRoot = (Resolve-Path -LiteralPath $EvidenceRoot).Path
    $PolicyPath = (Resolve-Path -LiteralPath $PolicyPath).Path
    $policy = Read-Gate6Json $PolicyPath 'Gate6 inventory policy'
    Assert-Gate6InventoryPolicy $policy
    $sourceFreezePath = Resolve-Gate6EvidencePath `
        $EvidenceRoot 'source-freeze/full-profile-source-freeze.json'
    $filesManifestPath = Resolve-Gate6EvidencePath `
        $EvidenceRoot 'source-freeze/full-profile-files.json'
    $archivePath = Resolve-Gate6EvidencePath `
        $EvidenceRoot 'source-freeze/lumen-full-profile-source.tar.gz'
    $driverManifestPath = Resolve-Gate6EvidencePath `
        $EvidenceRoot 'full-profile-driver-manifest.json'
    $sourceFreezeSha256 = Get-Gate6Sha256 $sourceFreezePath
    $filesManifestSha256 = Get-Gate6Sha256 $filesManifestPath
    $archiveSha256 = Get-Gate6Sha256 $archivePath
    $driverManifestSha256 = Get-Gate6Sha256 $driverManifestPath

    $rows = @(
        Get-ChildItem -LiteralPath $EvidenceRoot -File -Recurse -Force | ForEach-Object {
            if (($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Gate6 evidence contains a reparse point: $($_.FullName)"
            }
            $path = Get-Gate6RelativeEvidencePath $EvidenceRoot $_.FullName
            [ordered]@{
                path = $path
                kind = Get-Gate6PolicyKind $policy $path
                bytes = $_.Length
                sha256 = Get-Gate6Sha256 $_.FullName
                sourceFreezeManifestSha256 = $sourceFreezeSha256
                driverSubmissionManifestSha256 = if (
                    Test-Gate6DriverBoundEvidencePath $policy $path
                ) { $driverManifestSha256 } else { '' }
            }
        } | Sort-Object path
    )
    $packageInventories = @(
        foreach ($expected in @($policy.packageInventories)) {
            $packageRows = @($rows | Where-Object {
                    [string]$_.kind -ceq [string]$expected.packageKind -and
                    ([string]$_.path).StartsWith('artifacts/', [StringComparison]::Ordinal)
                })
            if ($packageRows.Count -ne 1) {
                throw "Gate6 expected exactly one $($expected.packageKind) artifact."
            }
            $prefix = [string]$expected.root + '/'
            $inventoryRows = @($rows | Where-Object {
                    ([string]$_.path).StartsWith($prefix, [StringComparison]::Ordinal)
                })
            [ordered]@{
                name = [string]$expected.name
                packagePath = [string]$packageRows[0].path
                packageSha256 = [string]$packageRows[0].sha256
                inventoryRoot = [string]$expected.root
                fileCount = $inventoryRows.Count
                inventorySha256 = Get-Gate6InventoryRowsSha256 $rows ([string]$expected.root)
            }
        }
    )
    $manifest = [ordered]@{
        schema = [string]$policy.manifestSchema
        policySha256 = Get-Gate6Sha256 $PolicyPath
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
        packageInventories = $packageInventories
        files = $rows
    }
    Write-Gate6Json $ManifestPath $manifest
    return Assert-Gate6ArtifactManifest `
        -ManifestPath $ManifestPath `
        -EvidenceRoot $EvidenceRoot `
        -PolicyPath $PolicyPath
}
