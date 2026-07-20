[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ManifestPath,

    [Parameter(Mandatory = $true)]
    [string]$TestTarget,

    [Parameter(Mandatory = $true)]
    [string]$TestName,

    [string[]]$Features = @(),

    [ValidateRange(1, 600)]
    [int]$TimeoutSeconds = 120,

    [switch]$NoCapture
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Read-SharedUtf8([string]$Path) {
    if (-not [System.IO.File]::Exists($Path)) {
        return ""
    }

    try {
        $sharing = [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete
        $stream = [System.IO.File]::Open(
            $Path,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            $sharing
        )
        try {
            $reader = [System.IO.StreamReader]::new(
                $stream,
                [System.Text.Encoding]::UTF8,
                $true
            )
            try {
                return $reader.ReadToEnd()
            } finally {
                $reader.Dispose()
            }
        } finally {
            $stream.Dispose()
        }
    } catch [System.IO.IOException] {
        return ""
    }
}

function Publish-NewOutput(
    [string]$Path,
    [ref]$Cursor,
    [bool]$IsError
) {
    $content = Read-SharedUtf8 $Path
    if ($content.Length -lt $Cursor.Value) {
        $Cursor.Value = 0
    }
    if ($content.Length -eq $Cursor.Value) {
        return
    }

    $delta = $content.Substring($Cursor.Value)
    $Cursor.Value = $content.Length
    if ($IsError) {
        [Console]::Error.Write($delta)
    } else {
        [Console]::Out.Write($delta)
    }
}

$cargo = (Get-Command cargo -CommandType Application -ErrorAction Stop).Source
$arguments = [System.Collections.Generic.List[string]]::new()
foreach ($argument in @("test", "--locked", "--manifest-path", $ManifestPath)) {
    $arguments.Add($argument)
}
if ($Features.Count -gt 0) {
    $arguments.Add("--features")
    $arguments.Add(($Features -join ","))
}
foreach ($argument in @("--test", $TestTarget, $TestName, "--", "--exact")) {
    $arguments.Add($argument)
}
if ($NoCapture) {
    $arguments.Add("--nocapture")
}
$arguments.Add("--test-threads=1")

$tempRoot = if ($env:RUNNER_TEMP) {
    $env:RUNNER_TEMP
} else {
    [System.IO.Path]::GetTempPath()
}
$runId = [Guid]::NewGuid().ToString("N")
$stdoutPath = Join-Path $tempRoot "slipstream-cargo-$runId.stdout.log"
$stderrPath = Join-Path $tempRoot "slipstream-cargo-$runId.stderr.log"
$stdoutCursor = 0
$stderrCursor = 0
$process = $null

try {
    # Start-Process -Wait follows descendants. Poll the retained root handle so
    # an inherited output handle cannot keep this qualification open forever.
    $startOptions = @{
        FilePath = $cargo
        ArgumentList = $arguments.ToArray()
        NoNewWindow = $true
        PassThru = $true
        RedirectStandardOutput = $stdoutPath
        RedirectStandardError = $stderrPath
    }
    $process = Start-Process @startOptions
    Write-Output "[bounded-cargo] pid=$($process.Id) timeout_seconds=$TimeoutSeconds test=$TestName"

    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    while (-not $process.WaitForExit(250)) {
        Publish-NewOutput $stdoutPath ([ref]$stdoutCursor) $false
        Publish-NewOutput $stderrPath ([ref]$stderrCursor) $true
        if ($timer.Elapsed.TotalSeconds -ge $TimeoutSeconds) {
            if ($process.WaitForExit(0)) {
                break
            }
            Publish-NewOutput $stdoutPath ([ref]$stdoutCursor) $false
            Publish-NewOutput $stderrPath ([ref]$stderrCursor) $true
            $rootPid = $process.Id
            try {
                $process.Kill($true)
            } catch {
                throw "Exact cargo process $rootPid timed out and its retained-tree termination failed: $($_.Exception.Message)"
            }
            if (-not $process.WaitForExit(10000)) {
                throw "Exact cargo process $rootPid remained alive after retained-tree termination"
            }
            throw "Exact cargo process $rootPid exceeded the $TimeoutSeconds-second qualification deadline"
        }
    }
    $timer.Stop()
    $process.WaitForExit()
    Publish-NewOutput $stdoutPath ([ref]$stdoutCursor) $false
    Publish-NewOutput $stderrPath ([ref]$stderrCursor) $true

    if ($process.ExitCode -ne 0) {
        throw "Exact cargo process $($process.Id) exited with code $($process.ExitCode)"
    }

    $combined = "$(Read-SharedUtf8 $stdoutPath)`n$(Read-SharedUtf8 $stderrPath)"
    $lines = @($combined -split "`r?`n")
    if ($lines -notcontains "test $TestName ... ok") {
        throw "Expected exact cargo test did not execute: $TestName"
    }
} finally {
    if ($null -ne $process) {
        if (-not $process.HasExited) {
            try {
                $process.Kill($true)
                [void]$process.WaitForExit(10000)
            } catch {
                Write-Warning "Final exact-process cleanup failed: $($_.Exception.Message)"
            }
        }
        $process.Dispose()
    }
    Remove-Item -LiteralPath $stdoutPath, $stderrPath -Force -ErrorAction SilentlyContinue
}
