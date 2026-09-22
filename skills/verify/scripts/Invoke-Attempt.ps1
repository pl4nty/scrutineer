<#
.SYNOPSIS
Run one isolated reproduction attempt against the shipped artifact.

.DESCRIPTION
Launches the execution target in a fresh process with its own TEMP, TMP,
USERPROFILE and working directory, bounds it with a wall-clock timeout, kills
the whole process tree if it overruns, and records what happened: exit code in
decimal and as a Windows exception code, stdout, stderr, elapsed time, peak
working set, and any crash dump that appeared.

Windows has no ulimit -v reachable from PowerShell without P/Invoke, so memory
is measured rather than capped. The timeout is the bound.

Writes <Root>/attempt-<N>/attempt.json and prints it. Exit code is 0 when the
attempt ran (whatever the target did) and 2 when the attempt could not start —
that distinction is the difference between `not_reproduced` and `not_attempted`
in the report.

.EXAMPLE
pwsh -NoProfile -File scripts/Invoke-Attempt.ps1 -Number 1 `
  -Executable .verify/install/Contoso.Cli.exe `
  -Arguments @('convert', '.verify/poc/input.dxf') -TimeoutSeconds 180
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][int]$Number,
    [Parameter(Mandatory)][string]$Executable,
    [string[]]$Arguments = @(),
    [string]$Root = '.verify',
    [int]$TimeoutSeconds = 180,
    [string]$WorkingDirectory,
    [string]$StdinFile,
    [hashtable]$Environment = @{}
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$onWindows = if ($PSVersionTable.PSVersion.Major -lt 6) { $true } else { $IsWindows }

$attemptDir = Join-Path $Root "attempt-$Number"
$homeDir    = Join-Path $attemptDir 'home'
$tempDir    = Join-Path $attemptDir 'tmp'
foreach ($d in @($attemptDir, $homeDir, $tempDir)) {
    New-Item -ItemType Directory -Path $d -Force | Out-Null
}
$attemptDir = (Resolve-Path -LiteralPath $attemptDir).Path
$homeDir    = (Resolve-Path -LiteralPath $homeDir).Path
$tempDir    = (Resolve-Path -LiteralPath $tempDir).Path
$stdoutPath = Join-Path $attemptDir 'stdout.log'
$stderrPath = Join-Path $attemptDir 'stderr.log'

# This script is its own process, so mutating the environment here isolates the
# child without leaking into the caller or into the next attempt.
$env:TEMP = $tempDir
$env:TMP = $tempDir
$env:TMPDIR = $tempDir
$env:USERPROFILE = $homeDir
$env:HOME = $homeDir
$env:HOMEPATH = $homeDir
foreach ($key in $Environment.Keys) {
    Set-Item -Path "env:$key" -Value ([string]$Environment[$key])
}

if (-not $WorkingDirectory) { $WorkingDirectory = (Get-Location).Path }
$dumpsBefore = @(Get-ChildItem -LiteralPath $attemptDir -Filter '*.dmp' -Recurse -ErrorAction SilentlyContinue |
    ForEach-Object { $_.FullName })

$startArgs = @{
    FilePath               = $Executable
    WorkingDirectory       = $WorkingDirectory
    RedirectStandardOutput = $stdoutPath
    RedirectStandardError  = $stderrPath
    PassThru               = $true
}
if ($Arguments.Count -gt 0) { $startArgs['ArgumentList'] = $Arguments }
if ($StdinFile) { $startArgs['RedirectStandardInput'] = (Resolve-Path -LiteralPath $StdinFile).Path }
if ($onWindows) { $startArgs['NoNewWindow'] = $true }

$record = [ordered]@{
    number            = $Number
    started_utc       = (Get-Date).ToUniversalTime().ToString('o')
    executable        = $Executable
    arguments         = $Arguments
    working_directory = $WorkingDirectory
    temp              = $tempDir
    home              = $homeDir
    started           = $false
    timed_out         = $false
    exit_code         = $null
    exit_code_hex     = ''
    exception_name    = ''
    elapsed_seconds   = 0
    peak_working_set  = $null
    stdout_path       = $stdoutPath
    stderr_path       = $stderrPath
    stdout_tail       = ''
    stderr_tail       = ''
    new_dumps         = @()
    start_error       = ''
}

# Windows surfaces unhandled exceptions as the process exit code. Name the ones
# that decide a failure class so the report does not have to guess.
# Keyed by the formatted hex string: PowerShell parses a hex literal with the
# high bit set as a negative Int32, so numeric keys would never match.
$exceptionNames = @{
    '0xC0000005' = 'STATUS_ACCESS_VIOLATION'
    '0xC0000374' = 'STATUS_HEAP_CORRUPTION'
    '0xC0000409' = 'STATUS_STACK_BUFFER_OVERRUN'
    '0xC00000FD' = 'STATUS_STACK_OVERFLOW'
    '0xC0000094' = 'STATUS_INTEGER_DIVIDE_BY_ZERO'
    '0xC000001D' = 'STATUS_ILLEGAL_INSTRUCTION'
    '0x80000003' = 'STATUS_BREAKPOINT'
    '0xE0434352' = 'CLR_UNHANDLED_EXCEPTION'
    '0xE06D7363' = 'CPP_EH_EXCEPTION'
}

$stopwatch = [Diagnostics.Stopwatch]::StartNew()
$process = $null
try {
    $process = Start-Process @startArgs
    $record['started'] = $true
} catch {
    $record['start_error'] = $_.Exception.Message
}

if ($process) {
    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
        $record['timed_out'] = $true
        if ($onWindows) {
            & taskkill.exe /T /F /PID $process.Id 2>&1 | Out-Null
        } else {
            $process.Kill($true)
        }
        $process.WaitForExit(30000) | Out-Null
    }
    $stopwatch.Stop()
    $record['elapsed_seconds'] = [Math]::Round($stopwatch.Elapsed.TotalSeconds, 3)
    try {
        $code = $process.ExitCode
        $record['exit_code'] = $code
        $unsigned = [BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$code), 0)
        $hex = '0x{0:X8}' -f $unsigned
        $record['exit_code_hex'] = $hex
        if ($exceptionNames.ContainsKey($hex)) {
            $record['exception_name'] = $exceptionNames[$hex]
        }
    } catch {
        $record['start_error'] = "exit code unavailable: $($_.Exception.Message)"
    }
    try { $record['peak_working_set'] = $process.PeakWorkingSet64 } catch { }
} else {
    $stopwatch.Stop()
    $record['elapsed_seconds'] = [Math]::Round($stopwatch.Elapsed.TotalSeconds, 3)
}

function Get-Tail([string]$Path, [int]$Max = 4000) {
    if (-not (Test-Path -LiteralPath $Path)) { return '' }
    $text = Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue
    if (-not $text) { return '' }
    if ($text.Length -le $Max) { return $text }
    return $text.Substring($text.Length - $Max)
}
$record['stdout_tail'] = Get-Tail $stdoutPath
$record['stderr_tail'] = Get-Tail $stderrPath

$dumpsAfter = @(Get-ChildItem -LiteralPath $attemptDir -Filter '*.dmp' -Recurse -ErrorAction SilentlyContinue |
    ForEach-Object { $_.FullName })
$record['new_dumps'] = @($dumpsAfter | Where-Object { $dumpsBefore -notcontains $_ })

$json = $record | ConvertTo-Json -Depth 5
Set-Content -LiteralPath (Join-Path $attemptDir 'attempt.json') -Value $json -Encoding utf8
Write-Output $json

if (-not $record['started']) { exit 2 }
exit 0
