<#
.SYNOPSIS
Record exactly which image is about to be executed.

.DESCRIPTION
Emits the identity of one file as JSON: content hash, version resource,
Authenticode status, managed assembly version, PE machine type, and whether
symbols sit next to it. This is what makes a verify-windows report auditable —
a reader can re-download the release, hash it, and get the same value.

.EXAMPLE
pwsh -NoProfile -File scripts/Get-BinaryIdentity.ps1 -Path .verify/install/Contoso.Cli.exe
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Path,
    [string]$JsonPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$onWindows = if ($PSVersionTable.PSVersion.Major -lt 6) { $true } else { $IsWindows }
$file = Get-Item -LiteralPath $Path

# PE machine type, read straight from the header: e_lfanew at 0x3C, then the
# COFF machine word two bytes past the PE signature. Catches the x86/x64/arm64
# mismatch that otherwise shows up as an unhelpful "not a valid application".
function Get-PeMachine([string]$Image) {
    try {
        $stream = [IO.File]::OpenRead($Image)
        try {
            if ($stream.Length -lt 0x40) { return 'not-pe' }
            $reader = New-Object IO.BinaryReader($stream)
            $stream.Position = 0x3C
            $peOffset = $reader.ReadInt32()
            if ($peOffset -lt 0 -or ($peOffset + 6) -gt $stream.Length) { return 'not-pe' }
            $stream.Position = $peOffset
            if ($reader.ReadUInt32() -ne 0x00004550) { return 'not-pe' }
            switch ($reader.ReadUInt16()) {
                0x014C  { 'x86' }
                0x8664  { 'x64' }
                0xAA64  { 'arm64' }
                0x01C4  { 'arm' }
                default { 'unknown' }
            }
        } finally { $stream.Dispose() }
    } catch { 'unreadable' }
}

$authenticode = 'unchecked'
$signer = ''
if ($onWindows -and (Get-Command Get-AuthenticodeSignature -ErrorAction SilentlyContinue)) {
    $sig = Get-AuthenticodeSignature -LiteralPath $file.FullName
    $authenticode = switch ($sig.Status) {
        'Valid'     { 'valid' }
        'NotSigned' { 'unsigned' }
        default     { 'invalid' }
    }
    if ($sig.SignerCertificate) { $signer = $sig.SignerCertificate.Subject }
}

$assemblyVersion = ''
try {
    $assemblyVersion = [System.Reflection.AssemblyName]::GetAssemblyName($file.FullName).Version.ToString()
} catch {
    # Native image, or a managed image this runtime will not load: not an error.
}

$versionInfo = $file.VersionInfo
$pdb = [IO.Path]::ChangeExtension($file.FullName, '.pdb')

# A file with no version resource yields null properties; record an empty
# string so the report never carries a bare null where a value is expected.
function Get-VersionField([string]$Name) {
    if (-not $versionInfo) { return '' }
    $value = $versionInfo.$Name
    if ($null -eq $value) { return '' }
    return [string]$value
}

$record = [ordered]@{
    path             = $file.FullName
    sha256           = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    size_bytes       = $file.Length
    modified_utc     = $file.LastWriteTimeUtc.ToString('o')
    file_version     = Get-VersionField 'FileVersion'
    product_version  = Get-VersionField 'ProductVersion'
    company          = Get-VersionField 'CompanyName'
    original_name    = Get-VersionField 'OriginalFilename'
    assembly_version = $assemblyVersion
    machine          = Get-PeMachine $file.FullName
    authenticode     = $authenticode
    signer           = $signer
    symbols          = if (Test-Path -LiteralPath $pdb) { 'shipped' } else { 'absent' }
}

$json = $record | ConvertTo-Json -Depth 3
if ($JsonPath) {
    $parent = Split-Path -Parent $JsonPath
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    Set-Content -LiteralPath $JsonPath -Value $json -Encoding utf8
}
Write-Output $json
