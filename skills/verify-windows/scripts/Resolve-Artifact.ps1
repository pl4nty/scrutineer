<#
.SYNOPSIS
Download one published artifact, prove its identity, and record where it came from.

.DESCRIPTION
Downloads a single file from a publisher endpoint, hashes it, compares that hash
against the publisher's own checksum when one is available, and captures the
Authenticode signature. Writes a JSON record shaped like the `artifact.source`
block of the verify-windows report.

Exits 1 when the publisher's checksum does not match. That is a supply-chain
signal, not a failed reproduction: the caller must stop, not carry on.

.EXAMPLE
pwsh -NoProfile -File scripts/Resolve-Artifact.ps1 `
  -Uri https://github.com/contoso/cli/releases/download/v4.2.1/contoso-cli-4.2.1-win-x64.zip `
  -OutFile .verify/download/contoso-cli-4.2.1-win-x64.zip `
  -ChecksumUri https://github.com/contoso/cli/releases/download/v4.2.1/SHA256SUMS `
  -ReleaseTag v4.2.1
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Uri,
    [Parameter(Mandatory)][string]$OutFile,
    [string]$ExpectedSha256,
    [string]$ChecksumUri,
    [string]$ReleaseTag,
    [string]$ReleaseUrl,
    [string]$JsonPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# $IsWindows only exists in PowerShell 6+; referencing it under Set-StrictMode
# on Windows PowerShell 5.1 is an error, so short-circuit on the version first.
$onWindows = if ($PSVersionTable.PSVersion.Major -lt 6) { $true } else { $IsWindows }

function New-ParentDirectory([string]$Path) {
    $parent = Split-Path -Parent $Path
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
}

New-ParentDirectory $OutFile
Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing -MaximumRedirection 5
$file = Get-Item -LiteralPath $OutFile
$sha256 = (Get-FileHash -LiteralPath $OutFile -Algorithm SHA256).Hash.ToLowerInvariant()

# Publisher checksum: an explicit value wins, otherwise look the asset up in a
# checksum manifest (`<hash>  <name>` lines, as sha256sum and most release
# pipelines emit).
$checksumState = 'absent'
$publisherHash = ''
if ($ExpectedSha256) {
    $publisherHash = $ExpectedSha256.Trim().ToLowerInvariant()
} elseif ($ChecksumUri) {
    $manifest = (Invoke-WebRequest -Uri $ChecksumUri -UseBasicParsing -MaximumRedirection 5).Content
    if ($manifest -is [byte[]]) { $manifest = [Text.Encoding]::UTF8.GetString($manifest) }
    foreach ($line in ($manifest -split "`r?`n")) {
        $fields = $line.Trim() -split '\s+', 2
        if ($fields.Count -eq 2 -and $fields[1].TrimStart('*') -eq $file.Name) {
            $publisherHash = $fields[0].ToLowerInvariant()
            break
        }
    }
}
if ($publisherHash) {
    $checksumState = if ($publisherHash -eq $sha256) { 'matched' } else { 'mismatched' }
}

# Authenticode is Windows-only; on any other host record that it was not checked
# rather than implying the artifact is unsigned.
$authenticode = 'unchecked'
$signer = ''
if ($onWindows -and (Get-Command Get-AuthenticodeSignature -ErrorAction SilentlyContinue)) {
    $sig = Get-AuthenticodeSignature -LiteralPath $OutFile
    $authenticode = switch ($sig.Status) {
        'Valid'     { 'valid' }
        'NotSigned' { 'unsigned' }
        default     { 'invalid' }
    }
    if ($sig.SignerCertificate) { $signer = $sig.SignerCertificate.Subject }
}

$record = [ordered]@{
    release_tag        = $ReleaseTag
    release_url        = $ReleaseUrl
    asset_name         = $file.Name
    download_url       = $Uri
    local_path         = $file.FullName
    size_bytes         = $file.Length
    sha256             = $sha256
    publisher_checksum = $checksumState
    publisher_sha256   = $publisherHash
    authenticode       = $authenticode
    signer             = $signer
    signature_message  = if ($authenticode -eq 'invalid') { $sig.StatusMessage } else { '' }
    retrieved_utc      = (Get-Date).ToUniversalTime().ToString('o')
}

if (-not $JsonPath) { $JsonPath = "$OutFile.artifact.json" }
New-ParentDirectory $JsonPath
$json = $record | ConvertTo-Json -Depth 4
Set-Content -LiteralPath $JsonPath -Value $json -Encoding utf8
Write-Output $json

if ($checksumState -eq 'mismatched') {
    Write-Error "publisher checksum mismatch: manifest $publisherHash, downloaded $sha256"
    exit 1
}
