#!/usr/bin/env pwsh
# eitb — command-line demonstrator for the ITB PowerShell binding.
#
# Subcommands:
#
#   eitb.ps1 version                                   library + binding versions
#   eitb.ps1 profiles                                  registered profile catalogue
#   eitb.ps1 encrypt <profile> <in-file> <out-file>    Single Message encrypt
#   eitb.ps1 decrypt <profile> <blob-hex> <in-file> <out-file>
#
# `encrypt` prints the session blob to stderr as hex; feed that hex
# back to `decrypt` on the receiving side. `profiles` lists the
# registered profile catalogue one name per line; the profiles that
# carry a cipher surface are the ones `encrypt` / `decrypt` accept.

[CmdletBinding()]
param(
    [Parameter(Position = 0)][string]$Command,
    [Parameter(Position = 1, ValueFromRemainingArguments)][string[]]$Rest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '../Everanium.LibItb3/Everanium.LibItb3.psd1') -Force

[void](Set-ItbMemoryLimit -Bytes (4GB))
[void](Set-ItbGCPercent -Percent 100)

function Show-Usage {
    [Console]::Error.WriteLine(@'
usage: eitb.ps1 version
       eitb.ps1 profiles
       eitb.ps1 encrypt <profile> <in-file> <out-file>
       eitb.ps1 decrypt <profile> <blob-hex> <in-file> <out-file>
'@)
    exit 2
}

function Invoke-CmdVersion {
    $v = Get-ItbVersion
    Write-Output "libitb3 $($v.Library)"
    Write-Output "itb-csharp $($v.CSharpBinding)"
    Write-Output "itb-powershell $($v.Module)"
}

# Prints the registered profile catalogue one name per line in the
# sorted order Get-ItbProfileName returns.
function Invoke-CmdProfiles {
    foreach ($name in Get-ItbProfileName) {
        Write-Output $name
    }
}

# Profiles whose canonical name begins with "streaming-" route
# through the one-shot streaming buffered pair instead of the Single
# Message pair.
function Test-StreamingProfile {
    param([string]$Profile)
    return $Profile.StartsWith('streaming-', [System.StringComparison]::Ordinal)
}

# Recursively create the parent directory of $Path (mkdir -p).
function Assert-ParentDir {
    param([string]$Path)
    $parent = Split-Path -Parent $Path
    if ($parent) {
        [void](New-Item -ItemType Directory -Force -Path $parent)
    }
}

function Invoke-CmdEncrypt {
    param([string]$Profile, [string]$InFile, [string]$OutFile)
    $plain = [System.IO.File]::ReadAllBytes($InFile)
    $pipe = New-ItbPipeline -Profile $Profile
    try {
        $wire = if (Test-StreamingProfile $Profile) {
            Invoke-ItbEncryptStream -Pipeline $pipe -Data $plain
        } else {
            Invoke-ItbEncrypt -Pipeline $pipe -Data $plain
        }
        Assert-ParentDir $OutFile
        [System.IO.File]::WriteAllBytes($OutFile, $wire)
        [Console]::Error.WriteLine(
            [System.Convert]::ToHexStringLower((Save-ItbPipeline $pipe)))
        Write-Output ('encrypted {0} -> {1} ({2} -> {3} bytes)' -f `
                $InFile, $OutFile, $plain.Length, $wire.Length)
    }
    finally { $pipe.Dispose() }
}

function Invoke-CmdDecrypt {
    param([string]$Profile, [string]$BlobHex, [string]$InFile, [string]$OutFile)
    $blob = [System.Convert]::FromHexString($BlobHex)
    $wire = [System.IO.File]::ReadAllBytes($InFile)
    $pipe = Import-ItbPipeline -Blob $blob
    try {
        $plain = if (Test-StreamingProfile $Profile) {
            Invoke-ItbDecryptStream -Pipeline $pipe -Data $wire
        } else {
            Invoke-ItbDecrypt -Pipeline $pipe -Data $wire
        }
        Assert-ParentDir $OutFile
        [System.IO.File]::WriteAllBytes($OutFile, $plain)
        Write-Output ('decrypted {0} -> {1} ({2} -> {3} bytes)' -f `
                $InFile, $OutFile, $wire.Length, $plain.Length)
    }
    finally { $pipe.Dispose() }
}

try {
    $restCount = if ($null -ne $Rest) { $Rest.Count } else { 0 }
    switch ($Command) {
        'version' { Invoke-CmdVersion }
        'profiles' { Invoke-CmdProfiles }
        'encrypt' {
            if ($restCount -ne 3) { Show-Usage }
            Invoke-CmdEncrypt -Profile $Rest[0] -InFile $Rest[1] -OutFile $Rest[2]
        }
        'decrypt' {
            if ($restCount -ne 4) { Show-Usage }
            Invoke-CmdDecrypt -Profile $Rest[0] -BlobHex $Rest[1] `
                -InFile $Rest[2] -OutFile $Rest[3]
        }
        default { Show-Usage }
    }
    exit 0
}
catch {
    [Console]::Error.WriteLine("eitb: $($_.Exception.Message)")
    exit 1
}
