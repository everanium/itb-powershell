# Shared test scaffolding, dot-sourced from each *.Tests.ps1
# BeforeAll block: imports the module and provides a deterministic
# payload generator.

Import-Module (Join-Path $PSScriptRoot '../../Everanium.LibItb3/Everanium.LibItb3.psd1') -Force

function New-TestPayload {
    # Deterministic non-trivial payload (seeded System.Random fill —
    # .NET-side so MiB-scale fills stay fast under PowerShell).
    param(
        [Parameter(Mandatory)][int]$Size,
        [Parameter(Mandatory)][int]$Seed
    )
    $buf = [byte[]]::new($Size)
    [System.Random]::new($Seed).NextBytes($buf)
    Write-Output -NoEnumerate $buf
}

function Test-BytesEqual {
    param(
        [Parameter(Mandatory)][byte[]]$Left,
        [Parameter(Mandatory)][byte[]]$Right
    )
    [System.Linq.Enumerable]::SequenceEqual($Left, $Right)
}
