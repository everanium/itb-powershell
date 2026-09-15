# Shared timing + reporting helpers for the PowerShell binding
# micro-benchmarks, dot-sourced by BenchMessage.ps1 / BenchStream.ps1.
# Wall-clock via Stopwatch; output is a fixed-width table:
#
#   bench             size     mb_per_sec
#   message           1 MiB    <n>
#   ...
#
# Bench configuration is driven by environment variables so a
# side-by-side comparison with the root Go bench harness and the C#
# peer is straightforward:
#
#   ITB_NONCE_BITS     nonce width (default 512)
#   ITB_KEY_BITS       key bits (default 1024)
#   ITB_WITH_PARALLAX  parallax layer on/off (default false)
#   ITB_WITH_WRAPPER   wrapper layer on/off (default false)
#   ITB_INNER_HASH     opaque hash name (default: profile's)
#   ITB_PROFILE        profile name override
#   ITB_BENCH_MIN_SEC  per-case wall-clock budget (default 5.0)

Set-StrictMode -Version Latest

Import-Module (Join-Path $PSScriptRoot '../Everanium.LibItb3/Everanium.LibItb3.psd1') -Force

# Bench-scale allocation churn leaks Go scratch heap unboundedly
# without a soft memory cap + aggressive GC; the return values report
# the previous settings, not an error.
[void](Set-ItbMemoryLimit -Bytes (4GB))
[void](Set-ItbGCPercent -Percent 100)

# Payload sizes exercised by both shapes.
$script:BenchSizes = @(1MB, 16MB, 64MB)

# Iteration floor per case.
$script:BenchMinIters = 3

function Get-BenchMinSeconds {
    $raw = $env:ITB_BENCH_MIN_SEC
    $value = 0.0
    if ($raw -and [double]::TryParse(
            $raw, [System.Globalization.NumberStyles]::Float,
            [System.Globalization.CultureInfo]::InvariantCulture, [ref]$value) -and
        $value -gt 0.0) {
        return $value
    }
    return 5.0
}

function Get-BenchOpts {
    # Reads the bench-shape env vars into an opts hashtable. Defaults
    # match the root Go BENCH3.md pin so numbers are directly
    # comparable.
    $opts = [ordered]@{
        nonceBits    = if ($env:ITB_NONCE_BITS) { [long]$env:ITB_NONCE_BITS } else { 512 }
        keyBits      = if ($env:ITB_KEY_BITS) { [long]$env:ITB_KEY_BITS } else { 1024 }
        withParallax = $env:ITB_WITH_PARALLAX -in 'true', '1'
        withWrapper  = $env:ITB_WITH_WRAPPER -in 'true', '1'
    }
    if ($env:ITB_INNER_HASH) {
        $opts.innerHash = $env:ITB_INNER_HASH
    }
    if ($env:ITB_MAC_NAME) {
        $opts.macName = $env:ITB_MAC_NAME
    }
    New-ItbOpts -Options $opts
}

function Get-BenchProfileName {
    param([Parameter(Mandatory)][string]$Fallback)
    if ($env:ITB_PROFILE) { $env:ITB_PROFILE } else { $Fallback }
}

function Write-BenchHeader {
    Write-Host ('{0,-17} {1,-8} {2}' -f 'bench', 'size', 'mb_per_sec')
}

function Get-BenchSizeLabel {
    param([Parameter(Mandatory)][int]$Size)
    if ($Size -ge 1MB) { '{0} MiB' -f ($Size -shr 20) } else { '{0} KiB' -f ($Size -shr 10) }
}

function Invoke-BenchCase {
    # Runs $Body until the wall-clock budget is spent (with an
    # iteration floor + one untimed warm-up), then prints one table
    # row.
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][int]$Size,
        [Parameter(Mandatory)][scriptblock]$Body
    )
    & $Body   # warm-up
    $budget = Get-BenchMinSeconds
    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    $iters = 0
    while ($clock.Elapsed.TotalSeconds -lt $budget -or $iters -lt $script:BenchMinIters) {
        & $Body
        $iters++
    }
    $elapsed = $clock.Elapsed.TotalSeconds
    $mb = [double]$Size * $iters / 1MB
    Write-Host ('{0,-17} {1,-8} {2}' -f $Name, (Get-BenchSizeLabel $Size),
        ($mb / $elapsed).ToString('F1', [System.Globalization.CultureInfo]::InvariantCulture))
}

function New-BenchPayload {
    # CSPRNG-fill so plaintext content matches the root Go bench
    # (crypto/rand). Not in the timing loop.
    param([Parameter(Mandatory)][int]$Size)
    $buf = [byte[]]::new($Size)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($buf)
    Write-Output -NoEnumerate $buf
}
