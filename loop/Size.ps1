# Size and duration parsing and the human renderings of sizes, rates and
# durations. Every rendering here is part of the output contract shared
# with the Go harness and the other bindings' loop utilities, so the
# formats are fixed to the character, not to taste.
#
# PowerShell-specific. Every conversion and every format specifier names
# the invariant culture explicitly, because a formatter that relies on
# the thread's culture renders "1,5MB/s" the day someone runs it under a
# comma-decimal locale, and the output contract is byte-for-byte.

$script:Inv = [System.Globalization.CultureInfo]::InvariantCulture

# Suffix table for Convert-LoopSize, matched in order so the longer
# spellings win over their prefixes.
$script:SizeSuffixes = @(
    @('KIB', 1024L), @('KB', 1024L), @('K', 1024L),
    @('MIB', 1048576L), @('MB', 1048576L), @('M', 1048576L),
    @('GIB', 1073741824L), @('GB', 1073741824L), @('G', 1073741824L),
    @('B', 1L)
)

function Convert-LoopSize {
    <#
    .SYNOPSIS
    Parses a human byte-size string ("16MB", "1MiB", "512K",
    "1073741824") into a byte count.
    .DESCRIPTION
    Every suffix is a binary multiple: K/KB/KiB = 1024, M/MB/MiB =
    1024^2, G/GB/GiB = 1024^3, B or none = bytes; matching is
    case-insensitive and surrounding whitespace is trimmed. $null on a
    malformed or negative value.
    #>
    param([string]$Text)

    $upper = $Text.Trim().ToUpperInvariant()
    if ($upper.Length -eq 0) { return $null }

    $mult = 1L
    $digits = $upper
    foreach ($entry in $script:SizeSuffixes) {
        if ($upper.EndsWith($entry[0], [System.StringComparison]::Ordinal)) {
            $mult = [long]$entry[1]
            $digits = $upper.Substring(0, $upper.Length - $entry[0].Length)
            break
        }
    }

    $digits = $digits.TrimEnd()
    if ($digits.Length -eq 0) { return $null }
    foreach ($c in $digits.ToCharArray()) {
        if ($c -lt '0' -or $c -gt '9') { return $null }
    }

    $n = 0L
    if (-not [long]::TryParse($digits, [System.Globalization.NumberStyles]::None, $script:Inv, [ref]$n)) {
        return $null
    }
    # A product past the 64-bit range is a malformed size, not a number.
    # The bound is the exact integer quotient: the ordinary division
    # would produce a double that rounds up at the top of the range and
    # would let the product through.
    if ($mult -gt 1 -and $n -gt (Get-LoopQuotient ([long]::MaxValue) $mult)) { return $null }
    return $n * $mult
}

# Unit table for Convert-LoopDuration, matched in order so "ms" wins
# over "m" followed by a stray "s".
$script:DurationUnits = @(
    @('ns', 1.0), @('us', 1e3), @('ms', 1e6),
    @('s', 1e9), @('m', 6e10), @('h', 3.6e12)
)

function Convert-LoopDuration {
    <#
    .SYNOPSIS
    Parses the Go duration grammar into nanoseconds.
    .DESCRIPTION
    A sequence of decimal numbers each followed by a unit (h, m, s, ms,
    us, ns), such as "30s", "5m", "1h30m", "1.5s". $null on a malformed
    string.
    #>
    param([string]$Text)

    if ($Text.Length -eq 0) { return $null }
    $rest = $Text
    $total = 0.0
    while ($rest.Length -gt 0) {
        $numLen = 0
        while ($numLen -lt $rest.Length -and
               ([char]::IsAsciiDigit($rest[$numLen]) -or $rest[$numLen] -eq '.')) {
            $numLen++
        }
        if ($numLen -eq 0) { return $null }

        $v = 0.0
        if (-not [double]::TryParse($rest.Substring(0, $numLen),
                [System.Globalization.NumberStyles]::Float, $script:Inv, [ref]$v)) {
            return $null
        }

        $after = $rest.Substring($numLen)
        $nanos = $null
        foreach ($entry in $script:DurationUnits) {
            if ($after.StartsWith($entry[0], [System.StringComparison]::Ordinal)) {
                $tail = $after.Substring($entry[0].Length)
                # A unit whose next character is a letter is the prefix
                # of a longer token that is not a unit at all.
                if ($tail.Length -gt 0 -and [char]::IsAsciiLetter($tail[0])) { continue }
                $rest = $tail
                $nanos = [double]$entry[1]
                break
            }
        }
        if ($null -eq $nanos) { return $null }
        $total += $v * $nanos
    }

    if ($total -gt 9.2e18) { return $null }
    return [long]$total
}

function Get-LoopQuotient {
    # PowerShell-specific. Dividing two [long] values yields a [double],
    # and casting that back to [long] rounds rather than truncating, so
    # 4.925s renders as 5.925s. Every integer division here goes through
    # the exact .NET quotient instead.
    param([long]$Numerator, [long]$Divisor)
    $remainder = [long]0
    return [math]::DivRem($Numerator, $Divisor, [ref]$remainder)
}

function Format-LoopBytes {
    <#
    .SYNOPSIS
    Renders a byte count with a binary-unit suffix: "1.0GiB", "16.0MiB",
    "4.0KiB", "512B".
    #>
    param([long]$Bytes)

    if ($Bytes -ge 1073741824L) { return (([double]$Bytes / 1073741824.0).ToString('F1', $script:Inv) + 'GiB') }
    if ($Bytes -ge 1048576L) { return (([double]$Bytes / 1048576.0).ToString('F1', $script:Inv) + 'MiB') }
    if ($Bytes -ge 1024L) { return (([double]$Bytes / 1024.0).ToString('F1', $script:Inv) + 'KiB') }
    return ($Bytes.ToString($script:Inv) + 'B')
}

function Format-LoopBytesSigned {
    <#
    .SYNOPSIS
    Renders a possibly-negative byte delta with an explicit sign.
    #>
    param([long]$Bytes)
    if ($Bytes -lt 0) { return ('-' + (Format-LoopBytes (-$Bytes))) }
    return ('+' + (Format-LoopBytes $Bytes))
}

function Get-LoopMbPerSec {
    <#
    .SYNOPSIS
    Binary MiB per second over a nanosecond window; zero when the window
    is unmeasured.
    #>
    param([long]$Bytes, [long]$Nanos)
    if ($Nanos -le 0) { return 0.0 }
    return ([double]$Bytes / 1048576.0 / ([double]$Nanos / 1e9))
}

function Format-LoopRate {
    <#
    .SYNOPSIS
    Renders a throughput as "123.4MB/s" (binary MiB per second) or "n/a"
    for an unmeasured window.
    #>
    param([long]$Bytes, [long]$Nanos)
    if ($Nanos -le 0) { return 'n/a' }
    return ((Get-LoopMbPerSec $Bytes $Nanos).ToString('F1', $script:Inv) + 'MB/s')
}

function Get-LoopFraction {
    # The fractional part of a nanosecond remainder (0 .. 1e9) as ".ddd"
    # with trailing zeros removed; empty for zero.
    param([long]$FracNs)
    if ($FracNs -eq 0) { return '' }
    return ('.' + $FracNs.ToString('D9', $script:Inv).TrimEnd('0'))
}

function Format-LoopDuration {
    <#
    .SYNOPSIS
    Renders a duration the way Go's Duration prints.
    .DESCRIPTION
    Zero as "0s"; below one second as milliseconds ("900ms", "1.5ms");
    otherwise "[Hh][Mm]Ss" where the hour part appears when non-zero, the
    minute part when the hour part appears or the minutes are non-zero,
    and the seconds carry their fraction with trailing zeros removed
    ("5s", "5.003s", "1m0s", "1m5.25s", "1h0m0s"). The caller rounds
    first.
    #>
    param([long]$Nanos)

    $ns = [math]::Abs($Nanos)
    if ($ns -eq 0) { return '0s' }

    if ($ns -lt 1000000000L) {
        $ms = Get-LoopQuotient $ns 1000000L
        $msFrac = ($ns % 1000000L) * 1000L   # scaled to 9 digits
        return ($ms.ToString($script:Inv) + (Get-LoopFraction $msFrac) + 'ms')
    }

    $hours = Get-LoopQuotient $ns 3600000000000L
    $rem = $ns % 3600000000000L
    $minutes = Get-LoopQuotient $rem 60000000000L
    $rem = $rem % 60000000000L
    $seconds = Get-LoopQuotient $rem 1000000000L
    $frac = $rem % 1000000000L

    $sb = [System.Text.StringBuilder]::new()
    if ($hours -gt 0) { [void]$sb.Append($hours.ToString($script:Inv)).Append('h') }
    if ($hours -gt 0 -or $minutes -gt 0) { [void]$sb.Append($minutes.ToString($script:Inv)).Append('m') }
    [void]$sb.Append($seconds.ToString($script:Inv)).Append((Get-LoopFraction $frac)).Append('s')
    return $sb.ToString()
}

function Get-LoopRounded {
    <#
    .SYNOPSIS
    Rounds a nanosecond count to the nearest multiple of UnitNs.
    #>
    param([long]$Nanos, [long]$UnitNs)
    return ((Get-LoopQuotient ($Nanos + (Get-LoopQuotient $UnitNs 2)) $UnitNs) * $UnitNs)
}

function Format-LoopFloat {
    # Fixed-decimal rendering under the invariant culture.
    param([double]$Value, [int]$Decimals)
    return $Value.ToString('F' + $Decimals.ToString($script:Inv), $script:Inv)
}

function Format-LoopInt {
    # Decimal rendering under the invariant culture.
    param([long]$Value)
    return $Value.ToString($script:Inv)
}
