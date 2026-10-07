# Plaintext content: the payload modes, the seeded per-worker generator,
# and the buffer fill from the operating-system CSPRNG.

# Payload mode selector values for the --payload-mode flag.
#
#   - fixed: one CSPRNG-generated buffer per worker, held unchanged for
#     the whole run (the default).
#   - rotating: the buffer is regenerated before every iteration, so no
#     two encrypt calls see the same plaintext.
#   - pattern-zero / pattern-ff: degenerate constant fills (all 0x00 /
#     all 0xFF) probing minimum-entropy plaintext handling.
#   - pattern-ascii: a repeating 'A'..'Z' ramp probing low-entropy
#     structured text.
$script:PayloadModes = @('fixed', 'rotating', 'pattern-zero', 'pattern-ff', 'pattern-ascii')

function Test-LoopPayloadMode {
    <#
    .SYNOPSIS
    Whether Name is one of the five payload modes.
    #>
    param([string]$Name)
    return $script:PayloadModes -contains $Name
}

function Get-LoopSeedForWorker {
    <#
    .SYNOPSIS
    The seeded generator's starting state for one worker.
    .DESCRIPTION
    Seeded plaintext. The seed makes plaintext content reproducible so a
    failing iteration can be replayed with the same bytes; it governs
    nothing else — pipeline keys, nonces and masters stay CSPRNG-drawn,
    so a seeded run is a reproduction aid and never a security test. Each
    worker's stream is domain-separated by its id so seeded workers still
    hold pairwise-distinct buffers under the fixed and rotating modes.
    The generator is splitmix64: a few lines in any language, which is
    why it is the one every binding uses.
    #>
    param([uint64]$Seed, [int]$WorkerId)
    return (Add-LoopWrapped $Seed (Add-LoopWrapped ([uint64]$WorkerId) 1ul))
}

function Add-LoopWrapped {
    # PowerShell-specific. An unsigned sum that passes 2^64 is promoted
    # to [double] here rather than wrapping, which silently destroys the
    # generator, so the carry is folded by hand and every intermediate
    # stays inside the 64-bit range.
    param([uint64]$A, [uint64]$B)
    if ($B -eq 0ul) { return $A }
    $room = [uint64]::MaxValue - $B
    if ($A -gt $room) { return ($A - $room - 1ul) }
    return ($A + $B)
}

function Get-LoopWrappedProduct {
    # PowerShell-specific, for the same reason as Add-LoopWrapped: the
    # product is assembled from 32-bit limbs so that no intermediate
    # leaves [uint64] and gets promoted to [double].
    param([uint64]$A, [uint64]$B)
    $mask = 0xFFFFFFFFul
    $al = $A -band $mask
    $ah = $A -shr 32
    $bl = $B -band $mask
    $bh = $B -shr 32
    $ll = $al * $bl
    $mid = ((($al * $bh) -band $mask) + (($ah * $bl) -band $mask)) -band $mask
    $hi = (($ll -shr 32) + $mid) -band $mask
    return (($ll -band $mask) -bor ($hi -shl 32))
}

function Get-LoopSplitmix64 {
    # One splitmix64 step over the state held in the caller's reference.
    param([ref]$State)
    $s = Add-LoopWrapped ([uint64]$State.Value) 0x9E3779B97F4A7C15ul
    $State.Value = $s
    $z = Get-LoopWrappedProduct ($s -bxor ($s -shr 30)) 0xBF58476D1CE4E5B9ul
    $z = Get-LoopWrappedProduct ($z -bxor ($z -shr 27)) 0x94D049BB133111EBul
    return ($z -bxor ($z -shr 31))
}

# The glibc entry is bound through a compiled shim rather than called
# from script: see New-LoopNativeShim in the main unit for why the
# managed generator is not used here.
function Invoke-LoopFillRandom {
    <#
    .SYNOPSIS
    Fills Buffer from the operating-system CSPRNG; $false on failure.
    #>
    param([byte[]]$Buffer)
    return [LoopNative]::FillRandom($Buffer)
}

function Invoke-LoopFillPayload {
    <#
    .SYNOPSIS
    Writes one plaintext buffer according to the payload mode.
    .DESCRIPTION
    The fixed and rotating modes draw from the seeded generator when the
    run is seeded and from the OS CSPRNG otherwise; the pattern modes are
    deterministic regardless of the seed. $false when the CSPRNG fails.
    #>
    param(
        [string]$Mode,
        [bool]$Seeded,
        [ref]$Rng,
        [byte[]]$Buffer
    )

    switch ($Mode) {
        { $_ -eq 'fixed' -or $_ -eq 'rotating' } {
            if (-not $Seeded) { return (Invoke-LoopFillRandom $Buffer) }
            $i = 0
            while ($i -lt $Buffer.Length) {
                $v = Get-LoopSplitmix64 $Rng
                $n = [math]::Min(8, $Buffer.Length - $i)
                for ($k = 0; $k -lt $n; $k++) {
                    $Buffer[$i + $k] = [byte](($v -shr (8 * $k)) -band 0xFFul)
                }
                $i += 8
            }
            return $true
        }
        'pattern-zero' {
            [array]::Clear($Buffer, 0, $Buffer.Length)
            return $true
        }
        'pattern-ff' {
            [array]::Fill[byte]($Buffer, [byte]0xFF)
            return $true
        }
        default {
            for ($i = 0; $i -lt $Buffer.Length; $i++) {
                $Buffer[$i] = [byte](65 + ($i % 26))
            }
            return $true
        }
    }
}
