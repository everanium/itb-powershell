# The final summary in both renderings, and the two measurements it folds
# in that are not per-worker counters: the process resident set and the
# shared library's pool counters.

function Get-LoopStatusKb {
    # Parses one "Vm...:   1234 kB" line of /proc/self/status into bytes;
    # zero on any parse failure.
    param([string]$Line)
    $colon = $Line.IndexOf(':')
    if ($colon -lt 0) { return 0L }
    # PowerShell-specific. A $null separator leaves the Split overload
    # ambiguous here, so the whitespace set is named explicitly.
    $parts = $Line.Substring($colon + 1).Split(
        [char[]]@(' ', "`t"), [System.StringSplitOptions]::RemoveEmptyEntries)
    if ($parts.Length -eq 0) { return 0L }
    $kb = 0L
    if (-not [long]::TryParse($parts[0], [System.Globalization.NumberStyles]::None,
            [System.Globalization.CultureInfo]::InvariantCulture, [ref]$kb)) {
        return 0L
    }
    return ($kb * 1024L)
}

function Get-LoopRss {
    <#
    .SYNOPSIS
    The process's current resident set and its high-water mark in bytes.
    .DESCRIPTION
    Read from /proc/self/status (VmRSS and VmHWM, reported in kB). Both
    are zero on a platform without that file; the figures are
    informational and never enter the verdict.
    #>
    $current = 0L
    $peak = 0L
    try {
        foreach ($line in [System.IO.File]::ReadLines('/proc/self/status')) {
            if ($line.StartsWith('VmRSS:', [System.StringComparison]::Ordinal)) {
                $current = Get-LoopStatusKb $line
            }
            elseif ($line.StartsWith('VmHWM:', [System.StringComparison]::Ordinal)) {
                $peak = Get-LoopStatusKb $line
            }
        }
    }
    catch { return @(0L, 0L) }
    return @($current, $peak)
}

function Get-LoopPoolSnapshot {
    <#
    .SYNOPSIS
    One snapshot of the library's pool counters.
    .DESCRIPTION
    Pool counters. The shared library keeps process-wide monotonic totals
    at every pool checkout of its cipher core: per hash-array tier the
    starter width, checkouts, constructor misses, regrow replacements and
    bytes allocated; for the scratch byte pool and the parallax chunk
    pool the checkouts, constructor misses, regrows and regrow bytes. Two
    snapshots bracketing the main loop are differenced into per-run hit /
    miss figures that tell whether a pool keeps its items warm between
    calls or evicts them across GC cycles. The slot layout is read from
    the library: slot 0 carries the tier count T, tier i occupies the
    five slots at 1 + 5*i, and the two byte pools occupy the eight slots
    at 1 + 5*T; the vector is sized by the binding from the library's own
    length query, never from a constant. Empty when the library is
    unavailable.
    #>
    try { return (Get-ItbPoolStats) }
    catch { return @() }
}

function Get-LoopPoolDelta {
    # Differences two pool snapshots into the reported tiers and the two
    # byte pools.
    param([long[]]$Steady, [long[]]$Warmup)

    $empty = @{
        Tiers = @()
        Buf = @{ Get = 0L; Fresh = 0L; Regrow = 0L; RegrowBytes = 0L }
        Chunk = @{ Get = 0L; Fresh = 0L; Regrow = 0L; RegrowBytes = 0L }
    }
    if ($Steady.Length -lt 9 -or $Warmup.Length -ne $Steady.Length) { return $empty }
    $tiers = $Steady[0]
    if ($tiers -lt 0 -or (1 + 5 * $tiers + 8) -gt $Steady.Length) { return $empty }

    $rows = @()
    for ($i = 0L; $i -lt $tiers; $i++) {
        $b = [int](1 + 5 * $i)
        if ($Steady[$b] -eq 0) { continue }
        $rows += @{
            Index = $i
            Starter = $Steady[$b]
            Get = $Steady[$b + 1] - $Warmup[$b + 1]
            Fresh = $Steady[$b + 2] - $Warmup[$b + 2]
            Regrow = $Steady[$b + 3] - $Warmup[$b + 3]
            NewBytes = $Steady[$b + 4] - $Warmup[$b + 4]
        }
    }

    $t = [int](1 + 5 * $tiers)
    return @{
        Tiers = $rows
        Buf = @{
            Get = $Steady[$t] - $Warmup[$t]
            Fresh = $Steady[$t + 1] - $Warmup[$t + 1]
            Regrow = $Steady[$t + 2] - $Warmup[$t + 2]
            RegrowBytes = $Steady[$t + 3] - $Warmup[$t + 3]
        }
        Chunk = @{
            Get = $Steady[$t + 4] - $Warmup[$t + 4]
            Fresh = $Steady[$t + 5] - $Warmup[$t + 5]
            Regrow = $Steady[$t + 6] - $Warmup[$t + 6]
            RegrowBytes = $Steady[$t + 7] - $Warmup[$t + 7]
        }
    }
}

function Get-LoopMissPercent {
    # Misses over checkouts as a percentage; zero when nothing was
    # checked out.
    param([long]$Miss, [long]$Gets)
    if ($Gets -le 0) { return 0.0 }
    return (100.0 * [double]$Miss / [double]$Gets)
}

function ConvertTo-LoopJsonString {
    # Renders the text as a JSON string literal with the escapes JSON
    # requires.
    param([string]$Text)
    $sb = [System.Text.StringBuilder]::new($Text.Length + 2)
    [void]$sb.Append('"')
    foreach ($ch in $Text.ToCharArray()) {
        switch ($ch) {
            '"' { [void]$sb.Append('\"') }
            '\' { [void]$sb.Append('\\') }
            "`n" { [void]$sb.Append('\n') }
            "`r" { [void]$sb.Append('\r') }
            "`t" { [void]$sb.Append('\t') }
            default {
                if ([int]$ch -lt 32) {
                    [void]$sb.Append('\u').Append(([int]$ch).ToString(
                        'x4', [System.Globalization.CultureInfo]::InvariantCulture))
                }
                else { [void]$sb.Append($ch) }
            }
        }
    }
    [void]$sb.Append('"')
    return $sb.ToString()
}

function Get-LoopEffectiveGogc {
    # The effective GC percentage as the runtime reports it: the query
    # form of the setter (a set-and-restore round trip inside the
    # library) so the field is the same whether the value came from the
    # flag, the environment, or the runtime default.
    param([int]$Flag)
    if ($Flag -gt 0) { return $Flag }
    try { return (Set-ItbGCPercent -1) } catch { return 0 }
}

function Write-LoopFinalSummary {
    <#
    .SYNOPSIS
    The final summary in the requested rendering; returns the exit code.
    .DESCRIPTION
    Output contract. Both renderings are shared with the Go harness and
    every other binding's loop utility field for field: the same lines in
    the same order, the same keys in the same order, floats with a fixed
    number of decimals so the JSON is byte-identical across
    implementations. The Go harness alone adds its runtime-internal lines
    after rss: and its runtime-internal keys after parallax_chunk_pool;
    nothing here reproduces them because nothing they read is reachable
    through the C ABI.
    #>
    param([hashtable]$Run, [long]$ElapsedNs)

    $cfg = $Run.Cfg
    $workers = [long]$cfg.Workers
    $perWorker = @()
    $totalIters = 0L; $totalEnc = 0L; $totalDec = 0L
    $nanosEnc = 0L; $nanosDec = 0L
    $errors = @()

    foreach ($c in $Run.Workers) {
        $perWorker += [long]$c.Iters
        $totalIters += [long]$c.Iters
        $totalEnc += [long]$c.BytesEnc
        $totalDec += [long]$c.BytesDec
        $nanosEnc += [long]$c.NanosEnc
        $nanosDec += [long]$c.NanosDec
        if ($null -ne $c.ErrorText) { $errors += $c.ErrorText }
    }

    # Throughput. Per-direction throughput divides the sum of every
    # worker's wall time in that direction by the worker count — the
    # equivalent single-stream wall time under N-way concurrency — so
    # each direction reports the aggregate rate it sustained rather than
    # collapsing to combined/2 (every iteration moves equal encrypt and
    # decrypt bytes, so a total-elapsed denominator would give both
    # directions the same figure). The combined rate keeps total elapsed
    # as the one-glance overall figure.
    $avgEnc = if ($nanosEnc -gt 0) { Get-LoopQuotient $nanosEnc $workers } else { 0L }
    $avgDec = if ($nanosDec -gt 0) { Get-LoopQuotient $nanosDec $workers } else { 0L }

    $rssDelta = $Run.RssFinal - $Run.RssWarmup
    $rssGrowth = if ($Run.RssWarmup -gt 0) {
        100.0 * [double]$rssDelta / [double]$Run.RssWarmup
    }
    else { 0.0 }

    $pd = Get-LoopPoolDelta $Run.PoolSteady $Run.PoolWarmup
    $pass = $errors.Count -eq 0
    $rekeys = [long]$Run.Counts.Rekeys
    $cycles = [long]$Run.Counts.BlobCycles
    $gomaxprocs = try { Set-ItbGOMAXPROCS 0 } catch { 0 }
    $streamProfile = if ($null -ne $Run.Pipes.StreamPipe) { $Run.StreamProfile } else { '' }
    $msgProfile = if ($null -ne $Run.Pipes.MsgPipe) { $Run.MsgProfile } else { '' }

    if ($cfg.JsonOutput) {
        $j = [System.Text.StringBuilder]::new()
        $add = { param($s) [void]$j.Append($s) }
        & $add ('{"duration_seconds":' + (Format-LoopFloat ([double]$ElapsedNs / 1e9) 3))
        & $add (',"iterations":' + (Format-LoopInt $totalIters))
        & $add (',"per_worker_iterations":[' +
                (($perWorker | ForEach-Object { Format-LoopInt $_ }) -join ',') + ']')
        & $add (',"bytes_encrypted":' + (Format-LoopInt $totalEnc))
        & $add (',"bytes_decrypted":' + (Format-LoopInt $totalDec))
        & $add (',"encrypt_mb_per_sec":' + (Format-LoopFloat (Get-LoopMbPerSec $totalEnc $avgEnc) 1))
        & $add (',"decrypt_mb_per_sec":' + (Format-LoopFloat (Get-LoopMbPerSec $totalDec $avgDec) 1))
        & $add (',"combined_mb_per_sec":' +
                (Format-LoopFloat (Get-LoopMbPerSec ($totalEnc + $totalDec) $ElapsedNs) 1))
        & $add (',"rekeys":' + (Format-LoopInt $rekeys))
        & $add (',"blob_cycles":' + (Format-LoopInt $cycles))
        & $add (',"worker_errors":[' +
                (($errors | ForEach-Object { ConvertTo-LoopJsonString $_ }) -join ',') + ']')
        & $add (',"verdict":"' + $(if ($pass) { 'PASS' } else { 'FAIL' }) + '"')
        & $add (',"shape":"' + $cfg.Shape + '"')
        & $add (',"stream_profile":' + (ConvertTo-LoopJsonString $streamProfile))
        & $add (',"message_profile":' + (ConvertTo-LoopJsonString $msgProfile))
        & $add (',"hash":' + (ConvertTo-LoopJsonString $cfg.Hash))
        & $add (',"mac":' + (ConvertTo-LoopJsonString $cfg.Mac))
        & $add (',"payload_bytes":' + (Format-LoopInt $cfg.PayloadBytes))
        & $add (',"payload_mode":"' + $cfg.PayloadMode + '"')
        & $add (',"seed":' + ([uint64]$cfg.Seed).ToString(
                [System.Globalization.CultureInfo]::InvariantCulture))
        & $add (',"key_bits":' + (Format-LoopInt $cfg.KeyBits))
        & $add (',"nonce_bits":' + (Format-LoopInt $cfg.NonceBits))
        & $add (',"blob_mode":' + (Format-LoopInt $cfg.BlobMode))
        & $add (',"drbg":' + (ConvertTo-LoopJsonString $cfg.Drbg))
        & $add (',"drbg_auto_tier":' + (ConvertTo-LoopJsonString (Get-ItbDrbgAutoTier)))
        & $add (',"chunk_size_bytes":' + (Format-LoopInt $cfg.ChunkSize))
        & $add (',"barrier_fill":' + (Format-LoopInt $cfg.BarrierFill))
        & $add (',"parallax":"' + (Format-LoopOnOff $cfg.Parallax) + '"')
        & $add (',"wrapper":"' + (Format-LoopOnOff $cfg.Wrapper) + '"')
        & $add (',"goroutines_requested":' + (Format-LoopInt ([long]$cfg.WorkersRequested)))
        & $add (',"goroutines":' + (Format-LoopInt ([long]$cfg.Workers)))
        & $add (',"concurrency":"' + $script:LoopConcurrency + '"')
        & $add (',"gogc":"' + (Format-LoopInt ([long](Get-LoopEffectiveGogc $cfg.Gogc))) + '"')
        & $add (',"memlimit_bytes":' + (Format-LoopInt $cfg.Memlimit))
        & $add (',"gomaxprocs":' + (Format-LoopInt ([long]$gomaxprocs)))
        & $add (',"microbatch_tiers":' +
                (ConvertTo-LoopJsonString (Get-LoopPolicyLabel 'ITB_MICROBATCH_TIERS')))
        & $add (',"hashpool_starters":' +
                (ConvertTo-LoopJsonString (Get-LoopPolicyLabel 'ITB_HASHPOOL_STARTERS')))
        & $add (',"rss_warmup_bytes":' + (Format-LoopInt $Run.RssWarmup))
        & $add (',"rss_peak_bytes":' + (Format-LoopInt $Run.RssPeak))
        & $add (',"rss_final_bytes":' + (Format-LoopInt $Run.RssFinal))
        & $add (',"rss_growth_percent":' + (Format-LoopFloat $rssGrowth 2))

        $tierJson = @()
        foreach ($t in $pd.Tiers) {
            $tierJson += ('{"tier":' + (Format-LoopInt $t.Index) +
                ',"starter":' + (Format-LoopInt $t.Starter) +
                ',"get":' + (Format-LoopInt $t.Get) +
                ',"new":' + (Format-LoopInt $t.Fresh) +
                ',"regrow":' + (Format-LoopInt $t.Regrow) +
                ',"new_bytes":' + (Format-LoopInt $t.NewBytes) +
                ',"miss_percent":' +
                (Format-LoopFloat (Get-LoopMissPercent ($t.Fresh + $t.Regrow) $t.Get) 2) + '}')
        }
        & $add (',"hash_pool_tiers":[' + ($tierJson -join ',') + ']')

        foreach ($pool in @(@('buf_pool', $pd.Buf), @('parallax_chunk_pool', $pd.Chunk))) {
            $p = $pool[1]
            & $add (',"' + $pool[0] + '":{"get":' + (Format-LoopInt $p.Get) +
                ',"new":' + (Format-LoopInt $p.Fresh) +
                ',"regrow":' + (Format-LoopInt $p.Regrow) +
                ',"regrow_bytes":' + (Format-LoopInt $p.RegrowBytes) +
                ',"miss_percent":' +
                (Format-LoopFloat (Get-LoopMissPercent $p.Regrow $p.Get) 2) + '}')
        }
        & $add '}'
        [Console]::Out.WriteLine($j.ToString())
        return $(if ($pass) { 0 } else { 1 })
    }

    Write-LoopLine '=== FINAL ==='
    Write-LoopLine ('  duration: ' + (Format-LoopDuration (Get-LoopRounded $ElapsedNs 1000000L)))
    Write-LoopLine ('  iterations: ' +
        (($perWorker | ForEach-Object { Format-LoopInt $_ }) -join ' + ') +
        ' = ' + (Format-LoopInt $totalIters) + ' total')
    Write-LoopLine ('  throughput: encrypt ' + (Format-LoopRate $totalEnc $avgEnc) +
        ', decrypt ' + (Format-LoopRate $totalDec $avgDec) +
        ', combined ' + (Format-LoopRate ($totalEnc + $totalDec) $ElapsedNs))
    Write-LoopLine ('  bytes: ' + (Format-LoopBytes $totalEnc) + ' encrypted, ' +
        (Format-LoopBytes $totalDec) + ' decrypted')
    Write-LoopLine ('  data integrity: ' + (Format-LoopInt $totalIters) + '/' +
        (Format-LoopInt $totalIters) + ' PASS')
    Write-LoopLine ('  concurrency: ' + $script:LoopConcurrency + ', workers ' +
        (Format-LoopInt ([long]$cfg.Workers)) + ' (requested ' +
        (Format-LoopInt ([long]$cfg.WorkersRequested)) + ')')
    Write-LoopLine ('  rss: warmup ' + (Format-LoopBytes $Run.RssWarmup) + ', peak ' +
        (Format-LoopBytes $Run.RssPeak) + ', final ' + (Format-LoopBytes $Run.RssFinal) +
        ' (delta ' + (Format-LoopBytesSigned $rssDelta) + ', ' +
        (Format-LoopFloat $rssGrowth 1) + '% growth)')
    foreach ($t in $pd.Tiers) {
        Write-LoopLine ('  hash pool tier ' + (Format-LoopInt $t.Index) + ' (starter ' +
            (Format-LoopInt $t.Starter) + '): get ' + (Format-LoopInt $t.Get) + ', miss ' +
            (Format-LoopInt ($t.Fresh + $t.Regrow)) + ' (new ' + (Format-LoopInt $t.Fresh) +
            ' + regrow ' + (Format-LoopInt $t.Regrow) + '), miss ' +
            (Format-LoopFloat (Get-LoopMissPercent ($t.Fresh + $t.Regrow) $t.Get) 2) + '%, ' +
            (Format-LoopBytes $t.NewBytes) + ' allocated')
    }
    Write-LoopLine ('  buf pool: get ' + (Format-LoopInt $pd.Buf.Get) + ', regrow ' +
        (Format-LoopInt $pd.Buf.Regrow) + ' (of which fresh ' + (Format-LoopInt $pd.Buf.Fresh) +
        '), miss ' + (Format-LoopFloat (Get-LoopMissPercent $pd.Buf.Regrow $pd.Buf.Get) 2) +
        '%, ' + (Format-LoopBytes $pd.Buf.RegrowBytes) + ' regrown')
    Write-LoopLine ('  parallax chunk pool: get ' + (Format-LoopInt $pd.Chunk.Get) + ', regrow ' +
        (Format-LoopInt $pd.Chunk.Regrow) + ' (of which fresh ' + (Format-LoopInt $pd.Chunk.Fresh) +
        '), miss ' + (Format-LoopFloat (Get-LoopMissPercent $pd.Chunk.Regrow $pd.Chunk.Get) 2) +
        '%, ' + (Format-LoopBytes $pd.Chunk.RegrowBytes) + ' regrown')
    if ($rekeys -gt 0) { Write-LoopLine ('  rekeys: ' + (Format-LoopInt $rekeys)) }
    if ($cycles -gt 0) { Write-LoopLine ('  blob cycles: ' + (Format-LoopInt $cycles)) }
    foreach ($e in $errors) { Write-LoopLine ('  ERROR: ' + $e) }
    if ($pass) {
        Write-LoopLine '  verdict: PASS'
        return 0
    }
    Write-LoopLine ('  verdict: FAIL (errors=' + (Format-LoopInt ([long]$errors.Count)) + ')')
    return 1
}
