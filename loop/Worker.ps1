# The worker: its runspace body (one warmup iteration, the warmup
# barrier, the main loop), one iteration, the session pump loop the
# stream shape drives, and the round-trip comparison that decides
# between a worker error and a data mismatch.

# Cipher surfaces the --shape flag selects.
$script:LoopShapes = @('stream', 'message', 'stream_one_shot', 'both')

# Largest slice fed to a stream session per write; the drain after every
# write uses the same bound.
$script:LoopPumpSlice = 1048576

function Test-LoopShape {
    param([string]$Name)
    return $script:LoopShapes -contains $Name
}

function Get-LoopErrorDetail {
    <#
    .SYNOPSIS
    Renders a binding error the way every implementation reports a failed
    library call: "status <code>: <last error>". The library assembles the
    whole sentence — the class of failure and the case that raised it —
    so this reports what arrived and composes nothing.
    #>
    param([object]$ErrorObject)

    $ex = $ErrorObject
    if ($ex -is [System.Management.Automation.ErrorRecord]) { $ex = $ex.Exception }
    if ($null -eq $ex) { return 'unknown failure' }
    if ($ex -isnot [Everanium.Itb3.ItbException]) { return $ex.Message }

    $code = [int]$ex.Status
    # The C# layer under this binding folds the diagnostic into the
    # exception message behind a fixed prefix; strip that prefix to
    # recover the library's own text.
    $message = $ex.Message
    if ($message.StartsWith('itb: status=', [System.StringComparison]::Ordinal)) {
        $i = $message.IndexOf('): ', [System.StringComparison]::Ordinal)
        if ($i -ge 0) { $message = $message.Substring($i + 3) }
    }
    return ('status ' + (Format-LoopInt $code) + ': ' + $message)
}

function Set-LoopWorkerError {
    <#
    .SYNOPSIS
    Records the worker's error text (first error wins) and requests a
    stop of the whole run.
    #>
    param([hashtable]$Run, [int]$Id, [string]$Text)

    $c = $Run.Workers[$Id]
    [System.Threading.Monitor]::Enter($c.ErrorLock)
    try {
        if ($null -eq $c.ErrorText) { $c.ErrorText = $Text }
    }
    finally { [System.Threading.Monitor]::Exit($c.ErrorLock) }
    $Run.Flags.Stop = $true
}

function Invoke-LoopPump {
    <#
    .SYNOPSIS
    Drives one stream session over the whole buffer.
    .DESCRIPTION
    Pump loop. The Go harness hands ITB an io.Reader / io.Writer pair and
    ITB drives the chunk loop internally; the C ABI has no reader /
    writer entry, so the caller drives it: open a session, feed slices of
    at most 1 MiB, drain whatever the session has produced after every
    write (a read before end never blocks), end, then drain until the
    session reports finished (after end, a read on an empty spool blocks
    until the terminal bytes arrive). The whole produced output lands in
    the worker's reusable accumulator. The loop is written here rather
    than delegated to the module's pump cmdlet so it stands in the
    utility, at the same place, in every language. Returns $null on
    success, or a two-element array of the failing call and its error.
    #>
    param(
        [object]$Pipeline,
        [bool]$Encrypt,
        [byte[]]$Source,
        [int]$SourceLength,
        [System.IO.MemoryStream]$Accumulator,
        [byte[]]$Scratch
    )

    $Accumulator.SetLength(0)
    $session = $null
    try {
        try {
            $session = if ($Encrypt) {
                New-ItbEncryptStream -Pipeline $Pipeline
            }
            else {
                New-ItbDecryptStream -Pipeline $Pipeline
            }
        }
        catch { return @('StreamBegin', $_) }

        $off = 0
        while ($off -lt $SourceLength) {
            $n = [math]::Min($script:LoopPumpSlice, $SourceLength - $off)
            # PowerShell-specific. The session's write takes a whole
            # array, so each bounded feed is a fresh slice; there is no
            # offset / count entry to write through in place.
            $slice = [byte[]]::new($n)
            [array]::Copy($Source, $off, $slice, 0, $n)
            try { $session.Write($slice) }
            catch { return @('StreamWrite', $_) }

            while ($true) {
                $finished = $false
                try { $m = $session.Read($Scratch, [ref]$finished) }
                catch { return @('StreamRead', $_) }
                if ($m -eq 0) { break }
                $Accumulator.Write($Scratch, 0, $m)
            }
            $off += $n
        }

        try { $session.End() }
        catch { return @('StreamEnd', $_) }

        while ($true) {
            $finished = $false
            try { $m = $session.Read($Scratch, [ref]$finished) }
            catch { return @('StreamRead', $_) }
            $Accumulator.Write($Scratch, 0, $m)
            if ($finished) { break }
        }
        return $null
    }
    finally {
        if ($null -ne $session) { $session.Dispose() }
    }
}

function Get-LoopFirstDifference {
    # First offset at which the two buffers differ; the shorter length
    # when one is a prefix of the other.
    param([byte[]]$A, [int]$ALength, [byte[]]$B, [int]$BLength)
    $n = [math]::Min($ALength, $BLength)
    $i = 0
    while ($i -lt $n -and $A[$i] -eq $B[$i]) { $i++ }
    return $i
}

function Get-LoopHexWindow {
    # Up to 16 bytes of the buffer from the offset as lowercase hex, or
    # "-" when the buffer has no bytes there.
    param([byte[]]$Buffer, [int]$Length, [int]$Offset)
    if ($Offset -ge $Length) { return '-' }
    return [System.Convert]::ToHexStringLower($Buffer, $Offset, [math]::Min(16, $Length - $Offset))
}

function Set-LoopCipherError {
    # Records a worker error for a failed cipher call.
    param(
        [hashtable]$Run, [int]$Id, [long]$Iteration, [string]$Shape,
        [string]$Direction, [string]$Call, [object]$ErrorObject
    )
    $head = 'g' + $Id + ' iter ' + (Format-LoopInt $Iteration) + ' shape=' + $Shape + ': ' + $Direction
    $detail = Get-LoopErrorDetail $ErrorObject
    if ([string]::IsNullOrEmpty($Call)) {
        Set-LoopWorkerError $Run $Id ($head + ': ' + $detail)
    }
    else {
        Set-LoopWorkerError $Run $Id ($head + ': ' + $Call + ': ' + $detail)
    }
}

function Invoke-LoopIterationLocked {
    # The body of one iteration that runs under the read lock: pick the
    # surface, encrypt, decrypt, compare, bump the counters.
    param([hashtable]$Run, [hashtable]$Worker, [long]$Iteration)

    $c = $Run.Workers[$Worker.Id]
    $Run.PipesLock.EnterReadLock()
    try {
        # Shape dispatch. message is one whole-buffer call on the Single
        # Message Pipeline; stream_one_shot is one whole-buffer call on
        # the streaming Pipeline (the C ABI's ITB_Triple_EncryptStream,
        # which routes to the same one-shot stream entry the Go
        # harness calls by name); stream opens a session on the same
        # streaming Pipeline and drives the chunk loop from here. Under
        # both the three rotate by iteration number so the session path
        # and the whole-buffer path alternate on one handle inside every
        # worker — the cross-path state-reuse hazard this harness exists
        # to catch.
        $shape = $Run.Cfg.Shape
        if ($shape -eq 'both') {
            switch ($Iteration % 3) {
                0 { $shape = 'stream' }
                1 { $shape = 'message' }
                default { $shape = 'stream_one_shot' }
            }
        }

        # PowerShell-specific. The message and one-shot cmdlets return a
        # fresh array per call that the collector reclaims at the end of
        # the iteration; the pump accumulators are the worker's own and
        # are reused. $got / $gotLen hold the round-trip output for
        # either posture, so one comparison below serves both.
        $got = $null
        $gotLen = 0

        if ($shape -eq 'stream') {
            $pipe = $Run.Pipes.StreamPipe
            $t0 = [System.Diagnostics.Stopwatch]::GetTimestamp()
            $failure = Invoke-LoopPump $pipe $true $Worker.Plaintext $Worker.Plaintext.Length `
                $Worker.Wire $Worker.Scratch
            if ($null -ne $failure) {
                Set-LoopCipherError $Run $Worker.Id $Iteration $shape 'encrypt' $failure[0] $failure[1]
                return $false
            }
            $c.NanosEnc += (Get-LoopElapsedNs $t0)

            $t0 = [System.Diagnostics.Stopwatch]::GetTimestamp()
            $failure = Invoke-LoopPump $pipe $false $Worker.Wire.GetBuffer() ([int]$Worker.Wire.Length) `
                $Worker.Plain $Worker.Scratch
            if ($null -ne $failure) {
                Set-LoopCipherError $Run $Worker.Id $Iteration $shape 'decrypt' $failure[0] $failure[1]
                return $false
            }
            $c.NanosDec += (Get-LoopElapsedNs $t0)
            $got = $Worker.Plain.GetBuffer()
            $gotLen = [int]$Worker.Plain.Length
        }
        else {
            $pipe = if ($shape -eq 'message') { $Run.Pipes.MsgPipe } else { $Run.Pipes.StreamPipe }
            $t0 = [System.Diagnostics.Stopwatch]::GetTimestamp()
            try {
                $wire = if ($shape -eq 'message') {
                    Invoke-ItbEncrypt -Pipeline $pipe -Data $Worker.Plaintext
                }
                else {
                    Invoke-ItbEncryptStream -Pipeline $pipe -Data $Worker.Plaintext
                }
            }
            catch {
                Set-LoopCipherError $Run $Worker.Id $Iteration $shape 'encrypt' $null $_
                return $false
            }
            $c.NanosEnc += (Get-LoopElapsedNs $t0)

            $t0 = [System.Diagnostics.Stopwatch]::GetTimestamp()
            try {
                $got = if ($shape -eq 'message') {
                    Invoke-ItbDecrypt -Pipeline $pipe -Data $wire
                }
                else {
                    Invoke-ItbDecryptStream -Pipeline $pipe -Data $wire
                }
            }
            catch {
                Set-LoopCipherError $Run $Worker.Id $Iteration $shape 'decrypt' $null $_
                return $false
            }
            $c.NanosDec += (Get-LoopElapsedNs $t0)
            $gotLen = $got.Length
        }

        # Failure model. A cipher call that returns a non-OK status is a
        # worker error: it is recorded, the run is asked to stop, the
        # other workers finish their in-flight iteration, and the error
        # is listed in the summary with the FAIL verdict. A round-trip
        # that returns OK with different bytes is a data mismatch: the
        # process terminates here, without summary or cleanup, because
        # the Pipeline state that produced the wrong bytes is the
        # evidence and nothing that runs afterwards may touch it.
        # PowerShell-specific: [Environment]::Exit is the exit that
        # leaves handle finalizers unrun, which is the point — a
        # finalizer-driven free would release the very state the operator
        # is meant to inspect.
        $want = $Worker.Plaintext
        $off = Get-LoopFirstDifference $want $want.Length $got $gotLen
        if ($gotLen -ne $want.Length -or $off -ne $want.Length) {
            [Console]::Error.WriteLine(
                'loop: DATA MISMATCH g' + $Worker.Id + ' iter ' + (Format-LoopInt $Iteration) +
                ' shape=' + $shape + ': want ' + (Format-LoopInt $want.Length) +
                ' bytes, got ' + (Format-LoopInt $gotLen) +
                ' bytes, first difference at offset ' + (Format-LoopInt $off) +
                ': want ' + (Get-LoopHexWindow $want $want.Length $off) +
                ' got ' + (Get-LoopHexWindow $got $gotLen $off))
            [Console]::Error.Flush()
            [Console]::Out.Flush()
            [Environment]::Exit(3)
        }

        $c.Iters += 1L
        $c.BytesEnc += [long]$want.Length
        $c.BytesDec += [long]$gotLen
        return $true
    }
    finally { $Run.PipesLock.ExitReadLock() }
}

function Invoke-LoopIteration {
    <#
    .SYNOPSIS
    One iteration.
    .DESCRIPTION
    In order: refill the plaintext under rotating mode; take the read
    lock; pick the surface; encrypt (timed); decrypt (timed); compare the
    round-trip with the plaintext; bump the counters; release the lock.
    The whole round-trip runs under the read lock so handle-mutating
    maintenance (rekey, blob reopen) never lands between an encrypt and
    its matching decrypt — maintenance runs after this returns, from the
    worker loop. $false after recording a worker error.
    #>
    param([hashtable]$Run, [hashtable]$Worker, [long]$Iteration)

    if ($Worker.PayloadMode -eq 'rotating') {
        $rng = [uint64]$Worker.Rng
        $ok = Invoke-LoopFillPayload 'rotating' $Worker.Seeded ([ref]$rng) $Worker.Plaintext
        $Worker.Rng = $rng
        if (-not $ok) {
            Set-LoopWorkerError $Run $Worker.Id `
                ('g' + $Worker.Id + ' iter ' + (Format-LoopInt $Iteration) + ': payload refill: csprng')
            return $false
        }
    }
    return (Invoke-LoopIterationLocked $Run $Worker $Iteration)
}

function Set-LoopWorkerDone {
    # Marks this worker returned; the last one to return stamps the
    # finish instant and wakes main.
    param([hashtable]$Run)
    [System.Threading.Monitor]::Enter($Run.DoneLock)
    try {
        $Run.Done.Active -= 1
        if ($Run.Done.Active -eq 0) {
            $Run.Done.Finish = [System.Diagnostics.Stopwatch]::GetTimestamp()
            [System.Threading.Monitor]::Pulse($Run.DoneLock)
        }
    }
    finally { [System.Threading.Monitor]::Exit($Run.DoneLock) }
}

function Invoke-LoopWorker {
    <#
    .SYNOPSIS
    The worker body: one warmup iteration, the warmup barrier, then the
    main loop until a stop is requested or the fixed per-worker iteration
    budget (warmup included) is spent.
    .DESCRIPTION
    A failing warmup still passes both barriers so the launcher never
    waits on a worker that has already given up.
    #>
    param([hashtable]$Run, [hashtable]$Worker)

    # PowerShell-specific. A terminating error raised here does not end
    # the process: the runspace captures it and the invocation simply
    # stops, which would leave the launcher waiting on a barrier no
    # longer anyone signals. The handler below turns such an error into
    # the same recorded failure any other error path produces, and pays
    # whichever barrier signals this worker still owed.
    $warmupPaid = $false
    $gatePaid = $false
    try {
        # Warmup iteration — counted in the totals; its completion feeds
        # the post-warmup baselines.
        $ok = Invoke-LoopIteration $Run $Worker 0L
        [void]$Run.WarmupDone.SignalAndWait()
        $warmupPaid = $true
        [void]$Run.ReleaseGate.SignalAndWait()
        $gatePaid = $true
        if (-not $ok) { return }

        $iter = 1L
        while ($true) {
            if ($Run.Cfg.Iterations -gt 0 -and $iter -ge $Run.Cfg.Iterations) { break }
            if ($Run.Flags.Stop) { break }
            if (-not (Invoke-LoopIteration $Run $Worker $iter)) { break }
            if (-not (Invoke-LoopMaintenance $Run $Worker.Id $iter)) { break }
            $iter += 1L
        }
    }
    catch {
        Set-LoopWorkerError $Run $Worker.Id `
            ('g' + $Worker.Id + ': ' + $_.Exception.Message)
        if (-not $warmupPaid) { [void]$Run.WarmupDone.SignalAndWait() }
        if (-not $gatePaid) { [void]$Run.ReleaseGate.SignalAndWait() }
    }
    finally { Set-LoopWorkerDone $Run }
}
