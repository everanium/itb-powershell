# The maintenance operations that mutate a live Pipeline handle between
# iterations: master rotation (--rekey-every) and blob reopen
# (--blob-cycle-every).

# Byte length of each fresh master drawn for a rotation. Matches the size
# Init auto-generates for both the parallax and the wrapper master.
$script:LoopRekeyMasterSize = 32

function Invoke-LoopRekeyPipes {
    <#
    .SYNOPSIS
    Master rotation.
    .DESCRIPTION
    Rotates the parallax + wrapper masters on every active Pipeline under
    the write lock and retains the refreshed blob for subsequent blob
    reopens. Masters are drawn fresh from the OS CSPRNG on every rotation
    regardless of --seed (master rotation is pipeline keying, not
    plaintext content); a disabled layer passes no bytes, which Rekey
    ignores. The eight inner seeds and the MAC key are untouched by
    design — Rekey targets only the two outer-layer master secrets.
    #>
    param([hashtable]$Run, [int]$Id, [long]$Iteration)

    $head = 'g' + $Id + ' iter ' + (Format-LoopInt $Iteration)
    $perm = [byte[]]::new(0)
    $wrap = [byte[]]::new(0)

    if ($Run.Cfg.Parallax) {
        $perm = [byte[]]::new($script:LoopRekeyMasterSize)
        if (-not (Invoke-LoopFillRandom $perm)) {
            Set-LoopWorkerError $Run $Id ($head + ': csprng: parallax master')
            return $false
        }
    }
    if ($Run.Cfg.Wrapper) {
        $wrap = [byte[]]::new($script:LoopRekeyMasterSize)
        if (-not (Invoke-LoopFillRandom $wrap)) {
            Set-LoopWorkerError $Run $Id ($head + ': csprng: wrapper master')
            return $false
        }
    }

    $failure = $null
    $Run.PipesLock.EnterWriteLock()
    try {
        if ($null -ne $Run.Pipes.StreamPipe) {
            try {
                $Run.Pipes.StreamBlob = Invoke-ItbRekey -Pipeline $Run.Pipes.StreamPipe `
                    -PermMaster $perm -WrapMaster $wrap
            }
            catch {
                $failure = $head + ': Rekey(' + $Run.StreamProfile + '): ' + (Get-LoopErrorDetail $_)
            }
        }
        if ($null -eq $failure -and $null -ne $Run.Pipes.MsgPipe) {
            try {
                $Run.Pipes.MsgBlob = Invoke-ItbRekey -Pipeline $Run.Pipes.MsgPipe `
                    -PermMaster $perm -WrapMaster $wrap
            }
            catch {
                $failure = $head + ': Rekey(' + $Run.MsgProfile + '): ' + (Get-LoopErrorDetail $_)
            }
        }
    }
    finally { $Run.PipesLock.ExitWriteLock() }

    if ($null -ne $failure) {
        Set-LoopWorkerError $Run $Id $failure
        return $false
    }

    [System.Threading.Monitor]::Enter($Run.CounterLock)
    try {
        $Run.Counts.Rekeys += 1L
        $n = $Run.Counts.Rekeys
    }
    finally { [System.Threading.Monitor]::Exit($Run.CounterLock) }

    Write-LoopLine ('rekey: ' + $head + ' rotated parallax + wrapper masters (rekey #' +
                    (Format-LoopInt $n) + ')')
    return $true
}

function Invoke-LoopBlobCyclePipes {
    <#
    .SYNOPSIS
    Blob reopen.
    .DESCRIPTION
    Reopens every active Pipeline from its retained blob under the write
    lock: a fresh handle is loaded from the blob, the running handle is
    freed, and the fresh one is swapped in, so every later iteration
    round-trips through seeds and masters that survived a blob crossing.
    The input is the blob Init or the latest Rekey handed out, not a
    fresh Save: that is what a receiver holds, and reopening from it
    proves the handed-out bytes rather than the live state. The blob
    carries the Pipeline's full shape, so no override reaches the reopen.
    On a Load failure the running handle stays and the failure aborts the
    run.
    #>
    param([hashtable]$Run, [int]$Id, [long]$Iteration)

    $head = 'g' + $Id + ' iter ' + (Format-LoopInt $Iteration)
    $failure = $null
    $Run.PipesLock.EnterWriteLock()
    try {
        if ($null -ne $Run.Pipes.StreamPipe) {
            try {
                $fresh = Import-ItbPipeline -Blob $Run.Pipes.StreamBlob
                $Run.Pipes.StreamPipe.Dispose()
                $Run.Pipes.StreamPipe = $fresh
            }
            catch {
                $failure = $head + ': Load(' + $Run.StreamProfile + '): ' + (Get-LoopErrorDetail $_)
            }
        }
        if ($null -eq $failure -and $null -ne $Run.Pipes.MsgPipe) {
            try {
                $fresh = Import-ItbPipeline -Blob $Run.Pipes.MsgBlob
                $Run.Pipes.MsgPipe.Dispose()
                $Run.Pipes.MsgPipe = $fresh
            }
            catch {
                $failure = $head + ': Load(' + $Run.MsgProfile + '): ' + (Get-LoopErrorDetail $_)
            }
        }
    }
    finally { $Run.PipesLock.ExitWriteLock() }

    if ($null -ne $failure) {
        Set-LoopWorkerError $Run $Id $failure
        return $false
    }

    [System.Threading.Monitor]::Enter($Run.CounterLock)
    try {
        $Run.Counts.BlobCycles += 1L
        $n = $Run.Counts.BlobCycles
    }
    finally { [System.Threading.Monitor]::Exit($Run.CounterLock) }

    Write-LoopLine ('blob-cycle: ' + $head + ' reopened from session blob (cycle #' +
                    (Format-LoopInt $n) + ')')
    return $true
}

function Invoke-LoopMaintenance {
    <#
    .SYNOPSIS
    Handle mutation.
    .DESCRIPTION
    Runs the periodic Pipeline-mutating operations after a completed
    iteration: master rotation (--rekey-every) and blob reopen
    (--blob-cycle-every). Both intervals count per-worker iterations; the
    warmup iteration (iter 0) never triggers because the worker loop
    calls this for iter >= 1 only. Rekey rewrites the outer-layer keying
    of a live handle and a blob reopen replaces the handle outright; each
    takes the write lock, so in-flight cipher calls on other workers
    drain before anything changes and no encrypt is separated from its
    decrypt by either. $false after recording the worker error.
    #>
    param([hashtable]$Run, [int]$Id, [long]$Iteration)

    $cfg = $Run.Cfg
    if ($cfg.RekeyEvery -gt 0 -and ($Iteration % $cfg.RekeyEvery) -eq 0) {
        if (-not (Invoke-LoopRekeyPipes $Run $Id $Iteration)) { return $false }
    }
    if ($cfg.BlobCycleEvery -gt 0 -and ($Iteration % $cfg.BlobCycleEvery) -eq 0) {
        if (-not (Invoke-LoopBlobCyclePipes $Run $Id $Iteration)) { return $false }
    }
    return $true
}
