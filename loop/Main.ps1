# Long-run stress harness. The loop utility holds one Pipeline handle per
# exercised cipher surface for minutes, hammers it with concurrent
# encrypt -> decrypt -> compare round-trips from N workers, rotates the
# outer masters and reopens the handle from its session blob on a
# schedule, and reports whether the process survived with every byte
# intact. It is the PowerShell binding's counterpart of the Go harness
# under tools/loop: the same flags, the same round structure, the same
# summary in both renderings.
#
# The default shape is full production: the Streaming AEAD profile with
# parallax on, wrapper on, hmac-blake3 MAC, Areion-SoEM-512 inner hash,
# 1024-bit keys, and the compile-in 512-bit nonce width, driven through a
# stream session by three workers for five minutes on 16 MiB plaintexts.
# Every worker owns a distinct CSPRNG-generated plaintext held for the
# whole run, so any cross-call state leakage inside the Pipeline surfaces
# as a data mismatch between workers rather than cancelling out.
#
# A failure is one of two things. A cipher, rekey or load call that
# returns a non-OK status is a worker error: the run stops, the summary
# lists it, the verdict is FAIL and the exit code 1. A round-trip that
# returns without error but with different bytes is a data mismatch: the
# process terminates on the spot with exit code 3, printing the worker,
# the iteration and the first differing offset, and no summary — the
# state that produced the wrong bytes is the evidence. A crash inside the
# shared library or the host runtime has no exit code of its own here;
# surfacing it is what the utility is for. This binding runs a Go
# c-shared runtime and CoreCLR in one process, two runtimes that each
# drive threads through signals, which is the interaction the long run is
# meant to expose.
#
# Usage:
#
#   pwsh -NoProfile -File loop/Main.ps1 --duration 5m --goroutines 3 \
#        --shape stream --hash areion512 --mac hmac-blake3 \
#        --payload-size 16MB --memlimit auto --parallax on --wrapper on
#
# Ctrl-C triggers a graceful shutdown: in-flight iterations complete,
# then the partial summary prints.

$ErrorActionPreference = 'Stop'

$script:LoopDir = $PSScriptRoot
$script:LoopModulePath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'Everanium.LibItb3/Everanium.LibItb3.psd1')

# ----------------------------------------------------------------------
# Flags
# ----------------------------------------------------------------------

# One command-line flag: its name, the type label the usage prints, its
# help text, whether it takes a value, the kind the value is parsed as,
# and the default. Values are validated after the whole line is parsed.
# The table is in alphabetical order — the order the usage prints.
$script:LoopFlags = @(
    @{ Name = 'barrier-fill'; Type = 'int'; Kind = 'int'; Default = 0
       Help = 'DRBG barrier fill margin: 1 | 2 | 4 | 8 | 16 | 32; 0 = profile default (1)' }
    @{ Name = 'blob-cycle-every'; Type = 'int'; Kind = 'int'; Default = 0; NoDefault = $true
       Help = 'reopen each pipeline from its session blob every N iterations per worker; 0 = never' }
    @{ Name = 'blob-mode'; Type = 'int'; Kind = 'int'; Default = 1
       Help = 'container floor sizing mode: 1 (per-region, default) | 2 (per-container)' }
    @{ Name = 'chunk-size'; Type = 'string'; Kind = 'string'; Default = '0'
       Help = 'streaming chunk-size budget (e.g. 4MB); 0 = profile default; inert for pure message shape' }
    @{ Name = 'drbg'; Type = 'string'; Kind = 'string'; Default = ''
       Help = 'DRBG fill primitive name (see itb3 drbgs); empty = profile default (auto tier)' }
    @{ Name = 'duration'; Type = 'duration'; Kind = 'string'; Default = '5m'
       Help = 'run duration (Go format: 30s / 5m / 1h); ignored when --iterations > 0' }
    @{ Name = 'gogc'; Type = 'int'; Kind = 'int'; Default = 0
       Help = 'GC trigger percentage; 0 = leave the runtime default' }
    @{ Name = 'gomaxprocs'; Type = 'int'; Kind = 'int'; Default = 0
       Help = 'Go runtime GOMAXPROCS override; 0 = inherit from the environment' }
    @{ Name = 'goroutines'; Type = 'int'; Kind = 'int'; Default = 3
       Help = 'concurrent workers (1..10); on runtimes without parallelism values above 1 are clamped to 1' }
    @{ Name = 'hash'; Type = 'string'; Kind = 'string'; Default = 'areion512'
       Help = 'inner ITB hash primitive name' }
    @{ Name = 'iterations'; Type = 'int'; Kind = 'int'; Default = 0; NoDefault = $true
       Help = 'fixed per-worker iteration count; 0 = duration-based' }
    @{ Name = 'json-output'; Type = ''; Kind = 'bool'; Default = $false
       Help = 'print the final summary as one compact JSON object instead of log lines' }
    @{ Name = 'key-bits'; Type = 'int'; Kind = 'int'; Default = 0
       Help = 'per-seed key width in bits: 512 | 1024 | 2048; 0 = profile default (1024)' }
    @{ Name = 'mac'; Type = 'string'; Kind = 'string'; Default = 'hmac-blake3'
       Help = 'MAC primitive name' }
    @{ Name = 'memlimit'; Type = 'string'; Kind = 'string'; Default = 'auto'
       Help = 'Go heap soft limit: auto (1GiB when goroutines <= 3, else 256MiB, applied only when the runtime has no limit) or a size (e.g. 512MB)' }
    @{ Name = 'memprofile'; Type = 'string'; Kind = 'string'; Default = ''
       Help = 'write a Go runtime heap profile (pprof) to this path at the end of the run; empty = none' }
    @{ Name = 'nonce-bits'; Type = 'int'; Kind = 'int'; Default = 0
       Help = 'on-wire nonce width in bits: 128 | 256 | 512; 0 = profile default (512)' }
    @{ Name = 'parallax'; Type = 'string'; Kind = 'string'; Default = 'on'
       Help = 'parallax layer: on | off' }
    @{ Name = 'payload-mode'; Type = 'string'; Kind = 'string'; Default = 'fixed'
       Help = 'plaintext content: fixed | rotating | pattern-zero | pattern-ff | pattern-ascii' }
    @{ Name = 'payload-size'; Type = 'string'; Kind = 'string'; Default = '16MB'
       Help = 'per-iteration plaintext size (e.g. 1MB / 16MB / 64MB)' }
    @{ Name = 'profile'; Type = 'string'; Kind = 'string'; Default = ''
       Help = "exercise this single registered triple profile (overrides --shape with the profile's surface); empty = shape-based profile pair" }
    @{ Name = 'rekey-every'; Type = 'int'; Kind = 'int'; Default = 0; NoDefault = $true
       Help = 'rotate the parallax + wrapper masters via Rekey every N iterations per worker; 0 = never' }
    @{ Name = 'seed'; Type = 'uint'; Kind = 'uint'; Default = 0; NoDefault = $true
       Help = 'deterministic plaintext RNG seed for bug reproduction, NOT for security testing (pipeline keys stay CSPRNG-drawn); 0 = crypto/rand plaintexts' }
    @{ Name = 'shape'; Type = 'string'; Kind = 'string'; Default = 'stream'
       Help = 'cipher surface to exercise: stream | message | stream_one_shot | both' }
    @{ Name = 'wrapper'; Type = 'string'; Kind = 'string'; Default = 'on'
       Help = 'wrapper layer: on | off' }
)

function Write-LoopUsage {
    [Console]::Error.WriteLine('Usage of loop:')
    foreach ($fl in $script:LoopFlags) {
        if ($fl.Type.Length -eq 0) {
            [Console]::Error.WriteLine('  -' + $fl.Name)
        }
        else {
            [Console]::Error.WriteLine('  -' + $fl.Name + ' ' + $fl.Type)
        }
        $suffix = ''
        if (-not $fl.NoDefault) {
            if ($fl.Kind -eq 'int' -and $fl.Default -ne 0) {
                $suffix = ' (default ' + (Format-LoopInt ([long]$fl.Default)) + ')'
            }
            elseif ($fl.Kind -eq 'string' -and ([string]$fl.Default).Length -gt 0) {
                $suffix = ' (default "' + $fl.Default + '")'
            }
        }
        [Console]::Error.WriteLine("    `t" + $fl.Help + $suffix)
    }
}

function Read-LoopArgv {
    <#
    .SYNOPSIS
    Parses argv into the raw flag values.
    .DESCRIPTION
    Accepts -name value, --name value, -name=value and --name=value; a
    boolean flag takes no value unless given as -name=true / -name=false.
    Returns 'help' for -h / --help (usage printed), 'error' after
    printing the error, or 'ok'.
    #>
    param([string[]]$Argv, [hashtable]$Raw)

    $i = 0
    while ($i -lt $Argv.Length) {
        $arg = $Argv[$i]
        if ($arg.Length -le 1 -or $arg[0] -ne '-') {
            Write-LoopError ('unexpected positional arguments: [' + $arg + ']')
            return 'error'
        }

        $bare = if ($arg.StartsWith('--', [System.StringComparison]::Ordinal)) {
            $arg.Substring(2)
        }
        else { $arg.Substring(1) }

        if ($bare -eq 'h' -or $bare -eq 'help') {
            Write-LoopUsage
            return 'help'
        }

        $inline = $null
        $name = $bare
        $eq = $bare.IndexOf('=')
        if ($eq -ge 0) {
            $inline = $bare.Substring($eq + 1)
            $name = $bare.Substring(0, $eq)
        }

        $fl = $script:LoopFlags | Where-Object { $_.Name -eq $name } | Select-Object -First 1
        if ($null -eq $fl) {
            Write-LoopError ('flag provided but not defined: -' + $name)
            Write-LoopUsage
            return 'error'
        }

        if ($null -ne $inline) { $value = $inline }
        elseif ($fl.Kind -eq 'bool') { $value = 'true' }
        else {
            $i++
            if ($i -ge $Argv.Length) {
                Write-LoopError ('flag needs an argument: -' + $fl.Name)
                return 'error'
            }
            $value = $Argv[$i]
        }

        switch ($fl.Kind) {
            'int' {
                $parsed = 0L
                if (-not [long]::TryParse($value,
                        [System.Globalization.NumberStyles]::AllowLeadingSign,
                        [System.Globalization.CultureInfo]::InvariantCulture, [ref]$parsed)) {
                    Write-LoopError ('invalid value "' + $value + '" for flag -' + $fl.Name)
                    return 'error'
                }
                $Raw[$fl.Name] = $parsed
            }
            'uint' {
                $parsedU = [uint64]0
                if (-not [uint64]::TryParse($value,
                        [System.Globalization.NumberStyles]::None,
                        [System.Globalization.CultureInfo]::InvariantCulture, [ref]$parsedU)) {
                    Write-LoopError ('invalid value "' + $value + '" for flag -' + $fl.Name)
                    return 'error'
                }
                $Raw[$fl.Name] = $parsedU
            }
            'bool' {
                if ($value -eq 'true') { $Raw[$fl.Name] = $true }
                elseif ($value -eq 'false') { $Raw[$fl.Name] = $false }
                else {
                    Write-LoopError ('invalid value "' + $value + '" for flag -' + $fl.Name)
                    return 'error'
                }
            }
            default { $Raw[$fl.Name] = $value }
        }
        $i++
    }
    return 'ok'
}

function Test-LoopHashRegistered {
    # Whether the name is in the shipped hash registry the module returns.
    param([string]$Name)
    try { return ((Get-ItbHashName) -contains $Name) } catch { return $false }
}

function Get-LoopProfileSurface {
    <#
    .SYNOPSIS
    Resolves a registered profile to the shape family its record's mode
    exposes.
    .DESCRIPTION
    Read through the module's lookup: a mode beginning with "streaming"
    exposes the stream surfaces, one beginning with "singlemsg" the
    message surface, "blob-only" none. Prints the validation message and
    returns $null on rejection.
    #>
    param([string]$Name)
    try { $p = Get-ItbProfile -Name $Name }
    catch {
        Write-LoopError ('--profile "' + $Name + '" is not a registered triple profile')
        return $null
    }
    if ($p.Mode.StartsWith('streaming', [System.StringComparison]::Ordinal)) { return 'stream' }
    if ($p.Mode.StartsWith('singlemsg', [System.StringComparison]::Ordinal)) { return 'message' }
    Write-LoopError ('--profile "' + $Name + '" carries no cipher surface (blob-only mode)')
    return $null
}

function Get-LoopNarrowedShape {
    # Applies a --profile's surface to the requested shape: a
    # message-surface profile forces message; a stream-surface profile
    # keeps stream or stream_one_shot as requested and turns message or
    # both into stream.
    param([string]$Requested, [string]$Surface)
    if ($Surface -eq 'message') { return 'message' }
    if ($Requested -eq 'stream_one_shot') { return 'stream_one_shot' }
    return 'stream'
}

function Read-LoopConfig {
    <#
    .SYNOPSIS
    Builds the resolved config from argv.
    .DESCRIPTION
    Returns a hashtable with Code and Cfg: Code 0 with a Cfg for a run,
    Code 0 with $null for help, Code 2 with $null after printing
    "loop: <message>" for the first failing rule.
    #>
    param([string[]]$Argv)

    $raw = @{}
    foreach ($fl in $script:LoopFlags) { $raw[$fl.Name] = $fl.Default }
    $status = Read-LoopArgv $Argv $raw
    if ($status -eq 'error') { return @{ Code = 2; Cfg = $null } }
    if ($status -eq 'help') { return @{ Code = 0; Cfg = $null } }

    $bad = { param($m) Write-LoopError $m; return @{ Code = 2; Cfg = $null } }

    $durationNs = Convert-LoopDuration $raw['duration']
    if ($null -eq $durationNs -or $durationNs -le 0) {
        return (& $bad ('--duration must be positive, got ' + $raw['duration']))
    }
    if ($raw['iterations'] -lt 0) {
        return (& $bad ('--iterations must be >= 0, got ' + (Format-LoopInt $raw['iterations'])))
    }
    if ($raw['goroutines'] -lt 1 -or $raw['goroutines'] -gt $script:LoopMaxWorkers) {
        return (& $bad ('--goroutines must be in 1..' + $script:LoopMaxWorkers +
                        ', got ' + (Format-LoopInt $raw['goroutines'])))
    }

    # Concurrency mode. This binding runs shared-handle: worker runspaces
    # call into one Pipeline handle concurrently. A runspace boundary is
    # in-process and does not copy the object, the handle under the
    # module is the C# layer's SafeHandle over an opaque Go-side registry
    # key, and nothing in either layer is thread-affine, so --goroutines
    # is the runspace count verbatim, never clamped.
    $workers = [int]$raw['goroutines']

    if (-not (Test-LoopShape $raw['shape'])) {
        return (& $bad ('--shape must be stream | message | stream_one_shot | both, got "' +
                        $raw['shape'] + '"'))
    }
    if (-not (Test-LoopHashRegistered $raw['hash'])) {
        return (& $bad ('--hash "' + $raw['hash'] + '" is not a registered hash primitive'))
    }

    # --mac is validated by Init: the C ABI enumerates no MAC names.
    $payload = Convert-LoopSize $raw['payload-size']
    if ($null -eq $payload) {
        return (& $bad ('--payload-size: invalid size "' + $raw['payload-size'] + '"'))
    }
    if ($payload -lt 1) { return (& $bad '--payload-size must be at least 1 byte') }

    $memlimitAuto = $raw['memlimit'] -eq 'auto'
    if ($memlimitAuto) {
        $memlimit = if ($workers -le 3) { 1073741824L } else { 268435456L }
    }
    else {
        $memlimit = Convert-LoopSize $raw['memlimit']
        if ($null -eq $memlimit) {
            return (& $bad ('--memlimit: invalid size "' + $raw['memlimit'] + '"'))
        }
    }

    if ($raw['gogc'] -lt 0) {
        return (& $bad ('--gogc must be >= 0, got ' + (Format-LoopInt $raw['gogc'])))
    }
    if ($raw['parallax'] -ne 'on' -and $raw['parallax'] -ne 'off') {
        return (& $bad ('--parallax must be on | off, got "' + $raw['parallax'] + '"'))
    }
    if ($raw['wrapper'] -ne 'on' -and $raw['wrapper'] -ne 'off') {
        return (& $bad ('--wrapper must be on | off, got "' + $raw['wrapper'] + '"'))
    }

    $shape = $raw['shape']
    if (([string]$raw['profile']).Length -gt 0) {
        $surface = Get-LoopProfileSurface $raw['profile']
        if ($null -eq $surface) { return @{ Code = 2; Cfg = $null } }
        $shape = Get-LoopNarrowedShape $shape $surface
    }

    if (@(0, 512, 1024, 2048) -notcontains $raw['key-bits']) {
        return (& $bad ('--key-bits must be 512 | 1024 | 2048 (or 0 = profile default), got ' +
                        (Format-LoopInt $raw['key-bits'])))
    }
    if (@(0, 128, 256, 512) -notcontains $raw['nonce-bits']) {
        return (& $bad ('--nonce-bits must be 128 | 256 | 512 (or 0 = profile default), got ' +
                        (Format-LoopInt $raw['nonce-bits'])))
    }
    if (@(1, 2) -notcontains $raw['blob-mode']) {
        return (& $bad ('--blob-mode must be 1 (per-region) | 2 (per-container), got ' +
                        (Format-LoopInt $raw['blob-mode'])))
    }
    if (@(0, 1, 2, 4, 8, 16, 32) -notcontains $raw['barrier-fill']) {
        return (& $bad ('--barrier-fill must be 1 | 2 | 4 | 8 | 16 | 32 (or 0 = profile default), got ' +
                        (Format-LoopInt $raw['barrier-fill'])))
    }
    # --drbg is validated by Init: the C ABI enumerates no DRBG names.

    $chunkSize = Convert-LoopSize $raw['chunk-size']
    if ($null -eq $chunkSize) {
        return (& $bad ('--chunk-size: invalid size "' + $raw['chunk-size'] + '"'))
    }
    if ($raw['gomaxprocs'] -lt 0) {
        return (& $bad ('--gomaxprocs must be > 0 when specified, got ' +
                        (Format-LoopInt $raw['gomaxprocs'])))
    }
    if ($raw['rekey-every'] -lt 0) {
        return (& $bad ('--rekey-every must be >= 0, got ' + (Format-LoopInt $raw['rekey-every'])))
    }
    if ($raw['blob-cycle-every'] -lt 0) {
        return (& $bad ('--blob-cycle-every must be >= 0, got ' +
                        (Format-LoopInt $raw['blob-cycle-every'])))
    }
    if (-not (Test-LoopPayloadMode $raw['payload-mode'])) {
        return (& $bad ('--payload-mode must be fixed | rotating | pattern-zero | pattern-ff | ' +
                        'pattern-ascii, got "' + $raw['payload-mode'] + '"'))
    }

    return @{
        Code = 0
        Cfg = @{
            DurationNs = [long]$durationNs
            Iterations = [long]$raw['iterations']
            WorkersRequested = $workers
            Workers = $workers
            Shape = $shape
            Hash = [string]$raw['hash']
            Mac = [string]$raw['mac']
            PayloadBytes = [long]$payload
            Memlimit = [long]$memlimit
            MemlimitAuto = $memlimitAuto
            Gogc = [int]$raw['gogc']
            Parallax = ($raw['parallax'] -eq 'on')
            Wrapper = ($raw['wrapper'] -eq 'on')
            ProfileName = [string]$raw['profile']
            KeyBits = [long]$raw['key-bits']
            NonceBits = [long]$raw['nonce-bits']
            BlobMode = [long]$raw['blob-mode']
            ChunkSize = [long]$chunkSize
            BarrierFill = [long]$raw['barrier-fill']
            Drbg = [string]$raw['drbg']
            Gomaxprocs = [int]$raw['gomaxprocs']
            RekeyEvery = [long]$raw['rekey-every']
            BlobCycleEvery = [long]$raw['blob-cycle-every']
            PayloadMode = [string]$raw['payload-mode']
            Seed = [uint64]$raw['seed']
            JsonOutput = [bool]$raw['json-output']
            Memprofile = [string]$raw['memprofile']
        }
    }
}

# ----------------------------------------------------------------------
# Pipelines
# ----------------------------------------------------------------------

function New-LoopPipeline {
    <#
    .SYNOPSIS
    Constructs one Pipeline against the profile and retains its Init blob.
    .DESCRIPTION
    Every flag-carried override goes into the opts (zero values included
    — the shared library treats zero as "profile default"), then the Init
    blob is obtained once through Save-ItbPipeline: the module's
    construction cmdlet does not hand the blob back, and the bytes are
    the ones Init produced. Later blob reopens use the retained blob;
    Save is never called again. $null after printing the failure.
    #>
    param([hashtable]$Cfg, [string]$Profile)

    $options = [ordered]@{
        innerHash = $Cfg.Hash
        macName = $Cfg.Mac
        withParallax = $(if ($Cfg.Parallax) { 'true' } else { 'false' })
        withWrapper = $(if ($Cfg.Wrapper) { 'true' } else { 'false' })
        keyBits = (Format-LoopInt $Cfg.KeyBits)
        nonceBits = (Format-LoopInt $Cfg.NonceBits)
        barrierFill = (Format-LoopInt $Cfg.BarrierFill)
        drbg = $Cfg.Drbg
        chunkSize = (Format-LoopInt $Cfg.ChunkSize)
    }

    if ($Cfg.ProfileName.Length -gt 0) {
        # Supplies the keystream-capable primitive for every layer the
        # profile record leaves unnamed and the run engages: a missing
        # parallax palette becomes three copies of the fill cipher (with
        # the library's default segment size when the record carries
        # none), a missing outer cipher becomes the fill cipher. These
        # are opts overrides that fold into the resolved record the blob
        # carries — a derived profile is never registered, so no name the
        # receiver did not agree to reaches the wire.
        try { $rec = Get-ItbProfile -Name $Cfg.ProfileName }
        catch {
            Write-LoopError ('--profile "' + $Cfg.ProfileName + '" is not a registered triple profile')
            return $null
        }
        $filled = $false
        if ($Cfg.Parallax -and $rec.Palette.Length -eq 0) {
            $options['parallaxPalette'] = (@($script:LoopKeystreamFillCipher) * 3) -join ','
            if ($rec.Segment -eq 0) {
                # A recipe that never carried a palette never carried a
                # segment size either, and the schedule rejects zero.
                $options['parallaxSegmentSize'] = (Format-LoopInt $script:LoopKeystreamFillSegment)
            }
            $filled = $true
        }
        if ($Cfg.Wrapper -and $rec.Outer.Length -eq 0) {
            $options['outerCipher'] = $script:LoopKeystreamFillCipher
            $filled = $true
        }
        if ($filled) {
            Write-LoopError ($Cfg.ProfileName +
                ' leaves the requested keystream layers unnamed; ' +
                $script:LoopKeystreamFillCipher + ' supplied for them')
        }
    }

    try { $pipe = New-ItbPipeline -Profile $Profile -Opts $options }
    catch {
        Write-LoopError ('Init(' + $Profile + '): ' + (Get-LoopErrorDetail $_))
        return $null
    }

    try { $blob = Save-ItbPipeline $pipe }
    catch {
        Write-LoopError ('Save(' + $Profile + '): ' + (Get-LoopErrorDetail $_))
        $pipe.Dispose()
        return $null
    }

    if ($Cfg.BlobMode -eq 2) {
        # The sizing mode is not an Opts knob: the Init blob is edited
        # and the pipeline reopened from it, so the retained blob (the
        # one blob-cycle reopens from) carries the edited mode.
        $pipe.Dispose()
        try { $blob = Set-LoopInnerBlobMode $blob 2 }
        catch {
            Write-LoopError ('rewrite blob mode: ' + $_.Exception.Message)
            return $null
        }
        try { $pipe = Import-ItbPipeline -Blob $blob }
        catch {
            Write-LoopError ('reload Mode 2 blob: ' + (Get-LoopErrorDetail $_))
            return $null
        }
    }

    Write-LoopPipelineInitialised $Profile $blob
    return @{ Pipe = $pipe; Blob = $blob }
}

function Write-LoopPipelineInitialised {
    <#
    .SYNOPSIS
    Prints the construction line with the recipe read back from the blob.
    .DESCRIPTION
    The recipe is read from the blob the Pipeline handed out, not echoed
    from the flags: every construction override is proven to have reached
    the library by the value the receiver would see. Record values that
    are empty (a No MAC profile's MAC, a mixed profile's single hash)
    print as "-".
    #>
    param([string]$Profile, [byte[]]$Blob)

    $head = 'pipeline initialised: profile=' + $Profile + ' blob=' +
            (Format-LoopInt ([long]$Blob.Length)) + ' bytes'
    try { $rec = Get-ItbProfile -Blob $Blob }
    catch {
        Write-LoopLine ($head + ' (inspect: ' + (Get-LoopErrorDetail $_) + ')')
        return
    }

    $dash = { param($s) if ([string]::IsNullOrEmpty($s)) { '-' } else { $s } }
    $orZero = { param($v) if ($null -eq $v) { 0 } else { [int]$v } }
    Write-LoopLine ($head +
        ' hash=' + (& $dash $rec.Hash) +
        ' key-bits=' + (Format-LoopInt ([long]$rec.KeyBits)) +
        ' nonce-bits=' + (Format-LoopInt ([long](& $orZero $rec.NonceBits))) +
        ' barrier-fill=' + (Format-LoopInt ([long](& $orZero $rec.BarrierFill))) +
        ' chunk-size=' + (Format-LoopInt ([long]$rec.Chunk)) +
        ' mac=' + (& $dash $rec.Mac) +
        ' parallax=' + (Format-LoopOnOff $rec.Parallax) +
        ' wrapper=' + (Format-LoopOnOff $rec.Wrapper) +
        $(if ($rec.ContainerMode -eq 2) { ' container-mode=2' } else { '' }) +
        $(if (-not [string]::IsNullOrEmpty($rec.Drbg)) { ' drbg=' + $rec.Drbg } else { '' }))
}

function Set-LoopInnerBlobMode {
    <#
    .SYNOPSIS
    Returns a copy of a session blob with the inner blob's sizing mode set.
    .DESCRIPTION
    The inner blob ("ib") of a wrap-layer session blob carries the
    container floor sizing mode (1 = per-region, 2 = per-container). The
    wrap layer's profile record carries its own "mode" (a string), so
    only the inner blob's integer field is set; no key is added, integers
    keep their literals, and strings are written without escaping the
    base64 alphabet.
    #>
    param([byte[]]$Blob, [int]$Mode)

    $root = [System.Text.Json.Nodes.JsonNode]::Parse([System.Text.Encoding]::UTF8.GetString($Blob))
    if ($root -isnot [System.Text.Json.Nodes.JsonObject]) {
        throw [System.FormatException]::new('session blob is not a JSON object')
    }
    $ib = $root['ib']
    if ($ib -isnot [System.Text.Json.Nodes.JsonObject] -or -not $ib.ContainsKey('mode')) {
        throw [System.FormatException]::new('inner blob mode field not found')
    }
    $ib['mode'] = [System.Text.Json.Nodes.JsonValue]::Create([int]$Mode)
    $buf = [System.IO.MemoryStream]::new()
    try {
        $options = [System.Text.Json.JsonWriterOptions]::new()
        $options.Encoder = [System.Text.Encodings.Web.JavaScriptEncoder]::UnsafeRelaxedJsonEscaping
        $w = [System.Text.Json.Utf8JsonWriter]::new([System.IO.Stream]$buf, $options)
        try { $root.WriteTo($w) } finally { $w.Dispose() }
        return ,$buf.ToArray()
    }
    finally { $buf.Dispose() }
}

# ----------------------------------------------------------------------
# Run
# ----------------------------------------------------------------------

function Invoke-LoopRun {
    param([string[]]$Argv)

    New-LoopNativeShim
    # The host ignores SIGPIPE; the shim restores the default disposition
    # before the first line is printed, so a consumer that stops reading
    # ends the run the way it ends the reference (see the shim).
    [LoopNative]::RestoreSigpipe()
    Import-Module $script:LoopModulePath -Force

    $parsed = Read-LoopConfig $Argv
    if ($null -eq $parsed.Cfg) { return $parsed.Code }
    $cfg = $parsed.Cfg

    # Runtime shaping. A long run under allocation churn grows the Go
    # heap inside the shared library without bound unless a soft limit
    # paces the collector, so a limit is always in force: an explicit
    # --memlimit is set as given, and auto caps the heap only when the
    # runtime reports no limit at all (a limit already installed from the
    # environment is left standing). The GC percentage and GOMAXPROCS are
    # set only when their flag is non-zero — a zero flag skips the setter
    # rather than calling it with zero, because zero is a real value to
    # the GC-percent setter, and a call would clobber whatever the
    # environment installed. All of it lands before any Pipeline exists
    # so the baselines are taken under the shaped runtime.
    if ($cfg.MemlimitAuto) {
        if ((Set-ItbMemoryLimit -1) -eq [long]::MaxValue) {
            [void](Set-ItbMemoryLimit $cfg.Memlimit)
        }
    }
    else {
        [void](Set-ItbMemoryLimit $cfg.Memlimit)
    }
    $cfg.Memlimit = Set-ItbMemoryLimit -1
    if ($cfg.Gogc -gt 0) { [void](Set-ItbGCPercent $cfg.Gogc) }
    if ($cfg.Gomaxprocs -gt 0) { [void](Set-ItbGOMAXPROCS $cfg.Gomaxprocs) }

    Write-LoopLine ('start: duration=' + (Format-LoopDuration $cfg.DurationNs) +
        ' iterations=' + (Format-LoopInt $cfg.Iterations) +
        ' goroutines=' + (Format-LoopInt ([long]$cfg.WorkersRequested)) +
        ' workers=' + (Format-LoopInt ([long]$cfg.Workers)) +
        ' concurrency=' + $script:LoopConcurrency +
        ' shape=' + $cfg.Shape + ' hash=' + $cfg.Hash + ' mac=' + $cfg.Mac +
        ' payload=' + (Format-LoopBytes $cfg.PayloadBytes) +
        ' memlimit=' + (Format-LoopBytes $cfg.Memlimit) +
        ' parallax=' + (Format-LoopOnOff $cfg.Parallax) +
        ' wrapper=' + (Format-LoopOnOff $cfg.Wrapper))
    Write-LoopLine ('overrides: profile="' + $cfg.ProfileName + '"' +
        ' key-bits=' + (Format-LoopInt $cfg.KeyBits) +
        ' nonce-bits=' + (Format-LoopInt $cfg.NonceBits) +
        ' chunk-size=' + (Format-LoopBytes $cfg.ChunkSize) +
        ' barrier-fill=' + (Format-LoopInt $cfg.BarrierFill) +
        ' gomaxprocs=' + (Format-LoopInt ([long]$cfg.Gomaxprocs)) +
        ' rekey-every=' + (Format-LoopInt $cfg.RekeyEvery) +
        ' blob-cycle-every=' + (Format-LoopInt $cfg.BlobCycleEvery) +
        ' payload-mode=' + $cfg.PayloadMode +
        ' seed=' + ([uint64]$cfg.Seed).ToString([System.Globalization.CultureInfo]::InvariantCulture) +
        ' json-output=' + $(if ($cfg.JsonOutput) { 'true' } else { 'false' }) +
        $(if ($cfg.BlobMode -ne 1) { ' blob-mode=' + (Format-LoopInt $cfg.BlobMode) } else { '' }) +
        $(if ($cfg.Drbg.Length -gt 0) { ' drbg=' + $cfg.Drbg } else { '' }))
    Write-LoopLine ('policy: microbatch-tiers=' + (Get-LoopPolicyLabel 'ITB_MICROBATCH_TIERS') +
        ' hashpool-starters=' + (Get-LoopPolicyLabel 'ITB_HASHPOOL_STARTERS'))

    # Pipeline construction — one shared handle per exercised shape.
    # stream and stream_one_shot share the streaming handle.
    $streamProfile = if ($cfg.ProfileName.Length -eq 0) {
        $script:LoopDefaultStreamProfile
    }
    else { $cfg.ProfileName }
    $msgProfile = if ($cfg.ProfileName.Length -eq 0) {
        $script:LoopDefaultMessageProfile
    }
    else { $cfg.ProfileName }

    $pipes = [hashtable]::Synchronized(@{
        StreamPipe = $null; MsgPipe = $null
        StreamBlob = [byte[]]::new(0); MsgBlob = [byte[]]::new(0)
    })

    if ($cfg.Shape -eq 'stream' -or $cfg.Shape -eq 'stream_one_shot' -or $cfg.Shape -eq 'both') {
        $built = New-LoopPipeline $cfg $streamProfile
        if ($null -eq $built) { return 1 }
        $pipes.StreamPipe = $built.Pipe
        $pipes.StreamBlob = $built.Blob
    }
    if ($cfg.Shape -eq 'message' -or $cfg.Shape -eq 'both') {
        $built = New-LoopPipeline $cfg $msgProfile
        if ($null -eq $built) { return 1 }
        $pipes.MsgPipe = $built.Pipe
        $pipes.MsgBlob = $built.Blob
    }

    # Allocation posture. Per-worker plaintexts are allocated once and
    # held for the whole run (rotating mode refills them in place per
    # iteration); the pump accumulators and the drain scratch live inside
    # each worker and are reused across iterations; the bounded feed
    # slice and the message / one-shot outputs are allocated per call and
    # reclaimed per iteration. Under the default fixed CSPRNG mode every
    # worker's buffer is distinct, so cross-worker data crossover is
    # detectable; pattern modes trade that property for content edge-case
    # coverage.
    $states = @()
    for ($id = 0; $id -lt $cfg.Workers; $id++) {
        $w = @{
            Id = $id
            Plaintext = [byte[]]::new([int]$cfg.PayloadBytes)
            PayloadMode = $cfg.PayloadMode
            Seeded = ($cfg.Seed -ne 0)
            Rng = (Get-LoopSeedForWorker $cfg.Seed $id)
            Wire = [System.IO.MemoryStream]::new()
            Plain = [System.IO.MemoryStream]::new()
            Scratch = [byte[]]::new($script:LoopPumpSlice)
        }
        $rng = [uint64]$w.Rng
        $ok = Invoke-LoopFillPayload $cfg.PayloadMode $w.Seeded ([ref]$rng) $w.Plaintext
        $w.Rng = $rng
        if (-not $ok) {
            Write-LoopError 'payload fill: csprng'
            return 1
        }
        $states += $w
    }

    # Graceful stop. SIGINT / SIGTERM set a flag the main thread polls
    # while it waits for the workers; it turns the flag into the stop
    # request every worker checks before starting an iteration, so a
    # signal interrupts nothing mid-call — the in-flight encrypt /
    # decrypt / compare completes, the worker returns, and the partial
    # summary prints with the verdict the completed iterations earned.
    [LoopNative]::InstallSignals()

    $run = [hashtable]::Synchronized(@{
        Cfg = $cfg
        StreamProfile = $streamProfile
        MsgProfile = $msgProfile
        # Handle mutation. Iterations hold the read side for their whole
        # encrypt -> decrypt -> compare; rekey and blob reopen take the
        # write side, so no cipher call is in flight while a handle's
        # keying changes or the handle itself is swapped, and no encrypt
        # is separated from its decrypt by either.
        PipesLock = [System.Threading.ReaderWriterLockSlim]::new(
            [System.Threading.LockRecursionPolicy]::NoRecursion)
        Pipes = $pipes
        CounterLock = [object]::new()
        DoneLock = [object]::new()
        Counts = [hashtable]::Synchronized(@{ Rekeys = 0L; BlobCycles = 0L })
        Flags = [hashtable]::Synchronized(@{ Stop = $false })
        Done = [hashtable]::Synchronized(@{ Active = $cfg.Workers; Finish = 0L })
        Workers = @()
        WarmupDone = [System.Threading.Barrier]::new($cfg.Workers + 1)
        ReleaseGate = [System.Threading.Barrier]::new($cfg.Workers + 1)
        RssWarmup = 0L; RssPeak = 0L; RssFinal = 0L
        PoolWarmup = @(); PoolSteady = @()
        LoopDir = $script:LoopDir
        ModulePath = $script:LoopModulePath
    })
    $counters = @()
    for ($i = 0; $i -lt $cfg.Workers; $i++) {
        $counters += @{
            Iters = 0L; BytesEnc = 0L; BytesDec = 0L; NanosEnc = 0L; NanosDec = 0L
            ErrorText = $null; ErrorLock = [object]::new()
        }
    }
    $run.Workers = $counters

    # Warmup barrier. Every worker runs one iteration and waits; the
    # clock starts only once all of them have paid their first-call costs
    # (pool warm-up, lazy kernel dispatch, page faults on the payload
    # buffers, and on this runtime the per-runspace module import and
    # first parse of the worker body), and the RSS and pool baselines
    # taken here describe a process that has already run the whole cipher
    # path once per worker.
    $warmupStart = [System.Diagnostics.Stopwatch]::GetTimestamp()
    $pool = [runspacefactory]::CreateRunspacePool(1, $cfg.Workers)
    $pool.Open()
    $body = {
        param($Run, $Worker)
        $ErrorActionPreference = 'Stop'
        # A worker that dies while loading its own declarations has none
        # of the helpers the rest of the harness reports errors with, and
        # has not yet paid either barrier — so the bootstrap carries a
        # handler written in bare runtime calls, which records the
        # failure on this worker's counters, asks for a stop, releases
        # both barriers and marks the worker returned. Without it a
        # missing unit or a failed module import stops the run in a wait
        # that nothing ever ends.
        try {
            . (Join-Path $Run.LoopDir 'Size.ps1')
            . (Join-Path $Run.LoopDir 'Payload.ps1')
            . (Join-Path $Run.LoopDir 'Ops.ps1')
            . (Join-Path $Run.LoopDir 'Worker.ps1')
            . (Join-Path $Run.LoopDir 'Shared.ps1')
            Import-Module $Run.ModulePath
        }
        catch {
            $c = $Run.Workers[$Worker.Id]
            [System.Threading.Monitor]::Enter($c.ErrorLock)
            try {
                if ($null -eq $c.ErrorText) {
                    $c.ErrorText = 'g' + $Worker.Id + ' worker start: ' +
                        $_.Exception.Message
                }
            }
            finally { [System.Threading.Monitor]::Exit($c.ErrorLock) }
            $Run.Flags.Stop = $true
            [void]$Run.WarmupDone.SignalAndWait()
            [void]$Run.ReleaseGate.SignalAndWait()
            [System.Threading.Monitor]::Enter($Run.DoneLock)
            try {
                $Run.Done.Active -= 1
                if ($Run.Done.Active -eq 0) {
                    $Run.Done.Finish = [System.Diagnostics.Stopwatch]::GetTimestamp()
                    [System.Threading.Monitor]::Pulse($Run.DoneLock)
                }
            }
            finally { [System.Threading.Monitor]::Exit($Run.DoneLock) }
            return
        }
        Invoke-LoopWorker $Run $Worker
    }
    $jobs = @()
    foreach ($w in $states) {
        $ps = [powershell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddScript($body.ToString()).AddArgument($run).AddArgument($w)
        $jobs += @{ PS = $ps; Handle = $ps.BeginInvoke() }
    }

    [void]$run.WarmupDone.SignalAndWait()
    $rss = Get-LoopRss
    $rssWarmup = $rss[0]
    $poolWarmup = Get-LoopPoolSnapshot
    Write-LoopLine ('warmup: ' + (Format-LoopInt ([long]$cfg.Workers)) +
        ' workers x 1 iter completed in ' +
        (Format-LoopDuration (Get-LoopRounded (Get-LoopElapsedNs $warmupStart) 100000000L)) +
        ' (baseline rss=' + (Format-LoopBytes $rssWarmup) + ')')

    # Open the gate; the duration is a deadline the waiter below enforces
    # in duration mode.
    $startTicks = [System.Diagnostics.Stopwatch]::GetTimestamp()
    [void]$run.ReleaseGate.SignalAndWait()

    # Wait for every worker, polling every 100 ms so the deadline and a
    # signal are both noticed promptly.
    $finishTicks = $startTicks
    [System.Threading.Monitor]::Enter($run.DoneLock)
    try {
        while ($run.Done.Active -gt 0) {
            if ([LoopNative]::SignalSeen -or
                ($cfg.Iterations -eq 0 -and (Get-LoopElapsedNs $startTicks) -ge $cfg.DurationNs)) {
                $run.Flags.Stop = $true
            }
            [void][System.Threading.Monitor]::Wait($run.DoneLock, 100)
        }
        if ($run.Done.Finish -ne 0) { $finishTicks = $run.Done.Finish }
    }
    finally { [System.Threading.Monitor]::Exit($run.DoneLock) }

    $elapsedNs = Get-LoopTicksAsNs ($finishTicks - $startTicks)
    $rss = Get-LoopRss
    $run.RssFinal = $rss[0]
    $run.RssPeak = $rss[1]
    $run.PoolSteady = Get-LoopPoolSnapshot
    $run.RssWarmup = $rssWarmup
    $run.PoolWarmup = $poolWarmup

    foreach ($j in $jobs) {
        try { [void]$j.PS.EndInvoke($j.Handle) }
        catch {
            Write-LoopError ('worker runspace: ' + $_.Exception.Message)
        }
        $j.PS.Dispose()
    }
    $pool.Close()

    if ($cfg.Memprofile.Length -gt 0) {
        try {
            Write-ItbHeapProfile $cfg.Memprofile
            Write-LoopLine ('memprofile: heap profile written to ' + $cfg.Memprofile)
        }
        catch { Write-LoopError ('memprofile: ' + (Get-LoopErrorDetail $_)) }
    }

    $code = Write-LoopFinalSummary $run $elapsedNs
    if ($null -ne $run.Pipes.StreamPipe) { $run.Pipes.StreamPipe.Dispose() }
    if ($null -ne $run.Pipes.MsgPipe) { $run.Pipes.MsgPipe.Dispose() }
    return $code
}

. (Join-Path $PSScriptRoot 'Shared.ps1')
. (Join-Path $PSScriptRoot 'Size.ps1')
. (Join-Path $PSScriptRoot 'Payload.ps1')
. (Join-Path $PSScriptRoot 'Ops.ps1')
. (Join-Path $PSScriptRoot 'Worker.ps1')
. (Join-Path $PSScriptRoot 'Summary.ps1')

exit (Invoke-LoopRun $args)
