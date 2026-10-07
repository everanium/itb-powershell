# Shared declarations of the utility: the run-wide constants, the two
# output writers, the clock, and the compiled shim for the two native
# services the script language cannot express.
#
# PowerShell-specific. A worker runs in its own runspace and has to
# re-source what it needs; dot-sourcing the main unit there would launch
# a second harness, so everything both sides use lives here, in the same
# role a C implementation's shared header plays.

# --goroutines ceiling; the harness targets modest hosts and each worker
# pins payload-sized buffers for the whole run.
$script:LoopMaxWorkers = 10

# The concurrency mode this binding implements, as the summary reports it
# (shared-handle / independent-handles / single).
$script:LoopConcurrency = 'shared-handle'

# Profiles the shape-based pair is built against when --profile is empty.
$script:LoopDefaultStreamProfile = 'streaming-aead-triple-mac-v1'
$script:LoopDefaultMessageProfile = 'singlemsg-triple-mac-v1'

# The keystream-capable primitive supplied for a layer a profile leaves
# unnamed: PRF-grade, so sound outside the barrier, and the closest
# relative of the AES-based inner primitive whose profiles need the fill.
$script:LoopKeystreamFillCipher = 'aescmac'

# The parallax segment size a filled palette runs with — the library's
# own default; a schedule rejects zero.
$script:LoopKeystreamFillSegment = 4093

function New-LoopNativeShim {
    <#
    .SYNOPSIS
    Compiles the two native services the script language cannot express.
    .DESCRIPTION
    PowerShell-specific, and the only compiled code in this utility: a
    signal handler must be a real delegate, because the runtime calls it
    on a thread that has no engine for a script block to run in and the
    process aborts if one is offered; and the plaintext fill must reach
    the kernel CSPRNG entry directly, because the managed generator
    reaches it through a userspace reseeding layer whose kernel draws no
    longer track the number of fills, which makes the plaintext-content
    flags unobservable from outside the process. Neither service touches
    the cipher: every ITB call in this utility goes through the module.
    #>
    if ('LoopNative' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class LoopNative
{
    private static volatile bool _signalSeen;
    private static PosixSignalRegistration _sigint;
    private static PosixSignalRegistration _sigterm;

    public static bool SignalSeen { get { return _signalSeen; } }

    // SIGTERM reaches this handler and its cancel holds. SIGINT does
    // not: the host installs its own disposition for it and terminates
    // the process before a registration here is consulted, which a
    // Console.CancelKeyPress subscriber does not change either. The
    // registration stays so the request is stated where a reader looks
    // for it, and so a host that stops claiming the signal is served.
    public static void InstallSignals()
    {
        _sigint = PosixSignalRegistration.Create(PosixSignal.SIGINT, Handle);
        _sigterm = PosixSignalRegistration.Create(PosixSignal.SIGTERM, Handle);
    }

    private static void Handle(PosixSignalContext ctx)
    {
        ctx.Cancel = true;
        _signalSeen = true;
    }

    [DllImport("libc", EntryPoint = "signal")]
    private static extern IntPtr sys_signal(int sig, IntPtr handler);

    // The host ignores SIGPIPE and the console stream drops a write to
    // a closed pipe without a word, so a consumer that stops reading
    // would leave the process printing into nothing and exiting 0 with
    // its verdict undelivered. With the default disposition back the
    // first such write ends the process, which is what every other
    // implementation does and what a fleet driver expects.
    public static void RestoreSigpipe()
    {
        sys_signal(13, IntPtr.Zero);
    }

    [DllImport("libc", EntryPoint = "getrandom", SetLastError = true)]
    private static extern IntPtr getrandom(IntPtr buf, UIntPtr buflen, uint flags);

    public static bool FillRandom(byte[] buf)
    {
        GCHandle pin = GCHandle.Alloc(buf, GCHandleType.Pinned);
        try
        {
            IntPtr basePtr = pin.AddrOfPinnedObject();
            int off = 0;
            while (off < buf.Length)
            {
                // The entry returns short on a signal and caps a single
                // draw, so the fill loops until every byte is in place.
                IntPtr r = getrandom(basePtr + off, (UIntPtr)(uint)(buf.Length - off), 0);
                long n = r.ToInt64();
                if (n <= 0) { return false; }
                off += (int)n;
            }
            return true;
        }
        finally { pin.Free(); }
    }
}
'@
}

function Write-LoopLine {
    <#
    .SYNOPSIS
    Prints one prefixed status line to stdout.
    .DESCRIPTION
    PowerShell-specific. The line goes to the process stdout writer
    rather than through the output stream, because the maintenance lines
    are written from worker runspaces whose streams do not reach the
    host's console; the writer is synchronised, so concurrent lines do
    not interleave.
    #>
    param([string]$Line)
    [Console]::Out.WriteLine('[loop] ' + $Line)
}

function Write-LoopError {
    # Prints one prefixed error line to stderr.
    param([string]$Line)
    [Console]::Error.WriteLine('loop: ' + $Line)
}

function Format-LoopOnOff {
    param([bool]$Value)
    if ($Value) { return 'on' }
    return 'off'
}

function Get-LoopPolicyLabel {
    # Renders an encoder policy env value for the summary: the raw string
    # when set, "default" when the shipped ladder applies.
    param([string]$Name)
    $v = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($v)) { return 'default' }
    return $v.TrimStart()
}

$script:LoopNsPerTick = 1e9 / [System.Diagnostics.Stopwatch]::Frequency

function Get-LoopElapsedNs {
    # Nanoseconds elapsed since a Stopwatch timestamp reading.
    param([long]$Since)
    return [long](([System.Diagnostics.Stopwatch]::GetTimestamp() - $Since) * $script:LoopNsPerTick)
}

function Get-LoopTicksAsNs {
    param([long]$Ticks)
    return [long]($Ticks * $script:LoopNsPerTick)
}

