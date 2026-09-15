## ITB PowerShell Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Thin proxy over the C# binding ([`../csharp/`](https://github.com/everanium/itb/tree/main/bindings/csharp/)) — plain
CLR interop via `Add-Type`, no FFI hop of its own; the C# `Everanium.LibItb3.dll`
assembly carries the source-generated P/Invoke surface over the
libitb3 `ITB_Triple_*` C ABI, including the BUFFER_TOO_SMALL
retry-once path and the native-library resolver. Every hash-name /
MAC-name / cipher-name / profile-name is an opaque string passed
through to Go for validation; the binding carries no ITB
construction logic.

The public surface is a Verb-Noun cmdlet set over the C# `Pipeline`
type: `New-ItbPipeline` / `Import-ItbPipeline` / `Save-ItbPipeline` /
`Invoke-ItbRekey` / `Set-ItbMaxWorkers` / `Close-ItbPipeline` for the
session, `Get-ItbProfile` / `Get-ItbProfileName` / `New-ItbProfile` /
`Register-ItbProfile` for the profile registry and blob inspection,
the lifecycle, `Invoke-ItbEncrypt` / `Invoke-ItbDecrypt` for Single
Message, `Invoke-ItbEncryptStream` / `Invoke-ItbDecryptStream`
(one-shot bytes, file-to-file, or stream-to-stream pumps) and
`New-ItbEncryptStream` / `New-ItbDecryptStream` (caller-driven
incremental sessions) for streaming, `New-ItbOpts` for the opts
pass-through, and `Get-ItbVersion` / `Set-ItbMemoryLimit` /
`Set-ItbGCPercent` for diagnostics and the Go runtime knobs. The
underlying CLR objects (`[Everanium.Itb3.Pipeline]`, `[Everanium.Itb3.Opts]`, session
types) are returned as-is, so direct method calls
(`$pipeline.EncryptMessage($bytes)`, `$session.Write($bytes)`)
remain available alongside the cmdlets. Errors surface as
`[Everanium.Itb3.ItbException]` (unwrapped from PowerShell's method-invocation
wrapper) carrying the structural `Status` code plus the
`ITB_LastError` diagnostic — catch with `try` / `catch
[Everanium.Itb3.ItbException]` and inspect `$_.Exception.Status`.

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go dotnet-sdk
paru -S powershell-bin        # pwsh 7.4+ (AUR)
pwsh -Command 'Install-Module Pester -Scope CurrentUser -Force'   # tests only
```

Generic Linux / macOS: a Go toolchain, the .NET SDK (net10.0 target
framework, for the C# peer), and PowerShell 7.4+. Windows: the same;
libitb3 builds as `libitb3.dll`.

## Build

The binding itself is a script module with no compilation step. The
convenience driver builds the C# peer (libitb3.so + `Everanium.LibItb3.dll` via
`../csharp/build.sh`) and verifies the module imports cleanly:

```bash
./bindings/powershell/build.sh
```

## Assembly and library lookup order

The C# `Everanium.LibItb3.dll` assembly is located at module import time:

1. `ITB_CSHARP_DLL` environment variable (path to `Everanium.LibItb3.dll`).
2. The sibling C# binding's `bin/Release` then `bin/Debug` output,
   relative to the module (in-repo builds).

Native libitb3 resolution is inherited from the C# binding's
resolver: `ITB_LIBITB3_PATH`, then `<repo>/dist/<os>-<arch>/` located
by walking up from the assembly directory, then the OS default
loader path.

## Usage example

```powershell
Import-Module ./bindings/powershell/Everanium.LibItb3/Everanium.LibItb3.psd1

$sender   = New-ItbPipeline -Profile 'singlemsg-triple-mac-v1'
$receiver = Import-ItbPipeline -Blob (Save-ItbPipeline $sender)

$wire  = Invoke-ItbEncrypt -Pipeline $sender -Data 'any text or binary data'
$plain = Invoke-ItbDecrypt -Pipeline $receiver -Data $wire
[System.Text.Encoding]::UTF8.GetString($plain)

Close-ItbPipeline $sender
Close-ItbPipeline $receiver
# Or persist the session to disk and reopen it later:
#   Save-ItbPipeline -Pipeline $sender -Path /path/session.blob
#   $receiver = Import-ItbPipeline -Path /path/session.blob
```

Opts override the profile default at `New-ItbPipeline` (chunk size,
outer cipher, parallax on/off, wrapper on/off, MAC name, palette,
`maxWorkers`) as a hashtable passed to `-Opts`; the blob the receiver
imports carries the resolved shape, so `Import-ItbPipeline` takes no
opts:

```powershell
$opts = @{ chunkSize = 65536; withWrapper = $false }
$sender   = New-ItbPipeline -Profile 'singlemsg-triple-mac-v1' -Opts $opts
$receiver = Import-ItbPipeline -Blob (Save-ItbPipeline $sender)
```

`Invoke-ItbRekey` rotates the parallax + wrapper masters mid-session
(the eight ITB seeds and MAC key are fixed for the session lifetime
by design) and returns the refreshed blob; the receiver picks up
the new masters through a fresh `Save-ItbPipeline` /
`Import-ItbPipeline` handshake:

```powershell
$perm = [byte[]]::new(32); $wrap = [byte[]]::new(32)
$rotated = Invoke-ItbRekey -Pipeline $sender -PermMaster $perm -WrapMaster $wrap
$receiver = Import-ItbPipeline -Blob $rotated
```

For bounded-memory streaming, the pump shapes move a file or any
`System.IO.Stream` source into a sink through an incremental
session:

```powershell
Invoke-ItbEncryptStream -Pipeline $sender -InFile big.bin -OutFile big.itb
Invoke-ItbDecryptStream -Pipeline $receiver -InFile big.itb -OutFile back.bin
```

The explicit `New-ItbEncryptStream` / `New-ItbDecryptStream`
sessions expose `Write` / `End` / `Read` for caller-driven loops;
`Read` takes a `[ref]` finished flag:

```powershell
$session = New-ItbEncryptStream -Pipeline $sender
$session.Write($bytes)
$session.End()
$buf = [byte[]]::new(65536)
$finished = $false
while (-not $finished) {
    $n = $session.Read($buf, [ref]$finished)
    # consume $buf[0..($n-1)]
}
$session.Dispose()
```

Profile names, opts keys, and every primitive name are validated by
the Go side; a rejected string surfaces as `[Everanium.Itb3.ItbException]`
carrying the `Status` code plus the `ITB_LastError` diagnostic.
Opts are passed as hashtables (rendered pair-wise into the
URL-query opts string: booleans as `true` / `false`, byte arrays as
lowercase hex, arrays comma-joined) or as a prebuilt `[Everanium.Itb3.Opts]`:

```powershell
$pipe = New-ItbPipeline -Profile 'streaming-aead-triple-mac-v1' `
    -Opts @{ chunkSize = 65536; innerHash = 'blake3' }
```

## Persisting sessions

The blob `Save-ItbPipeline` returns is self-describing: it carries the profile
record (the resolved pipeline shape) alongside the key material, so
a receiver reconstructs the session from the blob alone.

```powershell
$blob = Save-ItbPipeline -Pipeline $sender                 # current session blob
Save-ItbPipeline -Pipeline $sender -Path /path/session.blob # same bytes, written by the library (mode 0600)
$a = Import-ItbPipeline -Blob $blob                        # reopen from bytes
$b = Import-ItbPipeline -Path /path/session.blob           # reopen from a file
$c = Import-ItbPipeline -Blob $blob -PermMaster $perm -WrapMaster $wrap # master override
$p = Get-ItbProfile -Blob $blob                            # a Profile object; no Pipeline opened
```

Load works for blobs generated with shipped primitives (every entry
in the shipped catalogue). Blobs generated by Go programs that use
`hashes.Register` or `macs.Register` to install custom primitives
cannot be loaded through this binding — the receiver must use the Go
library directly and register the same custom primitive under the
same name before opening. Attempting to load such a blob through
this binding surfaces `[Everanium.Itb3.Status]::RecipePrimitiveUnknown`. A blob from an earlier wrap-layer
version surfaces `[Everanium.Itb3.Status]::BadInput`; a record that fails the profile field
rules surfaces `[Everanium.Itb3.Status]::BlobMalformedRecipe`.

The profile registry is reachable through the same `Itb.Profile`
record:

```powershell
$names = Get-ItbProfileName                                # sorted registry names
$shipped = Get-ItbProfile -Name 'singlemsg-triple-nomac-v1'
$custom = New-ItbProfile @{ Mode = 'singlemsg-nomac'; Width = 512; Hash = 'areion512'
                            KeyBits = 1024; Wrapper = $false; Parallax = $false }
Register-ItbProfile -Name 'my-profile' -Profile $custom    # validated by Go; duplicate -> ProfileExists
Register-ItbProfile -Name 'other-profile' -Profile @{ Mode = 'singlemsg-nomac'; Width = 512
                                                      Hash = 'areion512'; KeyBits = 1024 }
```

`Itb.Profile` is a plain record plus JSON codec — no validation happens
on the binding side. `Get-ItbProfile -Blob` / `Get-ItbProfile -Name` return it; `Register-ItbProfile`
accepts it; an unknown name at `New-ItbPipeline` / `Get-ItbProfile -Name` surfaces `[Everanium.Itb3.Status]::UnknownProfile`.

Runtime tuning: `Set-ItbMaxWorkers -Pipeline $pipe -Count $n` sets the worker cap for every
subsequent cipher call (`n <= 0` selects auto, `n > 256` is clamped
to 256); the receiver may pick its own worker cap after `Import-ItbPipeline` — the
cap is per-machine and never written to the blob.

## Memory

Two process-wide knobs constrain Go runtime arena pacing, readable
at libitb3 load time via env vars (`ITB_GOMEMLIMIT`, `ITB_GOGC`) and
adjustable at any time programmatically. Pass a negative value to
query without changing:

```powershell
Set-ItbMemoryLimit -Bytes 4GB
Set-ItbGCPercent -Percent 100
```

## Testing

```bash
./bindings/powershell/run_tests.sh
```

The harness builds the C# peer, exports `ITB_LIBITB3_PATH`, and
invokes Pester over `Tests/Everanium.LibItb3.Tests`. Positional arguments narrow
the run to matching test files (e.g. `./run_tests.sh Smoke`). The
suite covers Single Message round trips per shipped profile, stream
pumps (file and stream shapes), incremental sessions with
pathological batch sizes, tampered-wire failure stickiness,
mid-flight cancellation, rekey, session persistence (save / load, saveF / loadF, inspect, lookup / profiles / register, maxWorkers), error mapping,
and opts rendering — surface parity checks; the deep suite lives in
Go under the shipped tree.

## Benchmarking

```bash
./bindings/powershell/run_bench.sh            # both shapes
./bindings/powershell/run_bench.sh message    # Single Message shape only
./bindings/powershell/run_bench.sh stream     # stream-pump shape only
```

`Stopwatch`-timed micro-benches: `EncryptMessage` and stream-pump
throughput at 1 MiB / 16 MiB / 64 MiB. Shape and budget are driven
by the `ITB_*` env vars listed in `Bench/BenchUtil.ps1`; defaults
match the root Go BENCH3.md pin. The cipher work runs on the .NET /
Go side, so PowerShell adds one scriptblock hop per whole-payload
iteration — negligible at MiB scale.

## itb3 CLI

The Go core ships an openssl-style CLI utility
[`itb3`](https://github.com/everanium/itb/tree/main/cmd/itb3/) that generates session blobs on disk
(`itb3 genblob <mode> <hash> -o blob.json`); this binding reopens
such blobs via `Import-ItbPipeline -Path`. `itb3` also encrypts /
decrypts payloads directly on disk (`-i` / `-o`) or through stdin /
stdout, rotates outer masters, and inspects stored blobs. See
[`cmd/itb3/README.md`](https://github.com/everanium/itb/blob/main/cmd/itb3/README.md) for the full
subcommand reference.

## eitb utility

The `eitb/eitb.ps1` script mirrors the shipped Go `tools/eitb` scope
for shell smoke tests:

```bash
cd bindings/powershell/eitb
./eitb.ps1 version
./eitb.ps1 profiles
./eitb.ps1 encrypt singlemsg-triple-mac-v1 in.bin out.bin  # blob hex on stderr
./eitb.ps1 decrypt singlemsg-triple-mac-v1 <blob-hex> out.bin back.bin
```

## Limitations

- The binding wraps the Triple Pipeline surface only. The Low-Level
  seed / MAC / blob / wrapper / parallax APIs are not exposed — use
  the shipped Go core for those.
- PowerShell cannot hold ByRef-like values (`ReadOnlySpan` /
  `Span`); every C# entry consumed by the module returns `byte[]` /
  `Itb.Profile` / `string` values. Passing `byte[]` arguments into
  span-typed parameters is handled by the PowerShell binder.
- Cipher cmdlets return `byte[]` as a single pipeline item
  (`Write-Output -NoEnumerate`); when piping a byte array INTO a
  cmdlet, prefix with a comma (`,$wire | Invoke-ItbDecrypt ...`) or
  pass it via `-Data` — an unwrapped array is accumulated
  element-wise, which is correct but slow for large payloads.
- Streaming-decrypt caveat: chunked Streaming AEAD verifies per
  chunk, so plaintext of verified chunks is released before a later
  chunk can fail authentication.
- `ITB_LastError` is process-global last-write-wins; the textual
  diagnostic attached to an `ItbException` may belong to a different
  call under concurrent use. The status code is always attributable.
- `Invoke-ItbRekey` must not run concurrently with cipher calls or
  open stream sessions on the same Pipeline.
- `Everanium.LibItb3.dll` and libitb3 must be reachable at runtime through the
  lookup order above.

## License

Apache-2.0 — see [LICENSE](https://github.com/everanium/itb/blob/main/LICENSE).
