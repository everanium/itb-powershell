# Whole-buffer Stream throughput vs plaintext size (Streaming
# Non-AEAD profile) at 1 MiB / 16 MiB / 64 MiB. Times
# Pipeline.EncryptStreamOneShot / DecryptStreamOneShot, the single
# FFI round-trip surface for callers holding the whole payload in
# memory.

. (Join-Path $PSScriptRoot 'BenchUtil.ps1')

$pipe = New-ItbPipeline `
    -Profile (Get-BenchProfileName -Fallback 'streaming-noaead-triple-v1') `
    -Opts (Get-BenchOpts)
try {
    Write-BenchHeader
    foreach ($size in $script:BenchSizes) {
        $plain = New-BenchPayload -Size $size
        Invoke-BenchCase -Name 'stream_one_shot' -Size $size -Body {
            [void]$pipe.EncryptStreamOneShot($plain)
        }.GetNewClosure()
        # Pre-encrypt one wire outside the decrypt timing loop.
        $decWire = $pipe.EncryptStreamOneShot($plain)
        Invoke-BenchCase -Name 'stream_one_shot-dec' -Size $size -Body {
            [void]$pipe.DecryptStreamOneShot($decWire)
        }.GetNewClosure()
    }
}
finally {
    $pipe.Dispose()
}
