# Stream-pump throughput vs plaintext size (Streaming Non-AEAD
# profile) at 1 MiB / 16 MiB / 64 MiB.

. (Join-Path $PSScriptRoot 'BenchUtil.ps1')

$pipe = New-ItbPipeline `
    -Profile (Get-BenchProfileName -Fallback 'streaming-noaead-triple-v1') `
    -Opts (Get-BenchOpts)
try {
    Write-BenchHeader
    foreach ($size in $script:BenchSizes) {
        $plain = New-BenchPayload -Size $size
        Invoke-BenchCase -Name 'stream_pump' -Size $size -Body {
            $wire = [System.IO.MemoryStream]::new(
                [int]($size + ($size -shr 2) + 131072))
            $pipe.EncryptStreamPump(
                [System.IO.MemoryStream]::new($plain, $false), $wire)
        }.GetNewClosure()
        # Pre-encrypt one wire outside the decrypt timing loop.
        $setupWire = [System.IO.MemoryStream]::new(
            [int]($size + ($size -shr 2) + 131072))
        $pipe.EncryptStreamPump(
            [System.IO.MemoryStream]::new($plain, $false), $setupWire)
        $decWire = $setupWire.ToArray()
        Invoke-BenchCase -Name 'stream_pump-dec' -Size $size -Body {
            $out = [System.IO.MemoryStream]::new([int]($size + 131072))
            $pipe.DecryptStreamPump(
                [System.IO.MemoryStream]::new($decWire, $false), $out)
        }.GetNewClosure()
    }
}
finally {
    $pipe.Dispose()
}
