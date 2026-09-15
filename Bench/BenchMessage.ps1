# EncryptMessage throughput vs plaintext size (Single Message
# profile) at 1 MiB / 16 MiB / 64 MiB.

. (Join-Path $PSScriptRoot 'BenchUtil.ps1')

$pipe = New-ItbPipeline `
    -Profile (Get-BenchProfileName -Fallback 'singlemsg-triple-nomac-v1') `
    -Opts (Get-BenchOpts)
try {
    Write-BenchHeader
    foreach ($size in $script:BenchSizes) {
        $plain = New-BenchPayload -Size $size
        # The cipher call runs on the .NET side; the scriptblock hop
        # is once per whole-payload iteration, so PowerShell overhead
        # is negligible at MiB scale.
        Invoke-BenchCase -Name 'message' -Size $size -Body {
            [void]$pipe.EncryptMessage($plain)
        }.GetNewClosure()
        # Pre-encrypt one wire outside the decrypt timing loop.
        $decWire = $pipe.EncryptMessage($plain)
        Invoke-BenchCase -Name 'message-dec' -Size $size -Body {
            [void]$pipe.DecryptMessage($decWire)
        }.GetNewClosure()
    }
}
finally {
    $pipe.Dispose()
}
