# Explicit Write / End / Read round trip with pathological batch
# sizes (17-byte feed, 23-byte drain) across multiple chunks.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelper.ps1')

    function Invoke-BatchedSession {
        # Feeds $Payload in 17-byte writes, then End + 23-byte drains.
        param(
            [Parameter(Mandatory)][object]$Session,
            [Parameter(Mandatory)][byte[]]$Payload
        )
        try {
            for ($off = 0; $off -lt $Payload.Length; $off += 17) {
                $n = [Math]::Min(17, $Payload.Length - $off)
                $batch = [byte[]]::new($n)
                [System.Array]::Copy($Payload, $off, $batch, 0, $n)
                $Session.Write($batch)
            }
            $Session.End()
            $spool = [System.IO.MemoryStream]::new()
            $buf = [byte[]]::new(23)
            $finished = $false
            while ($true) {
                $n = $Session.Read($buf, [ref]$finished)
                $spool.Write($buf, 0, $n)
                if ($finished) { break }
            }
            Write-Output -NoEnumerate $spool.ToArray()
        }
        finally { $Session.Dispose() }
    }
}

Describe 'Incremental stream sessions' {
    It 'round-trips 64 KiB with 17-byte writes and 23-byte drains' {
        # Small chunk size so the 64 KiB payload spans many chunks.
        $opts = @{ chunkSize = 4096 }
        $sender = New-ItbPipeline -Profile 'streaming-aead-triple-mac-v1' -Opts $opts
        try {
            $receiver = Import-ItbPipeline -Blob (Save-ItbPipeline $sender)
            try {
                $plain = New-TestPayload -Size 64KB -Seed 2001

                $wire = Invoke-BatchedSession `
                    -Session (New-ItbEncryptStream -Pipeline $sender) -Payload $plain
                $wire.Length | Should -BeGreaterThan 0

                $back = Invoke-BatchedSession `
                    -Session (New-ItbDecryptStream -Pipeline $receiver) -Payload $wire
                (Test-BytesEqual $back $plain) | Should -BeTrue
            }
            finally { $receiver.Dispose() }
        }
        finally { $sender.Dispose() }
    }
}
