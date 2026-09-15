# Single Message round trip across every shipped cipher profile at
# small (4 KiB) and medium (256 KiB) payloads. The blob-only profile
# has no cipher surface and is exercised in Error.Tests.ps1 instead.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelper.ps1')
}

Describe 'Message round trips' {
    It 'round-trips <_> at 4 KiB and 256 KiB' -ForEach @(
        'streaming-aead-triple-mac-v1'
        'streaming-noaead-triple-v1'
        'singlemsg-triple-mac-v1'
        'singlemsg-triple-nomac-v1'
        'streaming-aead-triple-mac-mixed-v1'
        'streaming-noaead-triple-mixed-v1'
        'singlemsg-triple-mac-mixed-v1'
        'singlemsg-triple-nomac-mixed-v1'
    ) {
        $profile = $_
        $sender = New-ItbPipeline -Profile $profile
        try {
            $receiver = Import-ItbPipeline -Blob (Save-ItbPipeline $sender)
            try {
                foreach ($size in 4KB, 256KB) {
                    $plain = New-TestPayload -Size $size -Seed $size
                    $wire = Invoke-ItbEncrypt -Pipeline $sender -Data $plain
                    $back = Invoke-ItbDecrypt -Pipeline $receiver -Data $wire
                    (Test-BytesEqual $back $plain) | Should -BeTrue `
                        -Because "profile $profile size $size must round-trip"
                }
            }
            finally { $receiver.Dispose() }
        }
        finally { $sender.Dispose() }
    }
}
