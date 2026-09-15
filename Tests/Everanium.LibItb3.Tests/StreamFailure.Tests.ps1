# Failure-path behavior of stream sessions: a tampered wire fails
# with a sticky MAC failure, and disposing a session mid-flight
# leaves the Pipeline usable.
#
# The tamper check uses a position probe rather than a single bit
# flip because the over-sized container carries CSPRNG residue in the
# non-payload area — a flip that lands inside the residue is
# architecturally inert (residue is not payload) and the session
# finishes clean. Probing 32 evenly-spaced positions makes the
# all-residue probability negligible; the first position that
# surfaces an error must give Status MacFailure and remain sticky on
# subsequent reads.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelper.ps1')
}

Describe 'Stream failure paths' {
    It 'fails sticky with MacFailure on a tampered wire' {
        $sender = New-ItbPipeline -Profile 'streaming-aead-triple-mac-v1'
        try {
            $receiver = Import-ItbPipeline -Blob (Save-ItbPipeline $sender)
            try {
                $plain = New-TestPayload -Size 64KB -Seed 3001
                $baseWire = Invoke-ItbEncryptStream -Pipeline $sender -Data $plain
                $baseWire.Length | Should -BeGreaterThan 128

                $probes = 32
                # Evenly spread through the wire body; skip the first /
                # last 16 bytes so a hit against the outer envelope
                # framing does not muddy the observation.
                $bodyStart = 16
                $stride = [int](($baseWire.Length - 32) / $probes)
                $surfaced = $false

                for ($probe = 0; $probe -lt $probes; $probe++) {
                    $idx = $bodyStart + $probe * $stride
                    $wire = [byte[]]$baseWire.Clone()
                    $wire[$idx] = $wire[$idx] -bxor 0x01

                    $session = New-ItbDecryptStream -Pipeline $receiver
                    try {
                        # Ignore Write / End status — the failure may
                        # surface on either side or only on the drain.
                        try {
                            $session.Write($wire)
                            $session.End()
                        }
                        catch { }

                        $buf = [byte[]]::new(4096)
                        $firstErr = $null
                        $finishedClean = $false
                        $finished = $false
                        while ($true) {
                            try {
                                [void]$session.Read($buf, [ref]$finished)
                                if ($finished) {
                                    $finishedClean = $true
                                    break
                                }
                            }
                            catch {
                                $firstErr = $_.Exception.InnerException
                                break
                            }
                        }
                        if ($finishedClean) {
                            # Residue hit at this offset — next probe.
                            continue
                        }
                        $firstErr | Should -BeOfType ([Everanium.Itb3.ItbException])
                        $firstErr.Status | Should -Be ([Everanium.Itb3.Status]::MacFailure) `
                            -Because "probe $probe (byte $idx) must surface a MAC failure"

                        # Sticky: a subsequent read reports the same status.
                        try {
                            [void]$session.Read($buf, [ref]$finished)
                            throw 'expected a sticky failure on re-read'
                        }
                        catch [System.Management.Automation.MethodInvocationException] {
                            $_.Exception.InnerException.Status |
                                Should -Be $firstErr.Status
                        }
                        $surfaced = $true
                        break
                    }
                    finally { $session.Dispose() }
                }
                $surfaced | Should -BeTrue `
                    -Because ("some probe among $probes evenly-spaced positions " +
                    'must surface a MAC failure')
            }
            finally { $receiver.Dispose() }
        }
        finally { $sender.Dispose() }
    }

    It 'leaves the Pipeline usable after disposing a session mid-flight' {
        $sender = New-ItbPipeline -Profile 'streaming-aead-triple-mac-v1'
        try {
            $session = New-ItbEncryptStream -Pipeline $sender
            $block = [byte[]]::new(100000)
            for ($i = 0; $i -lt $block.Length; $i++) { $block[$i] = 0xA5 }
            $session.Write($block)
            # Disposed here without End() — Dispose cancels and frees
            # the session; the test completing (process not hanging)
            # is the assertion.
            $session.Dispose()

            $receiver = Import-ItbPipeline -Blob (Save-ItbPipeline $sender)
            try {
                $wire = Invoke-ItbEncrypt -Pipeline $sender -Data 'after cancel'
                $back = Invoke-ItbDecrypt -Pipeline $receiver -Data $wire
                [System.Text.Encoding]::UTF8.GetString($back) | Should -Be 'after cancel'
            }
            finally { $receiver.Dispose() }
        }
        finally { $sender.Dispose() }
    }
}
