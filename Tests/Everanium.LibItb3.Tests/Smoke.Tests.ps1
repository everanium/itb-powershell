# New-ItbPipeline -> Save-ItbPipeline -> Import-ItbPipeline -> encrypt -> decrypt
# round trip.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelper.ps1')
}

Describe 'Smoke' {
    It 'round-trips a Single Message through Init / Import' {
        $sender = New-ItbPipeline -Profile 'singlemsg-triple-mac-v1'
        try {
            $blob = Save-ItbPipeline $sender
            $blob | Should -Not -BeNullOrEmpty
            $blob.GetType().Name | Should -Be 'Byte[]'

            $receiver = Import-ItbPipeline -Blob $blob
            try {
                $plain = [System.Text.Encoding]::UTF8.GetBytes('smoke round-trip payload')
                $wire = Invoke-ItbEncrypt -Pipeline $sender -Data $plain
                (Test-BytesEqual $wire $plain) | Should -BeFalse

                $back = Invoke-ItbDecrypt -Pipeline $receiver -Data $wire
                (Test-BytesEqual $back $plain) | Should -BeTrue
            }
            finally { $receiver.Dispose() }
        }
        finally { $sender.Dispose() }
    }

    It 'accepts a string -Data and supports pipeline input' {
        $sender = New-ItbPipeline -Profile 'singlemsg-triple-mac-v1'
        try {
            $receiver = Import-ItbPipeline -Blob (Save-ItbPipeline $sender)
            try {
                $wire = Invoke-ItbEncrypt -Pipeline $sender -Data 'string payload'
                $back = , $wire | Invoke-ItbDecrypt -Pipeline $receiver
                [System.Text.Encoding]::UTF8.GetString($back) | Should -Be 'string payload'
            }
            finally { $receiver.Dispose() }
        }
        finally { $sender.Dispose() }
    }

    It 'reports library, C# binding, and module versions' {
        $v = Get-ItbVersion
        $v.Library | Should -Not -BeNullOrEmpty
        $v.CSharpBinding | Should -Not -BeNullOrEmpty
        $v.Module | Should -Not -BeNullOrEmpty
    }
}
