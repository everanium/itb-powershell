# Round trip through the stream pumps (file-to-file and
# stream-to-stream shapes) plus one-shot / pump cross-compatibility
# on a Streaming AEAD profile.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelper.ps1')
}

Describe 'Stream pumps' {
    BeforeAll {
        $script:Sender = New-ItbPipeline -Profile 'streaming-aead-triple-mac-v1'
        $script:Receiver = Import-ItbPipeline -Blob (Save-ItbPipeline $script:Sender)
    }

    AfterAll {
        $script:Receiver.Dispose()
        $script:Sender.Dispose()
    }

    It 'pump round-trips 1 MiB through MemoryStream endpoints' {
        $plain = New-TestPayload -Size 1MB -Seed 1001
        $wire = [System.IO.MemoryStream]::new()
        Invoke-ItbEncryptStream -Pipeline $script:Sender `
            -Source ([System.IO.MemoryStream]::new($plain, $false)) -Destination $wire
        $wire.Length | Should -BeGreaterThan 0

        $back = [System.IO.MemoryStream]::new()
        Invoke-ItbDecryptStream -Pipeline $script:Receiver `
            -Source ([System.IO.MemoryStream]::new($wire.ToArray(), $false)) `
            -Destination $back
        (Test-BytesEqual $back.ToArray() $plain) | Should -BeTrue
    }

    It 'pump round-trips file-to-file' {
        $plain = New-TestPayload -Size 300KB -Seed 1002
        $dir = Join-Path ([System.IO.Path]::GetTempPath()) `
            "itb-pwsh-test-$([guid]::NewGuid().ToString('n'))"
        New-Item -ItemType Directory -Path $dir | Out-Null
        try {
            $inFile = Join-Path $dir 'plain.bin'
            $wireFile = Join-Path $dir 'wire.bin'
            $backFile = Join-Path $dir 'back.bin'
            [System.IO.File]::WriteAllBytes($inFile, $plain)

            Invoke-ItbEncryptStream -Pipeline $script:Sender `
                -InFile $inFile -OutFile $wireFile
            (Get-Item $wireFile).Length | Should -BeGreaterThan 0

            Invoke-ItbDecryptStream -Pipeline $script:Receiver `
                -InFile $wireFile -OutFile $backFile
            $back = [System.IO.File]::ReadAllBytes($backFile)
            (Test-BytesEqual $back $plain) | Should -BeTrue
        }
        finally {
            Remove-Item -Recurse -Force $dir
        }
    }

    It 'one-shot wire decodes through the pump and vice versa' {
        $plain = New-TestPayload -Size 64KB -Seed 1003
        $wire = Invoke-ItbEncryptStream -Pipeline $script:Sender -Data $plain
        $wire.GetType().Name | Should -Be 'Byte[]'

        $back = [System.IO.MemoryStream]::new()
        Invoke-ItbDecryptStream -Pipeline $script:Receiver `
            -Source ([System.IO.MemoryStream]::new($wire, $false)) -Destination $back
        (Test-BytesEqual $back.ToArray() $plain) | Should -BeTrue

        $back2 = Invoke-ItbDecryptStream -Pipeline $script:Receiver -Data $wire
        (Test-BytesEqual $back2 $plain) | Should -BeTrue
    }
}
