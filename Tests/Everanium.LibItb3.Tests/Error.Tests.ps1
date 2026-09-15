# Error-mapping surface: opaque-string relay, closed Pipeline,
# duplicate profile registration (with an 8-entry mixed
# constellation), unknown lookup, Set-ItbMaxWorkers on a closed handle.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelper.ps1')
}

Describe 'Error mapping' {
    It 'surfaces an unknown profile as UnknownProfile with a diagnostic' {
        try {
            New-ItbPipeline -Profile 'no-such-profile'
            throw 'expected ItbException'
        }
        catch [Everanium.Itb3.ItbException] {
            $_.Exception.Status | Should -Be ([Everanium.Itb3.Status]::UnknownProfile)
            $_.Exception.Message | Should -Not -BeNullOrEmpty
        }
    }

    It 'surfaces an unknown lookup name as UnknownProfile' {
        try {
            Get-ItbProfile -Name 'no-such-profile'
            throw 'expected ItbException'
        }
        catch [Everanium.Itb3.ItbException] {
            $_.Exception.Status | Should -Be ([Everanium.Itb3.Status]::UnknownProfile)
        }
    }

    It 'reports TripleClosed from Set-ItbMaxWorkers after Close-ItbPipeline -KeepHandle' {
        $pipe = New-ItbPipeline -Profile 'singlemsg-triple-mac-v1'
        try {
            Close-ItbPipeline -Pipeline $pipe -KeepHandle
            try {
                Set-ItbMaxWorkers -Pipeline $pipe -Count 2
                throw 'expected ItbException'
            }
            catch [Everanium.Itb3.ItbException] {
                $_.Exception.Status | Should -Be ([Everanium.Itb3.Status]::TripleClosed)
            }
        }
        finally { $pipe.Dispose() }
    }

    It 'reports TripleClosed after Close-ItbPipeline -KeepHandle' {
        $pipe = New-ItbPipeline -Profile 'singlemsg-triple-mac-v1'
        try {
            Close-ItbPipeline -Pipeline $pipe -KeepHandle
            Close-ItbPipeline -Pipeline $pipe -KeepHandle   # idempotent
            try {
                Invoke-ItbEncrypt -Pipeline $pipe -Data 'payload'
                throw 'expected ItbException'
            }
            catch [Everanium.Itb3.ItbException] {
                $_.Exception.Status | Should -Be ([Everanium.Itb3.Status]::TripleClosed)
            }
        }
        finally { $pipe.Dispose() }
    }

    It 'registers a mixed profile, round-trips it, and rejects a duplicate' {
        # 8-entry width-256 mixed constellation, layers off.
        $profile = [ordered]@{
            Mode     = 'singlemsg-nomac'
            Width    = 256
            Hashes   = @('blake3', 'blake2s', 'areion256', 'blake2b256',
                'chacha20', 'blake3', 'blake2s', 'areion256')
            KeyBits  = 1024
            Parallax = $false
            Wrapper  = $false
        }
        Register-ItbProfile -Name 'pwsh-binding-test-mixed' -Profile $profile

        $sender = New-ItbPipeline -Profile 'pwsh-binding-test-mixed'
        try {
            $receiver = Import-ItbPipeline -Blob (Save-ItbPipeline $sender)
            try {
                $wire = Invoke-ItbEncrypt -Pipeline $sender -Data 'custom profile'
                $back = Invoke-ItbDecrypt -Pipeline $receiver -Data $wire
                [System.Text.Encoding]::UTF8.GetString($back) | Should -Be 'custom profile'
            }
            finally { $receiver.Dispose() }
        }
        finally { $sender.Dispose() }

        # Duplicate name is a distinct status.
        try {
            Register-ItbProfile -Name 'pwsh-binding-test-mixed' -Profile $profile
            throw 'expected ItbException'
        }
        catch [Everanium.Itb3.ItbException] {
            $_.Exception.Status | Should -Be ([Everanium.Itb3.Status]::ProfileExists)
        }
    }

    It 'relays an opaque unknown primitive name to Go for rejection' {
        # The binding performs no name validation of its own.
        try {
            New-ItbPipeline -Profile 'singlemsg-triple-mac-v1' `
                -Opts @{ innerHash = 'no-such-hash' }
            throw 'expected ItbException'
        }
        catch [Everanium.Itb3.ItbException] {
            $_.Exception.Status | Should -Not -Be ([Everanium.Itb3.Status]::Ok)
        }
    }
}
