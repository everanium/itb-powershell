# Runtime diagnostics surface: GOMAXPROCS query / set / restore, the
# heap-profile writer, the pool-counter snapshot and its slot layout,
# and the hash-registry enumeration.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelper.ps1')
}

Describe 'Runtime' {
    It 'queries, sets and restores GOMAXPROCS' {
        $orig = Set-ItbGOMAXPROCS 0
        $orig | Should -BeGreaterThan 0
        Set-ItbGOMAXPROCS -3 | Should -Be $orig
        Set-ItbGOMAXPROCS ($orig + 1) | Should -Be $orig
        Set-ItbGOMAXPROCS 0 | Should -Be ($orig + 1)
        Set-ItbGOMAXPROCS $orig | Should -Be ($orig + 1)
    }

    It 'writes a heap profile and rejects an empty path' {
        $dir = Join-Path ([System.IO.Path]::GetTempPath()) "itb-loop-test-heap-pwsh-$PID"
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        try {
            $path = Join-Path $dir 'heap.prof'
            Write-ItbHeapProfile $path
            (Get-Item $path).Length | Should -BeGreaterThan 0
        }
        finally { Remove-Item -Recurse -Force $dir }

        # The empty path falls back to ITB_MEMPROFILE inside libitb3;
        # with the variable clear there is nothing to fall back to.
        $env:ITB_MEMPROFILE = $null
        { Write-ItbHeapProfile '' } | Should -Throw
    }

    It 'reports a pool-counter vector matching the declared slot layout' {
        $len = Get-ItbPoolStatsLength
        $len | Should -BeGreaterOrEqual 9
        $v = Get-ItbPoolStats
        $v.Length | Should -Be $len
        $tiers = $v[0]
        $tiers | Should -BeGreaterThan 0
        (1 + 5 * $tiers + 8) | Should -Be $len
    }

    It 'enumerates the shipped hash registry in canonical order' {
        $names = Get-ItbHashName
        $names[0] | Should -Be 'aesitb128'
        $names | Should -Contain 'areion512'
    }
}
