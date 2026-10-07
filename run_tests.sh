#!/usr/bin/env bash
#
# One-step test runner for the PowerShell binding. Builds the C# peer via
# build.sh, points ITB_LIBITB3_PATH at the freshly-built shared library, then
# invokes Pester over Tests/Everanium.LibItb3.Tests. Positional arguments narrow
# the run to matching test files (e.g. `./run_tests.sh Smoke StreamPump`).
#
# The test files are not compiled, so what has to be current is the C#
# assembly they bind. build.sh delegates that to ../csharp/build.sh,
# which cleans and rebuilds its own tree, so the assembly exercised
# here is always the one this invocation produced. Set
# ITB_SKIP_CLEAN=1 to keep the existing artefacts and build
# incrementally instead.
#
# Usage:
#   ./run_tests.sh          # all tests
#   ./run_tests.sh Smoke    # only Tests/Everanium.LibItb3.Tests/Smoke.Tests.ps1

set -eu
set -o pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"
DIST_DIR="$REPO_ROOT/dist/linux-amd64"

./build.sh

export ITB_LIBITB3_PATH="$DIST_DIR/libitb3.so"
export ITB_PWSH_TEST_FILTERS="$*"

exec pwsh -NoProfile -Command '
    $filters = @($env:ITB_PWSH_TEST_FILTERS -split "\s+" | Where-Object { $_ })
    $path = if ($filters.Count -gt 0) {
        $filters | ForEach-Object { "Tests/Everanium.LibItb3.Tests/$_.Tests.ps1" }
    } else {
        "Tests/Everanium.LibItb3.Tests"
    }
    $config = New-PesterConfiguration
    $config.Run.Path = $path
    $config.Run.Exit = $true
    $config.Output.Verbosity = "Detailed"
    Invoke-Pester -Configuration $config
'
