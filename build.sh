#!/usr/bin/env bash
#
# build.sh -- one-step build for the PowerShell binding. The binding
# itself has no compilation step (script module); this driver builds
# the C# peer it proxies (libitb3.so + Everanium.LibItb3.dll via ../csharp/build.sh)
# and then verifies the module and the eitb script both load cleanly
# under pwsh. Prerequisites (Go, dotnet-sdk, pwsh 7.4+) must be
# installed separately; see README.md "Prerequisites" section.
#
# Nothing here is compiled, so the only artefacts this binding owns are
# Pester's test result output; those are removed first so no report can
# survive from an earlier invocation.
#
# The C# assembly is a shared producer, not something this binding
# owns, so it is never deleted from here: ../csharp/build.sh is invoked
# instead and performs its own clean. That clean is what this binding
# depends on, because the module resolves the assembly through a
# `bin/<config>/net*/Everanium.LibItb3.dll` glob -- a target framework
# directory left behind beside the current one would make that glob
# ambiguous, and the module would bind whichever the glob happened to
# return.
#
# Set ITB_SKIP_CLEAN=1 to keep the existing artefacts and build
# incrementally; it propagates to the C# layer as well. With no
# environment set the wipe always runs.
#
# Usage:
#   ./build.sh             # default build (full asm stack)
#   ./build.sh --noitbasm  # opt out of ITB's SIMD asm kernels

set -eu
set -o pipefail

cd "$(dirname "$0")"
BINDING_DIR="$(pwd -P)"
REPO_ROOT="$(cd ../.. && pwd -P)"
SKIP_CLEAN="${ITB_SKIP_CLEAN:-0}"

case "${1:-}" in
    --noitbasm) CSHARP_ARGS=(--noitbasm); shift;;
    -h|--help)  echo "usage: $0 [--noitbasm]"; exit 0;;
    "")         CSHARP_ARGS=();;
    *)          echo "unknown option: $1" >&2; exit 2;;
esac

# clean_under <root> <relative-path>...
#
# Removes each relative path under <root>. A target is removed only
# when it is a literal relative path (no leading slash, no ".."), it
# exists, and it still resolves inside <root> after symlinks are
# followed -- so a target can never escape the tree it belongs to.
# Every removal is logged before it happens, and a failing rm aborts
# the script rather than being swallowed.
clean_under() {
    local root="$1"; shift
    local rel abs
    root="$(realpath -e "$root")"
    for rel in "$@"; do
        case "$rel" in
            "" | /* | *..*)
                echo "clean: refusing suspicious target '$rel'" >&2
                exit 1
                ;;
        esac
        abs="$root/$rel"
        if [ ! -e "$abs" ] && [ ! -L "$abs" ]; then
            echo "[clean] (absent) $abs"
            continue
        fi
        abs="$(realpath -e "$abs")"
        case "$abs/" in
            "$root"/?*) ;;
            *)
                echo "clean: refusing to remove '$abs' -- outside $root" >&2
                exit 1
                ;;
        esac
        echo "[clean] rm -rf $abs"
        rm -rf "$abs"
    done
}

if [ "$SKIP_CLEAN" = "1" ]; then
    echo "==> ITB_SKIP_CLEAN=1 — keeping existing artefacts"
else
    echo "==> cleaning PowerShell binding artefacts"
    clean_under "$BINDING_DIR" TestResults Tests/TestResults
fi

echo "==> building C# peer (libitb3.so + Everanium.LibItb3.dll)"
../csharp/build.sh "${CSHARP_ARGS[@]:+${CSHARP_ARGS[@]}}"

cd "$BINDING_DIR"
export ITB_LIBITB3_PATH="${ITB_LIBITB3_PATH:-$REPO_ROOT/dist/linux-amd64/libitb3.so}"

echo "==> verifying module import (pwsh)"
pwsh -NoProfile -Command '
    Import-Module ./Everanium.LibItb3/Everanium.LibItb3.psd1 -Force
    $v = Get-ItbVersion
    Write-Host ("libitb3 {0} / itb-csharp {1} / module {2}" -f `
        $v.Library, $v.CSharpBinding, $v.Module)
'

# eitb is a script rather than a compiled artefact, so there is nothing
# to produce for it. Running the `version` subcommand is the equivalent
# guarantee: it imports the module, binds the C# assembly the build just
# produced and exercises the script end to end.
echo "==> verifying eitb script (pwsh)"
pwsh -NoProfile -File eitb/eitb.ps1 version

echo "==> ready: ./run_tests.sh"
