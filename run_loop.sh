#!/usr/bin/env bash
#
# Fleet entry point for the loop stress harness of the PowerShell
# binding: nothing is built here (the harness is script, and libitb3.so
# plus the C# assembly it binds are assumed built by build.sh), so the
# script is exec'd with every argument passed through.
#
# Usage:
#   ./run_loop.sh --duration 2m --shape both

set -eu
set -o pipefail

cd "$(dirname "$0")"

exec pwsh -NoProfile -File loop/Main.ps1 "$@"
