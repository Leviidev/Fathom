#!/usr/bin/env bash
# Builds the self-test as a static-pie x86-64 Linux binary.
#
# Cross-compiled in an amd64 Alpine container because nothing on macOS produces Linux
# ELFs natively. static-pie specifically: a non-PIE binary wants to load at 0x400000 and
# an iOS process has nothing mappable down there (see the README).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST_DIR="${1:-$HOME/Desktop}"

docker run --rm --platform linux/amd64 -v "$HERE":/work -w /work alpine:3.20 sh -c '
    apk add --no-cache gcc musl-dev >/dev/null 2>&1
    # Deliberately not stripped: when the guest stalls, Fathom logs the guest RIP, and
    # symbols are what turn that number into a function name. (RIP minus the load base
    # Fathom logs at startup gives the address to look up.)
    for program in fathom-selftest tictactoe play2048; do
        gcc -static-pie -O2 -g -o "$program" "$program.c"
        nm -n "$program" > "$program.symbols"
    done
    # Only the self-test can run unattended; the games want a terminal.
    ./fathom-selftest > /dev/null
'

echo "==> Built"
file "$HERE/fathom-selftest" "$HERE/tictactoe" "$HERE/play2048"

mkdir -p "$DEST_DIR"
for program in fathom-selftest tictactoe play2048; do
    cp -f "$HERE/$program" "$DEST_DIR/$program"
    echo "==> Copied $DEST_DIR/$program"
done
echo "==> Symbols alongside each binary (for resolving a logged guest RIP)"
