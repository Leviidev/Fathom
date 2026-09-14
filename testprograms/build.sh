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
    gcc -static-pie -O2 -g -o fathom-selftest fathom-selftest.c
    ./fathom-selftest > /dev/null
    nm -n fathom-selftest > fathom-selftest.symbols
'

echo "==> Built $HERE/fathom-selftest"
file "$HERE/fathom-selftest"

mkdir -p "$DEST_DIR"
cp -f "$HERE/fathom-selftest" "$DEST_DIR/fathom-selftest"
echo "==> Copied to $DEST_DIR/fathom-selftest"
echo "==> Symbols in $HERE/fathom-selftest.symbols (for resolving a logged guest RIP)"
