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
    gcc -static-pie -O2 -s -o fathom-selftest fathom-selftest.c
    ./fathom-selftest > /dev/null
'

echo "==> Built $HERE/fathom-selftest"
file "$HERE/fathom-selftest"

mkdir -p "$DEST_DIR"
cp -f "$HERE/fathom-selftest" "$DEST_DIR/fathom-selftest"
echo "==> Copied to $DEST_DIR/fathom-selftest"
