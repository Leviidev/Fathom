#!/usr/bin/env bash
# Fetches an Alpine x86-64 minirootfs and stages it as the guest root filesystem that
# ships inside the app.
#
# Alpine is the first target because it is tiny -- a few megabytes -- which matters when
# the rootfs has to travel inside the IPA. Fathom has no networking yet, so there is no
# way to download one on device. It is musl-based; glibc (Debian) comes later, when
# Steam needs it.
#
# The result is an *uncompressed* tar, because the IPA is a zip and compresses it anyway,
# and because a plain tar is something the app can unpack without a decompressor.
set -euo pipefail

VERSION="${ALPINE_VERSION:-3.22.5}"
BRANCH="v${VERSION%.*}"
ARCH="x86_64"
NAME="alpine-minirootfs-${VERSION}-${ARCH}.tar.gz"
BASE="https://dl-cdn.alpinelinux.org/alpine/${BRANCH}/releases/${ARCH}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$REPO_ROOT/Fathom/Resources/guest-rootfs.tar"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> downloading $NAME"
curl -fsSL --retry 3 -o "$WORK/$NAME" "$BASE/$NAME"
curl -fsSL --retry 3 -o "$WORK/$NAME.sha256" "$BASE/$NAME.sha256"

echo "==> verifying checksum"
expected="$(awk '{print $1}' "$WORK/$NAME.sha256")"
actual="$(shasum -a 256 "$WORK/$NAME" | awk '{print $1}')"
if [ "$expected" != "$actual" ]; then
    echo "checksum mismatch: expected $expected, got $actual" >&2
    exit 1
fi
echo "    $actual"

echo "==> repacking as an uncompressed tar"
mkdir -p "$WORK/root"
tar -xzf "$WORK/$NAME" -C "$WORK/root" --no-same-owner --no-same-permissions
# Alpine ships no /dev, /proc or /sys in the minirootfs; the guest expects them to exist.
mkdir -p "$WORK/root/dev" "$WORK/root/proc" "$WORK/root/sys" "$WORK/root/tmp" "$WORK/root/root"
# COPYFILE_DISABLE stops macOS tar from writing an AppleDouble "._name" companion entry
# for every file, which would otherwise double the entry count and litter the guest root
# with 500-odd files Linux has no use for.
COPYFILE_DISABLE=1 tar -cf "$OUT" --no-mac-metadata -C "$WORK/root" .

printf '==> wrote %s (%s)\n' "$OUT" "$(du -h "$OUT" | cut -f1)"
printf '    alpine %s, %s files\n' "$VERSION" "$(tar -tf "$OUT" | wc -l | tr -d ' ')"
