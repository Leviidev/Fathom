#!/usr/bin/env bash
# Builds a Debian root filesystem with Steam's launcher installed, for running under
# Fathom on macOS.
#
# The .deb is only a bootstrapper: 61 files, of which the one that matters is
# bootstraplinux_ubuntu12_32.tar.xz. Steam downloads the rest of itself on first run.
#
# Unpacking it needs care. Debian uses merged-/usr, so /lib is a *symlink* to usr/lib,
# and the package ships a ./lib/udev directory. Letting tar extract that replaces the
# symlink with a real directory containing nothing but udev rules -- at which point no
# library on the system can be found and every binary fails to start.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEB="${DEB:-$HOME/Downloads/steam_latest.deb}"
ROOT="${1:-$REPO_ROOT/build/steam-root}"

if [[ ! -f "$DEB" ]]; then
    echo "error: $DEB not found; put Valve's steam .deb there or set DEB=" >&2
    exit 1
fi

bash "$REPO_ROOT/scripts/fetch-debian-rootfs.sh" "$ROOT"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> unpacking $(basename "$DEB")"
(cd "$WORK" && ar x "$DEB")
mkdir -p "$WORK/payload"
tar -xJf "$WORK/data.tar.xz" -C "$WORK/payload"

export ROOT
echo "==> installing over the root filesystem, following its symlinks"
# -L makes cp follow the rootfs's own /lib -> usr/lib rather than replacing it.
(cd "$WORK/payload" && find . -type d -exec mkdir -p "$ROOT/{}" \; )
(cd "$WORK/payload" && find . -type f -exec sh -c 'd="$ROOT/$(dirname "$1")"; mkdir -p "$d"; cp -p "$1" "$d/"' _ {} \; )
(cd "$WORK/payload" && find . -type l -exec sh -c 'd="$ROOT/$(dirname "$1")"; mkdir -p "$d"; cp -P "$1" "$d/"' _ {} \; )

mkdir -p "$ROOT/root" "$ROOT/tmp"
chmod 1777 "$ROOT/tmp"

echo "==> checking the root filesystem still works"
if [[ ! -L "$ROOT/lib" ]]; then
    echo "warning: /lib is no longer a symlink; libraries will not be found" >&2
fi
printf '==> ready: %s\n' "$ROOT"
printf '    run with: build/host/fathom-run --root %s --env HOME=/root /bin/bash /usr/bin/steam\n' "$ROOT"
