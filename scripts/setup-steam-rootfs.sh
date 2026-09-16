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

echo "==> installing the launcher"
# One entry point for both the app and the host runner. Steam draws into an X server, so
# something has to be listening on :0 before the client starts -- and it has to be the
# same session, because the client finds the server through a socket inside this root.
mkdir -p "$ROOT/usr/local/bin"
cat > "$ROOT/usr/local/bin/fathom-steam" <<'LAUNCHER'
#!/bin/bash
# Starts a display, then Steam on it.
export HOME="${HOME:-/root}"
export USER="${USER:-root}"
export DISPLAY="${DISPLAY:-:0}"
export PATH=/usr/local/bin:/usr/bin:/bin
export LANG="${LANG:-C}"
# Steam's own runtime is a second copy of a distribution, and this root already is one.
export STEAMOS=0
export STEAM_RUNTIME="${STEAM_RUNTIME:-0}"

# Starting a session is starting a machine: the X server's lock, its socket and Steam's
# pid file all describe a process from the last run that is no longer there. Left alone,
# the server refuses to start and Steam decides it is already running and exits.
rm -rf /tmp/.X0-lock /tmp/.X11-unix /tmp/fb /tmp/.fathom-abstract
rm -f "$HOME/.steampid" "$HOME/.steam/steam.pid" "$HOME/.steam/steam.pipe"
mkdir -p /tmp/fb /tmp/.X11-unix /tmp/.ICE-unix
chmod 1777 /tmp/.X11-unix /tmp/.ICE-unix

# -fbdir puts the framebuffer in a file, which is how the host gets the picture: it maps
# the same file and every pixel X draws is already in its address space.
Xvfb :0 -ac -screen 0 "${FATHOM_SCREEN:-1280x720x24}" -fbdir /tmp/fb &

for _ in $(seq 1 400); do
    [ -e /tmp/.X11-unix/X0 ] && break
    usleep 25000 2>/dev/null || sleep 1
done
if [ ! -e /tmp/.X11-unix/X0 ]; then
    echo "fathom-steam: the X server did not start" >&2
    exit 1
fi

exec /root/.local/share/Steam/steam.sh "$@"
LAUNCHER
chmod +x "$ROOT/usr/local/bin/fathom-steam"

echo "==> checking the root filesystem still works"
if [[ ! -L "$ROOT/lib" ]]; then
    echo "warning: /lib is no longer a symlink; libraries will not be found" >&2
fi
printf '==> ready: %s\n' "$ROOT"
printf '    run with: build/host/fathom-run --root %s --env HOME=/root /usr/local/bin/fathom-steam\n' "$ROOT"
