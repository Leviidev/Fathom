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

# A passwd entry for the user the guest actually is. Fathom reports uid 1000, and this
# root filesystem came out of a container image that only ever had root in it -- so
# getpwuid() finds nothing, and Steam, which asks it where home is rather than trusting
# $HOME, gives up with "Home directory not accessible: Permission denied".
if ! grep -q "^fathom:" "$ROOT/etc/passwd"; then
    echo 'fathom:x:1000:1000:Fathom:/root:/bin/bash' >> "$ROOT/etc/passwd"
fi
if ! grep -q "^fathom:" "$ROOT/etc/group"; then
    echo 'fathom:x:1000:' >> "$ROOT/etc/group"
fi

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
# Steam's web helper is started through pressure-vessel, which builds a container out of
# bubblewrap and user namespaces. Pointed here instead, at an entry point that runs the
# helper directly under the runtime's own loader -- see usr/local/lib/fathom-steamrt.
export STEAM_RUNTIME_STEAMRT="${STEAM_RUNTIME_STEAMRT:-/usr/local/lib/fathom-steamrt}"

# Starting a session is starting a machine: the X server's lock, its socket and Steam's
# pid file all describe a process from the last run that is no longer there. Left alone,
# the server refuses to start and Steam decides it is already running and exits.
rm -rf /tmp/.X0-lock /tmp/.X11-unix /tmp/fb /tmp/.fathom-abstract
# Chromium's "am I already running" lock, left behind by the last session. It names the
# process that held it, and process numbers here start again from the same place every
# time -- so the lock always appears to belong to something still alive, and the web
# helper spends its startup trying to hand over to an instance that is not there.
rm -rf /tmp/.com.valvesoftware.Steam.*
# And the half of that lock that lives in the profile. It is a symlink naming the process
# that held it -- "fathom-83" -- and process numbers here start again from the same place
# every session, so the web helper reads it, finds a process 83 alive, decides that is
# another copy of itself holding the profile, and waits for a copy that does not exist.
rm -f "$HOME/.local/share/Steam/config/htmlcache/SingletonLock" \
      "$HOME/.local/share/Steam/config/htmlcache/SingletonCookie" \
      "$HOME/.local/share/Steam/config/htmlcache/SingletonSocket"
rm -f "$HOME/.steampid" "$HOME/.steam/steam.pid" "$HOME/.steam/steam.pipe"
mkdir -p /tmp/fb /tmp/.X11-unix /tmp/.ICE-unix
chmod 1777 /tmp/.X11-unix /tmp/.ICE-unix

# -fbdir puts the framebuffer in a file, which is how the host gets the picture: it maps
# the same file and every pixel X draws is already in its address space.
Xvfb :0 -ac +extension RANDR +extension GLX -screen 0 "${FATHOM_SCREEN:-1280x720x24}" -fbdir /tmp/fb &

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

mkdir -p "$ROOT/usr/local/lib/fathom-steamrt"
cat > "$ROOT/usr/local/lib/fathom-steamrt/_v2-entry-point" <<'ENTRYPOINT'
#!/bin/bash
# Fathom's stand-in for pressure-vessel's entry point.
#
# Steam runs its web helper inside a container that pressure-vessel builds with
# bubblewrap and user namespaces. There are none of those here -- there is no kernel to
# ask -- so the container is skipped and the helper is run directly. What the container
# was mostly there for is the runtime's own libraries, and those are on disk either way:
# the helper is started under that runtime's loader, with its library path, because its
# glibc and this root's are different versions and a loader can only load the libc it was
# built against.
#
# Reached through STEAM_RUNTIME_STEAMRT, so none of Valve's own files are modified.

# pressure-vessel's own options come first, then "--", then the command.
while [ "$#" -gt 0 ]; do
    case "$1" in
        (--) shift; break ;;
        (*) shift ;;
    esac
done
if [ "$#" -eq 0 ]; then
    echo "fathom: the steam runtime entry point was given nothing to run" >&2
    exit 1
fi

depot="${HOME:-/root}/.local/share/Steam/steamrt64/pv-runtime/steam-runtime-steamrt"
files=
for candidate in "$depot"/*/files; do
    [ -d "$candidate" ] && files="$candidate"
done

# The depot ships each library under its own file name -- libgobject-2.0.so.0.6600.8,
# libc-2.31.so -- and nothing under the name a program actually asks for. pressure-vessel
# makes those links while it builds the container; with no container to build, ldconfig
# makes them here instead, once. It reads each library's own SONAME, which for glibc's
# own libraries cannot be worked out from the file name at all.
links=/usr/local/lib/fathom-steamrt/links
if [ -n "$files" ] && [ ! -e "$links/.ready" ]; then
    mkdir -p "$links"
    for library in "$files"/lib/x86_64-linux-gnu/*.so*; do
        [ -f "$library" ] && ln -sf "$library" "$links/${library##*/}"
    done
    /sbin/ldconfig -n "$links"
    : > "$links/.ready"
fi

loader=
if [ -n "$files" ]; then
    for candidate in "$links"/ld-linux-x86-64.so.2 "$files"/lib/x86_64-linux-gnu/ld-*.so; do
        [ -x "$candidate" ] && { loader="$candidate"; break; }
    done
fi

# The command Steam passes is a wrapper whose whole job is to set LD_LIBRARY_PATH=. and
# exec ./steamwebhelper. Done here instead, because the loader has to be named explicitly.
case "$1" in
    (*steamwebhelper_sniper_wrap.sh)
        directory="$(dirname "$1")"
        shift
        # --no-zygote: Chromium normally forks a zygote early and forks every renderer
        # from it. A fork here shares its parent's memory rather than copying it, and the
        # zygote is forked out of a browser process that already has a dozen threads, so
        # the child comes up holding locks nothing will ever release. Without the zygote
        # each child is started with fork and exec straight away.
        #
        # --disable-gpu: there is no GL here for a 64-bit program. Left to look, the
        # helper's libGL loads a driver out of this root filesystem, which is built
        # against a different glibc from the one the helper is running -- two C libraries
        # in one process, and GLib's type system stops working. Chromium draws in
        # software instead, which is what it does on any machine without a GPU.
        #
        # --enable-features=NetworkServiceInProcess: Chromium normally runs its network
        # service as a separate process, and separate processes here are forks of a
        # browser that already has a dozen threads. In process, there is nothing to
        # launch and nothing to wait for.
        extra="--no-zygote --disable-gpu --disable-gpu-compositing --disable-software-rasterizer"
        extra="$extra --enable-features=NetworkServiceInProcess2,NetworkServiceInProcess"
        # --no-proxy-server: the last thing the helper does before it goes quiet is ask
        # D-Bus for the desktop's proxy settings, twice, and there is no D-Bus here. With
        # no proxy to configure there is nothing to ask.
        extra="$extra --no-proxy-server"
        # Set FATHOM_WEBHELPER_VERBOSE to have Chromium say what it is doing; its log
        # goes wherever Steam pointed --log-file, which is the Steam logs directory.
        if [ -n "${FATHOM_WEBHELPER_VERBOSE:-}" ]; then
            extra="$extra --enable-logging --v=1"
        fi
        if [ -n "${FATHOM_WEBHELPER_SINGLE_PROCESS:-}" ]; then
            extra="$extra --single-process"
        fi
        # --no-zygote: Chromium normally forks a zygote early and forks every renderer
        # from it. A fork here shares its parent's memory rather than copying it, and the
        # zygote is forked out of a browser process that already has a dozen threads, so
        # the child comes up holding locks nothing will ever release. Without the zygote
        # each child is started with fork and exec straight away, which is the path
        # everything else in this root already takes.
        if [ -n "$loader" ]; then
            exec "$loader" --library-path "$directory:$links" "$directory/steamwebhelper" "$@" $extra
        fi
        export LD_LIBRARY_PATH="$directory:$links${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
        exec "$directory/steamwebhelper" "$@" $extra
        ;;
esac

exec "$@"
ENTRYPOINT
chmod +x "$ROOT/usr/local/lib/fathom-steamrt/_v2-entry-point"

echo "==> checking the root filesystem still works"
if [[ ! -L "$ROOT/lib" ]]; then
    echo "warning: /lib is no longer a symlink; libraries will not be found" >&2
fi
printf '==> ready: %s\n' "$ROOT"
printf '    run with: build/host/fathom-run --root %s --env HOME=/root /usr/local/bin/fathom-steam\n' "$ROOT"
