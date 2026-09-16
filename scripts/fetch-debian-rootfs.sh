#!/usr/bin/env bash
# Builds a Debian (glibc) root filesystem for testing on macOS.
#
# Steam is built against glibc and will not run on musl, so the Alpine root filesystem
# that ships in the app cannot host it. This exports a real Debian userland out of a
# container image, which also arrives with bash, coreutils and python already installed --
# so none of it has to be fetched by a package manager first.
#
# Not bundled into the IPA: at ~75MB unpacked it is far too large, and it is only needed
# for the Steam work. The app still ships Alpine.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${IMAGE:-debian:bookworm-slim}"
# Absolute, because docker -v refuses a relative path and reads it as a volume name.
OUT_DIR="$(cd "$(dirname "${1:-$REPO_ROOT/build/debian-root}")" 2>/dev/null && pwd)/$(basename "${1:-$REPO_ROOT/build/debian-root}")"

if ! docker info >/dev/null 2>&1; then
    echo "==> starting colima (this project's docker is colima, not Docker Desktop)"
    colima start
fi

# Steam's own Depends line names these. xz-utils matters most: Debian's tar shells out to
# an external xz for a .tar.xz, and the Steam bootstrap is exactly that -- without it tar
# reports "xz: Cannot exec" and the installation stops before it starts.
PACKAGES="${PACKAGES:-xz-utils python3 ca-certificates file}"

echo "==> building an image from $IMAGE with: $PACKAGES"
docker rm -f fathom-debian-build fathom-debian-export >/dev/null 2>&1 || true
# i386 as well as amd64: Steam's client is a 32-bit binary and asks for
# /lib/ld-linux.so.2 and the rest of the 32-bit glibc, none of which an amd64-only
# installation carries.
#
# Xvfb and the X client libraries are here too, and they are i386 for a reason that is
# not obvious: Fathom decides the guest's word size once, from the program it is given,
# and a session started on a 32-bit binary decodes and numbers syscalls for i386
# throughout. A 64-bit X server in the same session would be decoded as 32-bit code. So
# everything that has to run alongside Steam is the 32-bit build of it.
I386_PACKAGES="${I386_PACKAGES:-libc6:i386 libstdc++6:i386 xvfb:i386 x11-utils:i386 \
    libx11-6:i386 libxext6:i386 libxrender1:i386 libxfixes3:i386 libxdamage1:i386 \
    libxi6:i386 libxrandr2:i386 libxcursor1:i386 libxcomposite1:i386 libxinerama1:i386 \
    libxtst6:i386 libxss1:i386 libxkbcommon0:i386 libgl1:i386 libegl1:i386 \
    libgl1-mesa-dri:i386 libnss3:i386 libnspr4:i386 libdbus-1-3:i386 \
    libudev1:i386 libpulse0:i386 libva2:i386 libvdpau1:i386}"
docker run --platform linux/amd64 --name fathom-debian-build "$IMAGE" \
    sh -c "apt-get update -qq && apt-get install -y --no-install-recommends $PACKAGES \
           && dpkg --add-architecture i386 && apt-get update -qq \
           && apt-get install -y --no-install-recommends $I386_PACKAGES" >/dev/null
docker commit fathom-debian-build fathom-debian:latest >/dev/null
docker rm -f fathom-debian-build >/dev/null 2>&1 || true

echo "==> exporting"
docker create --platform linux/amd64 --name fathom-debian-export fathom-debian:latest /bin/true >/dev/null
trap 'docker rm -f fathom-debian-export >/dev/null 2>&1 || true' EXIT

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"
docker export fathom-debian-export | tar -x -C "$OUT_DIR"

# The minimal image has no resolver, and musl and glibc alike silently fail every lookup
# without one.
printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' > "$OUT_DIR/etc/resolv.conf"

# The executables that have to be 32-bit.
#
# Debian will not co-install two architectures of the same program -- both builds own the
# same path -- so apt gave us the amd64 build of each of these. That is fine for anything
# this session never runs, but Fathom fixes the guest's word size once, from the program
# it is started on, so a 64-bit binary exec'd inside a 32-bit session is decoded as i386
# and runs off into nonsense. Two of them are reached in practice: the shell Steam's
# client forks, and xkbcomp, which every X server execs while building its keymap. Both
# are unpacked by hand and put in place over the amd64 build.
#
# busybox is used for the shell because dash has no static build and pulling a second
# dynamic linker's worth of i386 libraries in for one program is not worth it.
echo "==> installing 32-bit builds of the programs this session execs"
docker run --platform linux/amd64 --rm -v "$OUT_DIR:/out" "$IMAGE" sh -c '
    set -e
    dpkg --add-architecture i386
    apt-get update -qq
    mkdir -p /tmp/debs/partial /tmp/x
    apt-get install -y --no-install-recommends -o Dir::Cache::archives=/tmp/debs \
        --download-only busybox-static:i386 x11-xkb-utils:i386 >/dev/null
    for deb in /tmp/debs/*.deb; do dpkg-deb -x "$deb" /tmp/x; done
    cp /tmp/x/bin/busybox /out/bin/busybox32
    cp /tmp/x/usr/bin/xkbcomp /out/usr/bin/xkbcomp
' >/dev/null
ln -sf busybox32 "$OUT_DIR/bin/sh"

# X11 wants these to exist before any server or client starts.
mkdir -p "$OUT_DIR/tmp/.X11-unix" "$OUT_DIR/tmp/.ICE-unix"
chmod 1777 "$OUT_DIR/tmp/.X11-unix" "$OUT_DIR/tmp/.ICE-unix"

printf '==> %s files in %s\n' "$(find "$OUT_DIR" -mindepth 1 | wc -l | tr -d ' ')" "$OUT_DIR"
