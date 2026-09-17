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
# Deliberately no 64-bit Mesa. Steam's web helper runs against the Steam runtime's own
# glibc, and this root filesystem's is a different version; installing Mesa here makes the
# helper's libGL load a driver from this root, which drags this root's glibc into a process
# already running the runtime's -- and GObject's type system, which keeps its state in
# whichever copy initialised it, falls apart. The helper is told not to look for GL at all
# instead (see setup-steam-rootfs.sh).

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
#
# zenity is in here rather than with the amd64 packages for the same reason: steam.sh
# pipes tar into it to show unpack progress, and with nothing on the other end of that
# pipe the unpack reports failure -- but zenity is a GTK program, and the GTK stack this
# root already carries for Steam is the i386 one, so the i386 build costs almost nothing
# while the amd64 build would pull in a second copy of two hundred packages.
I386_PACKAGES="${I386_PACKAGES:-libc6:i386 libstdc++6:i386 xvfb:i386 x11-utils:i386 \
    libx11-6:i386 libxext6:i386 libxrender1:i386 libxfixes3:i386 libxdamage1:i386 \
    libxi6:i386 libxrandr2:i386 libxcursor1:i386 libxcomposite1:i386 libxinerama1:i386 \
    libxtst6:i386 libxss1:i386 libxkbcommon0:i386 libgl1:i386 libegl1:i386 \
    libgl1-mesa-dri:i386 libnss3:i386 libnspr4:i386 libdbus-1-3:i386 \
    libudev1:i386 libpulse0:i386 libva2:i386 libvdpau1:i386 \
    libglib2.0-0:i386 libgtk-3-0:i386 libgdk-pixbuf-2.0-0:i386 libpango-1.0-0:i386 \
    libcairo2:i386 libatk1.0-0:i386 libatk-bridge2.0-0:i386 libcups2:i386 \
    libdbus-glib-1-2:i386 libgbm1:i386 libasound2:i386 libxcb-dri3-0:i386 \
    libxcb-present0:i386 libxcb-sync1:i386 libxshmfence1:i386 libdrm2:i386 \
    libgtk2.0-0:i386 libnss3:i386 libcurl4:i386 libopenal1:i386 libsdl2-2.0-0:i386 \
    zenity:i386 \
    libusb-1.0-0:i386 libvulkan1:i386 libglx-mesa0:i386 libegl-mesa0:i386}"
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
# busybox supplies the shell and the utilities, and it has to be the *position
# independent* build rather than busybox-static. Every guest process shares one address
# space here, so two processes running the same non-PIE binary would both insist on its
# fixed load address and land on top of each other -- which a shell pipeline does
# immediately, since both the shell and the utility it pipes into are the same binary.
echo "==> installing 32-bit builds of the programs this session execs"
docker run --platform linux/amd64 --rm -v "$OUT_DIR:/out" "$IMAGE" sh -c '
    set -e
    dpkg --add-architecture i386
    apt-get update -qq
    mkdir -p /tmp/debs/partial /tmp/x
    apt-get install -y --no-install-recommends -o Dir::Cache::archives=/tmp/debs \
        --download-only busybox:i386 x11-xkb-utils:i386 >/dev/null
    # bash is fetched on its own: apt refuses to resolve it as an i386 package while
    # the amd64 build of the same version is installed, and only the file is wanted.
    (cd /tmp && apt-get download bash:i386 >/dev/null 2>&1 && dpkg-deb -x /tmp/bash_*_i386.deb /tmp/x)
    for deb in /tmp/debs/*.deb; do dpkg-deb -x "$deb" /tmp/x; done
    find /tmp/x -name busybox -type f -exec cp {} /out/bin/busybox32 \;
    cp /tmp/x/usr/bin/xkbcomp /out/usr/bin/xkbcomp
    # Steam's launcher is a bash script and uses bash-only syntax; busybox's ash
    # silently mangles it and the launcher aborts saying it cannot find Steam.
    cp /tmp/x/bin/bash /out/bin/bash
' >/dev/null
# cp through a bind mount does not carry the execute bit across, and a program that is
# runnable but not marked executable is worse than one that is missing: exec works, so it
# looks installed, while every `test -x` and every PATH search skips it.
chmod +x "$OUT_DIR/bin/busybox32" "$OUT_DIR/bin/bash" "$OUT_DIR/usr/bin/xkbcomp"

ln -sf busybox32 "$OUT_DIR/bin/sh"

# A 32-bit userland in front of the 64-bit one.
#
# Debian's coreutils, grep, sed and the rest are the amd64 builds, and they cannot be
# co-installed alongside i386 copies -- one path, one architecture. A session started on a
# 32-bit program can only run 32-bit code, so every one of those a shell script reaches for
# is a program that cannot run. busybox has all of them in a single static i386 binary, so
# they go into /usr/local/bin, which comes first on PATH: nothing is overwritten, and the
# Debian binaries stay where they are for a 64-bit session to use.
#
# The list is written out rather than read from `busybox --list`, because busybox32 is a
# guest binary and nothing on the build host can run it. These are the applets a shell
# script actually reaches for. The archive tools are deliberately absent: busybox's tar
# has no --blocking-factor and its xz has no --robot, and steam.sh asks for both when it
# unpacks the runtime, so it is the real GNU ones that have to be on PATH -- a 64-bit
# build of them now runs happily from a 32-bit shell. The system-level applets busybox
# also carries (init, mount, modprobe and friends) are left out too, since a stand-in for
# those would be answering for something it does not own.
echo "==> linking busybox's applets into /usr/local/bin for 32-bit sessions"
mkdir -p "$OUT_DIR/usr/local/bin"
for applet in \
    '[' ar arch awk base64 basename bunzip2 bzcat bzip2 cat chgrp chmod chown chroot cmp \
    cp cpio cut date dd df diff dirname dos2unix du echo ed egrep env expand expr factor \
    fallocate false fgrep find fold free getopt grep groups head hexdump \
    hostname id ipcalc kill killall less link ln logname ls md5sum mkdir mkfifo mknod \
    mktemp more mv nl nproc nslookup od paste patch pidof printf ps pwd readlink realpath \
    rev rm rmdir sed seq setsid sha1sum sha256sum sha512sum shuf sleep sort stat strings \
    stty sync tac tail tee test time timeout touch tr true truncate tty uname \
    uncompress unexpand uniq unlink unzip uptime usleep wc wget which who \
    whoami xargs xxd yes; do
    ln -sf /bin/busybox32 "$OUT_DIR/usr/local/bin/$applet"
done

# X11 wants these to exist before any server or client starts.
mkdir -p "$OUT_DIR/tmp/.X11-unix" "$OUT_DIR/tmp/.ICE-unix"
chmod 1777 "$OUT_DIR/tmp/.X11-unix" "$OUT_DIR/tmp/.ICE-unix"

printf '==> %s files in %s\n' "$(find "$OUT_DIR" -mindepth 1 | wc -l | tr -d ' ')" "$OUT_DIR"
