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
OUT_DIR="${1:-$REPO_ROOT/build/debian-root}"

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
I386_PACKAGES="${I386_PACKAGES:-libc6:i386 libstdc++6:i386}"
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

printf '==> %s files in %s\n' "$(find "$OUT_DIR" -mindepth 1 | wc -l | tr -d ' ')" "$OUT_DIR"
