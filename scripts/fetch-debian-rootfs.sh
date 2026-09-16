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

echo "==> exporting $IMAGE"
docker rm -f fathom-debian-export >/dev/null 2>&1 || true
docker create --platform linux/amd64 --name fathom-debian-export "$IMAGE" /bin/true >/dev/null
trap 'docker rm -f fathom-debian-export >/dev/null 2>&1 || true' EXIT

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"
docker export fathom-debian-export | tar -x -C "$OUT_DIR"

# The minimal image has no resolver, and musl and glibc alike silently fail every lookup
# without one.
printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' > "$OUT_DIR/etc/resolv.conf"

printf '==> %s files in %s\n' "$(find "$OUT_DIR" -mindepth 1 | wc -l | tr -d ' ')" "$OUT_DIR"
