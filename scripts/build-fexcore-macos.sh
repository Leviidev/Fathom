#!/usr/bin/env bash
# Builds FEXCore for native macOS arm64, so the emulator runtime can be exercised on the
# Mac before an IPA is ever built.
#
# This is the same source tree as the iOS build and the same JIT; only the host differs.
# FEXCore's allocator already branches on TARGET_OS_IPHONE: iOS goes through the
# dual-mapped BreakGetJITMapping path that a sideloaded app needs, while every other
# Apple platform uses plain MAP_JIT, which macOS grants to any binary carrying the
# allow-jit entitlement. Nothing in Fathom's own runtime needs to change.
#
# xxhash is forced to the vendored copy. Cross-compiling to iOS finds no system one and
# builds External/xxhash, but a native macOS configure finds Homebrew's and links against
# that instead -- which is not in this repo's library directory, so the link fails on
# XXH3_64bits and nothing explains why.
#
# The libraries land somewhere separate on purpose. Fathom/Libs holds the *iOS* archives
# that generate_project.rb links into the app, and dropping macOS ones on top of them
# produces an app that configures, builds, and then fails at link with a silent
# architecture mismatch.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Fathom builds against its own branch of FEXCore, not AetherPS4's checkout. The 32-bit
# work adds a guest-memory base to the JIT, which AetherPS4 neither needs nor expects, so
# it lives on the `fathom-32bit` branch in a git worktree. Both share one object store;
# AetherPS4's tree stays on `main` and is untouched.
FEXCORE_SRC="${FEXCORE_SRC:-$HOME/Documents/Coding/fathom-fexcore/runtime/sources/fexcore-darwin}"
BUILD_DIR="${BUILD_DIR:-$REPO_ROOT/build/fexcore-macos}"
LIBS_DIR="$REPO_ROOT/build/fexcore-macos-libs"

if [[ ! -d "$FEXCORE_SRC" ]]; then
    echo "error: FEXCore source tree not found at $FEXCORE_SRC" >&2
    exit 1
fi

echo "==> Configuring FEXCore for macOS (arm64)"
cmake -S "$FEXCORE_SRC" -B "$BUILD_DIR" -G Ninja \
    -DCMAKE_SYSTEM_PROCESSOR=arm64 \
    -DCMAKE_DISABLE_FIND_PACKAGE_xxhash=ON \
    -DCMAKE_OSX_SYSROOT=macosx \
    -DCMAKE_OSX_ARCHITECTURES=arm64 \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_FEXCORE_ONLY=ON \
    -DBUILD_FEXCORE_SMOKE=OFF \
    -DBUILD_TESTING=OFF \
    -DENABLE_JEMALLOC_GLIBC_ALLOC=OFF \
    -DENABLE_FEX_ALLOCATOR=ON \
    -DENABLE_CCACHE=ON \
    -DENABLE_LTO=OFF \
    -DENABLE_WERROR=OFF \
    -DENABLE_STRICT_WERROR=OFF \
    -DTUNE_CPU=none \
    -DCMAKE_CXX_FLAGS=-DMETA_NO_STD_FORWARD_DECLARATIONS

echo "==> Building FEXCore"
cmake --build "$BUILD_DIR" --target FEXCore Common CommonTools JemallocLibs

echo "==> Collecting static libraries into $LIBS_DIR"
rm -rf "$LIBS_DIR"
mkdir -p "$LIBS_DIR"
found=0
while IFS= read -r lib; do
    cp -f "$lib" "$LIBS_DIR/"
    found=$((found + 1))
done < <(find "$BUILD_DIR" -name '*.a' -not -path '*/CMakeFiles/*')

if [[ "$found" -eq 0 ]]; then
    echo "error: build produced no static libraries" >&2
    exit 1
fi
echo "==> Done: $found libraries in $LIBS_DIR"
