#!/usr/bin/env bash
# Builds FEXCore (the x86-64 -> ARM64 JIT that Fathom runs guest code on) for arm64 iOS
# and copies the resulting static libraries into Fathom/Libs/ where generate_project.rb
# picks them up.
#
# The source tree is not vendored into this repo. FEXCORE_SRC below is the single place
# that path is configured; scripts/generate_project.rb reads the same default for its
# header search paths.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Fathom builds against its own branch of FEXCore, not AetherPS4's checkout. The 32-bit
# work adds a guest-memory base to the JIT, which AetherPS4 neither needs nor expects, so
# it lives on the `fathom-32bit` branch in a git worktree. Both share one object store;
# AetherPS4's tree stays on `main` and is untouched.
FEXCORE_SRC="${FEXCORE_SRC:-$HOME/Documents/Coding/fathom-fexcore/runtime/sources/fexcore-darwin}"
BUILD_DIR="${BUILD_DIR:-$REPO_ROOT/build/fexcore-ios}"
LIBS_DIR="$REPO_ROOT/Fathom/Libs"
# Must match IPHONEOS_DEPLOYMENT_TARGET in generate_project.rb -- some of FEXCore's
# object code is compiled assuming this floor.
DEPLOYMENT_TARGET="18.0"

if [[ ! -d "$FEXCORE_SRC" ]]; then
    echo "error: FEXCore source tree not found at $FEXCORE_SRC" >&2
    echo "       set FEXCORE_SRC=/path/to/fexcore-darwin and re-run" >&2
    exit 1
fi

echo "==> Configuring FEXCore for iOS (arm64, $DEPLOYMENT_TARGET)"
echo "    source: $FEXCORE_SRC"
echo "    build:  $BUILD_DIR"

# CMAKE_SYSTEM_PROCESSOR has to be passed explicitly: cross-compiling to iOS leaves it
# empty, and FEX's own architecture detection (CMakeLists.txt's "Architecture Handling"
# block) hard-errors with "Unsupported processor type ." rather than falling back to the
# host's arch.
#
# BUILD_FEXCORE_ONLY skips the whole Linux-application/syscall-emulation half of FEX
# (which does not build for Darwin at all) and leaves just the JIT core plus the
# Common/CommonTools helpers Fathom's runtime calls into for host-feature detection.
# BUILD_FEXCORE_SMOKE=OFF drops the standalone probe executable -- it needs a
# FEXCORE_SMOKE_SOURCE and would not link for an iOS sysroot anyway.
# BUILD_TESTING=OFF is required, not just tidy: FEX's unit-test CMake calls
# catch_discover_tests(), which only exists once Catch2 has been found, and Catch2
# is not vendored here -- configure hard-fails on "Unknown CMake command" otherwise.
cmake -S "$FEXCORE_SRC" -B "$BUILD_DIR" -G Ninja \
    -DCMAKE_SYSTEM_NAME=iOS \
    -DCMAKE_SYSTEM_PROCESSOR=arm64 \
    -DCMAKE_OSX_SYSROOT=iphoneos \
    -DCMAKE_OSX_ARCHITECTURES=arm64 \
    -DCMAKE_OSX_DEPLOYMENT_TARGET="$DEPLOYMENT_TARGET" \
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
# JemallocLibs is not a dependency of the static FEXCore target (only of FEXCore_shared),
# but it is where AllocatorHooks.cpp lives -- and on iOS that file carries the whole
# dual-mapped JIT allocator (iOSJITAlloc / GetExecutableAddress / GetWritableAddress)
# that FEXCore's JIT calls into. Leaving it out configures and builds cleanly and then
# fails at the app link with undefined symbols, so it is named explicitly here.
cmake --build "$BUILD_DIR" --target FEXCore Common CommonTools JemallocLibs

echo "==> Copying static libraries into $LIBS_DIR"
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

echo "==> Verifying every copied library is arm64 (a stale host-arch build here"
echo "    links fine against nothing and fails only at the final app link)"
for lib in "$LIBS_DIR"/*.a; do
    arch_line=$(lipo -info "$lib")
    case "$arch_line" in
        *arm64*) ;;
        *) echo "error: $lib is not arm64: $arch_line" >&2; exit 1 ;;
    esac
done

echo "==> Done: $found libraries in $LIBS_DIR"
ls -1 "$LIBS_DIR"
