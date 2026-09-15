#!/usr/bin/env bash
# Builds Fathom's runtime as a native macOS command-line program.
#
# macOS grants MAP_JIT only to a binary that carries the allow-jit entitlement, so the
# result is ad-hoc signed with one. Without that the JIT's code buffers cannot be made
# executable and FEXCore fails to initialise -- the same symptom as a missing JIT
# permission on the phone, for the same underlying reason.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FEXCORE_SRC="${FEXCORE_SRC:-$HOME/Documents/Coding/AetherCore4/aetherps4-public-release/runtime/sources/fexcore-darwin}"
FEX_BUILD="${FEX_BUILD:-$REPO_ROOT/build/fexcore-macos}"
LIBS_DIR="$REPO_ROOT/build/fexcore-macos-libs"
OUT_DIR="$REPO_ROOT/build/host"
OUT="$OUT_DIR/fathom-run"

if [[ ! -d "$LIBS_DIR" ]]; then
    echo "==> FEXCore for macOS is not built yet"
    bash "$REPO_ROOT/scripts/build-fexcore-macos.sh"
fi

mkdir -p "$OUT_DIR"

INCLUDES=(
    -I"$REPO_ROOT/Fathom/Sources/Runtime"
    -I"$FEXCORE_SRC/FEXCore/include"
    -I"$FEXCORE_SRC/Source"
    -I"$FEXCORE_SRC/FEXHeaderUtils"
    -I"$FEXCORE_SRC/CodeEmitter"
    -I"$FEXCORE_SRC/External/fmt/include"
    -I"$FEXCORE_SRC/External/unordered_dense/include"
    -I"$FEXCORE_SRC/External/range-v3/include"
    -I"$FEXCORE_SRC/External/vixl/src"
    -I"$FEXCORE_SRC/External/xxhash"
    -I"$FEXCORE_SRC/External/tiny-json"
    -I"$FEX_BUILD/include"
    -I"$FEX_BUILD/generated"
)

echo "==> Compiling the runtime for macOS"
objects=()
for source in "$REPO_ROOT"/Fathom/Sources/Runtime/*.cpp "$REPO_ROOT"/tools/fathom-run.cpp; do
    name="$(basename "$source" .cpp)"
    clang++ -target arm64-apple-macos14.4 \
        -std=c++20 -O1 -g \
        -DARCHITECTURE_arm64=1 \
        -Wall -Wno-unused-parameter \
        "${INCLUDES[@]}" \
        -c "$source" -o "$OUT_DIR/$name.o"
    objects+=("$OUT_DIR/$name.o")
done

echo "==> Linking"
# Repeated in a group: these archives reference each other both ways, and a single pass
# leaves undefined symbols depending on the order they happen to be listed in.
clang++ -target arm64-apple-macos14.4 -o "$OUT" "${objects[@]}" \
    -Wl,-search_paths_first \
    "$LIBS_DIR"/*.a "$LIBS_DIR"/*.a \
    -framework CoreFoundation -framework Foundation -lc++ -lpthread

echo "==> Signing with the JIT entitlement"
cat > "$OUT_DIR/jit.entitlements" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.cs.allow-jit</key>
    <true/>
</dict>
</plist>
PLIST
codesign --force --sign - --entitlements "$OUT_DIR/jit.entitlements" "$OUT"

echo "==> Done: $OUT"
