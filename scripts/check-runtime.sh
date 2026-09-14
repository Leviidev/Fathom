#!/usr/bin/env bash
# Compiles the C++ runtime against the iOS SDK without going through Xcode.
# Much faster than a full app build when iterating on the emulator core.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FEXCORE_SRC="${FEXCORE_SRC:-$HOME/Documents/Coding/AetherCore4/aetherps4-public-release/runtime/sources/fexcore-darwin}"
BUILD_DIR="${BUILD_DIR:-$REPO_ROOT/build/fexcore-ios}"
OUT_DIR="${OUT_DIR:-$REPO_ROOT/build/runtime-check}"
SDK="$(xcrun --sdk iphoneos --show-sdk-path)"

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
    -I"$BUILD_DIR/include"
    -I"$BUILD_DIR/generated"
)

status=0
for source in "$REPO_ROOT"/Fathom/Sources/Runtime/*.cpp; do
    name="$(basename "$source" .cpp)"
    echo "==> $name"
    xcrun --sdk iphoneos clang++ \
        -target arm64-apple-ios18.0 \
        -isysroot "$SDK" \
        -std=c++20 -O1 -g0 \
        -DARCHITECTURE_arm64=1 \
        -Wall -Wno-unused-parameter \
        "${INCLUDES[@]}" \
        -c "$source" -o "$OUT_DIR/$name.o" || status=1
done

if [[ "$status" -ne 0 ]]; then
    exit "$status"
fi

# Linking is the half that actually proves the FEXCore integration: every symbol the
# engine reaches for has to exist in the libraries the app will ship. A compile-only
# check passes happily with a missing FEXCore target and fails inside Xcode much later.
echo "==> link"
cat > "$OUT_DIR/link_probe.c" <<'PROBE'
#include "fathom_api.h"
int main(void) {
    fathom_diagnostics diagnostics;
    fathom_probe_device(&diagnostics);
    fathom_program_info info;
    fathom_inspect_program("/dev/null", &info);
    fathom_session_config config;
    fathom_session_config_defaults(&config);
    fathom_session* session = fathom_session_create(&config, 0, 0);
    fathom_session_run(session);
    fathom_session_request_stop(session);
    fathom_session_destroy(session);
    return fathom_runtime_available() ? 0 : 1;
}
PROBE

xcrun --sdk iphoneos clang++ \
    -target arm64-apple-ios18.0 \
    -isysroot "$SDK" \
    "${INCLUDES[@]}" \
    -x c -std=c11 "$OUT_DIR/link_probe.c" \
    -x none \
    "$OUT_DIR"/*.o \
    "$REPO_ROOT"/Fathom/Libs/*.a \
    -lc++ \
    -o "$OUT_DIR/link_probe" || exit 1

echo "==> linked: $(lipo -info "$OUT_DIR/link_probe")"
