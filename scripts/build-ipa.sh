#!/usr/bin/env bash
# Builds Fathom unsigned and packages it as an .ipa on the Desktop, which is where the
# sideloading tool picks it up from.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR="$REPO_ROOT/Fathom"
SCHEME="Fathom"
CONFIGURATION="${CONFIGURATION:-Release}"
DEST_DIR="${1:-$HOME/Desktop}"

if [[ ! -d "$APP_DIR/$SCHEME.xcodeproj" ]]; then
    echo "==> Generating the Xcode project"
    ruby "$REPO_ROOT/scripts/generate_project.rb"
fi

cd "$APP_DIR"

echo "==> Building $SCHEME ($CONFIGURATION, iphoneos, unsigned)"
# Unsigned on purpose: the sideloading tool does the real signing, and signing here with
# a development identity would just be stripped and replaced.
xcodebuild \
    -project "$SCHEME.xcodeproj" \
    -scheme "$SCHEME" \
    -configuration "$CONFIGURATION" \
    -sdk iphoneos \
    -destination "generic/platform=iOS" \
    CODE_SIGNING_ALLOWED=NO \
    build

BUILD_DIR=$(xcodebuild \
    -project "$SCHEME.xcodeproj" \
    -scheme "$SCHEME" \
    -configuration "$CONFIGURATION" \
    -sdk iphoneos \
    -showBuildSettings 2>/dev/null | awk -F'= ' '/ CONFIGURATION_BUILD_DIR =/ {print $2; exit}')
APP_PATH="$BUILD_DIR/$SCHEME.app"

if [[ ! -d "$APP_PATH" ]]; then
    echo "error: built app not found at $APP_PATH" >&2
    exit 1
fi

# BreakpointJIT has to physically exist in the bundle: FEXCore dlopen()s it by path when
# it needs executable memory, and nothing at build time references it, so a missing copy
# phase produces an app that builds fine and cannot JIT at runtime.
if [[ ! -x "$APP_PATH/Frameworks/BreakpointJIT.framework/BreakpointJIT" ]]; then
    echo "error: BreakpointJIT.framework is missing from the built app" >&2
    exit 1
fi

echo "==> Packaging"
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

mkdir -p "$WORK_DIR/Payload"
cp -R "$APP_PATH" "$WORK_DIR/Payload/"

mkdir -p "$DEST_DIR"
IPA_PATH="$DEST_DIR/$SCHEME.ipa"

# Built to a temporary name and moved into place, so an interrupted run never leaves a
# half-written .ipa where a complete one used to be.
(cd "$WORK_DIR" && zip -qr "$WORK_DIR/$SCHEME.ipa" Payload)
mv -f "$WORK_DIR/$SCHEME.ipa" "$IPA_PATH"

echo "==> Done: $IPA_PATH ($(du -h "$IPA_PATH" | cut -f1))"
