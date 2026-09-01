#!/bin/sh
# Make dist/Orka.app portable.
# The Rust dylib keeps an absolute install name from the build machine.
# This script copies the dylib into the bundle, rewrites the load path
# to @rpath, and signs the bundle again.
# Usage: scripts/package-app.sh <path-to-Orka.app>
set -eu

APP="$1"
BIN="$APP/Contents/MacOS/Orka"
FRAMEWORKS="$APP/Contents/Frameworks"
DYLIB=liborka_ffi.dylib

# Sign with the same stable identity as the Xcode build.
# An ad-hoc signature here would drop TCC grants on every build.
# Set ORKA_SIGN_IDENTITY=- for an ad-hoc signature (CI without a certificate).
SIGN_IDENTITY="${ORKA_SIGN_IDENTITY:-Developer ID Application}"

# Notarization requires the hardened runtime and a secure timestamp.
# Ad-hoc signatures cannot carry a timestamp, so skip it for "-".
SIGN_FLAGS="--options runtime"
if [ "$SIGN_IDENTITY" != "-" ]; then
  SIGN_FLAGS="$SIGN_FLAGS --timestamp"
fi

# Find the absolute load path that the linker recorded.
OLD_PATH=$(otool -L "$BIN" | awk "/$DYLIB/ {print \$1}")
if [ -z "$OLD_PATH" ]; then
  echo "error: $BIN does not link $DYLIB" >&2
  exit 1
fi

case "$OLD_PATH" in
  @rpath/*)
    echo "$BIN already links $DYLIB via @rpath."
    ;;
  *)
    mkdir -p "$FRAMEWORKS"
    cp "$OLD_PATH" "$FRAMEWORKS/$DYLIB"
    install_name_tool -id "@rpath/$DYLIB" "$FRAMEWORKS/$DYLIB"
    install_name_tool -change "$OLD_PATH" "@rpath/$DYLIB" "$BIN"
    # install_name_tool breaks the signature. Sign inside-out.
    # shellcheck disable=SC2086
    codesign --force --sign "$SIGN_IDENTITY" $SIGN_FLAGS "$FRAMEWORKS/$DYLIB"
    # shellcheck disable=SC2086
    codesign --force --sign "$SIGN_IDENTITY" $SIGN_FLAGS "$APP"
    ;;
esac

codesign --verify --deep --strict "$APP"
echo "Packaged $APP"
