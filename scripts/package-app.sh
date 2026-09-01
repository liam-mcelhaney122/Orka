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
SIGN_IDENTITY="${ORKA_SIGN_IDENTITY:-Apple Development}"

# Notarization requires a secure timestamp and the hardened runtime on
# every signature in the bundle, not only the outer app. Skip these for
# local "Apple Development" builds: they slow down the sign step and
# are not needed for a build that never leaves this Mac.
CODESIGN_EXTRA_ARGS=""
if [ "$SIGN_IDENTITY" != "Apple Development" ]; then
  CODESIGN_EXTRA_ARGS="--options runtime --timestamp"
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
    codesign --force --sign "$SIGN_IDENTITY" $CODESIGN_EXTRA_ARGS "$FRAMEWORKS/$DYLIB"
    codesign --force --sign "$SIGN_IDENTITY" $CODESIGN_EXTRA_ARGS "$APP"
    ;;
esac

codesign --verify --deep --strict "$APP"
echo "Packaged $APP"
