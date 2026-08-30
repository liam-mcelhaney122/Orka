#!/bin/sh
# Build the Rust core and regenerate the Swift bindings.
# Run this before an Xcode build when Rust code changes.
set -eu

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

cargo build --release -p orka-ffi

cargo run --release -p orka-ffi --bin uniffi-bindgen -- \
  generate \
  --library target/release/liborka_ffi.dylib \
  --language swift \
  --out-dir app/Generated

# The app uses a bridging header. The modulemap is not needed.
rm -f app/Generated/orka_ffiFFI.modulemap

echo "Rust build and Swift bindings are up to date."
