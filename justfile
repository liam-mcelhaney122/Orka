# Build recipes for Orka. Run `just` for the list.

# xcodebuild needs a full Xcode, not the command-line tools.
export DEVELOPER_DIR := "/Applications/Xcode.app"

# cargo is not on the PATH in every shell.
cargo := home_directory() / ".cargo/bin/cargo"
derived_data := justfile_directory() / "build/DerivedData"
dist_app := justfile_directory() / "dist/Orka.app"

# List the recipes.
default:
    @just --list

# Build the Rust core (release).
rust:
    {{cargo}} build --release

# The Xcode project links the release Rust library, so every app
# recipe builds the Rust core first.

# Build the app (Debug).
debug: rust
    xcodebuild -project app/Orka.xcodeproj -scheme Orka \
        -configuration Debug -derivedDataPath "{{derived_data}}" build

# Build the app (Release).
release: rust
    xcodebuild -project app/Orka.xcodeproj -scheme Orka \
        -configuration Release -derivedDataPath "{{derived_data}}" build

# Build Release and copy the app to dist/Orka.app.
dist: release
    rm -rf "{{dist_app}}"
    ditto "{{derived_data}}/Build/Products/Release/Orka.app" "{{dist_app}}"
    @echo "Built {{dist_app}}"

# Build dist and relaunch the app from it.
run: dist
    -killall Orka 2>/dev/null
    open "{{dist_app}}"

# Remove build products. Keeps dist/.
clean:
    rm -rf "{{derived_data}}"
    {{cargo}} clean --release
