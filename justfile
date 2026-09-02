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

# Build the Rust core (release) and regenerate the Swift bindings.
rust:
    ./scripts/build-rust.sh

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
    ./scripts/package-app.sh "{{dist_app}}"
    @echo "Built {{dist_app}}"

# Build dist and relaunch the app from it.
run: dist
    -killall Orka 2>/dev/null
    open "{{dist_app}}"

# Run the Rust and Swift test suites.
test:
    {{cargo}} test --workspace
    xcodebuild test -project app/Orka.xcodeproj -scheme OrkaTests \
        -destination "platform=macOS"

# Remove build products. Keeps dist/.
clean:
    rm -rf "{{derived_data}}"
    {{cargo}} clean --release

# --- Opt-in daemon bench tier ------------------------------------
#
# `bench-up` starts every real daemon `cargo test --test bench_mounts`
# and friends can use under ORKA_BENCH=1: Homebrew's smbd, the NFS
# bench server, and sshd. Each daemon is optional except the NFS
# server: a missing Homebrew package is reported and skipped, not a
# hard failure, since a workstation without `samba` installed should
# still be able to build and run the rest of the suite. Implicit FTPS
# has no daemon here; docs/TESTING.md describes the manual check and
# the ports every daemon uses.

# Start every opt-in bench daemon. Safe to run again: each daemon is
# skipped if its own PID file already names a live process.
bench-up:
    #!/usr/bin/env bash
    set -euo pipefail
    cd "{{justfile_directory()}}"
    mkdir -p bench/run

    # smbd (Homebrew samba; Apple's own /usr/sbin/smbd cannot read
    # this config and is not usable here).
    # Homebrew renames the daemon to samba-dot-org-smbd so it does not
    # shadow Apple's /usr/sbin/smbd.
    SMBD=""
    for candidate in /opt/homebrew/sbin/samba-dot-org-smbd /usr/local/sbin/samba-dot-org-smbd \
            /opt/homebrew/sbin/smbd /usr/local/sbin/smbd; do
        if [ -x "$candidate" ]; then SMBD="$candidate"; break; fi
    done
    if [ -n "$SMBD" ]; then
        SMBPASSWD="$(dirname "$SMBD")/samba-dot-org-smbpasswd"
        if [ ! -x "$SMBPASSWD" ]; then SMBPASSWD="$(dirname "$SMBD")/smbpasswd"; fi
        if [ ! -x "$SMBPASSWD" ]; then SMBPASSWD="$(dirname "$(dirname "$SMBD")")/bin/smbpasswd"; fi
        RUN="$(pwd)/bench/run/samba"
        mkdir -p "$RUN/shares/secure" "$RUN/shares/guest" "$RUN/private" "$RUN/pid"
        # Samba maps every login to a Unix account, so the bench user
        # is the current account. bench_mounts.rs reads the same name.
        # `-L` must come first: without it a non-root smbpasswd talks
        # to a server instead of editing the local password database.
        BENCH_USER="${ORKA_BENCH_SMB_USER:-$(id -un)}"
        sed -e "s#@BENCH_RUN@#$RUN#g" -e "s#@BENCH_USER@#$BENCH_USER#g" bench/smb.conf > "$RUN/smb.conf"
        # smbpasswd -L edits the local database and needs root; the
        # files it creates go back to the bench user so smbd can read
        # them without root.
        if [ ! -f "$RUN/passdb.tdb" ]; then
            if sudo -n true 2>/dev/null; then
                printf 'orka-bench\norka-bench\n' \
                    | sudo "$SMBPASSWD" -L -c "$RUN/smb.conf" -s -a "$BENCH_USER" \
                    || echo "smbpasswd: failed (see output above); the SMB bench will skip"
                sudo chown -R "$BENCH_USER" "$RUN"
            else
                echo "smbpasswd: skipped, passwordless sudo is not available; the SMB password tests will fail"
            fi
        fi
        # smbd must run as root. Its atomic directory create makes a
        # temporary directory, then renames it as the file owner, and
        # that seteuid step fails on an unprivileged daemon, so every
        # mkdir over SMB is denied. A real SMB server runs as root too.
        SMBD_SUDO=""
        if sudo -n true 2>/dev/null; then SMBD_SUDO="sudo"; fi
        if [ ! -f bench/run/smbd.pid ] || ! kill -0 "$(cat bench/run/smbd.pid)" 2>/dev/null; then
            # An optional daemon that fails to start must not stop the
            # recipe; the SMB tests skip when the port is closed.
            if $SMBD_SUDO "$SMBD" -s "$RUN/smb.conf" -D > "$RUN/smbd.out" 2>&1; then
                sleep 1
                $SMBD_SUDO cp "$RUN/pid/smbd.pid" bench/run/smbd.pid 2>/dev/null || true
                $SMBD_SUDO chmod 644 bench/run/smbd.pid 2>/dev/null || true
                echo "smbd: listening on 127.0.0.1:4450 as ${SMBD_SUDO:-$(id -un)} (config $RUN/smb.conf)"
            else
                echo "smbd: failed to start; the SMB bench will skip"
                cat "$RUN/smbd.out"
            fi
        else
            echo "smbd: already running on 127.0.0.1:4450"
        fi
    else
        echo "smbd: skipped, Homebrew samba is not installed (brew install samba)"
    fi

    # Implicit FTPS (port 990) has no bench daemon: Homebrew's vsftpd
    # is built without SSL. See docs/TESTING.md for the manual check.

    # NFS bench server: an in-process daemon, no system package needed.
    mkdir -p bench/run/nfs/export
    if [ ! -f bench/run/nfs.pid ] || ! kill -0 "$(cat bench/run/nfs.pid)" 2>/dev/null; then
        nohup {{cargo}} run -p orka-core --example nfs_bench_server -- \
            23890 "$(pwd)/bench/run/nfs/export" > bench/run/nfs.log 2>&1 &
        echo $! > bench/run/nfs.pid
        sleep 1
    fi
    echo "nfs_bench_server: listening on 127.0.0.1:23890 (see docs/TESTING.md for the mount_nfs options it needs)"

    # sshd: no SFTP bench in this crate uses it yet, but `just
    # bench-up` starts it so one can be added without a recipe change.
    SSHD="/usr/sbin/sshd"
    if [ -x "$SSHD" ]; then
        RUN="$(pwd)/bench/run/sshd"
        mkdir -p "$RUN"
        if [ ! -f "$RUN/ssh_host_ed25519_key" ]; then
            ssh-keygen -q -t ed25519 -N "" -f "$RUN/ssh_host_ed25519_key"
        fi
        if [ ! -f "$RUN/bench_key" ]; then
            ssh-keygen -q -t ed25519 -N "" -f "$RUN/bench_key"
            cp "$RUN/bench_key.pub" "$RUN/authorized_keys"
        fi
        sed "s#@BENCH_RUN@#$RUN#g" bench/sshd_config > "$RUN/sshd_config"
        if [ ! -f bench/run/sshd.pid ] || ! kill -0 "$(cat bench/run/sshd.pid)" 2>/dev/null; then
            "$SSHD" -f "$RUN/sshd_config"
            sleep 1
            cp "$RUN/sshd.pid" bench/run/sshd.pid
        fi
        echo "sshd: listening on 127.0.0.1:2222 (key $RUN/bench_key)"
    else
        echo "sshd: skipped, no sshd binary found"
    fi

# Run every bench, including the opt-in daemon tier. Needs `just
# bench-up` first for the SMB and FTPS cases; the NFS tests start
# their own server and do not need `bench-up` at all.
bench:
    ORKA_BENCH=1 {{cargo}} test --workspace --no-fail-fast -- --include-ignored

# Stop every daemon `bench-up` started and unmount any share a bench
# test left mounted. Safe to run even when `bench-up` was never run.
bench-down:
    #!/usr/bin/env bash
    set -uo pipefail
    cd "{{justfile_directory()}}"
    SMBD_SUDO=""
    if sudo -n true 2>/dev/null; then SMBD_SUDO="sudo"; fi
    for name in smbd nfs sshd; do
        pid_file="bench/run/$name.pid"
        if [ -f "$pid_file" ]; then
            if [ "$name" = smbd ]; then
                $SMBD_SUDO kill "$(cat "$pid_file")" 2>/dev/null || true
                $SMBD_SUDO rm -f "$pid_file"
            else
                kill "$(cat "$pid_file")" 2>/dev/null || true
                rm -f "$pid_file"
            fi
        fi
    done
    # Daemon output helps diagnose a refused mount or a failed start
    # on a CI runner, where nobody can read the files afterwards.
    for log in bench/run/samba/log.smbd bench/run/samba/smbd.out bench/run/nfs.log; do
        if [ -s "$log" ]; then echo "== $log (last 40 lines)"; tail -n 40 "$log"; fi
    done
    if [ -s bench/run/samba/log.smbd ]; then
        echo "== bench/run/samba/log.smbd (denials and errors)"
        grep -i 'NT_STATUS_ACCESS_DENIED\|failed\|denied' bench/run/samba/log.smbd | tail -n 20
    fi
    # A bench test that panicked mid-mount can leave a share mounted;
    # sweep anything still mounted under Orka's mount directory.
    mounts_dir="$HOME/Library/Application Support/Orka/mounts"
    if [ -d "$mounts_dir" ]; then
        for mount_point in "$mounts_dir"/*; do
            [ -d "$mount_point" ] || continue
            umount -f "$mount_point" 2>/dev/null || true
            rmdir "$mount_point" 2>/dev/null || true
        done
    fi
    echo "bench-down: daemons stopped, leftover mounts swept"

# Run the manual live-connector smoke tests against real cloud
# accounts. Needs ORKA_LIVE_* variables set; see docs/TESTING.md.
smoke-live:
    ORKA_LIVE=1 {{cargo}} test --workspace --test smoke_live -- --include-ignored
