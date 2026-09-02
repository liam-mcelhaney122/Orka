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
# and friends can use under ORKA_BENCH=1: Homebrew's smbd, vsftpd
# (implicit FTPS, needs sudo), the NFS bench server, and sshd. Each
# daemon is optional except the NFS server: a missing Homebrew package
# is reported and skipped, not a hard failure, since a workstation
# without `samba`/`vsftpd` installed should still be able to build and
# run the rest of the suite. See docs/TESTING.md for the full picture
# and the ports every daemon uses.

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
        if [ ! -f "$RUN/passdb.tdb" ]; then
            printf 'orka-bench\norka-bench\n' \
                | "$SMBPASSWD" -L -c "$RUN/smb.conf" -s -a "$BENCH_USER" \
                || echo "smbpasswd: failed (see output above); the SMB bench will skip"
        fi
        if [ ! -f bench/run/smbd.pid ] || ! kill -0 "$(cat bench/run/smbd.pid)" 2>/dev/null; then
            # An optional daemon that fails to start must not stop the
            # recipe; the SMB tests skip when the port is closed.
            if "$SMBD" -s "$RUN/smb.conf" -D > "$RUN/smbd.out" 2>&1; then
                sleep 1
                cp "$RUN/pid/smbd.pid" bench/run/smbd.pid 2>/dev/null || true
                echo "smbd: listening on 127.0.0.1:4450 (config $RUN/smb.conf)"
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

    # vsftpd (implicit FTPS is fixed at port 990, which needs root).
    VSFTPD="/opt/homebrew/sbin/vsftpd"
    if [ ! -x "$VSFTPD" ]; then VSFTPD="/usr/local/sbin/vsftpd"; fi
    if [ -x "$VSFTPD" ] && sudo -n true 2>/dev/null; then
        mkdir -p bench/tls
        if [ ! -f bench/tls/cert.pem ]; then
            openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
                -subj "/CN=Orka bench CA" \
                -keyout bench/tls/ca-key.pem -out bench/tls/ca.pem
            openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost" \
                -keyout bench/tls/key.pem -out bench/tls/csr.pem
            openssl x509 -req -in bench/tls/csr.pem -CA bench/tls/ca.pem \
                -CAkey bench/tls/ca-key.pem -CAcreateserial \
                -out bench/tls/cert.pem -days 3650 -sha256 \
                -extfile <(printf 'subjectAltName=DNS:localhost,IP:127.0.0.1')
        fi
        RUN="$(pwd)/bench/run/vsftpd"
        mkdir -p "$RUN/anon"
        sed -e "s#@BENCH_RUN@#$RUN#g" -e "s#@BENCH_TLS@#$(pwd)/bench/tls#g" \
            bench/vsftpd.conf > "$RUN/vsftpd.conf"
        # vsftpd refuses a config file that is not owned by root.
        sudo chown root "$RUN/vsftpd.conf"
        if ! pgrep -f "$RUN/vsftpd.conf" > /dev/null 2>&1; then
            # vsftpd writes a startup failure to file descriptor 0, so
            # that descriptor is opened on the output file as well.
            if sudo "$VSFTPD" "$RUN/vsftpd.conf" 0<> "$RUN/vsftpd.out" 1>&0 2>&0; then
                sleep 1
                echo "vsftpd: listening on 127.0.0.1:990 (implicit TLS, started with sudo)"
            else
                echo "vsftpd: failed to start; the FTPS bench will skip"
                cat "$RUN/vsftpd.out"
            fi
        else
            echo "vsftpd: already running on 127.0.0.1:990"
        fi
    elif [ -x "$VSFTPD" ]; then
        echo "vsftpd: skipped, passwordless sudo is not available in this shell"
    else
        echo "vsftpd: skipped, Homebrew vsftpd is not installed (brew install vsftpd)"
    fi

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
    ORKA_BENCH=1 {{cargo}} test --workspace -- --include-ignored

# Stop every daemon `bench-up` started and unmount any share a bench
# test left mounted. Safe to run even when `bench-up` was never run.
bench-down:
    #!/usr/bin/env bash
    set -uo pipefail
    cd "{{justfile_directory()}}"
    for name in smbd nfs sshd; do
        pid_file="bench/run/$name.pid"
        if [ -f "$pid_file" ]; then
            kill "$(cat "$pid_file")" 2>/dev/null || true
            rm -f "$pid_file"
        fi
    done
    # Daemon output helps diagnose a refused mount or a failed start
    # on a CI runner, where nobody can read the files afterwards.
    for log in bench/run/samba/log.smbd bench/run/samba/smbd.out bench/run/vsftpd/vsftpd.out bench/run/nfs.log; do
        if [ -s "$log" ]; then echo "== $log (last 40 lines)"; tail -n 40 "$log"; fi
    done
    if pgrep -f "bench/run/vsftpd/vsftpd.conf" > /dev/null 2>&1; then
        sudo pkill -f "bench/run/vsftpd/vsftpd.conf" 2>/dev/null || true
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
