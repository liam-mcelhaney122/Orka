//! Manual live-connector smoke tests, against real accounts and real
//! servers.
//!
//! Nothing here runs in CI: every test is `#[ignore]` and needs a
//! person to provision a real credential first (a Kerberos ticket, or
//! an OAuth token obtained through the manual checklist in
//! `docs/TESTING.md`) and pass its connection details through an
//! `ORKA_LIVE_*` variable. Run the whole file with:
//!
//!   just smoke-live
//!   # or directly:
//!   ORKA_LIVE=1 cargo test --workspace --test smoke_live -- --include-ignored
//!
//! A test returns early with a skip message when `ORKA_LIVE` is not
//! `1`, exactly like the `ORKA_BENCH` tier in `bench_mounts.rs`, so an
//! accidental `--include-ignored` run elsewhere in the workspace never
//! reaches out to a real account. Once `ORKA_LIVE=1` is set, a missing
//! per-connector variable is a real failure with a clear message,
//! not a second, silent skip: at that point a person asked for this
//! tier and should be told exactly what is missing.

use orka_core::vfs::connections::{AuthMethod, BackendFactory, ConnectionConfig, SecretProvider};
use orka_core::vfs::mount::MountFactory;
use orka_core::vfs::oauth::TokenSet;
use orka_core::vfs::Scheme;
use orka_core::ListOptions;
use std::sync::Arc;

fn live_enabled() -> bool {
    std::env::var("ORKA_LIVE").as_deref() == Ok("1")
}

/// Reads a required `ORKA_LIVE_*` variable, or fails with a message
/// naming exactly what to set. Unlike the bench tier's daemon checks,
/// a missing variable here is a hard failure: `ORKA_LIVE=1` already
/// told this test the operator wants it to run for real.
fn required_var(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!("set {name} to run this live smoke test; see the checklist in docs/TESTING.md")
    })
}

struct NoSecret;
impl SecretProvider for NoSecret {
    fn get_secret(&self, _connection_id: &str) -> Option<String> {
        None
    }
}

/// Kerberos SMB: run `kinit` by hand first (see docs/TESTING.md), then
/// point this at a real share the ticket can access.
///
///   ORKA_LIVE_SMB_HOST     server/share, e.g. fileserver.example.com/homes
///   ORKA_LIVE_SMB_USER     DOMAIN;user or user, matching the Kerberos principal
#[test]
#[ignore = "needs a live Kerberos ticket and a real SMB share; run with `just smoke-live`"]
fn smb_kerberos_live_smoke() {
    if !live_enabled() {
        eprintln!("skipping: set ORKA_LIVE=1 to run the live smoke tier");
        return;
    }
    let host = required_var("ORKA_LIVE_SMB_HOST");
    let username = required_var("ORKA_LIVE_SMB_USER");

    let config = ConnectionConfig {
        id: "live-smb-kerberos".to_string(),
        display_name: "Live SMB (Kerberos)".to_string(),
        scheme: Scheme::Smb,
        host,
        port: 445,
        username,
        initial_path: "/".to_string(),
        auth: AuthMethod::Kerberos,
    };
    let backend = MountFactory
        .connect(&config, Arc::new(NoSecret))
        .expect("Kerberos SMB connect failed; confirm `klist` shows a valid ticket");
    backend
        .list_dir("/", &ListOptions::default())
        .expect("listing the share root failed");
}

/// Kerberos NFS: run `kinit` by hand first, then point this at a real
/// export configured for `sec=krb5`.
///
///   ORKA_LIVE_NFS_HOST     server:/export, e.g. nfs.example.com:/export/home
#[test]
#[ignore = "needs a live Kerberos ticket and a real NFS export; run with `just smoke-live`"]
fn nfs_kerberos_live_smoke() {
    if !live_enabled() {
        eprintln!("skipping: set ORKA_LIVE=1 to run the live smoke tier");
        return;
    }
    let host = required_var("ORKA_LIVE_NFS_HOST");

    let config = ConnectionConfig {
        id: "live-nfs-kerberos".to_string(),
        display_name: "Live NFS (Kerberos)".to_string(),
        scheme: Scheme::Nfs,
        host,
        port: 2049,
        username: String::new(),
        initial_path: "/".to_string(),
        auth: AuthMethod::Kerberos,
    };
    let backend = MountFactory.connect(&config, Arc::new(NoSecret)).expect(
        "Kerberos NFS connect failed; confirm `klist` shows a valid ticket and the \
                 export allows sec=krb5",
    );
    backend
        .list_dir("/", &ListOptions::default())
        .expect("listing the export root failed");
}

/// A previously-obtained OAuth token set for one of the three OAuth
/// connectors. Getting the token itself is the manual step: sign in
/// once through Orka's own OAuth flow (see docs/TESTING.md), then
/// copy the token JSON the keychain now holds into the matching
/// `ORKA_LIVE_*_TOKEN_JSON` variable.
fn live_token(var: &str) -> TokenSet {
    let json = required_var(var);
    TokenSet::from_json(&json)
        .unwrap_or_else(|e| panic!("{var} does not hold a valid token set: {e}"))
}

struct FixedToken(String);
impl SecretProvider for FixedToken {
    fn get_secret(&self, _connection_id: &str) -> Option<String> {
        Some(self.0.clone())
    }
}

/// Google Drive OAuth, against a real Google account.
///
///   ORKA_LIVE_GOOGLE_CLIENT_ID     the OAuth client id used to sign in
///   ORKA_LIVE_GOOGLE_TOKEN_JSON    a TokenSet JSON blob from a completed sign-in
#[test]
#[ignore = "needs a real Google account and a previously obtained OAuth token; run with `just smoke-live`"]
fn google_drive_live_smoke() {
    if !live_enabled() {
        eprintln!("skipping: set ORKA_LIVE=1 to run the live smoke tier");
        return;
    }
    let client_id = required_var("ORKA_LIVE_GOOGLE_CLIENT_ID");
    let token = live_token("ORKA_LIVE_GOOGLE_TOKEN_JSON");

    let config = ConnectionConfig {
        id: "live-google-drive".to_string(),
        display_name: "Live Google Drive".to_string(),
        scheme: Scheme::Gdrive,
        host: "drive.google.com".to_string(),
        port: 443,
        username: String::new(),
        initial_path: "/".to_string(),
        auth: AuthMethod::OAuthApp {
            client_id,
            tenant_id: String::new(),
        },
    };
    let secrets: Arc<dyn SecretProvider> = Arc::new(FixedToken(
        token.to_json().expect("re-encode the live token set"),
    ));
    let backend = orka_core::vfs::gdrive::GdriveFactory
        .connect(&config, secrets)
        .expect("Google Drive connect failed; the token may have expired, sign in again");
    backend
        .list_dir("/", &ListOptions::default())
        .expect("listing My Drive's root failed");
}

/// Dropbox OAuth, against a real Dropbox account.
///
///   ORKA_LIVE_DROPBOX_CLIENT_ID     the OAuth client id (app key) used to sign in
///   ORKA_LIVE_DROPBOX_TOKEN_JSON    a TokenSet JSON blob from a completed sign-in
#[test]
#[ignore = "needs a real Dropbox account and a previously obtained OAuth token; run with `just smoke-live`"]
fn dropbox_live_smoke() {
    if !live_enabled() {
        eprintln!("skipping: set ORKA_LIVE=1 to run the live smoke tier");
        return;
    }
    let client_id = required_var("ORKA_LIVE_DROPBOX_CLIENT_ID");
    let token = live_token("ORKA_LIVE_DROPBOX_TOKEN_JSON");

    let config = ConnectionConfig {
        id: "live-dropbox".to_string(),
        display_name: "Live Dropbox".to_string(),
        scheme: Scheme::Dropbox,
        host: "dropbox.com".to_string(),
        port: 443,
        username: String::new(),
        initial_path: "/".to_string(),
        auth: AuthMethod::OAuthApp {
            client_id,
            tenant_id: String::new(),
        },
    };
    let secrets: Arc<dyn SecretProvider> = Arc::new(FixedToken(
        token.to_json().expect("re-encode the live token set"),
    ));
    let backend = orka_core::vfs::dropbox::DropboxFactory
        .connect(&config, secrets)
        .expect("Dropbox connect failed; the token may have expired, sign in again");
    backend
        .list_dir("/", &ListOptions::default())
        .expect("listing the Dropbox root failed");
}

/// Azure ADLS Gen2 OAuth, against a real storage account.
///
///   ORKA_LIVE_AZURE_ACCOUNT          storage account name (this is `host`)
///   ORKA_LIVE_AZURE_FILESYSTEM       the ADLS filesystem (container) name, used as the root
///   ORKA_LIVE_AZURE_TENANT_ID        the Azure AD tenant id used to sign in
///   ORKA_LIVE_AZURE_CLIENT_ID        the OAuth client id used to sign in
///   ORKA_LIVE_AZURE_TOKEN_JSON       a TokenSet JSON blob from a completed sign-in
#[test]
#[ignore = "needs a real Azure storage account and a previously obtained OAuth token; run with `just smoke-live`"]
fn azure_adls_live_smoke() {
    if !live_enabled() {
        eprintln!("skipping: set ORKA_LIVE=1 to run the live smoke tier");
        return;
    }
    let account = required_var("ORKA_LIVE_AZURE_ACCOUNT");
    let filesystem = required_var("ORKA_LIVE_AZURE_FILESYSTEM");
    let tenant_id = required_var("ORKA_LIVE_AZURE_TENANT_ID");
    let client_id = required_var("ORKA_LIVE_AZURE_CLIENT_ID");
    let token = live_token("ORKA_LIVE_AZURE_TOKEN_JSON");

    let config = ConnectionConfig {
        id: "live-azure-adls".to_string(),
        display_name: "Live Azure ADLS".to_string(),
        scheme: Scheme::Adls,
        host: account,
        port: 443,
        username: String::new(),
        initial_path: format!("/{filesystem}"),
        auth: AuthMethod::OAuthApp {
            client_id,
            tenant_id,
        },
    };
    let secrets: Arc<dyn SecretProvider> = Arc::new(FixedToken(
        token.to_json().expect("re-encode the live token set"),
    ));
    let backend = orka_core::vfs::adls::AdlsFactory
        .connect(&config, secrets)
        .expect("Azure ADLS connect failed; the token may have expired, sign in again");
    let root = format!("/{filesystem}");
    backend
        .list_dir(&root, &ListOptions::default())
        .unwrap_or_else(|e| panic!("listing {root} failed: {e}"));
}
