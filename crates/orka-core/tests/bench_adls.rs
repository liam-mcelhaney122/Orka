//! Proves every ADLS Gen2 sign-in path against a fake `dfs` REST
//! endpoint: shared key, a SAS query string, a pasted bearer token, a
//! service principal, and a signed-in OAuth app.
//!
//! One [`FakeAdls`] and one [`FakeOAuth`] back every test in this
//! file, started once behind a [`OnceLock`]: the ADLS backend reads
//! `ORKA_ENDPOINT_AZURE_LOGIN` and `ORKA_EXTRA_CA_FILE` from the
//! process environment when it builds a connection, and an
//! environment variable is process-global, so it can only be set
//! once, before anything in this binary might read it. Each test uses
//! its own filesystem name, so the fakes' shared state (the request
//! log, the file tree) never crosses between tests even when `cargo
//! test` runs them concurrently.

mod support;

use orka_bench::fake_adls::{AdlsConfig, FakeAdls};
use orka_bench::fake_oauth::{FakeOAuth, OAuthConfig};
use orka_core::vfs::adls::AdlsFactory;
use orka_core::vfs::connections::{AuthMethod, BackendFactory, ConnectionConfig, SecretProvider};
use orka_core::vfs::oauth::TokenSet;
use orka_core::vfs::Scheme;
use orka_core::ListOptions;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex, OnceLock};

const SHARED_KEY_BYTES: &[u8] = b"orka-bench-adls-shared-key-material";
const SAS_QUERY: &str = "sv=2023-11-03&sig=orka-bench-adls-sas-signature";
const STATIC_BEARER: &str = "orka-bench-adls-pasted-bearer-token";
const OAUTH_CLIENT_ID: &str = "orka-bench-adls-client";
const OAUTH_CLIENT_SECRET: &str = "orka-bench-adls-client-secret";
const OAUTH_TENANT: &str = "orka-bench-adls-tenant";

/// The two fakes this whole test binary shares, plus the environment
/// they need pointed at them. Built exactly once.
struct Fakes {
    adls: FakeAdls,
    oauth: FakeOAuth,
}

fn fakes() -> &'static Fakes {
    static FAKES: OnceLock<Fakes> = OnceLock::new();
    FAKES.get_or_init(|| {
        let oauth = FakeOAuth::start(
            OAuthConfig::new(OAUTH_CLIENT_ID).with_client_secret(OAUTH_CLIENT_SECRET),
        );
        let adls = FakeAdls::start(AdlsConfig {
            account_name: "orkabenchaccount".to_string(),
            shared_key_base64: Some(shared_key_b64()),
            sas_token: Some(SAS_QUERY.to_string()),
            token_store: Some(oauth.token_store()),
            static_bearer: Some(STATIC_BEARER.to_string()),
        });
        // Read once, here, before any connection in this binary is
        // built. `orka_core`'s ADLS backend resolves both of these
        // when a connection is built and keeps the result for that
        // connection's whole life, so setting them any later than
        // this would risk a connection built earlier not seeing them.
        //
        // SAFETY: this `OnceLock` runs its initializer exactly once,
        // and nothing else in this test binary touches these two
        // variables, so there is no concurrent reader or writer to
        // race with.
        unsafe {
            std::env::set_var("ORKA_EXTRA_CA_FILE", adls.ca_file_path());
            std::env::set_var("ORKA_ENDPOINT_AZURE_LOGIN", oauth.base_url());
        }
        Fakes { adls, oauth }
    })
}

fn shared_key_b64() -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    STANDARD.encode(SHARED_KEY_BYTES)
}

/// A minimal [`SecretProvider`] backed by an in-memory map, recording
/// every `set_secret` call so a test can read back a refreshed token.
struct RecordingSecrets(Mutex<HashMap<String, String>>);

impl RecordingSecrets {
    fn seeded(connection_id: &str, value: &str) -> Arc<RecordingSecrets> {
        let mut map = HashMap::new();
        map.insert(connection_id.to_string(), value.to_string());
        Arc::new(RecordingSecrets(Mutex::new(map)))
    }
}

impl SecretProvider for RecordingSecrets {
    fn get_secret(&self, connection_id: &str) -> Option<String> {
        self.0.lock().unwrap().get(connection_id).cloned()
    }

    fn set_secret(&self, connection_id: &str, value: &str) {
        self.0
            .lock()
            .unwrap()
            .insert(connection_id.to_string(), value.to_string());
    }
}

fn config_for(id: &str, filesystem: &str, host: String, auth: AuthMethod) -> ConnectionConfig {
    ConnectionConfig {
        id: id.to_string(),
        display_name: id.to_string(),
        scheme: Scheme::Adls,
        host,
        port: 443,
        username: filesystem.to_string(),
        initial_path: "/".to_string(),
        auth,
    }
}

fn count_grants(oauth: &FakeOAuth, grant_type: &str) -> usize {
    oauth
        .token_grants()
        .iter()
        .filter(|g| g.as_str() == grant_type)
        .count()
}

/// Decodes `%XX` escapes only, matching how `x-ms-rename-source` is
/// built (a whole-string percent-encode that also escapes the path's
/// own `/` separators, so decoding it recovers the literal path).
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
            if let Some(byte) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Runs the PKCE authorize/token-exchange flow against `oauth` and
/// returns the minted `(access_token, refresh_token)`. Used to seed a
/// real, fake-issued refresh token for the OAuth-app test, since the
/// fake only ever hands out a refresh token through this flow.
fn mint_pkce_tokens(oauth: &FakeOAuth) -> (String, String) {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use sha2::{Digest, Sha256};

    let verifier = "orka-bench-adls-pkce-verifier-at-least-43-chars-long";
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let redirect_uri = "http://127.0.0.1:9/callback";
    let state = "orka-bench-adls-state";

    let authorize_url = format!(
        "{}?client_id={OAUTH_CLIENT_ID}&redirect_uri={redirect_uri}&response_type=code&state={state}&code_challenge={challenge}&code_challenge_method=S256",
        oauth.authorize_url(),
    );
    let agent = ureq::AgentBuilder::new().redirects(0).build();
    let response = agent
        .get(&authorize_url)
        .call()
        .expect("authorize must respond");
    assert_eq!(
        response.status(),
        302,
        "authorize must redirect with a code"
    );
    let location = response
        .header("Location")
        .expect("redirect must carry Location")
        .to_string();
    let query = location.split_once('?').map(|(_, q)| q).unwrap_or("");
    let code = query
        .split('&')
        .find_map(|pair| pair.strip_prefix("code="))
        .expect("redirect must carry a code")
        .to_string();

    let body: serde_json::Value = ureq::post(&oauth.token_url())
        .send_form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", redirect_uri),
            ("client_id", OAUTH_CLIENT_ID),
            ("code_verifier", verifier),
            ("client_secret", OAUTH_CLIENT_SECRET),
        ])
        .expect("code exchange must succeed")
        .into_json()
        .expect("token response must be JSON");
    (
        body["access_token"]
            .as_str()
            .expect("access_token")
            .to_string(),
        body["refresh_token"]
            .as_str()
            .expect("refresh_token")
            .to_string(),
    )
}

// --- 1. Shared key ---

#[test]
fn shared_key_signs_every_request_and_passes_conformance() {
    let f = fakes();
    let fs_name = "fs-sharedkey";
    f.adls.create_filesystem(fs_name);

    let config = config_for(
        "conn-sharedkey",
        fs_name,
        f.adls.host_with_port(),
        AuthMethod::SharedKey,
    );
    let secrets = RecordingSecrets::seeded(&config.id, &shared_key_b64());
    let backend = AdlsFactory
        .connect(&config, secrets)
        .expect("connect must succeed offline");

    support::conformance::exercise_backend(&*backend, "/");

    assert!(
        f.adls.verified_signature_count() > 0,
        "the fake must have verified at least one SharedKey signature"
    );
}

// --- 2. SAS token ---

#[test]
fn sas_token_authorizes_every_request_including_pagination() {
    let f = fakes();
    let fs_name = "fs-sas";
    f.adls.create_filesystem(fs_name);

    let config = config_for(
        "conn-sas",
        fs_name,
        f.adls.host_with_port(),
        AuthMethod::SasToken,
    );
    let secrets = RecordingSecrets::seeded(&config.id, SAS_QUERY);
    let backend = AdlsFactory
        .connect(&config, secrets)
        .expect("connect must succeed offline");

    support::conformance::exercise_backend(&*backend, "/");

    // A listing that needs more than one page: five entries, two per
    // page, so the client must follow at least one continuation.
    f.adls.set_page_size(2);
    for i in 0..5 {
        f.adls.seed_file(fs_name, &format!("page-{i}.bin"), b"x");
    }
    let entries = backend
        .list_dir("/", &ListOptions::default())
        .expect("a paginated listing must still return every entry");
    assert_eq!(
        entries.len(),
        5,
        "pagination must not drop or duplicate entries"
    );

    let path_prefix = format!("/{fs_name}/");
    let own_requests: Vec<_> = f
        .adls
        .requests()
        .into_iter()
        .filter(|r| r.path.starts_with(&path_prefix))
        .collect();
    let listing_requests: Vec<_> = own_requests
        .iter()
        .filter(|r| r.query_param("resource") == Some("filesystem"))
        .collect();
    assert!(
        listing_requests.len() > 1,
        "five entries at a page size of two must take more than one request"
    );
    for request in &own_requests {
        assert!(
            request.header("authorization").is_none(),
            "a SAS-authorized request must never carry an Authorization header"
        );
        assert!(
            request.query_param("sv").is_some() && request.query_param("sig").is_some(),
            "every request, continuation included, must keep the SAS query parameters"
        );
    }

    // A DNS failure on a SAS connection must never leak the signature.
    let bad_config = config_for(
        "conn-sas-dns-failure",
        "whatever-fs",
        "nonexistent.invalid".to_string(),
        AuthMethod::SasToken,
    );
    let bad_secrets = RecordingSecrets::seeded(&bad_config.id, SAS_QUERY);
    let bad_backend = AdlsFactory
        .connect(&bad_config, bad_secrets)
        .expect("connect validates the SAS token offline and never touches the network");
    let err = bad_backend
        .list_dir("/", &ListOptions::default())
        .expect_err("a non-resolving host must fail");
    assert!(
        !err.contains("sig="),
        "the error message must not leak the SAS signature: {err}"
    );
}

// --- 3. Pasted OAuth token ---

#[test]
fn pasted_bearer_token_authorizes_list_and_read() {
    let f = fakes();
    let fs_name = "fs-bearer";
    f.adls.create_filesystem(fs_name);
    f.adls.seed_file(fs_name, "hello.txt", b"hello bearer");

    let config = config_for(
        "conn-bearer",
        fs_name,
        f.adls.host_with_port(),
        AuthMethod::OAuthToken,
    );
    let secrets = RecordingSecrets::seeded(&config.id, STATIC_BEARER);
    let backend = AdlsFactory
        .connect(&config, secrets)
        .expect("connect must succeed offline");

    let entries = backend
        .list_dir("/", &ListOptions::default())
        .expect("list must succeed");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "hello.txt");

    let mut reader = backend.open_read("/hello.txt").expect("open must succeed");
    let mut content = Vec::new();
    reader.read_to_end(&mut content).expect("read must succeed");
    assert_eq!(content, b"hello bearer");

    let path_prefix = format!("/{fs_name}/");
    assert!(
        f.adls
            .requests()
            .iter()
            .any(|r| r.path.starts_with(&path_prefix) && r.bearer_token() == Some(STATIC_BEARER)),
        "the fake must have seen the pasted bearer token"
    );
}

// --- 4. Service principal ---

#[test]
fn service_principal_caches_the_token_and_retries_once_after_a_401() {
    let f = fakes();
    let fs_name = "fs-serviceprincipal";
    f.adls.create_filesystem(fs_name);
    f.adls.seed_file(fs_name, "a.txt", b"a");

    let config = config_for(
        "conn-serviceprincipal",
        fs_name,
        f.adls.host_with_port(),
        AuthMethod::ServicePrincipal {
            tenant_id: OAUTH_TENANT.to_string(),
            client_id: OAUTH_CLIENT_ID.to_string(),
        },
    );
    let secrets = RecordingSecrets::seeded(&config.id, OAUTH_CLIENT_SECRET);
    let backend = AdlsFactory
        .connect(&config, secrets)
        .expect("connect never fetches a service-principal token itself");

    let grants_before = count_grants(&f.oauth, "client_credentials");
    backend
        .list_dir("/", &ListOptions::default())
        .expect("the first request must fetch a token");
    let grants_after_first = count_grants(&f.oauth, "client_credentials");
    assert_eq!(
        grants_after_first - grants_before,
        1,
        "the first request must perform exactly one grant"
    );

    backend
        .list_dir("/", &ListOptions::default())
        .expect("the second request must reuse the cache");
    let grants_after_second = count_grants(&f.oauth, "client_credentials");
    assert_eq!(
        grants_after_second, grants_after_first,
        "a fresh cached token must not be re-fetched"
    );

    let path_prefix = format!("/{fs_name}/");
    let used_token = f
        .adls
        .requests()
        .iter()
        .rev()
        .filter(|r| r.path.starts_with(&path_prefix))
        .find_map(|r| r.bearer_token().map(str::to_string))
        .expect("a request carrying the service-principal's bearer token must have been logged");
    f.oauth.expire_access_token(&used_token);

    // The token is still fresh by the client's own clock, so only the
    // live 401 can tell the backend to run the grant again. One new
    // grant, then the retried request must succeed.
    backend
        .list_dir("/", &ListOptions::default())
        .expect("a 401 must trigger one client-credentials grant and then succeed");
    let grants_after_revoke = count_grants(&f.oauth, "client_credentials");
    assert_eq!(
        grants_after_revoke - grants_after_second,
        1,
        "a 401 must trigger exactly one more grant, not zero or a retry loop"
    );
    let retried_token = f
        .adls
        .requests()
        .iter()
        .rev()
        .filter(|r| r.path.starts_with(&path_prefix))
        .find_map(|r| r.bearer_token().map(str::to_string))
        .expect("the retried request must carry a bearer token");
    assert_ne!(
        retried_token, used_token,
        "the retry must send the new token, not the revoked one"
    );
    assert!(
        f.oauth.is_valid_access_token(&retried_token),
        "the retried token must be one the fake issued"
    );
}

// --- 5. OAuth app (signed-in) ---

#[test]
fn oauth_app_refreshes_an_expired_token_and_retries_once_after_a_401() {
    let f = fakes();
    let fs_name = "fs-oauthapp";
    f.adls.create_filesystem(fs_name);
    f.adls.seed_file(fs_name, "a.txt", b"a");

    let (_first_access_token, refresh_token) = mint_pkce_tokens(&f.oauth);
    let connection_id = "conn-oauthapp";
    let expired = TokenSet {
        access_token: "already-expired-access-token".to_string(),
        refresh_token: Some(refresh_token),
        expires_at_ms: 0,
        client_secret: Some(OAUTH_CLIENT_SECRET.to_string()),
    };
    let secrets = RecordingSecrets::seeded(connection_id, &expired.to_json().unwrap());

    let config = config_for(
        connection_id,
        fs_name,
        f.adls.host_with_port(),
        AuthMethod::OAuthApp {
            client_id: OAUTH_CLIENT_ID.to_string(),
            tenant_id: OAUTH_TENANT.to_string(),
        },
    );
    let backend = AdlsFactory
        .connect(&config, secrets.clone())
        .expect("connect only checks that a token is stored");

    let refresh_grants_before = count_grants(&f.oauth, "refresh_token");
    backend
        .list_dir("/", &ListOptions::default())
        .expect("the first request must refresh the already-expired token");
    let refresh_grants_after_first = count_grants(&f.oauth, "refresh_token");
    assert_eq!(
        refresh_grants_after_first - refresh_grants_before,
        1,
        "an expired token must refresh exactly once before the first request"
    );

    let stored = secrets
        .get_secret(connection_id)
        .expect("a refreshed token must be stored");
    let stored_set =
        TokenSet::from_json(&stored).expect("the stored secret must be a valid token set");
    assert_ne!(
        stored_set.access_token, "already-expired-access-token",
        "set_secret must carry the new token"
    );
    assert!(
        f.oauth.is_valid_access_token(&stored_set.access_token),
        "the stored access token must be one the fake actually issued"
    );

    // Revoke the token server-side and force a 401: one refresh, then
    // the retried request succeeds.
    f.oauth.expire_access_token(&stored_set.access_token);
    backend
        .list_dir("/", &ListOptions::default())
        .expect("a 401 must trigger exactly one more refresh and then succeed");
    let refresh_grants_after_second = count_grants(&f.oauth, "refresh_token");
    assert_eq!(
        refresh_grants_after_second - refresh_grants_after_first,
        1,
        "a 401 must trigger exactly one more refresh grant, not zero or a retry loop"
    );
}

// --- 6. Rename header and large-file append chunking ---

#[test]
fn rename_carries_the_source_header_and_a_large_file_is_one_append() {
    let f = fakes();
    let fs_name = "fs-large";
    f.adls.create_filesystem(fs_name);

    let config = config_for(
        "conn-large",
        fs_name,
        f.adls.host_with_port(),
        AuthMethod::SharedKey,
    );
    let secrets = RecordingSecrets::seeded(&config.id, &shared_key_b64());
    let backend = AdlsFactory
        .connect(&config, secrets)
        .expect("connect must succeed offline");

    // Rename.
    {
        let mut writer = backend
            .create_write("/rename_src.txt", None)
            .expect("create must succeed");
        writer.write_all(b"move me").expect("write must succeed");
        writer.finish().expect("finish must succeed");
    }
    backend
        .rename("/rename_src.txt", "/rename_dst.txt")
        .expect("rename must succeed");

    let path_prefix = format!("/{fs_name}/");
    let rename_request = f
        .adls
        .requests()
        .into_iter()
        .rfind(|r| {
            r.path.starts_with(&path_prefix)
                && r.method == "PUT"
                && r.query_param("action") == Some("rename")
        })
        .expect("the rename PUT must have been logged");
    let source_header = rename_request
        .header("x-ms-rename-source")
        .expect("x-ms-rename-source must be set")
        .to_string();
    assert_eq!(
        percent_decode(&source_header),
        format!("/{fs_name}/rename_src.txt"),
        "x-ms-rename-source must decode back to the source filesystem and path"
    );

    // Large file: orka_core's `ChannelWriter` forwards one `write()`
    // call as one append with no further splitting (see
    // `write_pump`/`ChannelWriter::write` in
    // `crates/orka-core/src/vfs/adls.rs`), and the conformance suite's
    // large-file step issues a single `write_all` of the whole
    // buffer. So a 3 MiB file must round-trip through exactly one
    // append call, not several.
    let size = 3 * 1024 * 1024;
    let mut data = vec![0u8; size];
    for (i, byte) in data.iter_mut().enumerate() {
        *byte = (i % 251) as u8;
    }
    {
        let mut writer = backend
            .create_write("/large.bin", Some(size as u64))
            .expect("create the large file");
        writer.write_all(&data).expect("write the large file");
        writer.finish().expect("finish the large file");
    }
    let mut reader = backend
        .open_read("/large.bin")
        .expect("open the large file");
    let mut actual = Vec::new();
    reader
        .read_to_end(&mut actual)
        .expect("read the large file");
    assert_eq!(actual, data, "the large file must round-trip exactly");

    let append_count = f
        .adls
        .requests()
        .into_iter()
        .filter(|r| {
            r.path.starts_with(&path_prefix)
                && r.method == "PATCH"
                && r.query_param("action") == Some("append")
                && r.path.contains("large.bin")
        })
        .count();
    assert_eq!(
        append_count, 1,
        "orka_core's writer never chunks a single write_all into more than one append"
    );
}

// --- 7. Write shapes: create before append, positions, empty files ---

/// The requests logged for one filesystem, in arrival order.
fn requests_for(f: &Fakes, fs_name: &str) -> Vec<orka_bench::fake_http::Request> {
    let path_prefix = format!("/{fs_name}/");
    f.adls
        .requests()
        .into_iter()
        .filter(|r| r.path.starts_with(&path_prefix))
        .collect()
}

#[test]
fn a_zero_byte_write_creates_the_file_and_flushes_at_position_zero() {
    let f = fakes();
    let fs_name = "fs-empty-file";
    f.adls.create_filesystem(fs_name);

    let config = config_for(
        "conn-empty-file",
        fs_name,
        f.adls.host_with_port(),
        AuthMethod::SharedKey,
    );
    let secrets = RecordingSecrets::seeded(&config.id, &shared_key_b64());
    let backend = AdlsFactory
        .connect(&config, secrets)
        .expect("connect must succeed offline");

    {
        let writer = backend
            .create_write("/empty.bin", Some(0))
            .expect("create must succeed");
        writer
            .finish()
            .expect("finish must succeed with no bytes written");
    }

    let stat = backend
        .stat("/empty.bin")
        .expect("an empty file must exist after finish");
    assert_eq!(stat.size, 0, "an empty file must report zero bytes");
    assert!(!stat.is_dir);
    let mut reader = backend.open_read("/empty.bin").expect("open must succeed");
    let mut content = Vec::new();
    reader.read_to_end(&mut content).expect("read must succeed");
    assert!(
        content.is_empty(),
        "an empty file must read back as no bytes"
    );

    let requests = requests_for(f, fs_name);
    let creates = requests
        .iter()
        .filter(|r| r.method == "PUT" && r.query_param("resource") == Some("file"))
        .count();
    assert_eq!(
        creates, 1,
        "the write must create the file with PUT ?resource=file"
    );
    let appends = requests
        .iter()
        .filter(|r| r.method == "PATCH" && r.query_param("action") == Some("append"))
        .count();
    assert_eq!(appends, 0, "a zero-byte write must not append");
    let flush = requests
        .iter()
        .find(|r| r.method == "PATCH" && r.query_param("action") == Some("flush"))
        .expect("the write must flush");
    assert_eq!(
        flush.query_param("position"),
        Some("0"),
        "an empty file flushes at position 0"
    );
}

#[test]
fn overwriting_a_longer_file_leaves_only_the_shorter_content() {
    let f = fakes();
    let fs_name = "fs-overwrite";
    f.adls.create_filesystem(fs_name);

    let config = config_for(
        "conn-overwrite",
        fs_name,
        f.adls.host_with_port(),
        AuthMethod::SharedKey,
    );
    let secrets = RecordingSecrets::seeded(&config.id, &shared_key_b64());
    let backend = AdlsFactory
        .connect(&config, secrets)
        .expect("connect must succeed offline");

    for content in [&b"a much longer first body"[..], &b"short"[..]] {
        let mut writer = backend
            .create_write("/f.txt", Some(content.len() as u64))
            .expect("create");
        writer.write_all(content).expect("write");
        writer.finish().expect("finish");
    }

    let stat = backend.stat("/f.txt").expect("stat");
    assert_eq!(
        stat.size, 5,
        "the overwrite must truncate before it appends"
    );
    let mut reader = backend.open_read("/f.txt").expect("open");
    let mut content = Vec::new();
    reader.read_to_end(&mut content).expect("read");
    assert_eq!(content, b"short", "no byte of the longer body may survive");

    // Every append names its byte offset, and each write starts at 0
    // because the create truncated the file first.
    let appends: Vec<_> = requests_for(f, fs_name)
        .into_iter()
        .filter(|r| r.method == "PATCH" && r.query_param("action") == Some("append"))
        .collect();
    assert_eq!(appends.len(), 2);
    for append in &appends {
        assert_eq!(
            append.query_param("position"),
            Some("0"),
            "each write starts at offset 0"
        );
    }
}

#[test]
fn a_chunked_write_appends_at_running_positions() {
    let f = fakes();
    let fs_name = "fs-chunks";
    f.adls.create_filesystem(fs_name);

    let config = config_for(
        "conn-chunks",
        fs_name,
        f.adls.host_with_port(),
        AuthMethod::SasToken,
    );
    let secrets = RecordingSecrets::seeded(&config.id, SAS_QUERY);
    let backend = AdlsFactory
        .connect(&config, secrets)
        .expect("connect must succeed offline");

    {
        let mut writer = backend.create_write("/chunks.bin", None).expect("create");
        writer.write_all(b"12345").expect("first chunk");
        writer.write_all(b"678").expect("second chunk");
        writer.write_all(b"90").expect("third chunk");
        writer.finish().expect("finish");
    }
    let mut reader = backend.open_read("/chunks.bin").expect("open");
    let mut content = Vec::new();
    reader.read_to_end(&mut content).expect("read");
    assert_eq!(content, b"1234567890");

    let positions: Vec<String> = requests_for(f, fs_name)
        .into_iter()
        .filter(|r| r.method == "PATCH" && r.query_param("action") == Some("append"))
        .map(|r| r.query_param("position").unwrap_or("").to_string())
        .collect();
    assert_eq!(
        positions,
        ["0", "5", "8"],
        "each append must name the offset its chunk starts at"
    );
    let flush = requests_for(f, fs_name)
        .into_iter()
        .rfind(|r| r.method == "PATCH" && r.query_param("action") == Some("flush"))
        .expect("the write must flush");
    assert_eq!(flush.query_param("position"), Some("10"));
    assert_eq!(
        flush.header("content-length"),
        Some("0"),
        "a flush carries no body"
    );
}

// --- 8. Listing and property shapes as the real service sends them ---

/// A client that talks to the fake directly with the pasted bearer
/// token, so a test can inspect raw answers and send request shapes
/// the backend never would. Trusts the fake's certificate through the
/// same `ORKA_EXTRA_CA_FILE` the backend reads.
fn raw_client(f: &Fakes) -> (ureq::Agent, String) {
    let agent = orka_core::vfs::http::agent().expect("the fake's CA file must be readable");
    let base = format!("{}/", f.adls.base_url());
    (agent, base)
}

/// The error is boxed because `ureq::Error` is large, and a test only
/// ever matches on its status.
type RawResult = Result<ureq::Response, Box<ureq::Error>>;

fn raw_get(agent: &ureq::Agent, url: &str) -> RawResult {
    agent
        .get(url)
        .set("Authorization", &format!("Bearer {STATIC_BEARER}"))
        .set("x-ms-version", "2023-11-03")
        .call()
        .map_err(Box::new)
}

fn raw_send(agent: &ureq::Agent, method: &str, url: &str, body: &[u8]) -> RawResult {
    agent
        .request(method, url)
        .set("Authorization", &format!("Bearer {STATIC_BEARER}"))
        .set("x-ms-version", "2023-11-03")
        .send_bytes(body)
        .map_err(Box::new)
}

fn status_of(result: RawResult) -> u16 {
    match result {
        Ok(response) => response.status(),
        Err(boxed) => match *boxed {
            ureq::Error::Status(status, _) => status,
            other => panic!("transport failure: {other}"),
        },
    }
}

#[test]
fn listing_uses_string_fields_and_the_backend_reads_them() {
    let f = fakes();
    let fs_name = "fs-list-shape";
    f.adls.create_filesystem(fs_name);
    f.adls.seed_file(fs_name, "data.bin", b"twelve bytes");
    f.adls.seed_file(fs_name, "sub/inner.txt", b"x");

    // The raw page: every value a string, `isDirectory` absent for a
    // file, `"true"` for a directory.
    let (agent, base) = raw_client(f);
    let page: serde_json::Value = raw_get(
        &agent,
        &format!("{base}{fs_name}?resource=filesystem&recursive=false"),
    )
    .expect("list must succeed")
    .into_json()
    .expect("the listing must be JSON");
    let paths = page["paths"].as_array().expect("paths array");
    let file = paths
        .iter()
        .find(|p| p["name"] == "data.bin")
        .expect("data.bin listed");
    assert_eq!(
        file["contentLength"],
        serde_json::json!("12"),
        "contentLength is a string"
    );
    assert!(
        file.get("isDirectory").is_none(),
        "a file carries no isDirectory field"
    );
    let dir = paths
        .iter()
        .find(|p| p["name"] == "sub")
        .expect("sub listed");
    assert_eq!(
        dir["isDirectory"],
        serde_json::json!("true"),
        "isDirectory is the string \"true\""
    );
    assert_eq!(dir["contentLength"], serde_json::json!("0"));

    // The backend reads those strings back as a size and a kind.
    let config = config_for(
        "conn-list-shape",
        fs_name,
        f.adls.host_with_port(),
        AuthMethod::OAuthToken,
    );
    let secrets = RecordingSecrets::seeded(&config.id, STATIC_BEARER);
    let backend = AdlsFactory
        .connect(&config, secrets)
        .expect("connect must succeed offline");
    let entries = backend
        .list_dir("/", &ListOptions::default())
        .expect("list must succeed");
    let file_entry = entries
        .iter()
        .find(|e| e.name == "data.bin")
        .expect("data.bin entry");
    assert_eq!(file_entry.size, 12);
    assert!(!file_entry.is_dir);
    assert!(
        file_entry.modified_ms > 0,
        "lastModified must parse from RFC 1123"
    );
    let dir_entry = entries.iter().find(|e| e.name == "sub").expect("sub entry");
    assert!(dir_entry.is_dir);
    assert_eq!(dir_entry.size, 0);
}

#[test]
fn properties_come_from_head_headers_with_no_body() {
    let f = fakes();
    let fs_name = "fs-head";
    f.adls.create_filesystem(fs_name);
    f.adls.seed_file(fs_name, "props.bin", b"seven b");

    let (agent, base) = raw_client(f);
    let response = agent
        .head(&format!("{base}{fs_name}/props.bin?action=getStatus"))
        .set("Authorization", &format!("Bearer {STATIC_BEARER}"))
        .set("x-ms-version", "2023-11-03")
        .call()
        .expect("HEAD must succeed");
    assert_eq!(response.header("x-ms-resource-type"), Some("file"));
    assert_eq!(response.header("Content-Length"), Some("7"));
    assert!(
        orka_core::vfs::http::parse_rfc1123_to_ms(response.header("Last-Modified").unwrap_or(""))
            .is_some(),
        "Last-Modified must be RFC 1123"
    );
    assert!(response.header("ETag").is_some());
    let mut body = Vec::new();
    response.into_reader().read_to_end(&mut body).expect("read");
    assert!(body.is_empty(), "a HEAD answer carries no body");

    // The old client shape, GET with action=getStatus and a JSON
    // body, is not a documented operation; the fake refuses it.
    assert_eq!(
        status_of(raw_get(
            &agent,
            &format!("{base}{fs_name}/props.bin?action=getStatus")
        )),
        400,
        "GET ?action=getStatus must be rejected"
    );

    // The backend's stat reads the headers.
    let config = config_for(
        "conn-head",
        fs_name,
        f.adls.host_with_port(),
        AuthMethod::OAuthToken,
    );
    let secrets = RecordingSecrets::seeded(&config.id, STATIC_BEARER);
    let backend = AdlsFactory
        .connect(&config, secrets)
        .expect("connect must succeed offline");
    let stat = backend.stat("/props.bin").expect("stat must succeed");
    assert_eq!(stat.size, 7);
    assert!(!stat.is_dir);
    assert!(stat.modified_ms > 0);
    let head_count = requests_for(f, fs_name)
        .iter()
        .filter(|r| r.method == "HEAD" && r.path.ends_with("props.bin"))
        .count();
    assert!(head_count >= 1, "stat must use HEAD");
    let err = backend
        .stat("/missing.bin")
        .expect_err("a missing path must fail");
    assert!(
        err.contains("not found"),
        "a HEAD 404 must read as not found: {err}"
    );
}

#[test]
fn a_ranged_read_is_honored() {
    let f = fakes();
    let fs_name = "fs-range";
    f.adls.create_filesystem(fs_name);
    f.adls.seed_file(fs_name, "range.bin", b"0123456789");

    let (agent, base) = raw_client(f);
    let url = format!("{base}{fs_name}/range.bin");
    let response = agent
        .get(&url)
        .set("Authorization", &format!("Bearer {STATIC_BEARER}"))
        .set("x-ms-version", "2023-11-03")
        .set("Range", "bytes=2-5")
        .call()
        .expect("a ranged read must succeed");
    assert_eq!(response.status(), 206);
    assert_eq!(response.header("Content-Range"), Some("bytes 2-5/10"));
    assert_eq!(response.into_string().expect("body"), "2345");

    let response = agent
        .get(&url)
        .set("Authorization", &format!("Bearer {STATIC_BEARER}"))
        .set("x-ms-version", "2023-11-03")
        .set("Range", "bytes=7-")
        .call()
        .expect("an open-ended range must succeed");
    assert_eq!(response.status(), 206);
    assert_eq!(response.into_string().expect("body"), "789");

    let unranged = raw_get(&agent, &url).expect("a plain read must succeed");
    assert_eq!(unranged.status(), 200);
    assert_eq!(unranged.into_string().expect("body"), "0123456789");
}

// --- 9. The fake rejects the shapes the old backend sent ---

#[test]
fn the_fake_rejects_appends_without_a_create_or_a_correct_position() {
    let f = fakes();
    let fs_name = "fs-strict";
    f.adls.create_filesystem(fs_name);
    let (agent, base) = raw_client(f);
    let file = format!("{base}{fs_name}/strict.bin");

    // Append before create: the path does not exist.
    assert_eq!(
        status_of(raw_send(
            &agent,
            "PATCH",
            &format!("{file}?action=append&position=0"),
            b"abc"
        )),
        404,
        "an append to a path that was never created must be 404"
    );

    // A create must carry Content-Length: 0. ureq sends none for a
    // body-less PUT, which is what the old mkdir did.
    let bare_put = agent
        .put(&format!("{file}?resource=file"))
        .set("Authorization", &format!("Bearer {STATIC_BEARER}"))
        .set("x-ms-version", "2023-11-03")
        .call()
        .map_err(Box::new);
    assert_eq!(
        status_of(bare_put),
        411,
        "a create with no Content-Length must be 411"
    );
    assert_eq!(
        status_of(raw_send(
            &agent,
            "PUT",
            &format!("{file}?resource=file"),
            b""
        )),
        201
    );

    // Append without a position: the old client's shape.
    assert_eq!(
        status_of(raw_send(
            &agent,
            "PATCH",
            &format!("{file}?action=append"),
            b"abc"
        )),
        400,
        "an append with no position must be 400"
    );
    // Append at the wrong offset.
    assert_eq!(
        status_of(raw_send(
            &agent,
            "PATCH",
            &format!("{file}?action=append&position=5"),
            b"abc"
        )),
        400,
        "an append at an offset that is not the current length must be 400"
    );
    assert_eq!(
        status_of(raw_send(
            &agent,
            "PATCH",
            &format!("{file}?action=append&position=0"),
            b"abc"
        )),
        202
    );
    assert_eq!(
        status_of(raw_send(
            &agent,
            "PATCH",
            &format!("{file}?action=append&position=3"),
            b"de"
        )),
        202
    );

    // Flush at the wrong length, then at the right one.
    assert_eq!(
        status_of(raw_send(
            &agent,
            "PATCH",
            &format!("{file}?action=flush&position=3&close=true"),
            b""
        )),
        400,
        "a flush at a position other than the appended length must be 400"
    );
    assert_eq!(
        status_of(raw_send(
            &agent,
            "PATCH",
            &format!("{file}?action=flush&position=5&close=true"),
            b""
        )),
        200
    );
    assert_eq!(
        raw_get(&agent, &file)
            .expect("read")
            .into_string()
            .expect("body"),
        "abcde"
    );

    // A second create truncates: the old content is gone.
    assert_eq!(
        status_of(raw_send(
            &agent,
            "PUT",
            &format!("{file}?resource=file"),
            b""
        )),
        201
    );
    assert_eq!(
        status_of(raw_send(
            &agent,
            "PATCH",
            &format!("{file}?action=flush&position=0&close=true"),
            b""
        )),
        200
    );
    assert_eq!(
        raw_get(&agent, &file)
            .expect("read")
            .into_string()
            .expect("body"),
        ""
    );
}
